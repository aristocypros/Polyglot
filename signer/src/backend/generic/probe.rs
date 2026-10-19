//! Fail-closed startup capability probe (`signer/src/backend/generic/probe.rs`).
//!
//! Implements Task 11 of Milestone 2 (Section 8 and Section 10 of `Specs.md`):
//!
//! The signer refuses to start, and states why, unless steps 1–4 succeed and step 5 leaves
//! zero leftover session objects on the token:
//! 1. **Step 1 (Library & Token)**: Load the PKCS#11 library, resolve the configured token slot,
//!    confirm the token is present and initialized, and open an authenticated RW user session.
//! 2. **Step 2 (`CKM_AES_GCM` Mechanism & Live Wrap/Unwrap Self-Test)**: Query `C_GetMechanismList`
//!    for `CKM_AES_GCM` and execute a live 64-byte seed wrap + unwrap round-trip with canonical
//!    AEAD Associated Authenticated Data (`AAD`), plus negative AAD-mismatch and ciphertext-tamper
//!    checks.
//! 3. **Step 3 (KEK Attribute Verification)**: Locate the KEK by label (`"kek-v1"`) and verify
//!    `CKA_CLASS = CKO_SECRET_KEY`, `CKA_KEY_TYPE = CKK_AES`, `CKA_EXTRACTABLE = false`,
//!    `CKA_SENSITIVE = true`, `CKA_ENCRYPT = true`, `CKA_DECRYPT = true`, 256-bit key length,
//!    and no disallowed usage flags (`CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`).
//! 4. **Step 4 (Built-In Derivation Vectors)**: Run the compiled-in published BIP32 (`secp256k1`,
//!    vectors 1–3) and SLIP10 (`ed25519`, vectors 1–2) self-tests via
//!    [`crate::derive::run_derivation_self_test`].
//! 5. **Step 5 (Per-Scheme Session-Object Signing Probe)**: For each v1 scheme
//!    (`(Scheme::Bip32, Curve::Secp256k1)` and `(Scheme::Slip10, Curve::Ed25519)`), derive a
//!    throwaway child key from a throwaway 64-byte seed, import it as a short-lived PKCS#11
//!    session object (`CKA_TOKEN = false`, `CKA_EXTRACTABLE = false`), sign, verify the signature
//!    against the derived public key, destroy the session object, and assert zero leftover session
//!    objects via `C_FindObjects`. If a curve fails in SoftHSM/PKCS#11, mark that scheme as
//!    [`SigningLocation::Software`] in [`Capabilities`] (after verifying the software fallback)
//!    without crashing; if steps 1–4 fail, abort startup with a descriptive [`BackendError::ProbeFailed`].

use std::fmt;

use cryptoki::mechanism::MechanismType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::backend::generic::crypto::{
    postprocess_ecdsa_signature, postprocess_ed25519_signature,
    sign_ed25519_software_with_pubkey, sign_secp256k1_ecdsa_software_with_pubkey,
    verify_ed25519_signature, verify_secp256k1_ecdsa,
};
use crate::backend::{
    build_aad_checked, derive_bip32_from_slice, derive_slip10_from_slice, BackendError,
    Capabilities, Curve, ProtectionLevel, Scheme, SigningLocation, DEFAULT_SEED_VERSION,
    WALLET_SEED_LEN, WRAPPED_SEED_LEN,
};
use crate::derive::{run_derivation_self_test, DerivationSelfTestError, HARDENED_FLAG};
use crate::pkcs11session::{
    parse_wrapped_seed, KekMetadata, Pkcs11Config, Pkcs11Library, Pkcs11Session,
};

/// Default backend identifier reported in [`Capabilities::backend`] for the SoftHSM generic tier.
pub const DEFAULT_GENERIC_BACKEND_NAME: &str = "softhsm-generic";

/// Default wrap mechanism identifier reported in [`Capabilities::wrap_mechanism`].
pub const DEFAULT_WRAP_MECHANISM_NAME: &str = "CKM_AES_GCM";

/// Reserved wallet identifier used exclusively in the Step 2 `CKM_AES_GCM` wrap/unwrap self-test.
pub const PROBE_SELFTEST_WALLET_ID: &str = "__probe_selftest__";

/// Reserved mismatched wallet identifier used to verify AAD rejection during Step 2 self-test.
pub const PROBE_WRONG_AAD_WALLET_ID: &str = "__probe_wrong_aad__";

/// Representative BIP32 derivation path (`m/44'/0'/0'/0/0`) used for the Step 5 `secp256k1` probe.
pub const PROBE_BIP32_PATH: [u32; 5] = [
    44 | HARDENED_FLAG,
    0 | HARDENED_FLAG,
    0 | HARDENED_FLAG,
    0,
    0,
];

/// Representative SLIP10 derivation path (`m/44'/501'/0'/0'`) used for the Step 5 `ed25519` probe.
pub const PROBE_SLIP10_PATH: [u32; 4] = [
    44 | HARDENED_FLAG,
    501 | HARDENED_FLAG,
    0 | HARDENED_FLAG,
    0 | HARDENED_FLAG,
];

/// Domain-separated message hashed with SHA-256 to produce the 32-byte digest for Step 5 `secp256k1` signing.
pub const PROBE_SECP256K1_DOMAIN_MSG: &[u8] = b"polyglot-startup-probe-secp256k1-v1";

/// Domain-separated message signed directly during Step 5 `ed25519` signing.
pub const PROBE_ED25519_MESSAGE: &[u8] = b"polyglot-startup-probe-ed25519-v1";

/// Identifies which of the 5 startup capability probe steps was executing when a failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStep {
    /// Step 1: Load PKCS#11 library, resolve configured token slot, and open an authenticated session.
    Step1LibraryAndToken,
    /// Step 2: Verify `CKM_AES_GCM` in `C_GetMechanismList` and run live wrap + unwrap self-test with AAD.
    Step2AesGcmMechanismAndSelfTest,
    /// Step 3: Locate KEK (`kek-v1`) and verify `CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`, encrypt/decrypt only.
    Step3KekValidation,
    /// Step 4: Run built-in published BIP32 and SLIP10 test vectors at boot.
    Step4DerivationVectors,
    /// Step 5: Per-scheme ephemeral session-object signing self-test and session-object hygiene check.
    Step5CurveSigningSelfTest,
}

impl ProbeStep {
    /// Returns the 1-based step number (`1..=5`) from Section 8 of `Specs.md`.
    pub const fn number(&self) -> u8 {
        match self {
            ProbeStep::Step1LibraryAndToken => 1,
            ProbeStep::Step2AesGcmMechanismAndSelfTest => 2,
            ProbeStep::Step3KekValidation => 3,
            ProbeStep::Step4DerivationVectors => 4,
            ProbeStep::Step5CurveSigningSelfTest => 5,
        }
    }

    /// Returns a concise identifier for the probe step.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProbeStep::Step1LibraryAndToken => "step_1_library_and_token",
            ProbeStep::Step2AesGcmMechanismAndSelfTest => "step_2_aes_gcm_mechanism_and_selftest",
            ProbeStep::Step3KekValidation => "step_3_kek_validation",
            ProbeStep::Step4DerivationVectors => "step_4_derivation_vectors",
            ProbeStep::Step5CurveSigningSelfTest => "step_5_curve_signing_selftest",
        }
    }
}

impl fmt::Display for ProbeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {} ({})", self.number(), self.as_str())
    }
}

/// Stable machine-readable error codes for fail-closed startup probe failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeFailureCode {
    /// Step 1 failed: PKCS#11 library could not be loaded, slot/token not present, or user login failed.
    LibraryOrSlotFailed,
    /// Step 2 failed: `C_GetMechanismList` on the configured slot does not include `CKM_AES_GCM`.
    MissingAesGcmMechanism,
    /// Step 2 failed: live `CKM_AES_GCM` wrap + unwrap self-test with AAD failed or did not enforce AAD.
    AesGcmSelfTestFailed,
    /// Step 3 failed: KEK (`kek-v1`) was not found on the token.
    KekNotFound,
    /// Step 3 failed: KEK (`kek-v1`) is extractable (`CKA_EXTRACTABLE=true`), not sensitive,
    /// wrong key type/size, or permits disallowed operations.
    InvalidKekAttributes,
    /// Step 4 failed: built-in BIP32 or SLIP10 derivation test vectors diverged at boot.
    DerivationSelfTestFailed,
    /// Step 5 failed: ephemeral session key object was not destroyed (`C_FindObjects` non-empty).
    SessionObjectHygieneFailed,
    /// Step 5 failed: software signing fallback failed to sign or verify for a scheme.
    SoftwareFallbackFailed,
}

impl ProbeFailureCode {
    /// Returns the canonical snake_case code string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProbeFailureCode::LibraryOrSlotFailed => "library_or_slot_failed",
            ProbeFailureCode::MissingAesGcmMechanism => "missing_aes_gcm_mechanism",
            ProbeFailureCode::AesGcmSelfTestFailed => "aes_gcm_self_test_failed",
            ProbeFailureCode::KekNotFound => "kek_not_found",
            ProbeFailureCode::InvalidKekAttributes => "invalid_kek_attributes",
            ProbeFailureCode::DerivationSelfTestFailed => "derivation_self_test_failed",
            ProbeFailureCode::SessionObjectHygieneFailed => "session_object_hygiene_failed",
            ProbeFailureCode::SoftwareFallbackFailed => "software_fallback_failed",
        }
    }
}

impl fmt::Display for ProbeFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detailed, structured startup probe failure returned by [`run_startup_probe_checked`]
/// and [`probe_library_checked`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("startup probe {step} failed [{code}]: {message}")]
pub struct ProbeFailure {
    /// Which of the 5 startup probe steps failed.
    pub step: ProbeStep,
    /// Machine-readable failure reason code.
    pub code: ProbeFailureCode,
    /// Human-readable explanation of why the signer refused to start.
    pub message: String,
    /// Underlying [`BackendError`] that triggered the probe abort.
    pub source_error: BackendError,
}

impl ProbeFailure {
    /// Creates a new [`ProbeFailure`].
    pub fn new(
        step: ProbeStep,
        code: ProbeFailureCode,
        message: impl Into<String>,
        source_error: BackendError,
    ) -> Self {
        Self {
            step,
            code,
            message: message.into(),
            source_error,
        }
    }

    /// Converts this structured failure into [`BackendError::ProbeFailed`].
    pub fn to_backend_error(&self) -> BackendError {
        BackendError::ProbeFailed(format!(
            "{} [{}]: {}",
            self.step, self.code, self.message
        ))
    }

    /// Consumes this structured failure and converts it into [`BackendError::ProbeFailed`].
    pub fn into_backend_error(self) -> BackendError {
        self.to_backend_error()
    }
}

impl From<ProbeFailure> for BackendError {
    fn from(failure: ProbeFailure) -> Self {
        failure.into_backend_error()
    }
}

/// Extracts the [`ProbeFailureCode`] embedded in a [`BackendError::ProbeFailed`] message, if present.
pub fn extract_probe_failure_code(err: &BackendError) -> Option<ProbeFailureCode> {
    let BackendError::ProbeFailed(msg) = err else {
        return None;
    };
    const ALL_CODES: [ProbeFailureCode; 8] = [
        ProbeFailureCode::LibraryOrSlotFailed,
        ProbeFailureCode::MissingAesGcmMechanism,
        ProbeFailureCode::AesGcmSelfTestFailed,
        ProbeFailureCode::KekNotFound,
        ProbeFailureCode::InvalidKekAttributes,
        ProbeFailureCode::DerivationSelfTestFailed,
        ProbeFailureCode::SessionObjectHygieneFailed,
        ProbeFailureCode::SoftwareFallbackFailed,
    ];
    for code in ALL_CODES {
        let bracketed = format!("[{}]", code.as_str());
        if msg.contains(&bracketed) {
            return Some(code);
        }
    }
    None
}

/// Configuration for executing the fail-closed startup capability probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    /// PKCS#11 library, slot, PIN file, and KEK label configuration.
    pub pkcs11: Pkcs11Config,
    /// Backend identifier published in [`Capabilities::backend`] (default: `"softhsm-generic"`).
    pub backend_name: String,
    /// Protection level published in [`Capabilities::protection_level`] (default: [`ProtectionLevel::GenericDev`]).
    pub protection_level: ProtectionLevel,
}

impl ProbeConfig {
    /// Creates a [`ProbeConfig`] with default generic-dev settings (`backend = "softhsm-generic"`,
    /// `protection_level = ProtectionLevel::GenericDev`).
    pub fn new(pkcs11: Pkcs11Config) -> Self {
        Self {
            pkcs11,
            backend_name: DEFAULT_GENERIC_BACKEND_NAME.to_string(),
            protection_level: ProtectionLevel::GenericDev,
        }
    }

    /// Creates a [`ProbeConfig`] with an explicit backend name and protection level
    /// (e.g., `"pkcs11-generic"` and [`ProtectionLevel::GenericHsm`] for a hardware PKCS#11 HSM).
    pub fn with_backend_and_protection(
        pkcs11: Pkcs11Config,
        backend_name: impl Into<String>,
        protection_level: ProtectionLevel,
    ) -> Self {
        Self {
            pkcs11,
            backend_name: backend_name.into(),
            protection_level,
        }
    }
}

/// Outcome of probing a single `(Scheme, Curve)` pair in Step 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurveProbeOutcome {
    /// Probed derivation scheme (`Bip32` or `Slip10`).
    pub scheme: Scheme,
    /// Probed elliptic curve (`Secp256k1` or `Ed25519`).
    pub curve: Curve,
    /// Determined signing location (`Hsm` if PKCS#11 session-object sign + verify succeeded,
    /// `Software` if the HSM lacked the curve/mechanism and software fallback succeeded).
    pub signing_location: SigningLocation,
    /// Diagnostic reason when `signing_location == SigningLocation::Software` (`None` when `Hsm`).
    pub hsm_fallback_reason: Option<String>,
}

impl CurveProbeOutcome {
    /// Returns `true` if this scheme/curve signs inside the HSM (`SigningLocation::Hsm`).
    pub const fn signs_in_hsm(&self) -> bool {
        self.signing_location.is_hsm()
    }
}

/// Complete report returned by a successful 5-step startup capability probe.
///
/// Contains the initialized [`Pkcs11Library`] handle, the probed [`Capabilities`] ready to
/// serve `GET /v1/signer` and [`crate::backend::Backend::capabilities`], and per-curve probe
/// diagnostics.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    /// Initialized PKCS#11 library handle bound to the verified token slot.
    pub library: Pkcs11Library,
    /// Probed backend capabilities (`backend`, `protection_level`, `schemes`, `max_depth`,
    /// `wrap_mechanism`, `derives_in_hsm`).
    pub capabilities: Capabilities,
    /// Trimmed `CK_TOKEN_INFO.label` of the probed PKCS#11 token.
    pub token_label: String,
    /// Verified KEK label (`"kek-v1"`).
    pub kek_label: String,
    /// Step 5 probe outcome for `(Scheme::Bip32, Curve::Secp256k1)`.
    pub secp256k1_outcome: CurveProbeOutcome,
    /// Step 5 probe outcome for `(Scheme::Slip10, Curve::Ed25519)`.
    pub ed25519_outcome: CurveProbeOutcome,
}

impl ProbeReport {
    /// Returns the probed [`SigningLocation`] (`Hsm` or `Software`) for `(scheme, curve)`.
    pub fn signing_location(&self, scheme: Scheme, curve: Curve) -> Option<SigningLocation> {
        self.capabilities.signing_location(scheme, curve)
    }
}

/// Executes the 5-step fail-closed startup capability probe from `config` and returns the
/// [`ProbeReport`] (or [`BackendError::ProbeFailed`] if any of steps 1–4 or hygiene checks fail).
pub fn run_startup_probe(config: ProbeConfig) -> Result<ProbeReport, BackendError> {
    run_startup_probe_checked(config).map_err(ProbeFailure::into_backend_error)
}

/// Executes the 5-step fail-closed startup capability probe from `pkcs11_config` using default
/// generic-tier settings (`"softhsm-generic"`, [`ProtectionLevel::GenericDev`]) and returns
/// the resulting [`Capabilities`].
pub fn probe_pkcs11_config(pkcs11_config: Pkcs11Config) -> Result<Capabilities, BackendError> {
    let report = run_startup_probe(ProbeConfig::new(pkcs11_config))?;
    Ok(report.capabilities)
}

/// Executes the 5-step fail-closed startup capability probe from `config`, returning a
/// structured [`ProbeFailure`] on abort.
pub fn run_startup_probe_checked(config: ProbeConfig) -> Result<ProbeReport, ProbeFailure> {
    if config.backend_name.trim().is_empty() {
        let err = BackendError::Config("backend_name must not be empty".to_string());
        return Err(ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            "backend_name must not be empty",
            err,
        ));
    }

    // Step 1: Load PKCS#11 library and verify configured token slot is present.
    let library = probe_step1_load_library(config.pkcs11)?;

    probe_library_checked(&library, config.backend_name, config.protection_level)
}

/// Executes the 5-step fail-closed startup capability probe against an already-opened
/// [`Pkcs11Library`], returning a [`ProbeReport`] or [`BackendError::ProbeFailed`].
pub fn probe_library(
    library: &Pkcs11Library,
    backend_name: impl Into<String>,
    protection_level: ProtectionLevel,
) -> Result<ProbeReport, BackendError> {
    probe_library_checked(library, backend_name, protection_level)
        .map_err(ProbeFailure::into_backend_error)
}

/// Executes the 5-step fail-closed startup capability probe against an already-opened
/// [`Pkcs11Library`], returning a [`ProbeReport`] or a structured [`ProbeFailure`].
pub fn probe_library_checked(
    library: &Pkcs11Library,
    backend_name: impl Into<String>,
    protection_level: ProtectionLevel,
) -> Result<ProbeReport, ProbeFailure> {
    probe_library_with_derivation_hook(
        library,
        backend_name,
        protection_level,
        run_derivation_self_test,
    )
}

/// Internal probe entry point allowing unit tests to inject a custom Step 4 derivation self-test
/// function while exercising the exact production 5-step pipeline.
pub(crate) fn probe_library_with_derivation_hook<F>(
    library: &Pkcs11Library,
    backend_name: impl Into<String>,
    protection_level: ProtectionLevel,
    derivation_self_test_fn: F,
) -> Result<ProbeReport, ProbeFailure>
where
    F: FnOnce() -> Result<(), DerivationSelfTestError>,
{
    let backend_name = backend_name.into();
    if backend_name.trim().is_empty() {
        let err = BackendError::Config("backend_name must not be empty".to_string());
        return Err(ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            "backend_name must not be empty",
            err,
        ));
    }

    // Step 1 (continued): Verify token is present/initialized on the resolved slot and open RW user session.
    let (token_label, session) = probe_step1_verify_token_and_open_session(library)?;

    // Ensure session starts with zero leftover session objects.
    verify_session_hygiene_or_fail(&session, "before startup probe self-tests")?;

    // Step 2a: Query C_GetMechanismList for CKM_AES_GCM.
    probe_step2_check_aes_gcm_mechanism(library)?;

    // Step 3: Locate KEK (`kek-v1`) and verify CKA_EXTRACTABLE=false, CKA_SENSITIVE=true,
    // encrypt/decrypt only (refuse to start if missing or extractable).
    let kek_meta = probe_step3_validate_kek(&session)?;

    // Step 2b: Execute live CKM_AES_GCM wrap + unwrap self-test round-trip with AAD
    // (plus negative AAD mismatch and tampered ciphertext checks).
    probe_step2_aes_gcm_wrap_unwrap_selftest(&session)?;

    // Step 4: Run built-in BIP32 and SLIP10 test vectors at boot (refuse to start on mismatch).
    probe_step4_derivation_vectors_with(derivation_self_test_fn)?;

    // Step 5: For each scheme (Bip32/Secp256k1 and Slip10/Ed25519), derive a throwaway child key,
    // load it as a session object, sign, verify signature with the public key, and destroy the
    // session object. If a curve fails in SoftHSM, mark that scheme as SigningLocation::Software.
    let throwaway_seed = session.generate_seed().map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step5CurveSigningSelfTest,
            ProbeFailureCode::LibraryOrSlotFailed,
            format!("failed to generate throwaway 64-byte seed via C_GenerateRandom: {err}"),
            err,
        )
    })?;

    let secp256k1_outcome = probe_step5_secp256k1_signing(&session, &throwaway_seed)?;
    let ed25519_outcome = probe_step5_ed25519_signing(&session, &throwaway_seed)?;

    // Final hygiene verification before closing the probe session.
    verify_session_hygiene_or_fail(&session, "after startup probe completion")?;
    session.close();

    let capabilities = Capabilities::new_generic(
        backend_name,
        protection_level,
        secp256k1_outcome.signing_location,
        ed25519_outcome.signing_location,
    );

    Ok(ProbeReport {
        library: library.clone(),
        capabilities,
        token_label,
        kek_label: kek_meta.label,
        secp256k1_outcome,
        ed25519_outcome,
    })
}

/// **Step 1a**: Loads the PKCS#11 library and resolves the configured token slot.
pub fn probe_step1_load_library(config: Pkcs11Config) -> Result<Pkcs11Library, ProbeFailure> {
    Pkcs11Library::open(config).map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            format!("failed to load PKCS#11 library or resolve configured token slot: {err}"),
            err,
        )
    })
}

/// **Step 1b**: Queries `C_GetTokenInfo` to confirm the token is present and initialized,
/// and opens an authenticated read-write user session (`CKU_USER`).
pub fn probe_step1_verify_token_and_open_session(
    library: &Pkcs11Library,
) -> Result<(String, Pkcs11Session), ProbeFailure> {
    let token_info = library.token_info().map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            format!(
                "PKCS#11 token not present or C_GetTokenInfo failed on slot {}: {err}",
                library.slot().id()
            ),
            err,
        )
    })?;

    if !token_info.token_initialized() {
        let err = BackendError::Pkcs11(format!(
            "PKCS#11 token in slot {} is not initialized",
            library.slot().id()
        ));
        return Err(ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            format!(
                "PKCS#11 token in slot {} is not initialized",
                library.slot().id()
            ),
            err,
        ));
    }

    let token_label = token_info.label().trim().to_string();

    let session = library.open_rw_session().map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step1LibraryAndToken,
            ProbeFailureCode::LibraryOrSlotFailed,
            format!(
                "failed to open authenticated PKCS#11 RW user session on token '{token_label}': {err}"
            ),
            err,
        )
    })?;

    Ok((token_label, session))
}

/// **Step 2a**: Queries `C_GetMechanismList` on the resolved slot and verifies that
/// `CKM_AES_GCM` is supported.
pub fn probe_step2_check_aes_gcm_mechanism(library: &Pkcs11Library) -> Result<(), ProbeFailure> {
    let supports_aes_gcm = library
        .supports_mechanism(MechanismType::AES_GCM)
        .map_err(|err| {
            ProbeFailure::new(
                ProbeStep::Step2AesGcmMechanismAndSelfTest,
                ProbeFailureCode::MissingAesGcmMechanism,
                format!("failed to query C_GetMechanismList for CKM_AES_GCM: {err}"),
                err,
            )
        })?;

    if !supports_aes_gcm {
        let msg = format!(
            "PKCS#11 slot {} does not advertise required mechanism CKM_AES_GCM in C_GetMechanismList",
            library.slot().id()
        );
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::MissingAesGcmMechanism,
            msg.clone(),
            BackendError::Pkcs11(msg),
        ));
    }

    Ok(())
}

/// **Step 3**: Locates the configured KEK (`"kek-v1"`) on the token and verifies that
/// `CKA_CLASS = CKO_SECRET_KEY`, `CKA_KEY_TYPE = CKK_AES`, `CKA_EXTRACTABLE = false`,
/// `CKA_SENSITIVE = true`, `CKA_ENCRYPT = true`, `CKA_DECRYPT = true`, 256-bit length, and
/// no disallowed usage flags (`CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`)
/// are enabled.
pub fn probe_step3_validate_kek(session: &Pkcs11Session) -> Result<KekMetadata, ProbeFailure> {
    session.verify_kek().map_err(|err| match &err {
        BackendError::KekNotFound(label) => ProbeFailure::new(
            ProbeStep::Step3KekValidation,
            ProbeFailureCode::KekNotFound,
            format!("required HSM KEK '{label}' not found on token"),
            err,
        ),
        BackendError::InvalidKekAttributes(details) => ProbeFailure::new(
            ProbeStep::Step3KekValidation,
            ProbeFailureCode::InvalidKekAttributes,
            format!("HSM KEK '{}' failed security attribute verification: {details}", session.kek_label()),
            err,
        ),
        other => ProbeFailure::new(
            ProbeStep::Step3KekValidation,
            ProbeFailureCode::InvalidKekAttributes,
            format!("failed to locate or validate HSM KEK '{}': {other}", session.kek_label()),
            err,
        ),
    })
}

/// **Step 2b**: Executes a live `CKM_AES_GCM` wrap + unwrap self-test round-trip with canonical
/// AAD on `session`, verifying:
/// 1. 64 random seed bytes from `C_GenerateRandom` wrap into a 92-byte blob (`12B IV || 64B ciphertext || 16B tag`).
/// 2. The ciphertext differs from the clear seed.
/// 3. Unwrapping with the exact AAD recovers the identical 64-byte seed into a `Zeroizing` buffer.
/// 4. Unwrapping with a different AAD is rejected (AAD binding is enforced).
/// 5. Unwrapping a tampered ciphertext/tag is rejected.
pub fn probe_step2_aes_gcm_wrap_unwrap_selftest(
    session: &Pkcs11Session,
) -> Result<(), ProbeFailure> {
    let test_seed: Zeroizing<[u8; WALLET_SEED_LEN]> = session.generate_seed().map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            format!("CKM_AES_GCM self-test failed to generate 64-byte seed via C_GenerateRandom: {err}"),
            err,
        )
    })?;

    let probe_aad = build_aad_checked(
        PROBE_SELFTEST_WALLET_ID,
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        session.kek_label(),
    )
    .map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            format!("CKM_AES_GCM self-test failed to build canonical AAD: {err}"),
            err,
        )
    })?;

    let wrapped_blob = session.wrap_seed(&*test_seed, &probe_aad).map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            format!("CKM_AES_GCM self-test wrap_seed failed: {err}"),
            err,
        )
    })?;

    if wrapped_blob.len() != WRAPPED_SEED_LEN {
        let msg = format!(
            "CKM_AES_GCM self-test wrap_seed returned {} bytes; expected {WRAPPED_SEED_LEN} bytes",
            wrapped_blob.len()
        );
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            msg.clone(),
            BackendError::WrapFailed(msg),
        ));
    }

    let parsed_blob = parse_wrapped_seed(&wrapped_blob).map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            format!("CKM_AES_GCM self-test produced malformed wrapped seed blob: {err}"),
            err,
        )
    })?;

    if &parsed_blob.ciphertext[..] == &test_seed[..] {
        let msg = "CKM_AES_GCM self-test ciphertext is identical to plaintext seed".to_string();
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            msg.clone(),
            BackendError::WrapFailed(msg),
        ));
    }

    let unwrapped_seed = session
        .unwrap_seed(&wrapped_blob, &probe_aad)
        .map_err(|err| {
            ProbeFailure::new(
                ProbeStep::Step2AesGcmMechanismAndSelfTest,
                ProbeFailureCode::AesGcmSelfTestFailed,
                format!("CKM_AES_GCM self-test unwrap_seed failed with matching AAD: {err}"),
                err,
            )
        })?;

    if &unwrapped_seed[..] != &test_seed[..] {
        let msg =
            "CKM_AES_GCM self-test round-trip mismatch: unwrapped seed does not match original seed"
                .to_string();
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            msg.clone(),
            BackendError::UnwrapFailed(msg),
        ));
    }

    // Negative check 1: Wrong AAD must fail closed.
    let wrong_aad = build_aad_checked(
        PROBE_WRONG_AAD_WALLET_ID,
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        session.kek_label(),
    )
    .map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            format!("CKM_AES_GCM self-test failed to construct wrong AAD: {err}"),
            err,
        )
    })?;

    if session.unwrap_seed(&wrapped_blob, &wrong_aad).is_ok() {
        let msg =
            "CKM_AES_GCM self-test failed: C_Decrypt accepted a wrapped seed with mismatched AAD"
                .to_string();
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            msg.clone(),
            BackendError::UnwrapFailed(msg),
        ));
    }

    // Negative check 2: Tampered ciphertext must fail closed.
    let mut tampered_blob = wrapped_blob;
    tampered_blob[12] ^= 0x01;
    if session.unwrap_seed(&tampered_blob, &probe_aad).is_ok() {
        let msg =
            "CKM_AES_GCM self-test failed: C_Decrypt accepted a tampered ciphertext".to_string();
        return Err(ProbeFailure::new(
            ProbeStep::Step2AesGcmMechanismAndSelfTest,
            ProbeFailureCode::AesGcmSelfTestFailed,
            msg.clone(),
            BackendError::UnwrapFailed(msg),
        ));
    }

    Ok(())
}

/// **Step 4**: Executes the built-in BIP32 (`secp256k1` vectors 1–3) and SLIP10 (`ed25519`
/// vectors 1–2) derivation self-test at boot.
pub fn probe_step4_derivation_vectors() -> Result<(), ProbeFailure> {
    probe_step4_derivation_vectors_with(run_derivation_self_test)
}

fn probe_step4_derivation_vectors_with<F>(derivation_self_test_fn: F) -> Result<(), ProbeFailure>
where
    F: FnOnce() -> Result<(), DerivationSelfTestError>,
{
    derivation_self_test_fn().map_err(|err| {
        let msg = format!("built-in BIP32/SLIP10 derivation vectors failed at boot: {err}");
        ProbeFailure::new(
            ProbeStep::Step4DerivationVectors,
            ProbeFailureCode::DerivationSelfTestFailed,
            msg,
            BackendError::DerivationSelfTest(err),
        )
    })
}

/// **Step 5a (`Bip32` / `Secp256k1`)**: Derives a throwaway `secp256k1` child key, loads it as a
/// short-lived PKCS#11 session object (`CKK_EC`, OID `1.3.132.0.10`), signs a 32-byte digest with
/// `CKM_ECDSA`, normalizes and verifies the signature against the derived 33-byte public key,
/// destroys the session object, and verifies zero leftover session objects.
///
/// If the HSM lacks `secp256k1` or `CKM_ECDSA`, verifies the software fallback and marks
/// `(Scheme::Bip32, Curve::Secp256k1)` as [`SigningLocation::Software`].
pub fn probe_step5_secp256k1_signing(
    session: &Pkcs11Session,
    throwaway_seed: &[u8; WALLET_SEED_LEN],
) -> Result<CurveProbeOutcome, ProbeFailure> {
    let derived_key = derive_bip32_from_slice(throwaway_seed, &PROBE_BIP32_PATH).map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step5CurveSigningSelfTest,
            ProbeFailureCode::DerivationSelfTestFailed,
            format!("failed to derive throwaway BIP32 secp256k1 key during Step 5 probe: {err}"),
            err,
        )
    })?;

    let digest_ga = Sha256::digest(PROBE_SECP256K1_DOMAIN_MSG);
    let mut digest32 = [0u8; 32];
    digest32.copy_from_slice(&digest_ga);

    // Attempt HSM session-object signing (imports key, signs with CKM_ECDSA, and immediately
    // calls C_DestroyObject via SessionKeyGuard).
    let hsm_attempt: Result<(), BackendError> = (|| {
        let raw_sig = session.sign_secp256k1_digest(derived_key.private_key(), &digest32)?;
        let normalized_sig = postprocess_ecdsa_signature(
            &raw_sig,
            &digest32,
            derived_key.public_key(),
            true,
        )?;
        let sig_64: [u8; 64] = normalized_sig
            .as_bytes()
            .try_into()
            .map_err(|_| BackendError::Crypto("normalized ECDSA signature length != 64".to_string()))?;
        verify_secp256k1_ecdsa(derived_key.public_key(), &digest32, &sig_64)?;
        Ok(())
    })();

    // Regardless of whether HSM signing succeeded or failed, verify zero leftover session objects.
    verify_session_hygiene_or_fail(session, "after secp256k1 session-object signing probe")?;

    match hsm_attempt {
        Ok(()) => Ok(CurveProbeOutcome {
            scheme: Scheme::Bip32,
            curve: Curve::Secp256k1,
            signing_location: SigningLocation::Hsm,
            hsm_fallback_reason: None,
        }),
        Err(hsm_err) => {
            // Verify that the software fallback succeeds and produces a valid low-S signature
            // with `signing_in_hsm == false`.
            let sw_sig = sign_secp256k1_ecdsa_software_with_pubkey(
                derived_key.private_key(),
                &digest32,
                derived_key.public_key(),
            )
            .map_err(|sw_err| {
                ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    format!(
                        "secp256k1 HSM signing failed ({hsm_err}) and software fallback also failed: {sw_err}"
                    ),
                    sw_err,
                )
            })?;

            if sw_sig.signing_in_hsm {
                let err = BackendError::Crypto(
                    "secp256k1 software fallback unexpectedly set signing_in_hsm=true".to_string(),
                );
                return Err(ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    "secp256k1 software fallback unexpectedly set signing_in_hsm=true",
                    err,
                ));
            }

            let sw_sig_64: [u8; 64] = sw_sig.as_bytes().try_into().map_err(|_| {
                let err = BackendError::Crypto(
                    "secp256k1 software fallback signature length != 64".to_string(),
                );
                ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    "secp256k1 software fallback signature length != 64",
                    err,
                )
            })?;

            verify_secp256k1_ecdsa(derived_key.public_key(), &digest32, &sw_sig_64).map_err(
                |ver_err| {
                    ProbeFailure::new(
                        ProbeStep::Step5CurveSigningSelfTest,
                        ProbeFailureCode::SoftwareFallbackFailed,
                        format!("secp256k1 software fallback signature verification failed: {ver_err}"),
                        ver_err,
                    )
                },
            )?;

            Ok(CurveProbeOutcome {
                scheme: Scheme::Bip32,
                curve: Curve::Secp256k1,
                signing_location: SigningLocation::Software,
                hsm_fallback_reason: Some(hsm_err.to_string()),
            })
        }
    }
}

/// **Step 5b (`Slip10` / `Ed25519`)**: Derives a throwaway `ed25519` child key, loads it as a
/// short-lived PKCS#11 session object (`CKK_EC_EDWARDS`), signs a test message with `CKM_EDDSA`,
/// verifies the 64-byte Ed25519 signature against the derived 32-byte public key, destroys the
/// session object, and verifies zero leftover session objects.
///
/// If the HSM lacks `ed25519` or `CKM_EDDSA`, verifies the software fallback and marks
/// `(Scheme::Slip10, Curve::Ed25519)` as [`SigningLocation::Software`].
pub fn probe_step5_ed25519_signing(
    session: &Pkcs11Session,
    throwaway_seed: &[u8; WALLET_SEED_LEN],
) -> Result<CurveProbeOutcome, ProbeFailure> {
    let derived_key =
        derive_slip10_from_slice(throwaway_seed, &PROBE_SLIP10_PATH).map_err(|err| {
            ProbeFailure::new(
                ProbeStep::Step5CurveSigningSelfTest,
                ProbeFailureCode::DerivationSelfTestFailed,
                format!("failed to derive throwaway SLIP10 ed25519 key during Step 5 probe: {err}"),
                err,
            )
        })?;

    // Attempt HSM session-object signing (imports key, signs with CKM_EDDSA, and immediately
    // calls C_DestroyObject via SessionKeyGuard).
    let hsm_attempt: Result<(), BackendError> = (|| {
        let raw_sig =
            session.sign_ed25519_message(derived_key.private_key(), PROBE_ED25519_MESSAGE)?;
        let processed = postprocess_ed25519_signature(
            &raw_sig,
            PROBE_ED25519_MESSAGE,
            derived_key.public_key(),
            true,
        )?;
        let sig_64: [u8; 64] = processed
            .as_bytes()
            .try_into()
            .map_err(|_| BackendError::Crypto("Ed25519 signature length != 64".to_string()))?;
        verify_ed25519_signature(derived_key.public_key(), PROBE_ED25519_MESSAGE, &sig_64)?;
        Ok(())
    })();

    // Regardless of whether HSM signing succeeded or failed, verify zero leftover session objects.
    verify_session_hygiene_or_fail(session, "after ed25519 session-object signing probe")?;

    match hsm_attempt {
        Ok(()) => Ok(CurveProbeOutcome {
            scheme: Scheme::Slip10,
            curve: Curve::Ed25519,
            signing_location: SigningLocation::Hsm,
            hsm_fallback_reason: None,
        }),
        Err(hsm_err) => {
            // Verify that the software fallback succeeds and produces a valid Ed25519 signature
            // with `signing_in_hsm == false`.
            let sw_sig = sign_ed25519_software_with_pubkey(
                derived_key.private_key(),
                PROBE_ED25519_MESSAGE,
                derived_key.public_key(),
            )
            .map_err(|sw_err| {
                ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    format!(
                        "ed25519 HSM signing failed ({hsm_err}) and software fallback also failed: {sw_err}"
                    ),
                    sw_err,
                )
            })?;

            if sw_sig.signing_in_hsm {
                let err = BackendError::Crypto(
                    "ed25519 software fallback unexpectedly set signing_in_hsm=true".to_string(),
                );
                return Err(ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    "ed25519 software fallback unexpectedly set signing_in_hsm=true",
                    err,
                ));
            }

            let sw_sig_64: [u8; 64] = sw_sig.as_bytes().try_into().map_err(|_| {
                let err = BackendError::Crypto(
                    "ed25519 software fallback signature length != 64".to_string(),
                );
                ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    "ed25519 software fallback signature length != 64",
                    err,
                )
            })?;

            verify_ed25519_signature(
                derived_key.public_key(),
                PROBE_ED25519_MESSAGE,
                &sw_sig_64,
            )
            .map_err(|ver_err| {
                ProbeFailure::new(
                    ProbeStep::Step5CurveSigningSelfTest,
                    ProbeFailureCode::SoftwareFallbackFailed,
                    format!("ed25519 software fallback signature verification failed: {ver_err}"),
                    ver_err,
                )
            })?;

            Ok(CurveProbeOutcome {
                scheme: Scheme::Slip10,
                curve: Curve::Ed25519,
                signing_location: SigningLocation::Software,
                hsm_fallback_reason: Some(hsm_err.to_string()),
            })
        }
    }
}

fn verify_session_hygiene_or_fail(
    session: &Pkcs11Session,
    context: &str,
) -> Result<(), ProbeFailure> {
    session.assert_no_session_objects().map_err(|err| {
        ProbeFailure::new(
            ProbeStep::Step5CurveSigningSelfTest,
            ProbeFailureCode::SessionObjectHygieneFailed,
            format!("HSM session-object hygiene check failed ({context}): {err}"),
            err,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::DEFAULT_KEK_LABEL;
    use crate::derive::MAX_DEPTH;
    use crate::pkcs11session::tests::{
        mock_state, mock_test_lock, C_GetFunctionList, MockPkcs11Object, MOCK_KEK_HANDLE,
        MOCK_SLOT_ID,
    };
    use crate::pkcs11session::{SlotSelector, SELF_MODULE_PATH};
    use cryptoki_sys::{CKM_ECDSA, CKM_EDDSA};

    fn mock_probe_config() -> ProbeConfig {
        let _keep_sym = C_GetFunctionList as usize;
        let pkcs11 = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id_and_label(MOCK_SLOT_ID as u64, "polyglot-softhsm"),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        ProbeConfig::new(pkcs11)
    }

    #[test]
    fn test_probe_full_hsm_success_and_capabilities_shape() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let report = run_startup_probe(mock_probe_config()).expect("startup probe should pass");

        assert_eq!(report.token_label, "polyglot-softhsm");
        assert_eq!(report.kek_label, DEFAULT_KEK_LABEL);
        assert!(report.secp256k1_outcome.signs_in_hsm());
        assert!(report.secp256k1_outcome.hsm_fallback_reason.is_none());
        assert!(report.ed25519_outcome.signs_in_hsm());
        assert!(report.ed25519_outcome.hsm_fallback_reason.is_none());

        let caps = &report.capabilities;
        assert_eq!(caps.backend, DEFAULT_GENERIC_BACKEND_NAME);
        assert_eq!(caps.protection_level, ProtectionLevel::GenericDev);
        assert_eq!(caps.max_depth, MAX_DEPTH as u8);
        assert_eq!(caps.wrap_mechanism, DEFAULT_WRAP_MECHANISM_NAME);
        assert!(!caps.derives_in_hsm);
        assert_eq!(caps.schemes.len(), 2);

        assert_eq!(
            caps.signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Hsm)
        );
        assert_eq!(
            caps.signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Hsm)
        );
        assert!(!caps.schemes[0].hardened_only);
        assert!(caps.schemes[1].hardened_only);

        // Verify zero open sessions or leftover session objects remain on the mock token.
        let st = mock_state().lock().unwrap();
        assert!(st.open_sessions.is_empty());
        assert!(st.objects.iter().all(|o| o.token));
        assert_eq!(st.destroyed_objects.len(), 2);
    }

    #[test]
    fn test_probe_step1_missing_library_or_bad_slot_fails_closed() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        // 1a. Missing PKCS#11 shared library file
        let missing_lib_cfg = ProbeConfig::new(Pkcs11Config::with_loaded_pin(
            "/nonexistent/path/to/libsofthsm2.so",
            SlotSelector::from_id(0),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        ));
        let failure = run_startup_probe_checked(missing_lib_cfg).unwrap_err();
        assert_eq!(failure.step, ProbeStep::Step1LibraryAndToken);
        assert_eq!(failure.code, ProbeFailureCode::LibraryOrSlotFailed);
        let backend_err = failure.into_backend_error();
        assert_eq!(
            extract_probe_failure_code(&backend_err),
            Some(ProbeFailureCode::LibraryOrSlotFailed)
        );

        // 1b. Nonexistent slot ID
        let wrong_slot_cfg = ProbeConfig::new(Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id(999),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        ));
        let slot_failure = run_startup_probe_checked(wrong_slot_cfg).unwrap_err();
        assert_eq!(slot_failure.step, ProbeStep::Step1LibraryAndToken);
        assert_eq!(slot_failure.code, ProbeFailureCode::LibraryOrSlotFailed);

        // 1c. Wrong user PIN fails login during Step 1
        let bad_pin_cfg = ProbeConfig::new(Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id(MOCK_SLOT_ID as u64),
            Zeroizing::new("wrong-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        ));
        let pin_failure = run_startup_probe_checked(bad_pin_cfg).unwrap_err();
        assert_eq!(pin_failure.step, ProbeStep::Step1LibraryAndToken);
        assert_eq!(pin_failure.code, ProbeFailureCode::LibraryOrSlotFailed);
    }

    #[test]
    fn test_probe_step2_missing_aes_gcm_or_failed_selftest_fails_closed() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        // 2a. CKM_AES_GCM missing from C_GetMechanismList
        mock_state().lock().unwrap().supported_mechanisms = vec![CKM_ECDSA, CKM_EDDSA];
        let mech_failure = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(
            mech_failure.step,
            ProbeStep::Step2AesGcmMechanismAndSelfTest
        );
        assert_eq!(mech_failure.code, ProbeFailureCode::MissingAesGcmMechanism);
        assert_eq!(
            extract_probe_failure_code(&mech_failure.to_backend_error()),
            Some(ProbeFailureCode::MissingAesGcmMechanism)
        );

        // 2b. CKM_AES_GCM present in mechanism list, but decrypt corrupts plaintext
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().corrupt_decrypt_plaintext = true;
        let corrupt_failure = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(
            corrupt_failure.step,
            ProbeStep::Step2AesGcmMechanismAndSelfTest
        );
        assert_eq!(corrupt_failure.code, ProbeFailureCode::AesGcmSelfTestFailed);

        // 2c. CKM_AES_GCM present, but HSM fails to check AAD on decrypt
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().ignore_aad_on_decrypt = true;
        let aad_failure = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(
            aad_failure.step,
            ProbeStep::Step2AesGcmMechanismAndSelfTest
        );
        assert_eq!(aad_failure.code, ProbeFailureCode::AesGcmSelfTestFailed);
        assert!(aad_failure.message.contains("mismatched AAD"));
    }

    #[test]
    fn test_probe_step3_missing_or_extractable_kek_fails_closed() {
        let _serial = mock_test_lock().lock().unwrap();

        // 3a. Missing KEK (`kek-v1` not present on token)
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().objects.clear();
        let missing_kek = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(missing_kek.step, ProbeStep::Step3KekValidation);
        assert_eq!(missing_kek.code, ProbeFailureCode::KekNotFound);
        assert_eq!(
            extract_probe_failure_code(&missing_kek.to_backend_error()),
            Some(ProbeFailureCode::KekNotFound)
        );

        // 3b. Extractable KEK (`CKA_EXTRACTABLE = true`) -> refuse to start
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().objects[0].extractable = Some(true);
        let extractable_kek = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(extractable_kek.step, ProbeStep::Step3KekValidation);
        assert_eq!(extractable_kek.code, ProbeFailureCode::InvalidKekAttributes);
        assert!(extractable_kek.message.contains("CKA_EXTRACTABLE"));

        // 3c. Non-sensitive KEK (`CKA_SENSITIVE = false`) -> refuse to start
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().objects[0].sensitive = Some(false);
        let insensitive_kek = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(insensitive_kek.step, ProbeStep::Step3KekValidation);
        assert_eq!(insensitive_kek.code, ProbeFailureCode::InvalidKekAttributes);
        assert!(insensitive_kek.message.contains("CKA_SENSITIVE"));

        // 3d. KEK with disallowed CKA_WRAP = true -> refuse to start
        mock_state().lock().unwrap().reset();
        let mut bad_wrap_kek =
            MockPkcs11Object::valid_kek(MOCK_KEK_HANDLE, DEFAULT_KEK_LABEL.as_bytes(), [0xA5; 32]);
        bad_wrap_kek.wrap = Some(true);
        mock_state().lock().unwrap().objects = vec![bad_wrap_kek];
        let wrap_kek_err = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(wrap_kek_err.step, ProbeStep::Step3KekValidation);
        assert_eq!(wrap_kek_err.code, ProbeFailureCode::InvalidKekAttributes);
    }

    #[test]
    fn test_probe_step4_derivation_vector_failure_fails_closed() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let cfg = mock_probe_config();
        let lib = Pkcs11Library::open(cfg.pkcs11).expect("open library");

        let failure = probe_library_with_derivation_hook(
            &lib,
            DEFAULT_GENERIC_BACKEND_NAME,
            ProtectionLevel::GenericDev,
            || {
                Err(DerivationSelfTestError::Bip32Mismatch(
                    "simulated TV1 public key mismatch".to_string(),
                ))
            },
        )
        .unwrap_err();

        assert_eq!(failure.step, ProbeStep::Step4DerivationVectors);
        assert_eq!(failure.code, ProbeFailureCode::DerivationSelfTestFailed);
        assert!(failure.message.contains("simulated TV1 public key mismatch"));
    }

    #[test]
    fn test_probe_step5_missing_curve_falls_back_to_software_without_crashing() {
        let _serial = mock_test_lock().lock().unwrap();

        // Case 1: SoftHSM rejects secp256k1 in CKA_EC_PARAMS, supports ed25519 in HSM
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().reject_secp256k1_import = true;

        let report_no_secp =
            run_startup_probe(mock_probe_config()).expect("probe must succeed with software fallback");
        assert_eq!(
            report_no_secp
                .capabilities
                .signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Software)
        );
        assert_eq!(
            report_no_secp
                .capabilities
                .signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Hsm)
        );
        assert!(report_no_secp
            .secp256k1_outcome
            .hsm_fallback_reason
            .is_some());
        assert!(report_no_secp.ed25519_outcome.hsm_fallback_reason.is_none());

        // Case 2: SoftHSM supports secp256k1 in HSM, lacks ed25519 (rejects CKK_EC_EDWARDS)
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().reject_ed25519_import = true;

        let report_no_ed =
            run_startup_probe(mock_probe_config()).expect("probe must succeed with software fallback");
        assert_eq!(
            report_no_ed
                .capabilities
                .signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Hsm)
        );
        assert_eq!(
            report_no_ed
                .capabilities
                .signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Software)
        );
        assert!(report_no_ed.secp256k1_outcome.hsm_fallback_reason.is_none());
        assert!(report_no_ed.ed25519_outcome.hsm_fallback_reason.is_some());

        // Case 3: Both curves fail signature verification or mechanism in HSM -> both mark Software
        // and session objects are still destroyed cleanly!
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().corrupt_ecdsa_signature = true;
        mock_state().lock().unwrap().corrupt_eddsa_signature = true;

        let report_both_sw =
            run_startup_probe(mock_probe_config()).expect("probe must succeed with both in software");
        assert_eq!(
            report_both_sw
                .capabilities
                .signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Software)
        );
        assert_eq!(
            report_both_sw
                .capabilities
                .signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Software)
        );
        // Verify both session objects were still created and destroyed cleanly despite signature verification failure!
        let st = mock_state().lock().unwrap();
        assert_eq!(st.destroyed_objects.len(), 2);
        assert!(st.objects.iter().all(|o| o.token));
    }

    #[test]
    fn test_probe_session_object_hygiene_violation_fails_closed() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        // Inject a pre-existing leftover session object (`token = false`) on the token
        let mut leaked_session_obj =
            MockPkcs11Object::valid_kek(99, b"leaked-session-key", [0x11; 32]);
        leaked_session_obj.token = false;
        mock_state().lock().unwrap().objects.push(leaked_session_obj);

        let failure = run_startup_probe_checked(mock_probe_config()).unwrap_err();
        assert_eq!(failure.step, ProbeStep::Step5CurveSigningSelfTest);
        assert_eq!(failure.code, ProbeFailureCode::SessionObjectHygieneFailed);
    }
}
