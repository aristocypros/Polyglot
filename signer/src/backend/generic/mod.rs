//! Generic PKCS#11 and software fallback backend implementation (`signer/src/backend/generic/mod.rs`).
//!
//! Implements Task 12 of Milestone 2 (Section 4 and Section 8 of `Specs.md`):
//! - Composes [`crate::pkcs11session`], [`crate::derive`], [`crypto`], and [`probe`] into
//!   [`GenericBackend`] implementing [`crate::backend::Backend`].
//! - [`GenericBackend::capabilities`]: returns cached startup probe [`Capabilities`].
//! - [`GenericBackend::create_wallet`]: generates a 64-byte random seed in the HSM via
//!   `C_GenerateRandom`, wraps it under the non-extractable AES-256 KEK (`"kek-v1"`) with
//!   `CKM_AES_GCM` and caller-supplied AAD, wipes the clear seed via [`zeroize::Zeroizing`],
//!   and returns the 92-byte wrapped blob (`12B IV || 64B ciphertext || 16B tag`).
//! - [`GenericBackend::public_key`]: validates path for scheme, unwraps the seed with AAD
//!   into a [`zeroize::Zeroizing`] buffer, derives the child key at `path` via [`derive_bip32`]
//!   or [`derive_slip10`], wipes seed & private key, and returns the compressed public key
//!   (`33` bytes for `secp256k1`, `32` bytes for `ed25519`).
//! - [`GenericBackend::sign`]: validates path and signing input, unwraps seed with AAD, derives
//!   the child key at `path`, signs via a short-lived PKCS#11 session object (`CKM_ECDSA` or
//!   `CKM_EDDSA`) when the probe marked the curve as [`SigningLocation::Hsm`] (or in software
//!   when the probe marked the curve as [`SigningLocation::Software`] or when the input is
//!   [`SigningInput::TaprootDigest32`]), destroys the session object, asserts zero leftover
//!   session objects (`C_FindObjects`), wipes all key buffers, and returns [`Signature`] with
//!   an honest `signing_in_hsm` boolean.

pub mod crypto;
pub mod probe;

pub use crypto::*;
pub use probe::*;

use std::fmt;

use crate::backend::{
    validate_scheme_curve, Backend, BackendError, Capabilities, Curve, ProtectionLevel, Scheme,
    Signature, SigningInput, SigningLocation, Spec, WalletRef,
};
use crate::derive::{derive_bip32, derive_slip10, DerivationPath};
use crate::pkcs11session::{Pkcs11Config, Pkcs11Library, Pkcs11Session};

/// Generic PKCS#11 backend with software derivation and per-curve HSM/software signing.
///
/// Constructed via [`GenericBackend::new`] or [`GenericBackend::from_pkcs11_config`], which
/// executes the 5-step fail-closed startup capability probe ([`run_startup_probe`]) before
/// returning a ready instance.
#[derive(Clone)]
pub struct GenericBackend {
    report: ProbeReport,
}

impl fmt::Debug for GenericBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericBackend")
            .field("token_label", &self.report.token_label)
            .field("kek_label", &self.report.kek_label)
            .field("capabilities", &self.report.capabilities)
            .finish()
    }
}

impl GenericBackend {
    /// Runs the 5-step fail-closed startup capability probe with `config` and constructs a
    /// [`GenericBackend`] if all mandatory checks (steps 1–4 and session-object hygiene) pass.
    pub fn new(config: ProbeConfig) -> Result<Self, BackendError> {
        let report = run_startup_probe(config)?;
        Ok(Self { report })
    }

    /// Runs the 5-step fail-closed startup capability probe using `pkcs11_config` and default
    /// generic-tier settings (`backend = "softhsm-generic"`, `protection_level = ProtectionLevel::GenericDev`).
    pub fn from_pkcs11_config(pkcs11_config: Pkcs11Config) -> Result<Self, BackendError> {
        Self::new(ProbeConfig::new(pkcs11_config))
    }

    /// Runs the 5-step fail-closed startup capability probe against an already-initialized
    /// [`Pkcs11Library`] and constructs a [`GenericBackend`].
    pub fn from_library(
        library: Pkcs11Library,
        backend_name: impl Into<String>,
        protection_level: ProtectionLevel,
    ) -> Result<Self, BackendError> {
        let report = probe_library(&library, backend_name, protection_level)?;
        Ok(Self { report })
    }

    /// Constructs a [`GenericBackend`] directly from a completed [`ProbeReport`].
    pub fn from_probe_report(report: ProbeReport) -> Self {
        Self { report }
    }

    /// Returns a reference to the underlying [`Pkcs11Library`].
    pub fn library(&self) -> &Pkcs11Library {
        &self.report.library
    }

    /// Returns a reference to the startup [`ProbeReport`].
    pub fn probe_report(&self) -> &ProbeReport {
        &self.report
    }

    /// Returns a reference to the cached [`Capabilities`] produced by the startup probe.
    pub fn capabilities_ref(&self) -> &Capabilities {
        &self.report.capabilities
    }

    /// Returns the probed [`SigningLocation`] (`Hsm` or `Software`) for `(scheme, curve)`.
    pub fn signing_location(&self, scheme: Scheme, curve: Curve) -> Option<SigningLocation> {
        self.report.capabilities.signing_location(scheme, curve)
    }

    /// Opens a fresh per-request PKCS#11 RW session on the backend's token slot.
    pub fn open_session(&self) -> Result<Pkcs11Session, BackendError> {
        self.report.library.open_rw_session()
    }
}

impl Backend for GenericBackend {
    fn capabilities(&self) -> Result<Capabilities, BackendError> {
        Ok(self.report.capabilities.clone())
    }

    fn create_wallet(&self, spec: &Spec, aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        spec.validate()?;
        if aad.is_empty() {
            return Err(BackendError::InvalidAad(
                "AEAD associated data (aad) must not be empty".to_string(),
            ));
        }

        let session = self.report.library.open_rw_session()?;

        // Generate 64 random seed bytes in the HSM (`C_GenerateRandom`) into a Zeroizing buffer.
        let seed = session.generate_seed()?;

        // Wrap the 64-byte seed under the HSM KEK (`kek-v1`) with `CKM_AES_GCM` and AAD.
        let wrap_res = session.wrap_seed(&*seed, aad);

        // Enforce session-object hygiene before returning.
        let hygiene_res = session.assert_no_session_objects();
        drop(seed);
        session.close();

        let wrapped = wrap_res?;
        hygiene_res?;
        Ok(wrapped)
    }

    fn public_key(&self, w: &WalletRef, path: &[u32]) -> Result<Vec<u8>, BackendError> {
        w.validate_scheme_curve()?;
        if w.aad.is_empty() {
            return Err(BackendError::InvalidAad(
                "AEAD associated data (aad) must not be empty".to_string(),
            ));
        }

        // Validate derivation path for the wallet's scheme before touching the HSM.
        let derivation_path = DerivationPath::from_slice(path)?;
        derivation_path.validate_for_scheme(w.scheme.into())?;

        let session = self.report.library.open_rw_session()?;

        // Unwrap the 64-byte seed into a Zeroizing<[u8; 64]> buffer.
        let unwrap_res = session.unwrap_seed(w.wrapped, w.aad);
        let hygiene_res = session.assert_no_session_objects();
        session.close();

        let seed = unwrap_res?;
        hygiene_res?;

        match w.scheme {
            Scheme::Bip32 => {
                let derived = derive_bip32(&*seed, &derivation_path)?;
                let pubkey = derived.public_key().to_vec();
                drop(derived);
                drop(seed);
                Ok(pubkey)
            }
            Scheme::Slip10 => {
                let derived = derive_slip10(&*seed, &derivation_path)?;
                let pubkey = derived.public_key().to_vec();
                drop(derived);
                drop(seed);
                Ok(pubkey)
            }
        }
    }

    fn sign(
        &self,
        w: &WalletRef,
        path: &[u32],
        input: SigningInput,
    ) -> Result<Signature, BackendError> {
        w.validate_scheme_curve()?;
        validate_signing_input_for_wallet(w.scheme, w.curve, input)?;

        if w.aad.is_empty() {
            return Err(BackendError::InvalidAad(
                "AEAD associated data (aad) must not be empty".to_string(),
            ));
        }

        // Validate derivation path for the wallet's scheme before touching the HSM.
        let derivation_path = DerivationPath::from_slice(path)?;
        derivation_path.validate_for_scheme(w.scheme.into())?;

        let signing_loc = self
            .report
            .capabilities
            .signing_location(w.scheme, w.curve)
            .ok_or(BackendError::UnsupportedSchemeCurve {
                scheme: w.scheme,
                curve: w.curve,
            })?;

        let session = self.report.library.open_rw_session()?;

        // Unwrap the 64-byte seed into a Zeroizing<[u8; 64]> buffer.
        let seed = match session.unwrap_seed(w.wrapped, w.aad) {
            Ok(s) => s,
            Err(err) => {
                let _ = session.assert_no_session_objects();
                session.close();
                return Err(err);
            }
        };

        let sign_result: Result<Signature, BackendError> = match (w.scheme, w.curve, input) {
            (Scheme::Bip32, Curve::Secp256k1, SigningInput::TaprootDigest32(taproot_digest)) => {
                // Per Section 4 and Section 8 of Specs.md, BIP340 Schnorr has no PKCS#11 mechanism
                // and is always signed in software with BIP86 key-path tweak (`signing_in_hsm: false`).
                let derived = derive_bip32(&*seed, &derivation_path)?;
                let res = sign_taproot_schnorr_software(derived.private_key(), taproot_digest);
                drop(derived);
                res
            }
            (Scheme::Bip32, Curve::Secp256k1, SigningInput::Digest32(digest32)) => {
                let derived = derive_bip32(&*seed, &derivation_path)?;
                let res = match signing_loc {
                    SigningLocation::Hsm => {
                        let raw_sig =
                            session.sign_secp256k1_digest(derived.private_key(), digest32)?;
                        postprocess_ecdsa_signature(
                            &raw_sig,
                            digest32,
                            derived.public_key(),
                            true,
                        )
                    }
                    SigningLocation::Software => sign_secp256k1_ecdsa_software_with_pubkey(
                        derived.private_key(),
                        digest32,
                        derived.public_key(),
                    ),
                };
                drop(derived);
                res
            }
            (Scheme::Slip10, Curve::Ed25519, SigningInput::Message(message)) => {
                let derived = derive_slip10(&*seed, &derivation_path)?;
                let res = match signing_loc {
                    SigningLocation::Hsm => {
                        let raw_sig =
                            session.sign_ed25519_message(derived.private_key(), message)?;
                        postprocess_ed25519_signature(
                            &raw_sig,
                            message,
                            derived.public_key(),
                            true,
                        )
                    }
                    SigningLocation::Software => sign_ed25519_software_with_pubkey(
                        derived.private_key(),
                        message,
                        derived.public_key(),
                    ),
                };
                drop(derived);
                res
            }
            _ => Err(BackendError::InvalidSigningInput {
                scheme: w.scheme,
                curve: w.curve,
                reason: "incompatible signing input variant for wallet scheme/curve".to_string(),
            }),
        };

        // Wipe the unwrapped seed before inspecting hygiene and closing the session.
        drop(seed);

        let hygiene_res = session.assert_no_session_objects();
        session.close();

        let signature = sign_result?;
        hygiene_res?;
        Ok(signature)
    }

    fn wrap_test_seed(&self, seed: &[u8], aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        let session = self.report.library.open_rw_session()?;
        let res = session.wrap_seed(seed, aad);
        let hygiene = session.assert_no_session_objects();
        session.close();
        hygiene?;
        res
    }

    fn count_session_objects(&self) -> Result<usize, BackendError> {
        let session = self.report.library.open_rw_session()?;
        let count = session.count_session_objects()?;
        session.close();
        Ok(count)
    }
}

/// Validates that `input` is a valid [`SigningInput`] variant for `(scheme, curve)`.
pub fn validate_signing_input_for_wallet(
    scheme: Scheme,
    curve: Curve,
    input: SigningInput,
) -> Result<(), BackendError> {
    validate_scheme_curve(scheme, curve)?;
    match (scheme, curve, input) {
        (Scheme::Bip32, Curve::Secp256k1, SigningInput::Digest32(_))
        | (Scheme::Bip32, Curve::Secp256k1, SigningInput::TaprootDigest32(_))
        | (Scheme::Slip10, Curve::Ed25519, SigningInput::Message(_)) => Ok(()),
        (Scheme::Bip32, Curve::Secp256k1, SigningInput::Message(_)) => {
            Err(BackendError::InvalidSigningInput {
                scheme,
                curve,
                reason: "bip32/secp256k1 requires Digest32 or TaprootDigest32, not Message"
                    .to_string(),
            })
        }
        (Scheme::Slip10, Curve::Ed25519, SigningInput::Digest32(_))
        | (Scheme::Slip10, Curve::Ed25519, SigningInput::TaprootDigest32(_)) => {
            Err(BackendError::InvalidSigningInput {
                scheme,
                curve,
                reason: "slip10/ed25519 requires Message, not Digest32/TaprootDigest32".to_string(),
            })
        }
        _ => Err(BackendError::UnsupportedSchemeCurve { scheme, curve }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        build_aad_checked, DEFAULT_KEK_LABEL, DEFAULT_SEED_VERSION, WRAPPED_SEED_LEN,
    };
    use crate::derive::{COMPRESSED_PUBKEY_LEN, ED25519_PUBKEY_LEN, HARDENED_FLAG};
    use crate::pkcs11session::tests::{
        mock_state, mock_test_lock, C_GetFunctionList, MOCK_SLOT_ID,
    };
    use crate::pkcs11session::{SlotSelector, SELF_MODULE_PATH};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    fn test_pkcs11_config() -> Pkcs11Config {
        let _keep_sym = C_GetFunctionList as usize;
        Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id_and_label(MOCK_SLOT_ID as u64, "polyglot-softhsm"),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        )
    }

    #[test]
    fn test_generic_backend_create_wallet_derive_and_sign_in_hsm() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let backend = GenericBackend::from_pkcs11_config(test_pkcs11_config())
            .expect("initialize GenericBackend");

        let caps = backend.capabilities().expect("get capabilities");
        assert_eq!(caps.backend, DEFAULT_GENERIC_BACKEND_NAME);
        assert_eq!(caps.protection_level, ProtectionLevel::GenericDev);
        assert!(!caps.derives_in_hsm);
        assert_eq!(
            caps.signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Hsm)
        );
        assert_eq!(
            caps.signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Hsm)
        );

        // 1. Create BIP32/secp256k1 wallet, derive public key, sign ECDSA digest (HSM) & Taproot (Software)
        let bip32_spec = Spec::new(Scheme::Bip32, Curve::Secp256k1);
        let bip32_aad = build_aad_checked(
            "w_bip32_test",
            Scheme::Bip32,
            Curve::Secp256k1,
            DEFAULT_SEED_VERSION,
            DEFAULT_KEK_LABEL,
        )
        .unwrap();

        let bip32_wrapped = backend
            .create_wallet(&bip32_spec, &bip32_aad)
            .expect("create bip32 wallet");
        assert_eq!(bip32_wrapped.len(), WRAPPED_SEED_LEN);

        let bip32_wallet = WalletRef::new(
            &bip32_wrapped,
            &bip32_aad,
            Scheme::Bip32,
            Curve::Secp256k1,
        );
        let eth_path = [
            44 | HARDENED_FLAG,
            60 | HARDENED_FLAG,
            0 | HARDENED_FLAG,
            0,
            0,
        ];

        let pubkey_secp = backend
            .public_key(&bip32_wallet, &eth_path)
            .expect("derive secp256k1 pubkey");
        assert_eq!(pubkey_secp.len(), COMPRESSED_PUBKEY_LEN);

        let digest_ga = Sha256::digest(b"test-evm-transaction-payload");
        let mut digest32 = [0u8; 32];
        digest32.copy_from_slice(&digest_ga);

        let sig_ecdsa = backend
            .sign(&bip32_wallet, &eth_path, SigningInput::Digest32(&digest32))
            .expect("sign secp256k1 digest in HSM");
        assert!(sig_ecdsa.signing_in_hsm);
        assert_eq!(sig_ecdsa.public_key, pubkey_secp);
        assert!(sig_ecdsa.r.is_some());
        assert!(sig_ecdsa.s.is_some());
        assert!(is_low_s(&sig_ecdsa.s.unwrap()).unwrap());
        assert!(sig_ecdsa.recovery_id.is_some());
        assert!(sig_ecdsa.der.is_some());

        let pubkey_arr: [u8; 33] = pubkey_secp.clone().try_into().unwrap();
        let sig_arr: [u8; 64] = sig_ecdsa.as_bytes().try_into().unwrap();
        verify_secp256k1_ecdsa(&pubkey_arr, &digest32, &sig_arr).expect("verify ECDSA sig");

        // Taproot BIP340 Schnorr on the same BIP32 wallet always signs in software (`signing_in_hsm == false`)
        let taproot_path = [
            86 | HARDENED_FLAG,
            0 | HARDENED_FLAG,
            0 | HARDENED_FLAG,
            0,
            0,
        ];
        let taproot_sig = backend
            .sign(
                &bip32_wallet,
                &taproot_path,
                SigningInput::TaprootDigest32(&digest32),
            )
            .expect("sign taproot digest in software");
        assert!(!taproot_sig.signing_in_hsm);
        assert!(taproot_sig.r.is_none());
        assert!(taproot_sig.s.is_none());
        assert!(taproot_sig.recovery_id.is_none());
        let tweaked_pub: [u8; 32] = taproot_sig.public_key.clone().try_into().unwrap();
        let schnorr_bytes: [u8; 64] = taproot_sig.as_bytes().try_into().unwrap();
        verify_bip340_schnorr(&tweaked_pub, &digest32, &schnorr_bytes)
            .expect("verify BIP340 Schnorr signature");

        // 2. Create SLIP10/ed25519 wallet, derive public key, sign message in HSM
        let slip10_spec = Spec::new(Scheme::Slip10, Curve::Ed25519);
        let slip10_aad = build_aad_checked(
            "w_slip10_test",
            Scheme::Slip10,
            Curve::Ed25519,
            DEFAULT_SEED_VERSION,
            DEFAULT_KEK_LABEL,
        )
        .unwrap();

        let slip10_wrapped = backend
            .create_wallet(&slip10_spec, &slip10_aad)
            .expect("create slip10 wallet");
        assert_eq!(slip10_wrapped.len(), WRAPPED_SEED_LEN);

        let slip10_wallet = WalletRef::new(
            &slip10_wrapped,
            &slip10_aad,
            Scheme::Slip10,
            Curve::Ed25519,
        );
        let sol_path = [
            44 | HARDENED_FLAG,
            501 | HARDENED_FLAG,
            0 | HARDENED_FLAG,
            0 | HARDENED_FLAG,
        ];

        let pubkey_ed = backend
            .public_key(&slip10_wallet, &sol_path)
            .expect("derive ed25519 pubkey");
        assert_eq!(pubkey_ed.len(), ED25519_PUBKEY_LEN);

        let message = b"solana-system-transfer-message-bytes";
        let sig_ed = backend
            .sign(&slip10_wallet, &sol_path, SigningInput::Message(message))
            .expect("sign ed25519 message in HSM");
        assert!(sig_ed.signing_in_hsm);
        assert_eq!(sig_ed.public_key, pubkey_ed);
        let ed_pub_arr: [u8; 32] = pubkey_ed.try_into().unwrap();
        let ed_sig_arr: [u8; 64] = sig_ed.as_bytes().try_into().unwrap();
        verify_ed25519_signature(&ed_pub_arr, message, &ed_sig_arr)
            .expect("verify Ed25519 signature");

        // Confirm zero open sessions and zero leftover session objects
        let st = mock_state().lock().unwrap();
        assert!(st.open_sessions.is_empty());
        assert!(st.objects.iter().all(|o| o.token));
    }

    #[test]
    fn test_generic_backend_software_fallback_and_error_hygiene() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();
        mock_state().lock().unwrap().reject_secp256k1_import = true;
        mock_state().lock().unwrap().reject_ed25519_import = true;

        let backend = GenericBackend::from_pkcs11_config(test_pkcs11_config())
            .expect("initialize GenericBackend with software fallback");

        let caps = backend.capabilities().unwrap();
        assert_eq!(
            caps.signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Software)
        );
        assert_eq!(
            caps.signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Software)
        );

        // Sign with BIP32/secp256k1 in software fallback -> signing_in_hsm must be false
        let bip32_spec = Spec::new(Scheme::Bip32, Curve::Secp256k1);
        let bip32_aad = build_aad_checked(
            "w_sw_bip32",
            Scheme::Bip32,
            Curve::Secp256k1,
            DEFAULT_SEED_VERSION,
            DEFAULT_KEK_LABEL,
        )
        .unwrap();
        let bip32_wrapped = backend.create_wallet(&bip32_spec, &bip32_aad).unwrap();
        let bip32_wallet = WalletRef::new(
            &bip32_wrapped,
            &bip32_aad,
            Scheme::Bip32,
            Curve::Secp256k1,
        );
        let path = [44 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0, 1];
        let digest = [0x42u8; 32];
        let sig_secp = backend
            .sign(&bip32_wallet, &path, SigningInput::Digest32(&digest))
            .expect("software fallback secp256k1 sign");
        assert!(!sig_secp.signing_in_hsm);

        // Sign with SLIP10/ed25519 in software fallback -> signing_in_hsm must be false
        let slip10_spec = Spec::new(Scheme::Slip10, Curve::Ed25519);
        let slip10_aad = build_aad_checked(
            "w_sw_slip10",
            Scheme::Slip10,
            Curve::Ed25519,
            DEFAULT_SEED_VERSION,
            DEFAULT_KEK_LABEL,
        )
        .unwrap();
        let slip10_wrapped = backend.create_wallet(&slip10_spec, &slip10_aad).unwrap();
        let slip10_wallet = WalletRef::new(
            &slip10_wrapped,
            &slip10_aad,
            Scheme::Slip10,
            Curve::Ed25519,
        );
        let ed_path = [44 | HARDENED_FLAG, 501 | HARDENED_FLAG, 0 | HARDENED_FLAG];
        let sig_ed = backend
            .sign(&slip10_wallet, &ed_path, SigningInput::Message(b"hello"))
            .expect("software fallback ed25519 sign");
        assert!(!sig_ed.signing_in_hsm);

        // Verify rejection of non-hardened SLIP10 path and incompatible SigningInput
        assert!(backend
            .public_key(&slip10_wallet, &[44 | HARDENED_FLAG, 0])
            .is_err());
        assert!(backend
            .sign(&bip32_wallet, &path, SigningInput::Message(b"wrong"))
            .is_err());
        assert!(backend
            .sign(&slip10_wallet, &ed_path, SigningInput::Digest32(&digest))
            .is_err());

        // Verify wrong AAD and swapped wallet blob fail closed
        let swapped_wallet = WalletRef::new(
            &bip32_wrapped,
            &slip10_aad,
            Scheme::Bip32,
            Curve::Secp256k1,
        );
        assert!(matches!(
            backend.public_key(&swapped_wallet, &path),
            Err(BackendError::UnwrapFailed(_))
        ));
    }
}
