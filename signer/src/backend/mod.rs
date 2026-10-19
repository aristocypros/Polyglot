//! Backend interface and core cryptographic domain types (Section 8 of `Specs.md`).
//!
//! Defines the vendor-neutral [`Backend`] trait and associated types used across
//! the generic PKCS#11 backend, chain codecs, envelope processor, and conformance suite.

pub mod generic;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::derive::{
    derive_bip32, derive_slip10, Bip32Error, Bip32Key, DerivationPath, DerivationScheme,
    DerivationSelfTestError, PathError, Slip10Error, Slip10Key, MAX_DEPTH,
};

/// Default wallet seed version for AEAD Associated Authenticated Data (AAD).
pub const DEFAULT_SEED_VERSION: u32 = 1;

/// Default HSM AES-256 KEK label for seed wrapping (`CKM_AES_GCM`).
pub const DEFAULT_KEK_LABEL: &str = "kek-v1";

/// Canonical field delimiter used in AEAD Associated Authenticated Data (AAD).
pub const AAD_DELIMITER: char = '|';

/// Expected byte length of a raw wallet seed generated in the HSM (`C_GenerateRandom`).
pub const WALLET_SEED_LEN: usize = 64;

/// Expected byte length of an AES-256-GCM IV (96 bits).
pub const AES_GCM_IV_LEN: usize = 12;

/// Expected byte length of an AES-256-GCM authentication tag (128 bits).
pub const AES_GCM_TAG_LEN: usize = 16;

/// Expected byte length of a wrapped 64-byte seed blob: `IV (12B) || ciphertext (64B) || tag (16B)`.
pub const WRAPPED_SEED_LEN: usize = AES_GCM_IV_LEN + WALLET_SEED_LEN + AES_GCM_TAG_LEN;

/// Vendor-neutral cryptographic backend interface.
///
/// The generic backend implements this trait using PKCS#11 (`C_GenerateRandom`,
/// `CKM_AES_GCM` wrap/unwrap, short-lived session-object signing) combined with
/// pure-Rust BIP32/SLIP10 key derivation. Future native HSM backends implement
/// the exact same trait while keeping seed material inside the HSM boundary.
pub trait Backend: Send + Sync {
    /// Returns the backend's probed capabilities and protection level.
    fn capabilities(&self) -> Result<Capabilities, BackendError>;

    /// Creates a 64-byte seed inside the backend and returns it wrapped under the HSM KEK
    /// bound to the caller-supplied AEAD associated data (`aad`).
    fn create_wallet(&self, spec: &Spec, aad: &[u8]) -> Result<Vec<u8>, BackendError>;

    /// Derives and returns the compressed public key (`33` bytes for `secp256k1`,
    /// `32` bytes for `ed25519`) at `path` for the given wrapped wallet.
    fn public_key(&self, w: &WalletRef, path: &[u32]) -> Result<Vec<u8>, BackendError>;

    /// Signs a 32-byte digest, a raw message, or a Taproot BIP341 sighash digest
    /// using the child key derived at `path` for the given wrapped wallet.
    fn sign(
        &self,
        w: &WalletRef,
        path: &[u32],
        input: SigningInput,
    ) -> Result<Signature, BackendError>;

    /// Conformance/test hook for wrapping a known 64-byte seed blob under the backend's
    /// KEK with caller-supplied AAD (e.g. for BIP32 and SLIP10 published vector verification).
    fn wrap_test_seed(&self, _seed: &[u8], _aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        Err(BackendError::Config(
            "wrap_test_seed is not supported by this backend".to_string(),
        ))
    }

    /// Conformance/test hook for querying the number of active session objects on the token.
    fn count_session_objects(&self) -> Result<usize, BackendError> {
        Ok(0)
    }
}

/// Input payload to be signed by [`Backend::sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningInput<'a> {
    /// 32-byte pre-hashed digest for ECDSA (`secp256k1`).
    Digest32(&'a [u8; 32]),
    /// Raw message bytes for Ed25519 (`ed25519`).
    Message(&'a [u8]),
    /// 32-byte BIP341 Taproot sighash digest for BIP340 Schnorr signing with
    /// BIP86 key-path tweak (`secp256k1`, always executed in software).
    TaprootDigest32(&'a [u8; 32]),
}

/// Reference to a wrapped wallet and its verified AEAD context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletRef<'a> {
    /// Wrapped seed blob (`IV || ciphertext || tag`).
    pub wrapped: &'a [u8],
    /// Canonical AAD bytes built by the signer from the verified request body.
    pub aad: &'a [u8],
    /// Key derivation scheme (`Bip32` or `Slip10`).
    pub scheme: Scheme,
    /// Elliptic curve (`Secp256k1` or `Ed25519`).
    pub curve: Curve,
}

impl<'a> WalletRef<'a> {
    /// Constructs a new [`WalletRef`].
    pub const fn new(wrapped: &'a [u8], aad: &'a [u8], scheme: Scheme, curve: Curve) -> Self {
        Self {
            wrapped,
            aad,
            scheme,
            curve,
        }
    }

    /// Validates that the wallet's `(scheme, curve)` combination is supported.
    pub fn validate_scheme_curve(&self) -> Result<(), BackendError> {
        validate_scheme_curve(self.scheme, self.curve)
    }
}

/// Wallet creation specification passed to [`Backend::create_wallet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// Key derivation scheme (`bip32` or `slip10`).
    pub scheme: Scheme,
    /// Elliptic curve (`secp256k1` or `ed25519`).
    pub curve: Curve,
}

impl Spec {
    /// Creates a new wallet [`Spec`].
    pub const fn new(scheme: Scheme, curve: Curve) -> Self {
        Self { scheme, curve }
    }

    /// Validates that `(scheme, curve)` is a supported v1 combination.
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_scheme_curve(self.scheme, self.curve)
    }
}

/// Protection level reported on `/v1/signer` and every signed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// SoftHSMv2 PKCS#11 token with key derivation in signer memory (prototype only).
    #[serde(rename = "generic-dev")]
    GenericDev,
    /// Hardware PKCS#11 HSM with key derivation in signer memory.
    #[serde(rename = "generic-hsm")]
    GenericHsm,
    /// Key derivation and signing entirely inside the HSM (future native tier).
    #[serde(rename = "native")]
    Native,
}

impl ProtectionLevel {
    /// Returns the canonical wire string (`"generic-dev"`, `"generic-hsm"`, or `"native"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            ProtectionLevel::GenericDev => "generic-dev",
            ProtectionLevel::GenericHsm => "generic-hsm",
            ProtectionLevel::Native => "native",
        }
    }
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProtectionLevel {
    type Err = BackendError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "generic-dev" => Ok(ProtectionLevel::GenericDev),
            "generic-hsm" => Ok(ProtectionLevel::GenericHsm),
            "native" => Ok(ProtectionLevel::Native),
            other => Err(BackendError::InvalidProtectionLevel(other.to_string())),
        }
    }
}

/// Hierarchical deterministic key derivation scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// BIP-0032 key derivation (supports hardened and non-hardened child indices on `secp256k1`).
    Bip32,
    /// SLIP-0010 key derivation (hardened-only child indices on `ed25519`).
    Slip10,
}

impl Scheme {
    /// Returns the canonical lowercase string (`"bip32"` or `"slip10"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Scheme::Bip32 => "bip32",
            Scheme::Slip10 => "slip10",
        }
    }

    /// Returns `true` if this scheme only permits hardened child indices (`>= 0x80000000`).
    pub const fn hardened_only(&self) -> bool {
        match self {
            Scheme::Bip32 => false,
            Scheme::Slip10 => true,
        }
    }

    /// Returns the expected v1 [`Curve`] for this derivation scheme.
    pub const fn expected_curve(&self) -> Curve {
        match self {
            Scheme::Bip32 => Curve::Secp256k1,
            Scheme::Slip10 => Curve::Ed25519,
        }
    }

    /// Returns `true` if `curve` is valid for this scheme in v1.
    pub const fn matches_curve(&self, curve: Curve) -> bool {
        matches!(
            (self, curve),
            (Scheme::Bip32, Curve::Secp256k1) | (Scheme::Slip10, Curve::Ed25519)
        )
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = BackendError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "bip32" => Ok(Scheme::Bip32),
            "slip10" => Ok(Scheme::Slip10),
            _ => Err(BackendError::InvalidScheme(s.to_string())),
        }
    }
}

impl From<Scheme> for DerivationScheme {
    fn from(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Bip32 => DerivationScheme::Bip32,
            Scheme::Slip10 => DerivationScheme::Slip10,
        }
    }
}

impl From<DerivationScheme> for Scheme {
    fn from(scheme: DerivationScheme) -> Self {
        match scheme {
            DerivationScheme::Bip32 => Scheme::Bip32,
            DerivationScheme::Slip10 => Scheme::Slip10,
        }
    }
}

/// Elliptic curve identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Curve {
    /// secp256k1 curve (used with BIP32 for Bitcoin, Ethereum/EVM, Tron, XRP Ledger).
    Secp256k1,
    /// Edwards25519 curve (used with SLIP10 for Solana).
    Ed25519,
}

impl Curve {
    /// Returns the canonical lowercase string (`"secp256k1"` or `"ed25519"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Curve::Secp256k1 => "secp256k1",
            Curve::Ed25519 => "ed25519",
        }
    }

    /// Returns the expected compressed public key byte length (`33` for `secp256k1`, `32` for `ed25519`).
    pub const fn public_key_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => crate::derive::COMPRESSED_PUBKEY_LEN,
            Curve::Ed25519 => crate::derive::ED25519_PUBKEY_LEN,
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Curve {
    type Err = BackendError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "secp256k1" => Ok(Curve::Secp256k1),
            "ed25519" => Ok(Curve::Ed25519),
            _ => Err(BackendError::InvalidCurve(s.to_string())),
        }
    }
}

/// Where the cryptographic signing operation executes for a given scheme/curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningLocation {
    /// Signing executes inside the PKCS#11 HSM token via a short-lived session object.
    Hsm,
    /// Signing executes in software inside the signer process (fallback when HSM lacks curve or mechanism).
    Software,
}

impl SigningLocation {
    /// Returns `"hsm"` or `"software"`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            SigningLocation::Hsm => "hsm",
            SigningLocation::Software => "software",
        }
    }

    /// Returns `true` if signing takes place inside the HSM (`SigningLocation::Hsm`).
    pub const fn is_hsm(&self) -> bool {
        matches!(self, SigningLocation::Hsm)
    }
}

impl fmt::Display for SigningLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-scheme capability entry determined by the startup probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeCap {
    /// Derivation scheme (`bip32` or `slip10`).
    pub scheme: Scheme,
    /// Elliptic curve (`secp256k1` or `ed25519`).
    pub curve: Curve,
    /// Whether only hardened derivation indices are permitted.
    pub hardened_only: bool,
    /// Whether signing for this scheme/curve runs in the HSM or in software.
    pub signing: SigningLocation,
}

impl SchemeCap {
    /// Constructs a [`SchemeCap`] for the given scheme, curve, and signing location.
    pub const fn new(scheme: Scheme, curve: Curve, signing: SigningLocation) -> Self {
        Self {
            scheme,
            curve,
            hardened_only: scheme.hardened_only(),
            signing,
        }
    }
}

/// Probed backend capabilities exposed via `GET /v1/signer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Backend identifier (e.g., `"softhsm-generic"`).
    pub backend: String,
    /// Protection level label (`"generic-dev"`, `"generic-hsm"`, or `"native"`).
    pub protection_level: ProtectionLevel,
    /// Supported derivation schemes and their probed signing locations.
    pub schemes: Vec<SchemeCap>,
    /// Maximum supported derivation path depth (`255`).
    pub max_depth: u8,
    /// Seed wrapping mechanism name (e.g., `"CKM_AES_GCM"`).
    pub wrap_mechanism: String,
    /// Whether child key derivation happens inside the HSM (`false` for generic tier).
    pub derives_in_hsm: bool,
}

impl Capabilities {
    /// Looks up the probed [`SigningLocation`] for a `(scheme, curve)` pair.
    pub fn signing_location(&self, scheme: Scheme, curve: Curve) -> Option<SigningLocation> {
        self.schemes
            .iter()
            .find(|cap| cap.scheme == scheme && cap.curve == curve)
            .map(|cap| cap.signing)
    }

    /// Constructs default generic-tier capabilities with the specified per-scheme signing locations.
    pub fn new_generic(
        backend: impl Into<String>,
        protection_level: ProtectionLevel,
        secp256k1_signing: SigningLocation,
        ed25519_signing: SigningLocation,
    ) -> Self {
        Self {
            backend: backend.into(),
            protection_level,
            schemes: vec![
                SchemeCap::new(Scheme::Bip32, Curve::Secp256k1, secp256k1_signing),
                SchemeCap::new(Scheme::Slip10, Curve::Ed25519, ed25519_signing),
            ],
            max_depth: MAX_DEPTH as u8,
            wrap_mechanism: "CKM_AES_GCM".to_string(),
            derives_in_hsm: false,
        }
    }
}

/// Cryptographic signature output returned by [`Backend::sign`].
///
/// Carries the raw 64-byte signature, optional decomposed/normalized ECDSA components
/// (`r`, low-S `s`, `recovery_id`, `der`), the derived public key, and the honest
/// `signing_in_hsm` indicator required in every signed response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Raw 64-byte signature:
    /// - ECDSA (`secp256k1`): `r (32B) || s (32B, low-S normalized)`
    /// - Ed25519 (`ed25519`): 64-byte Ed25519 signature
    /// - Taproot (`secp256k1`): 64-byte BIP340 Schnorr signature
    #[serde(with = "hex_serde")]
    pub bytes: Vec<u8>,

    /// 32-byte big-endian `r` scalar for ECDSA signatures (`None` for Ed25519 and Schnorr).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_array32_hex"
    )]
    pub r: Option<[u8; 32]>,

    /// 32-byte big-endian low-S normalized `s` scalar for ECDSA signatures (`None` for Ed25519 and Schnorr).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_array32_hex"
    )]
    pub s: Option<[u8; 32]>,

    /// ECDSA public key recovery ID (`0` or `1`, i.e. y-parity) matched against the derived
    /// compressed `secp256k1` public key (`None` for Ed25519 and BIP340 Schnorr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,

    /// Optional ASN.1 DER-encoded low-S ECDSA signature (used by Bitcoin and XRP Ledger).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_vec_hex"
    )]
    pub der: Option<Vec<u8>>,

    /// Derived public key corresponding to the signing key (`33B` compressed SEC1 for ECDSA,
    /// `32B` compressed Edwards point for Ed25519, or `32B` tweaked x-only pubkey for Taproot).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "hex_serde"
    )]
    pub public_key: Vec<u8>,

    /// `true` if the signature was generated inside the HSM via PKCS#11;
    /// `false` if generated in software fallback or via BIP340 Taproot Schnorr.
    pub signing_in_hsm: bool,
}

impl Signature {
    /// Constructs a normalized ECDSA (`secp256k1`) [`Signature`].
    pub fn new_ecdsa(
        r: [u8; 32],
        s: [u8; 32],
        recovery_id: u8,
        der: Option<Vec<u8>>,
        public_key: Vec<u8>,
        signing_in_hsm: bool,
    ) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(&s);
        Self {
            bytes,
            r: Some(r),
            s: Some(s),
            recovery_id: Some(recovery_id),
            der,
            public_key,
            signing_in_hsm,
        }
    }

    /// Constructs an Ed25519 (`ed25519`) [`Signature`].
    pub fn new_ed25519(sig: [u8; 64], public_key: [u8; 32], signing_in_hsm: bool) -> Self {
        Self {
            bytes: sig.to_vec(),
            r: None,
            s: None,
            recovery_id: None,
            der: None,
            public_key: public_key.to_vec(),
            signing_in_hsm,
        }
    }

    /// Constructs a BIP340 Taproot Schnorr [`Signature`].
    ///
    /// Per Section 4 and Section 8 of `Specs.md`, BIP340 Schnorr has no PKCS#11 mechanism
    /// and is always signed in software (`signing_in_hsm: false`).
    pub fn new_schnorr(sig: [u8; 64], tweaked_x_only_pubkey: [u8; 32]) -> Self {
        Self {
            bytes: sig.to_vec(),
            r: None,
            s: None,
            recovery_id: None,
            der: None,
            public_key: tweaked_x_only_pubkey.to_vec(),
            signing_in_hsm: false,
        }
    }

    /// Returns the raw signature bytes (`64` bytes).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the 65-byte `r (32B) || s (32B) || v (1B)` encoding for ECDSA signatures
    /// (used by Tron and Ethereum/EVM).
    pub fn to_rsv_bytes(&self) -> Option<[u8; 65]> {
        let r = self.r?;
        let s = self.s?;
        let v = self.recovery_id?;
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&r);
        out[32..64].copy_from_slice(&s);
        out[64] = v;
        Some(out)
    }
}

/// Structured errors returned by [`Backend`] implementations and domain helpers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackendError {
    #[error("invalid derivation path: {0}")]
    Path(#[from] PathError),

    #[error("BIP32 derivation error: {0}")]
    Bip32(#[from] Bip32Error),

    #[error("SLIP10 derivation error: {0}")]
    Slip10(#[from] Slip10Error),

    #[error("derivation self-test failed: {0}")]
    DerivationSelfTest(#[from] DerivationSelfTestError),

    #[error("unsupported scheme/curve combination: scheme={scheme}, curve={curve}")]
    UnsupportedSchemeCurve { scheme: Scheme, curve: Curve },

    #[error("invalid scheme '{0}': expected 'bip32' or 'slip10'")]
    InvalidScheme(String),

    #[error("invalid curve '{0}': expected 'secp256k1' or 'ed25519'")]
    InvalidCurve(String),

    #[error("invalid protection level '{0}': expected 'generic-dev', 'generic-hsm', or 'native'")]
    InvalidProtectionLevel(String),

    #[error("invalid AEAD associated data (AAD): {0}")]
    InvalidAad(String),

    #[error("invalid signing input for scheme={scheme}, curve={curve}: {reason}")]
    InvalidSigningInput {
        scheme: Scheme,
        curve: Curve,
        reason: String,
    },

    #[error("invalid wrapped seed blob: {0}")]
    InvalidWrappedSeed(String),

    #[error("HSM KEK '{0}' not found")]
    KekNotFound(String),

    #[error("HSM KEK attribute validation failed: {0}")]
    InvalidKekAttributes(String),

    #[error("HSM seed wrapping failed: {0}")]
    WrapFailed(String),

    #[error("HSM seed unwrapping failed (tampered ciphertext, wrong AAD, or invalid tag): {0}")]
    UnwrapFailed(String),

    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    #[error("HSM session object hygiene check failed: {count} leftover session object(s)")]
    SessionObjectHygieneFailed { count: usize },

    #[error("cryptographic signing error: {0}")]
    Crypto(String),

    #[error("startup capability probe failed: {0}")]
    ProbeFailed(String),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Validates that `scheme` and `curve` form a supported v1 pair:
/// - `(Scheme::Bip32, Curve::Secp256k1)`
/// - `(Scheme::Slip10, Curve::Ed25519)`
pub const fn validate_scheme_curve(scheme: Scheme, curve: Curve) -> Result<(), BackendError> {
    if scheme.matches_curve(curve) {
        Ok(())
    } else {
        Err(BackendError::UnsupportedSchemeCurve { scheme, curve })
    }
}

/// Canonical AEAD Associated Authenticated Data (AAD) components binding a wrapped seed
/// to a single wallet identity and cryptographic context.
///
/// Wire format: `"{wallet_id}|{scheme}|{curve}|{seed_version}|{kek_label}"` (UTF-8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AadComponents<'a> {
    pub wallet_id: &'a str,
    pub scheme: Scheme,
    pub curve: Curve,
    pub seed_version: u32,
    pub kek_label: &'a str,
}

impl<'a> AadComponents<'a> {
    /// Creates new [`AadComponents`].
    pub const fn new(
        wallet_id: &'a str,
        scheme: Scheme,
        curve: Curve,
        seed_version: u32,
        kek_label: &'a str,
    ) -> Self {
        Self {
            wallet_id,
            scheme,
            curve,
            seed_version,
            kek_label,
        }
    }

    /// Validates all components and returns the canonical AAD byte representation.
    pub fn to_checked_bytes(&self) -> Result<Vec<u8>, BackendError> {
        build_aad_checked(
            self.wallet_id,
            self.scheme,
            self.curve,
            self.seed_version,
            self.kek_label,
        )
    }

    /// Encodes the canonical AAD string `wallet_id|scheme|curve|seed_version|kek_label` as UTF-8 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        build_aad(
            self.wallet_id,
            self.scheme,
            self.curve,
            self.seed_version,
            self.kek_label,
        )
    }
}

/// Constructs the canonical AEAD Associated Authenticated Data (AAD) byte vector:
/// `wallet_id | scheme | curve | seed_version | kek_label`
///
/// Format: UTF-8 string `"{wallet_id}|{scheme}|{curve}|{seed_version}|{kek_label}"` using `|`
/// (`0x7c`) as the field separator with no surrounding whitespace.
///
/// Example: `b"w_01HZabc123|bip32|secp256k1|1|kek-v1"`.
pub fn build_aad(
    wallet_id: &str,
    scheme: Scheme,
    curve: Curve,
    seed_version: u32,
    kek_label: &str,
) -> Vec<u8> {
    format!(
        "{}{}{}{}{}{}{}{}{}",
        wallet_id,
        AAD_DELIMITER,
        scheme.as_str(),
        AAD_DELIMITER,
        curve.as_str(),
        AAD_DELIMITER,
        seed_version,
        AAD_DELIMITER,
        kek_label
    )
    .into_bytes()
}

/// Validates AAD inputs (rejecting empty strings, delimiter injection `'|'`, NUL bytes,
/// `seed_version == 0`, or mismatched `(scheme, curve)`) and returns the canonical AAD bytes.
pub fn build_aad_checked(
    wallet_id: &str,
    scheme: Scheme,
    curve: Curve,
    seed_version: u32,
    kek_label: &str,
) -> Result<Vec<u8>, BackendError> {
    validate_scheme_curve(scheme, curve)?;

    if wallet_id.is_empty() {
        return Err(BackendError::InvalidAad(
            "wallet_id must not be empty".to_string(),
        ));
    }
    if wallet_id.contains(AAD_DELIMITER) || wallet_id.contains('\0') {
        return Err(BackendError::InvalidAad(
            "wallet_id must not contain '|' or NUL".to_string(),
        ));
    }
    if seed_version == 0 {
        return Err(BackendError::InvalidAad(
            "seed_version must be >= 1".to_string(),
        ));
    }
    if kek_label.is_empty() {
        return Err(BackendError::InvalidAad(
            "kek_label must not be empty".to_string(),
        ));
    }
    if kek_label.contains(AAD_DELIMITER) || kek_label.contains('\0') {
        return Err(BackendError::InvalidAad(
            "kek_label must not contain '|' or NUL".to_string(),
        ));
    }

    Ok(build_aad(wallet_id, scheme, curve, seed_version, kek_label))
}

/// Derives a BIP32 (`secp256k1`) child key from raw `u32` path indices, bridging
/// [`Backend`] slice inputs (`path: &[u32]`) directly to [`DerivationPath::from_slice`]
/// and [`derive_bip32`].
pub fn derive_bip32_from_slice(seed: &[u8], path: &[u32]) -> Result<Bip32Key, BackendError> {
    let derivation_path = DerivationPath::from_slice(path)?;
    derivation_path.validate_for_scheme(Scheme::Bip32.into())?;
    Ok(derive_bip32(seed, &derivation_path)?)
}

/// Derives a SLIP10 (`ed25519`) child key from raw `u32` path indices, bridging
/// [`Backend`] slice inputs (`path: &[u32]`) directly to [`DerivationPath::from_slice`]
/// and [`derive_slip10`].
pub fn derive_slip10_from_slice(seed: &[u8], path: &[u32]) -> Result<Slip10Key, BackendError> {
    let derivation_path = DerivationPath::from_slice(path)?;
    derivation_path.validate_for_scheme(Scheme::Slip10.into())?;
    Ok(derive_slip10(seed, &derivation_path)?)
}

/// Derives the compressed public key (`33` bytes for `Bip32`/`Secp256k1`,
/// `32` bytes for `Slip10`/`Ed25519`) at `path` from a clear seed slice.
pub fn derive_public_key_from_seed(
    seed: &[u8],
    scheme: Scheme,
    curve: Curve,
    path: &[u32],
) -> Result<Vec<u8>, BackendError> {
    validate_scheme_curve(scheme, curve)?;
    match scheme {
        Scheme::Bip32 => {
            let key = derive_bip32_from_slice(seed, path)?;
            Ok(key.public_key().to_vec())
        }
        Scheme::Slip10 => {
            let key = derive_slip10_from_slice(seed, path)?;
            Ok(key.public_key().to_vec())
        }
    }
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod opt_vec_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

mod opt_array32_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                })?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

/// Loads and initializes a [`dyn Backend`] configured via the 4 portable PKCS#11 settings
/// specified in Task 32 and Section 10 of `Specs.md`:
/// - `CONFORMANCE_PKCS11_MODULE` (falls back to `PKCS11_MODULE_PATH`, system SoftHSM, or `:self:`)
/// - `CONFORMANCE_PKCS11_SLOT` (slot ID number or token label)
/// - `CONFORMANCE_PKCS11_PIN_FILE` (path to PIN file)
/// - `CONFORMANCE_KEK_LABEL` (defaults to `"kek-v1"`)
pub fn load_conformance_backend() -> Result<Box<dyn Backend>, BackendError> {
    let module_path = std::env::var("CONFORMANCE_PKCS11_MODULE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("PKCS11_MODULE_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .map(std::path::PathBuf::from)
        .or_else(|| crate::bootstrap::resolve_softhsm_module_path(None).ok())
        .unwrap_or_else(|| std::path::PathBuf::from(crate::pkcs11session::SELF_MODULE_PATH));

    let kek_label = std::env::var("CONFORMANCE_KEK_LABEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KEK_LABEL.to_string());

    let pin_file = match std::env::var("CONFORMANCE_PKCS11_PIN_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let tmp = std::env::temp_dir().join("polyglot_conformance_user.pin");
            let _ = std::fs::write(&tmp, b"test-softhsm-pin-1234\n");
            tmp
        }
    };

    let slot_selector = match std::env::var("CONFORMANCE_PKCS11_SLOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        Some(s) => {
            if let Ok(id) = s.parse::<u64>() {
                crate::pkcs11session::SlotSelector::from_id(id)
            } else {
                crate::pkcs11session::SlotSelector::from_label(s)
            }
        }
        None => {
            if module_path == std::path::Path::new(crate::pkcs11session::SELF_MODULE_PATH) {
                crate::pkcs11session::SlotSelector::from_id(7)
            } else {
                crate::pkcs11session::SlotSelector::from_label(crate::bootstrap::DEFAULT_TOKEN_LABEL)
            }
        }
    };

    let pkcs11_config = crate::pkcs11session::Pkcs11Config::new(
        module_path,
        slot_selector,
        pin_file,
        kek_label,
    );

    let backend = generic::GenericBackend::from_pkcs11_config(pkcs11_config)?;
    Ok(Box::new(backend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::HARDENED_FLAG;

    #[test]
    fn test_scheme_and_derivation_scheme_conversions() {
        let bip32_deriv: DerivationScheme = Scheme::Bip32.into();
        assert_eq!(bip32_deriv, DerivationScheme::Bip32);
        let bip32_back: Scheme = bip32_deriv.into();
        assert_eq!(bip32_back, Scheme::Bip32);

        let slip10_deriv: DerivationScheme = Scheme::Slip10.into();
        assert_eq!(slip10_deriv, DerivationScheme::Slip10);
        let slip10_back: Scheme = slip10_deriv.into();
        assert_eq!(slip10_back, Scheme::Slip10);

        assert!(!Scheme::Bip32.hardened_only());
        assert!(Scheme::Slip10.hardened_only());
        assert_eq!(Scheme::Bip32.expected_curve(), Curve::Secp256k1);
        assert_eq!(Scheme::Slip10.expected_curve(), Curve::Ed25519);
    }

    #[test]
    fn test_scheme_curve_validation_and_parsing() {
        assert!(validate_scheme_curve(Scheme::Bip32, Curve::Secp256k1).is_ok());
        assert!(validate_scheme_curve(Scheme::Slip10, Curve::Ed25519).is_ok());
        assert_eq!(
            validate_scheme_curve(Scheme::Bip32, Curve::Ed25519),
            Err(BackendError::UnsupportedSchemeCurve {
                scheme: Scheme::Bip32,
                curve: Curve::Ed25519
            })
        );
        assert_eq!(
            validate_scheme_curve(Scheme::Slip10, Curve::Secp256k1),
            Err(BackendError::UnsupportedSchemeCurve {
                scheme: Scheme::Slip10,
                curve: Curve::Secp256k1
            })
        );

        assert_eq!("bip32".parse::<Scheme>().unwrap(), Scheme::Bip32);
        assert_eq!("SLIP10".parse::<Scheme>().unwrap(), Scheme::Slip10);
        assert!("unknown".parse::<Scheme>().is_err());

        assert_eq!("secp256k1".parse::<Curve>().unwrap(), Curve::Secp256k1);
        assert_eq!("ED25519".parse::<Curve>().unwrap(), Curve::Ed25519);
        assert!("p256".parse::<Curve>().is_err());
    }

    #[test]
    fn test_protection_level_and_capabilities_json_serialization() {
        let caps = Capabilities::new_generic(
            "softhsm-generic",
            ProtectionLevel::GenericDev,
            SigningLocation::Hsm,
            SigningLocation::Software,
        );

        let json_val = serde_json::to_value(&caps).unwrap();
        assert_eq!(json_val["backend"], "softhsm-generic");
        assert_eq!(json_val["protection_level"], "generic-dev");
        assert_eq!(json_val["max_depth"], 255);
        assert_eq!(json_val["wrap_mechanism"], "CKM_AES_GCM");
        assert_eq!(json_val["derives_in_hsm"], false);

        let schemes = json_val["schemes"].as_array().unwrap();
        assert_eq!(schemes.len(), 2);
        assert_eq!(schemes[0]["scheme"], "bip32");
        assert_eq!(schemes[0]["curve"], "secp256k1");
        assert_eq!(schemes[0]["hardened_only"], false);
        assert_eq!(schemes[0]["signing"], "hsm");

        assert_eq!(schemes[1]["scheme"], "slip10");
        assert_eq!(schemes[1]["curve"], "ed25519");
        assert_eq!(schemes[1]["hardened_only"], true);
        assert_eq!(schemes[1]["signing"], "software");

        let round_trip: Capabilities = serde_json::from_value(json_val).unwrap();
        assert_eq!(round_trip, caps);
        assert_eq!(
            round_trip.signing_location(Scheme::Bip32, Curve::Secp256k1),
            Some(SigningLocation::Hsm)
        );
        assert_eq!(
            round_trip.signing_location(Scheme::Slip10, Curve::Ed25519),
            Some(SigningLocation::Software)
        );

        assert_eq!(
            serde_json::to_string(&ProtectionLevel::GenericHsm).unwrap(),
            "\"generic-hsm\""
        );
        assert_eq!(
            serde_json::to_string(&ProtectionLevel::Native).unwrap(),
            "\"native\""
        );
    }

    #[test]
    fn test_canonical_aad_construction_and_validation() {
        let aad = build_aad_checked(
            "w_01HZ8F3A",
            Scheme::Bip32,
            Curve::Secp256k1,
            DEFAULT_SEED_VERSION,
            DEFAULT_KEK_LABEL,
        )
        .unwrap();
        assert_eq!(aad, b"w_01HZ8F3A|bip32|secp256k1|1|kek-v1");

        let slip10_aad = AadComponents::new(
            "w_sol_99",
            Scheme::Slip10,
            Curve::Ed25519,
            1,
            "kek-v1",
        )
        .to_checked_bytes()
        .unwrap();
        assert_eq!(slip10_aad, b"w_sol_99|slip10|ed25519|1|kek-v1");

        // Reject empty wallet_id, pipe injection, zero version, empty kek_label, and mismatched curve
        assert!(build_aad_checked("", Scheme::Bip32, Curve::Secp256k1, 1, "kek-v1").is_err());
        assert!(
            build_aad_checked("w_1|injected", Scheme::Bip32, Curve::Secp256k1, 1, "kek-v1")
                .is_err()
        );
        assert!(build_aad_checked("w_1", Scheme::Bip32, Curve::Secp256k1, 0, "kek-v1").is_err());
        assert!(build_aad_checked("w_1", Scheme::Bip32, Curve::Secp256k1, 1, "").is_err());
        assert!(build_aad_checked("w_1", Scheme::Bip32, Curve::Secp256k1, 1, "kek|v1").is_err());
        assert!(build_aad_checked("w_1", Scheme::Bip32, Curve::Ed25519, 1, "kek-v1").is_err());
    }

    #[test]
    fn test_derive_integration_and_error_conversions() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // BIP32 TV1 m/0'/1
        let bip32_path = [HARDENED_FLAG, 1];
        let pubkey_bip32 =
            derive_public_key_from_seed(&seed, Scheme::Bip32, Curve::Secp256k1, &bip32_path)
                .unwrap();
        assert_eq!(
            hex::encode(&pubkey_bip32),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
        );

        // SLIP10 TV1 m/0'/1'
        let slip10_path = [HARDENED_FLAG, HARDENED_FLAG | 1];
        let pubkey_slip10 =
            derive_public_key_from_seed(&seed, Scheme::Slip10, Curve::Ed25519, &slip10_path)
                .unwrap();
        assert_eq!(
            hex::encode(&pubkey_slip10),
            "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"
        );

        // SLIP10 rejects non-hardened index and converts PathError -> BackendError::Path
        let err =
            derive_public_key_from_seed(&seed, Scheme::Slip10, Curve::Ed25519, &[HARDENED_FLAG, 1])
                .unwrap_err();
        assert!(matches!(
            err,
            BackendError::Path(PathError::NonHardenedIndexNotAllowed {
                position: 1,
                index: 1
            })
        ));

        // Exceeding depth 255 converts PathError::ExceedsMaxDepth -> BackendError::Path
        let deep_path = vec![HARDENED_FLAG; 256];
        let depth_err =
            derive_public_key_from_seed(&seed, Scheme::Bip32, Curve::Secp256k1, &deep_path)
                .unwrap_err();
        assert!(matches!(
            depth_err,
            BackendError::Path(PathError::ExceedsMaxDepth {
                depth: 256,
                max: 255
            })
        ));
    }

    #[test]
    fn test_signature_constructors_and_serialization() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let pubkey = vec![0x02u8; 33];
        let der = vec![0x30, 0x44];
        let sig = Signature::new_ecdsa(r, s, 1, Some(der.clone()), pubkey.clone(), true);

        assert_eq!(sig.as_bytes().len(), 64);
        assert_eq!(sig.r, Some(r));
        assert_eq!(sig.s, Some(s));
        assert_eq!(sig.recovery_id, Some(1));
        assert_eq!(sig.der, Some(der));
        assert!(sig.signing_in_hsm);

        let rsv = sig.to_rsv_bytes().unwrap();
        assert_eq!(&rsv[..32], &r);
        assert_eq!(&rsv[32..64], &s);
        assert_eq!(rsv[64], 1);

        let json = serde_json::to_string(&sig).unwrap();
        let decoded: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, sig);

        let schnorr = Signature::new_schnorr([0xaa; 64], [0xbb; 32]);
        assert!(!schnorr.signing_in_hsm);
        assert!(schnorr.to_rsv_bytes().is_none());
    }

    #[test]
    fn test_mock_backend_trait_object_compatibility() {
        struct DummyBackend;

        impl Backend for DummyBackend {
            fn capabilities(&self) -> Result<Capabilities, BackendError> {
                Ok(Capabilities::new_generic(
                    "softhsm-generic",
                    ProtectionLevel::GenericDev,
                    SigningLocation::Hsm,
                    SigningLocation::Hsm,
                ))
            }

            fn create_wallet(&self, spec: &Spec, aad: &[u8]) -> Result<Vec<u8>, BackendError> {
                spec.validate()?;
                if aad.is_empty() {
                    return Err(BackendError::InvalidAad("empty AAD".to_string()));
                }
                Ok(vec![0u8; WRAPPED_SEED_LEN])
            }

            fn public_key(&self, w: &WalletRef, path: &[u32]) -> Result<Vec<u8>, BackendError> {
                let seed = [0x01u8; WALLET_SEED_LEN];
                derive_public_key_from_seed(&seed, w.scheme, w.curve, path)
            }

            fn sign(
                &self,
                w: &WalletRef,
                path: &[u32],
                input: SigningInput,
            ) -> Result<Signature, BackendError> {
                let pubkey = self.public_key(w, path)?;
                match (w.scheme, w.curve, input) {
                    (Scheme::Bip32, Curve::Secp256k1, SigningInput::Digest32(_)) => Ok(
                        Signature::new_ecdsa([1u8; 32], [2u8; 32], 0, None, pubkey, true),
                    ),
                    (Scheme::Bip32, Curve::Secp256k1, SigningInput::TaprootDigest32(_)) => {
                        Ok(Signature::new_schnorr([3u8; 64], [4u8; 32]))
                    }
                    (Scheme::Slip10, Curve::Ed25519, SigningInput::Message(_)) => {
                        let pk: [u8; 32] = pubkey.try_into().unwrap();
                        Ok(Signature::new_ed25519([5u8; 64], pk, true))
                    }
                    _ => Err(BackendError::InvalidSigningInput {
                        scheme: w.scheme,
                        curve: w.curve,
                        reason: "mismatched signing input variant".to_string(),
                    }),
                }
            }
        }

        // Verify `dyn Backend` is object-safe and usable through a trait reference
        let backend: Box<dyn Backend> = Box::new(DummyBackend);
        let caps = backend.capabilities().unwrap();
        assert_eq!(caps.protection_level, ProtectionLevel::GenericDev);

        let spec = Spec::new(Scheme::Bip32, Curve::Secp256k1);
        let aad = build_aad("w_test", spec.scheme, spec.curve, 1, DEFAULT_KEK_LABEL);
        let wrapped = backend.create_wallet(&spec, &aad).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_SEED_LEN);

        let wref = WalletRef::new(&wrapped, &aad, spec.scheme, spec.curve);
        let path = [HARDENED_FLAG | 44, HARDENED_FLAG | 60, HARDENED_FLAG, 0, 0];
        let pk = backend.public_key(&wref, &path).unwrap();
        assert_eq!(pk.len(), 33);

        let digest = [0x99u8; 32];
        let sig = backend
            .sign(&wref, &path, SigningInput::Digest32(&digest))
            .unwrap();
        assert!(sig.signing_in_hsm);
        assert_eq!(sig.as_bytes().len(), 64);
    }
}
