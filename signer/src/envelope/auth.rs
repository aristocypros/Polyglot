//! Signer Trust Configuration and Policy Engine Authorization Signature Verification.
//!
//! This module implements:
//! - Read-only trust configuration ([`SignerConfig`]) parsed from `signer.yaml`.
//! - Pinned policy engine public keys ([`PinnedKey`]) with cryptographic algorithms
//!   (`ed25519` and `ES256`) and optional validity windows (`not_before`, `not_after`).
//! - Policy engine authorization verification ([`verify_authorization`], [`verify_authorization_at`]):
//!   - **`ed25519`**: Verifies 64-byte Ed25519 signature over `SHA-256(canonical_body_bytes)`.
//!   - **`ES256`**: Parses detached-payload JWS compact serialization (`<header_b64>..<sig_b64>`,
//!     RFC 7515 Appendix F), strictly validates JWS protected header (rejects `alg != "ES256"`,
//!     `alg == "none"`, mismatched `kid`, unknown `crit`), and verifies P-256 ECDSA signature
//!     over `ASCII(header_b64) || '.' || canonical_body_bytes`.
//! - Standardized signer rejection reason codes ([`AuthError::reason_code`]):
//!   `bad_signature`, `unknown_kid`, `key_expired`, `alg_mismatch`.

use std::path::Path;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::DecodePublicKey as Ed25519DecodePublicKey;
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey,
    VerifyingKey as P256VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors arising during trust configuration parsing or validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// I/O error reading configuration file.
    #[error("I/O error reading signer config: {0}")]
    Io(String),

    /// YAML syntax or deserialization error.
    #[error("invalid YAML in signer config: {0}")]
    InvalidYaml(String),

    /// Semantic configuration validation failure.
    #[error("signer config validation error: {0}")]
    Validation(String),
}

/// Errors arising during policy engine authorization verification.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AuthError {
    /// Key ID is not present in the pinned policy engine keys.
    #[error("unknown policy engine key id: '{0}'")]
    UnknownKid(String),

    /// Key is outside its validity window (`not_before` or `not_after`).
    #[error("key '{kid}' is not valid at this time (not_before={not_before:?}, not_after={not_after:?})")]
    KeyExpired {
        kid: String,
        not_before: Option<String>,
        not_after: Option<String>,
    },

    /// Algorithm mismatch between wire authorization, JWS header, or pinned configuration.
    #[error("algorithm mismatch: expected '{expected}', got '{got}'")]
    AlgMismatch { expected: String, got: String },

    /// Cryptographic signature is invalid, signature bytes are corrupt, or payload was tampered.
    #[error("bad signature: {0}")]
    BadSignature(String),

    /// Unknown critical header (`crit`) found in JWS protected header.
    #[error("unknown critical header in JWS: {0}")]
    UnknownCrit(String),

    /// Authorization payload syntax or structure is invalid.
    #[error("invalid authorization payload: {0}")]
    InvalidAuthorization(String),
}

impl AuthError {
    /// Returns the exact reason code string used for RFC 9457 Problem Details and signer audits.
    ///
    /// The four canonical reason codes defined in the specification are:
    /// - `"bad_signature"`
    /// - `"unknown_kid"`
    /// - `"key_expired"`
    /// - `"alg_mismatch"`
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnknownKid(_) => "unknown_kid",
            Self::KeyExpired { .. } => "key_expired",
            Self::AlgMismatch { .. } => "alg_mismatch",
            Self::UnknownCrit(_) => "alg_mismatch",
            Self::BadSignature(_) => "bad_signature",
            Self::InvalidAuthorization(_) => "bad_signature",
        }
    }

    /// Returns the top-level RFC 9457 error code (`"signer_rejected"`).
    pub const fn error_code(&self) -> &'static str {
        "signer_rejected"
    }
}

/// Signer deployment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Development profile: digest signing allowed by default.
    #[default]
    Dev,
    /// Production profile: blind digest signing rejected by default.
    Prod,
}

impl Profile {
    /// Returns the string representation (`"dev"` or `"prod"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported cryptographic algorithms for policy engine authorization keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PolicyAlg {
    /// Ed25519 signature over SHA-256(canonical_body_bytes).
    #[serde(rename = "ed25519", alias = "Ed25519")]
    Ed25519,
    /// ECDSA P-256 SHA-256 signature via detached JWS.
    #[serde(rename = "ES256", alias = "es256")]
    Es256,
}

impl PolicyAlg {
    /// Returns the canonical algorithm identifier string (`"ed25519"` or `"ES256"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Es256 => "ES256",
        }
    }
}

impl std::fmt::Display for PolicyAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Pinned policy engine public key entry from `signer.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKey {
    /// Key identifier (e.g. `"pe-dev-1"`).
    pub kid: String,

    /// Pinned cryptographic algorithm (`ed25519` or `ES256`).
    pub alg: PolicyAlg,

    /// Public key string: accepts hex (with or without `0x`), base64url/base64, or PEM.
    pub public_key: String,

    /// Optional UTC RFC 3339 not-before timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,

    /// Optional UTC RFC 3339 not-after (expiration) timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

impl PinnedKey {
    /// Validates whether this key is valid at the specified point in time.
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        if let Some(ref nbf_str) = self.not_before {
            let nbf = DateTime::parse_from_rfc3339(nbf_str)
                .map_err(|_| AuthError::KeyExpired {
                    kid: self.kid.clone(),
                    not_before: self.not_before.clone(),
                    not_after: self.not_after.clone(),
                })?
                .with_timezone(&Utc);
            if now < nbf {
                return Err(AuthError::KeyExpired {
                    kid: self.kid.clone(),
                    not_before: self.not_before.clone(),
                    not_after: self.not_after.clone(),
                });
            }
        }

        if let Some(ref naf_str) = self.not_after {
            let naf = DateTime::parse_from_rfc3339(naf_str)
                .map_err(|_| AuthError::KeyExpired {
                    kid: self.kid.clone(),
                    not_before: self.not_before.clone(),
                    not_after: self.not_after.clone(),
                })?
                .with_timezone(&Utc);
            if now > naf {
                return Err(AuthError::KeyExpired {
                    kid: self.kid.clone(),
                    not_before: self.not_before.clone(),
                    not_after: self.not_after.clone(),
                });
            }
        }

        Ok(())
    }

    /// Parses and validates the public key into an [`Ed25519VerifyingKey`].
    pub fn parse_ed25519_verifying_key(&self) -> Result<Ed25519VerifyingKey, AuthError> {
        parse_ed25519_verifying_key(&self.public_key)
    }

    /// Parses and validates the public key into a [`P256VerifyingKey`].
    pub fn parse_es256_verifying_key(&self) -> Result<P256VerifyingKey, AuthError> {
        parse_es256_verifying_key(&self.public_key)
    }
}

/// Read-only trust configuration loaded from `signer.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Audience identifier for this signer (e.g., `"signer-local-1"`).
    pub signer_id: String,

    /// Maximum allowable request lifetime in seconds (default: 600 seconds = 10 minutes).
    #[serde(default = "default_max_lifetime_seconds")]
    pub max_lifetime_seconds: u64,

    /// Allowable clock skew in seconds (default: 30 seconds).
    #[serde(default = "default_clock_skew_seconds")]
    pub clock_skew_seconds: u64,

    /// Profile (`dev` or `prod`).
    #[serde(default)]
    pub profile: Profile,

    /// Explicit override for blind digest/message signing.
    /// If not specified, defaults to `true` in `dev` and `false` in `prod`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_digest_signing: Option<bool>,

    /// Pinned policy engine public keys.
    #[serde(default, alias = "policy_keys")]
    pub policy_engine_keys: Vec<PinnedKey>,
}

const fn default_max_lifetime_seconds() -> u64 {
    600
}

const fn default_clock_skew_seconds() -> u64 {
    30
}

impl SignerConfig {
    /// Creates a minimal configuration with default settings.
    pub fn new(signer_id: impl Into<String>, profile: Profile) -> Self {
        Self {
            signer_id: signer_id.into(),
            max_lifetime_seconds: default_max_lifetime_seconds(),
            clock_skew_seconds: default_clock_skew_seconds(),
            profile,
            allow_digest_signing: None,
            policy_engine_keys: Vec::new(),
        }
    }

    /// Returns whether blind digest/message signing is allowed under this configuration.
    pub fn allow_digest_signing(&self) -> bool {
        self.allow_digest_signing.unwrap_or(match self.profile {
            Profile::Dev => true,
            Profile::Prod => false,
        })
    }

    /// Returns a reference to the pinned key matching the specified `kid`, if found.
    pub fn get_pinned_key(&self, kid: &str) -> Option<&PinnedKey> {
        self.policy_engine_keys.iter().find(|k| k.kid == kid)
    }

    /// Loads and parses a [`SignerConfig`] from a YAML string.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml::from_str(yaml_str)
            .map_err(|e| ConfigError::InvalidYaml(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Loads and parses a [`SignerConfig`] from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(format!("{}: {}", path.as_ref().display(), e)))?;
        Self::from_yaml_str(&content)
    }

    /// Validates configuration sanity (non-empty signer_id and valid public key encodings).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.signer_id.trim().is_empty() {
            return Err(ConfigError::Validation("signer_id must not be empty".into()));
        }
        for key in &self.policy_engine_keys {
            if key.kid.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "pinned policy key 'kid' must not be empty".into(),
                ));
            }
            match key.alg {
                PolicyAlg::Ed25519 => {
                    key.parse_ed25519_verifying_key().map_err(|e| {
                        ConfigError::Validation(format!(
                            "invalid ed25519 public key for kid '{}': {e}",
                            key.kid
                        ))
                    })?;
                }
                PolicyAlg::Es256 => {
                    key.parse_es256_verifying_key().map_err(|e| {
                        ConfigError::Validation(format!(
                            "invalid ES256 public key for kid '{}': {e}",
                            key.kid
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// Raw authorization payload on the wire inside an envelope: `{ kid, alg, sig?, jws? }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAuthorization {
    /// Policy engine key identifier.
    pub kid: String,

    /// Algorithm declared on the wire (`"ed25519"` or `"ES256"`).
    pub alg: String,

    /// 64-byte base64url-encoded signature for `ed25519`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,

    /// Detached-payload JWS compact serialization for `ES256` (`<header_b64>..<sig_b64>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
}

/// Strongly-typed policy engine authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum Authorization {
    /// Ed25519 signature authorization.
    #[serde(rename = "ed25519")]
    Ed25519 {
        kid: String,
        sig: String,
    },
    /// ES256 detached JWS authorization.
    #[serde(rename = "ES256")]
    Es256 {
        kid: String,
        jws: String,
    },
}

impl From<Authorization> for RawAuthorization {
    fn from(auth: Authorization) -> Self {
        match auth {
            Authorization::Ed25519 { kid, sig } => Self {
                kid,
                alg: "ed25519".to_string(),
                sig: Some(sig),
                jws: None,
            },
            Authorization::Es256 { kid, jws } => Self {
                kid,
                alg: "ES256".to_string(),
                sig: None,
                jws: Some(jws),
            },
        }
    }
}

/// JWS protected header structure strictly validated for ES256 detached signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwsHeader {
    /// Must be `"ES256"`.
    pub alg: String,

    /// Optional key identifier. If present, MUST match the authorization `kid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Optional critical header parameter array (RFC 7515 §4.1.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,

    /// Optional type parameter (e.g. `"JWT"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Optional unencoded payload indicator (RFC 7797).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b64: Option<bool>,
}

/// Verifies policy engine authorization against pinned keys using the current system time (`Utc::now()`).
pub fn verify_authorization<'a>(
    config: &'a SignerConfig,
    auth: &RawAuthorization,
    canonical_body_bytes: &[u8],
) -> Result<&'a PinnedKey, AuthError> {
    verify_authorization_at(config, auth, canonical_body_bytes, Utc::now())
}

/// Verifies policy engine authorization against pinned keys at a specific reference time.
pub fn verify_authorization_at<'a>(
    config: &'a SignerConfig,
    auth: &RawAuthorization,
    canonical_body_bytes: &[u8],
    now: DateTime<Utc>,
) -> Result<&'a PinnedKey, AuthError> {
    // Step 1: Look up the key ID in pinned policy engine keys.
    let pinned_key = config
        .get_pinned_key(&auth.kid)
        .ok_or_else(|| AuthError::UnknownKid(auth.kid.clone()))?;

    // Step 2: Verify the key is currently within its validity window.
    pinned_key.is_valid_at(now)?;

    // Step 3: Verify the wire algorithm matches the pinned algorithm.
    // If the wire algorithm does not match the pinned algorithm, reject immediately with alg_mismatch.
    if auth.alg != pinned_key.alg.as_str() {
        return Err(AuthError::AlgMismatch {
            expected: pinned_key.alg.as_str().to_string(),
            got: auth.alg.clone(),
        });
    }

    // Step 4: Verify cryptographic signature based on algorithm.
    match pinned_key.alg {
        PolicyAlg::Ed25519 => {
            verify_ed25519_auth(pinned_key, auth, canonical_body_bytes)?;
        }
        PolicyAlg::Es256 => {
            verify_es256_auth(pinned_key, auth, canonical_body_bytes)?;
        }
    }

    Ok(pinned_key)
}

/// Verifies a generic JSON authorization value against pinned configuration.
pub fn verify_authorization_value<'a>(
    config: &'a SignerConfig,
    auth_val: &serde_json::Value,
    canonical_body_bytes: &[u8],
) -> Result<&'a PinnedKey, AuthError> {
    verify_authorization_value_at(config, auth_val, canonical_body_bytes, Utc::now())
}

/// Verifies a generic JSON authorization value against pinned configuration at a reference time.
pub fn verify_authorization_value_at<'a>(
    config: &'a SignerConfig,
    auth_val: &serde_json::Value,
    canonical_body_bytes: &[u8],
    now: DateTime<Utc>,
) -> Result<&'a PinnedKey, AuthError> {
    let raw_auth: RawAuthorization = serde_json::from_value(auth_val.clone())
        .map_err(|e| AuthError::InvalidAuthorization(e.to_string()))?;
    verify_authorization_at(config, &raw_auth, canonical_body_bytes, now)
}

/// Verifies an Ed25519 authorization signature over SHA-256(canonical_body_bytes).
fn verify_ed25519_auth(
    pinned_key: &PinnedKey,
    auth: &RawAuthorization,
    canonical_body_bytes: &[u8],
) -> Result<(), AuthError> {
    let sig_str = auth.sig.as_deref().ok_or_else(|| {
        AuthError::BadSignature("missing 'sig' field for ed25519 authorization".into())
    })?;

    // Signature must be unpadded base64url
    let sig_bytes = Base64UrlUnpadded::decode_vec(sig_str.trim())
        .map_err(|e| AuthError::BadSignature(format!("invalid base64url signature: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(AuthError::BadSignature(format!(
            "invalid signature length {}, expected 64 bytes",
            sig_bytes.len()
        )));
    }

    let mut sig_fixed = [0u8; 64];
    sig_fixed.copy_from_slice(&sig_bytes);
    let signature = Ed25519Signature::from_bytes(&sig_fixed);

    let verifying_key = pinned_key.parse_ed25519_verifying_key()?;

    // ed25519 signature is computed over SHA-256(canonical_body_bytes)
    let body_hash: [u8; 32] = Sha256::digest(canonical_body_bytes).into();

    verifying_key
        .verify_strict(&body_hash, &signature)
        .map_err(|e| AuthError::BadSignature(format!("ed25519 verification failed: {e}")))?;

    Ok(())
}

/// Verifies an ES256 detached JWS signature over ASCII(header_b64) || '.' || canonical_body_bytes.
fn verify_es256_auth(
    pinned_key: &PinnedKey,
    auth: &RawAuthorization,
    canonical_body_bytes: &[u8],
) -> Result<(), AuthError> {
    let jws_str = auth.jws.as_deref().ok_or_else(|| {
        AuthError::BadSignature("missing 'jws' field for ES256 authorization".into())
    })?;

    // Parse detached-payload JWS compact string: `<protected_header_b64>..<sig_b64>` (RFC 7515 Appendix F)
    let parts: Vec<&str> = jws_str.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::BadSignature(
            "malformed detached JWS: expected exactly 3 dot-separated parts ('<header>..<sig>')".into(),
        ));
    }
    if !parts[1].is_empty() {
        return Err(AuthError::BadSignature(
            "malformed detached JWS: payload part must be empty between dots ('<header>..<sig>')".into(),
        ));
    }

    let header_b64 = parts[0];
    let sig_b64 = parts[2];

    // Decode protected header
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64)
        .map_err(|e| AuthError::BadSignature(format!("invalid base64url in JWS header: {e}")))?;

    // Parse JWS header strictly
    let header: JwsHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        // If alg in header was not ES256 or unknown fields present, reject
        AuthError::AlgMismatch {
            expected: "ES256".to_string(),
            got: format!("invalid or malformed JWS header: {e}"),
        }
    })?;

    // Reject alg != "ES256" (including "none")
    if header.alg != "ES256" {
        return Err(AuthError::AlgMismatch {
            expected: "ES256".to_string(),
            got: header.alg,
        });
    }

    // Reject mismatched kid if present in header
    if let Some(ref header_kid) = header.kid {
        if header_kid != &auth.kid {
            return Err(AuthError::UnknownKid(format!(
                "JWS header kid '{header_kid}' does not match authorization kid '{}'",
                auth.kid
            )));
        }
    }

    // Reject unknown critical headers (RFC 7515 §4.1.11)
    if let Some(ref crit) = header.crit {
        if !crit.is_empty() {
            return Err(AuthError::UnknownCrit(format!(
                "unsupported critical header(s): {crit:?}"
            )));
        }
    }

    // Decode signature bytes (must be 64-byte raw R || S)
    let sig_bytes = Base64UrlUnpadded::decode_vec(sig_b64)
        .map_err(|e| AuthError::BadSignature(format!("invalid base64url in JWS signature: {e}")))?;

    if sig_bytes.len() != 64 {
        return Err(AuthError::BadSignature(format!(
            "invalid ES256 signature length {}, expected 64 bytes (R || S)",
            sig_bytes.len()
        )));
    }

    let signature = P256Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| AuthError::BadSignature(format!("invalid P-256 signature bytes: {e}")))?;

    let verifying_key = pinned_key.parse_es256_verifying_key()?;

    // Build JWS signing input: ASCII(protected_header_b64) || '.' || canonical_body_bytes
    let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + canonical_body_bytes.len());
    signing_input.extend_from_slice(header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(canonical_body_bytes);

    // Verify ECDSA P-256 signature over signing_input (hashed with SHA-256 by the verifier)
    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|e| AuthError::BadSignature(format!("ES256 verification failed: {e}")))?;

    Ok(())
}

/// Parses an Ed25519 public key from hex, base64/base64url, or SubjectPublicKeyInfo PEM.
pub fn parse_ed25519_verifying_key(key_str: &str) -> Result<Ed25519VerifyingKey, AuthError> {
    let clean = key_str.trim();

    // Check PEM SPKI
    if clean.starts_with("-----BEGIN") {
        if let Ok(key) = Ed25519VerifyingKey::from_public_key_pem(clean) {
            return Ok(key);
        }
    }

    // Check hex (with or without 0x)
    let hex_str = clean.strip_prefix("0x").unwrap_or(clean);
    if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(hex_str) {
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| AuthError::BadSignature("invalid ed25519 key length".into()))?;
            return Ed25519VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| AuthError::BadSignature(format!("invalid ed25519 public key: {e}")));
        }
    }

    // Check base64url unpadded
    if let Ok(bytes) = Base64UrlUnpadded::decode_vec(clean) {
        if bytes.len() == 32 {
            let key_bytes: [u8; 32] = bytes.try_into().unwrap();
            return Ed25519VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| AuthError::BadSignature(format!("invalid ed25519 public key: {e}")));
        }
    }

    // Check standard base64
    if let Ok(bytes) = Base64::decode_vec(clean) {
        if bytes.len() == 32 {
            let key_bytes: [u8; 32] = bytes.try_into().unwrap();
            return Ed25519VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| AuthError::BadSignature(format!("invalid ed25519 public key: {e}")));
        }
    }

    Err(AuthError::BadSignature(
        "unrecognized Ed25519 public key format (expected 32-byte hex, base64url, or PEM)".into(),
    ))
}

/// Parses a P-256 public key from SEC1 hex (compressed/uncompressed), base64, or PEM.
pub fn parse_es256_verifying_key(key_str: &str) -> Result<P256VerifyingKey, AuthError> {
    let clean = key_str.trim();

    // Check PEM SPKI
    if clean.starts_with("-----BEGIN") {
        use p256::pkcs8::DecodePublicKey;
        if let Ok(key) = p256::PublicKey::from_public_key_pem(clean) {
            return Ok(P256VerifyingKey::from(key));
        }
    }

    // Check SEC1 hex (66 hex chars = 33 bytes compressed, 130 hex chars = 65 bytes uncompressed)
    let hex_str = clean.strip_prefix("0x").unwrap_or(clean);
    if (hex_str.len() == 66 || hex_str.len() == 130)
        && hex_str.chars().all(|c| c.is_ascii_hexdigit())
    {
        if let Ok(bytes) = hex::decode(hex_str) {
            if let Ok(key) = p256::PublicKey::from_sec1_bytes(&bytes) {
                return Ok(P256VerifyingKey::from(key));
            }
        }
    }

    // Check base64url unpadded
    if let Ok(bytes) = Base64UrlUnpadded::decode_vec(clean) {
        if bytes.len() == 33 || bytes.len() == 65 {
            if let Ok(key) = p256::PublicKey::from_sec1_bytes(&bytes) {
                return Ok(P256VerifyingKey::from(key));
            }
        }
    }

    // Check standard base64
    if let Ok(bytes) = Base64::decode_vec(clean) {
        if bytes.len() == 33 || bytes.len() == 65 {
            if let Ok(key) = p256::PublicKey::from_sec1_bytes(&bytes) {
                return Ok(P256VerifyingKey::from(key));
            }
        }
    }

    Err(AuthError::BadSignature(
        "unrecognized ES256 (P-256) public key format (expected SEC1 hex, base64url, or PEM)".into(),
    ))
}

// -----------------------------------------------------------------------------
// Helper functions for signing authorizations (used by tests, simulators, CLI)
// -----------------------------------------------------------------------------

/// Creates an Ed25519 authorization for a canonical request body.
pub fn sign_ed25519_authorization(
    signing_key: &Ed25519SigningKey,
    kid: &str,
    canonical_body_bytes: &[u8],
) -> RawAuthorization {
    use ed25519_dalek::Signer;

    let body_hash: [u8; 32] = Sha256::digest(canonical_body_bytes).into();
    let signature = signing_key.sign(&body_hash);
    let sig_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

    RawAuthorization {
        kid: kid.to_string(),
        alg: "ed25519".to_string(),
        sig: Some(sig_b64),
        jws: None,
    }
}

/// Creates an ES256 detached JWS authorization for a canonical request body.
pub fn sign_es256_authorization(
    signing_key: &P256SigningKey,
    kid: &str,
    canonical_body_bytes: &[u8],
) -> RawAuthorization {
    let jws = create_detached_jws(signing_key, kid, canonical_body_bytes);
    RawAuthorization {
        kid: kid.to_string(),
        alg: "ES256".to_string(),
        sig: None,
        jws: Some(jws),
    }
}

/// Creates a detached-payload JWS compact serialization string (`<header_b64>..<sig_b64>`).
pub fn create_detached_jws(
    signing_key: &P256SigningKey,
    kid: &str,
    canonical_body_bytes: &[u8],
) -> String {
    use p256::ecdsa::signature::Signer;

    let header = JwsHeader {
        alg: "ES256".to_string(),
        kid: Some(kid.to_string()),
        crit: None,
        typ: None,
        b64: None,
    };
    let header_json = serde_json::to_vec(&header).expect("serialize JwsHeader");
    let header_b64 = Base64UrlUnpadded::encode_string(&header_json);

    let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + canonical_body_bytes.len());
    signing_input.extend_from_slice(header_b64.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(canonical_body_bytes);

    let signature: P256Signature = signing_key.sign(&signing_input);
    let sig_bytes = signature.to_bytes();
    let sig_b64 = Base64UrlUnpadded::encode_string(sig_bytes.as_ref());

    format!("{header_b64}..{sig_b64}")
}

/// Combined error type for envelope JCS decoding and policy engine authorization verification.
#[derive(Debug, Error)]
pub enum EnvelopeAuthError {
    /// Failure during envelope JSON parsing, base64url body decoding, or canonicalization check.
    #[error(transparent)]
    Jcs(#[from] crate::envelope::JcsError),

    /// Failure during policy engine signature or authorization verification.
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl EnvelopeAuthError {
    /// Returns the exact reason code string.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Jcs(e) => e.reason_code(),
            Self::Auth(e) => e.reason_code(),
        }
    }

    /// Returns the top-level RFC 9457 error code (`"invalid_request"` or `"signer_rejected"`).
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Jcs(e) => e.error_code(),
            Self::Auth(e) => e.error_code(),
        }
    }
}

/// Verifies an envelope JSON string end-to-end:
/// 1. Parses envelope and strictly verifies canonical body bytes (RFC 8785).
/// 2. Verifies policy engine authorization against pinned signer configuration.
pub fn verify_envelope_and_auth<'a>(
    config: &'a SignerConfig,
    envelope_json: &str,
    now: Option<DateTime<Utc>>,
) -> Result<(crate::envelope::RequestBody, Vec<u8>, &'a PinnedKey), EnvelopeAuthError> {
    let (envelope, request_body, canonical_body_bytes) =
        crate::envelope::verify_envelope_json(envelope_json)?;
    let raw_auth: RawAuthorization = serde_json::from_value(envelope.authorization)
        .map_err(|e| AuthError::InvalidAuthorization(e.to_string()))?;
    let pinned_key = match now {
        Some(t) => verify_authorization_at(config, &raw_auth, &canonical_body_bytes, t)?,
        None => verify_authorization(config, &raw_auth, &canonical_body_bytes)?,
    };
    Ok((request_body, canonical_body_bytes, pinned_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    fn sample_body_canonical() -> Vec<u8> {
        b"{\"audience\":\"signer-local-1\",\"curve\":\"secp256k1\",\"decision_id\":\"dec-001\",\"expires_at\":\"2026-10-19T15:00:00Z\",\"nonce\":\"0123456789abcdef0123456789abcdef\",\"request_id\":\"11111111-2222-3333-4444-555555555555\",\"scheme\":\"bip32\",\"type\":\"create_wallet\",\"v\":1,\"wallet_id\":\"w-test-1\"}".to_vec()
    }

    #[test]
    fn test_ed25519_authorization_acceptance() {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-ed-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pub_hex,
                not_before: Some("2026-01-01T00:00:00Z".to_string()),
                not_after: Some("2027-01-01T00:00:00Z".to_string()),
            }],
        };

        let body = sample_body_canonical();
        let auth = sign_ed25519_authorization(&signing_key, "pe-ed-1", &body);

        let now = DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let res = verify_authorization_at(&config, &auth, &body, now);
        assert!(res.is_ok(), "Expected valid ed25519 auth, got: {:?}", res);
        assert_eq!(res.unwrap().kid, "pe-ed-1");
    }

    #[test]
    fn test_es256_authorization_acceptance() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = P256VerifyingKey::from(&signing_key);
        let pub_sec1 = verifying_key.to_encoded_point(false);
        let pub_hex = hex::encode(pub_sec1.as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-es-1".to_string(),
                alg: PolicyAlg::Es256,
                public_key: pub_hex,
                not_before: Some("2026-01-01T00:00:00Z".to_string()),
                not_after: Some("2027-01-01T00:00:00Z".to_string()),
            }],
        };

        let body = sample_body_canonical();
        let auth = sign_es256_authorization(&signing_key, "pe-es-1", &body);

        let now = DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let res = verify_authorization_at(&config, &auth, &body, now);
        assert!(res.is_ok(), "Expected valid ES256 auth, got: {:?}", res);
        assert_eq!(res.unwrap().kid, "pe-es-1");
    }

    #[test]
    fn test_reject_tampered_body_bad_signature() {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-ed-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pub_hex,
                not_before: None,
                not_after: None,
            }],
        };

        let body = sample_body_canonical();
        let auth = sign_ed25519_authorization(&signing_key, "pe-ed-1", &body);

        let mut tampered_body = body.clone();
        tampered_body.push(b' '); // mutate body

        let now = Utc::now();
        let err = verify_authorization_at(&config, &auth, &tampered_body, now).unwrap_err();
        assert_eq!(err.reason_code(), "bad_signature");

        // Also test ES256 with tampered body
        let es_signing_key = P256SigningKey::random(&mut OsRng);
        let es_pub = hex::encode(P256VerifyingKey::from(&es_signing_key).to_encoded_point(true).as_bytes());
        let es_config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-es-1".to_string(),
                alg: PolicyAlg::Es256,
                public_key: es_pub,
                not_before: None,
                not_after: None,
            }],
        };
        let es_auth = sign_es256_authorization(&es_signing_key, "pe-es-1", &body);
        let es_err = verify_authorization_at(&es_config, &es_auth, &tampered_body, now).unwrap_err();
        assert_eq!(es_err.reason_code(), "bad_signature");
    }

    #[test]
    fn test_reject_unknown_kid() {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let body = sample_body_canonical();
        let auth = sign_ed25519_authorization(&signing_key, "unknown-kid-xyz", &body);

        let config = SignerConfig::new("signer-local-1", Profile::Dev);
        let err = verify_authorization_at(&config, &auth, &body, Utc::now()).unwrap_err();
        assert_eq!(err.reason_code(), "unknown_kid");
    }

    #[test]
    fn test_reject_key_expired_and_not_yet_valid() {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-timed".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pub_hex,
                not_before: Some("2026-06-01T00:00:00Z".to_string()),
                not_after: Some("2026-06-30T23:59:59Z".to_string()),
            }],
        };

        let body = sample_body_canonical();
        let auth = sign_ed25519_authorization(&signing_key, "pe-timed", &body);

        // Before validity window
        let too_early = DateTime::parse_from_rfc3339("2026-05-31T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let err_early = verify_authorization_at(&config, &auth, &body, too_early).unwrap_err();
        assert_eq!(err_early.reason_code(), "key_expired");

        // After validity window
        let too_late = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let err_late = verify_authorization_at(&config, &auth, &body, too_late).unwrap_err();
        assert_eq!(err_late.reason_code(), "key_expired");
    }

    #[test]
    fn test_reject_alg_mismatch_and_alg_none() {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-ed".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pub_hex,
                not_before: None,
                not_after: None,
            }],
        };

        let body = sample_body_canonical();

        // 1. Alg mismatch: pinned is ed25519, wire claims ES256
        let auth_mismatch = RawAuthorization {
            kid: "pe-ed".to_string(),
            alg: "ES256".to_string(),
            sig: None,
            jws: Some("eyJhbGciOiJFUzI1NiJ9..sig".to_string()),
        };
        let err = verify_authorization_at(&config, &auth_mismatch, &body, Utc::now()).unwrap_err();
        assert_eq!(err.reason_code(), "alg_mismatch");

        // 2. Alg none in wire authorization
        let auth_none = RawAuthorization {
            kid: "pe-ed".to_string(),
            alg: "none".to_string(),
            sig: Some("dGVzdA".to_string()),
            jws: None,
        };
        let err_none = verify_authorization_at(&config, &auth_none, &body, Utc::now()).unwrap_err();
        assert_eq!(err_none.reason_code(), "alg_mismatch");
    }

    #[test]
    fn test_reject_jws_alg_none_and_alg_mismatch() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = P256VerifyingKey::from(&signing_key);
        let pub_hex = hex::encode(verifying_key.to_encoded_point(false).as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-es".to_string(),
                alg: PolicyAlg::Es256,
                public_key: pub_hex,
                not_before: None,
                not_after: None,
            }],
        };

        let body = sample_body_canonical();

        // Header with alg: "none"
        let bad_header_json = b"{\"alg\":\"none\",\"kid\":\"pe-es\"}";
        let bad_header_b64 = Base64UrlUnpadded::encode_string(bad_header_json);
        let dummy_sig_b64 = Base64UrlUnpadded::encode_string(&[0u8; 64]);
        let auth_alg_none = RawAuthorization {
            kid: "pe-es".to_string(),
            alg: "ES256".to_string(),
            sig: None,
            jws: Some(format!("{bad_header_b64}..{dummy_sig_b64}")),
        };

        let err = verify_authorization_at(&config, &auth_alg_none, &body, Utc::now()).unwrap_err();
        assert_eq!(err.reason_code(), "alg_mismatch");

        // Header with alg: "RS256"
        let rs_header_json = b"{\"alg\":\"RS256\",\"kid\":\"pe-es\"}";
        let rs_header_b64 = Base64UrlUnpadded::encode_string(rs_header_json);
        let auth_rs256 = RawAuthorization {
            kid: "pe-es".to_string(),
            alg: "ES256".to_string(),
            sig: None,
            jws: Some(format!("{rs_header_b64}..{dummy_sig_b64}")),
        };
        let err_rs = verify_authorization_at(&config, &auth_rs256, &body, Utc::now()).unwrap_err();
        assert_eq!(err_rs.reason_code(), "alg_mismatch");
    }

    #[test]
    fn test_reject_unknown_crit_header() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = P256VerifyingKey::from(&signing_key);
        let pub_hex = hex::encode(verifying_key.to_encoded_point(false).as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-es".to_string(),
                alg: PolicyAlg::Es256,
                public_key: pub_hex,
                not_before: None,
                not_after: None,
            }],
        };

        let body = sample_body_canonical();

        // Header containing "crit": ["unknown_extension"]
        let crit_header_json = b"{\"alg\":\"ES256\",\"kid\":\"pe-es\",\"crit\":[\"unknown_extension\"]}";
        let crit_header_b64 = Base64UrlUnpadded::encode_string(crit_header_json);
        let dummy_sig_b64 = Base64UrlUnpadded::encode_string(&[0u8; 64]);
        let auth_crit = RawAuthorization {
            kid: "pe-es".to_string(),
            alg: "ES256".to_string(),
            sig: None,
            jws: Some(format!("{crit_header_b64}..{dummy_sig_b64}")),
        };

        let err = verify_authorization_at(&config, &auth_crit, &body, Utc::now()).unwrap_err();
        assert_eq!(err.reason_code(), "alg_mismatch");
    }

    #[test]
    fn test_reject_jws_kid_mismatch() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = P256VerifyingKey::from(&signing_key);
        let pub_hex = hex::encode(verifying_key.to_encoded_point(false).as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: None,
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-es-real".to_string(),
                alg: PolicyAlg::Es256,
                public_key: pub_hex,
                not_before: None,
                not_after: None,
            }],
        };

        let body = sample_body_canonical();

        // Protected header carries kid: "pe-es-fake" while wire authorization claims "pe-es-real"
        let mismatch_header_json = b"{\"alg\":\"ES256\",\"kid\":\"pe-es-fake\"}";
        let mismatch_header_b64 = Base64UrlUnpadded::encode_string(mismatch_header_json);
        let dummy_sig_b64 = Base64UrlUnpadded::encode_string(&[0u8; 64]);
        let auth_mismatch = RawAuthorization {
            kid: "pe-es-real".to_string(),
            alg: "ES256".to_string(),
            sig: None,
            jws: Some(format!("{mismatch_header_b64}..{dummy_sig_b64}")),
        };

        let err = verify_authorization_at(&config, &auth_mismatch, &body, Utc::now()).unwrap_err();
        assert_eq!(err.reason_code(), "unknown_kid");
    }

    #[test]
    fn test_yaml_config_loading_and_defaults() {
        let yaml = r#"
signer_id: "signer-test-node"
profile: "prod"
policy_engine_keys:
  - kid: "pe-dev-1"
    alg: "ed25519"
    public_key: "0xa4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
    not_before: "2026-01-01T00:00:00Z"
    not_after: "2027-01-01T00:00:00Z"
"#;

        let config = SignerConfig::from_yaml_str(yaml).expect("valid yaml");
        assert_eq!(config.signer_id, "signer-test-node");
        assert_eq!(config.max_lifetime_seconds, 600);
        assert_eq!(config.clock_skew_seconds, 30);
        assert_eq!(config.profile, Profile::Prod);
        assert_eq!(config.allow_digest_signing(), false); // prod profile defaults to false
        assert_eq!(config.policy_engine_keys.len(), 1);

        let key = config.get_pinned_key("pe-dev-1").expect("key found");
        assert_eq!(key.alg, PolicyAlg::Ed25519);
        assert!(key.parse_ed25519_verifying_key().is_ok());

        // Test dev profile defaults allow_digest_signing to true
        let yaml_dev = r#"
signer_id: "signer-dev-node"
profile: "dev"
"#;
        let config_dev = SignerConfig::from_yaml_str(yaml_dev).expect("valid dev yaml");
        assert_eq!(config_dev.allow_digest_signing(), true);
    }

    #[test]
    fn test_public_key_formats_pem_and_base64() {
        use p256::pkcs8::EncodePublicKey;

        // 1. Ed25519 PEM & Base64url
        let ed_sk = Ed25519SigningKey::generate(&mut OsRng);
        let ed_vk = ed_sk.verifying_key();
        let ed_pem = ed_vk.to_public_key_pem(p256::pkcs8::spki::der::pem::LineEnding::LF).expect("pem");
        let ed_b64 = Base64UrlUnpadded::encode_string(ed_vk.as_bytes());

        let parsed_from_pem = parse_ed25519_verifying_key(&ed_pem).expect("parse pem");
        assert_eq!(parsed_from_pem.as_bytes(), ed_vk.as_bytes());

        let parsed_from_b64 = parse_ed25519_verifying_key(&ed_b64).expect("parse b64");
        assert_eq!(parsed_from_b64.as_bytes(), ed_vk.as_bytes());

        // 2. ES256 PEM, SEC1 compressed hex & uncompressed hex
        let es_sk = P256SigningKey::random(&mut OsRng);
        let es_vk = P256VerifyingKey::from(&es_sk);
        let es_pem = es_vk.to_public_key_pem(p256::pkcs8::spki::der::pem::LineEnding::LF).expect("es pem");
        let es_compressed_hex = hex::encode(es_vk.to_encoded_point(true).as_bytes());
        let es_uncompressed_hex = hex::encode(es_vk.to_encoded_point(false).as_bytes());

        let parsed_es_pem = parse_es256_verifying_key(&es_pem).expect("parse es pem");
        assert_eq!(parsed_es_pem, es_vk);

        let parsed_es_comp = parse_es256_verifying_key(&es_compressed_hex).expect("parse es compressed hex");
        assert_eq!(parsed_es_comp, es_vk);

        let parsed_es_uncomp = parse_es256_verifying_key(&es_uncompressed_hex).expect("parse es uncompressed hex");
        assert_eq!(parsed_es_uncomp, es_vk);
    }

    #[test]
    fn test_verify_envelope_and_auth_end_to_end() {
        let ed_sk = Ed25519SigningKey::generate(&mut OsRng);
        let ed_pub = hex::encode(ed_sk.verifying_key().as_bytes());

        let es_sk = P256SigningKey::random(&mut OsRng);
        let es_pub = hex::encode(P256VerifyingKey::from(&es_sk).to_encoded_point(false).as_bytes());

        let config = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
            policy_engine_keys: vec![
                PinnedKey {
                    kid: "pe-ed".to_string(),
                    alg: PolicyAlg::Ed25519,
                    public_key: ed_pub,
                    not_before: None,
                    not_after: None,
                },
                PinnedKey {
                    kid: "pe-es".to_string(),
                    alg: PolicyAlg::Es256,
                    public_key: es_pub,
                    not_before: None,
                    not_after: None,
                },
            ],
        };

        let body_bytes = sample_body_canonical();
        let body_b64 = Base64UrlUnpadded::encode_string(&body_bytes);

        // 1. Envelope with Ed25519 authorization
        let ed_auth = sign_ed25519_authorization(&ed_sk, "pe-ed", &body_bytes);
        let ed_env = serde_json::json!({
            "body": body_b64,
            "authorization": ed_auth,
        });
        let (body, canonical_bytes, key) =
            verify_envelope_and_auth(&config, &ed_env.to_string(), None).expect("ed25519 envelope ok");
        assert_eq!(body.request_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(canonical_bytes, body_bytes);
        assert_eq!(key.kid, "pe-ed");

        // 2. Envelope with ES256 authorization
        let es_auth = sign_es256_authorization(&es_sk, "pe-es", &body_bytes);
        let es_env = serde_json::json!({
            "body": body_b64,
            "authorization": es_auth,
        });
        let (body_es, _, key_es) =
            verify_envelope_and_auth(&config, &es_env.to_string(), None).expect("es256 envelope ok");
        assert_eq!(body_es.request_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(key_es.kid, "pe-es");

        // 3. Reject non-canonical body in envelope
        let bad_env = serde_json::json!({
            "body": Base64UrlUnpadded::encode_string(b"{\"v\":1, \"type\":\"sign\"}"),
            "authorization": ed_auth,
        });
        let err_bad_body = verify_envelope_and_auth(&config, &bad_env.to_string(), None).unwrap_err();
        assert_eq!(err_bad_body.reason_code(), "invalid_request"); // JCS error
    }
}
