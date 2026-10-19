//! RFC 8785 JSON Canonicalization Scheme (JCS) and strict request body verification.
//!
//! This module provides:
//! - Canonical serialization according to RFC 8785 (`to_canonical_json_bytes`, `to_canonical_json_string`).
//! - Strict deserialization (`#[serde(deny_unknown_fields)]`) of the envelope [`RequestBody`].
//! - Envelope parsing and base64url decoding ([`Envelope`]).
//! - Exact byte-for-byte canonical verification ensuring request bodies have not been mutated,
//!   reordered, or formatted with non-canonical whitespace.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{
    build_aad_checked, BackendError, Curve, Scheme, DEFAULT_KEK_LABEL, DEFAULT_SEED_VERSION,
};

/// Errors arising during RFC 8785 canonicalization, base64url decoding, or envelope verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JcsError {
    /// The envelope body string is not valid unpadded base64url data.
    #[error("invalid base64url body: {0}")]
    InvalidBase64(String),

    /// Deserialization failed due to invalid JSON syntax, type mismatch, or unknown fields.
    #[error("invalid request JSON: {0}")]
    InvalidRequest(String),

    /// Envelope version `v` is not recognized (must be `1`).
    #[error("unknown envelope version '{0}', expected 1")]
    UnknownVersion(u32),

    /// The base64url-decoded body bytes are not canonical according to RFC 8785.
    #[error("non-canonical body: decoded bytes do not match RFC 8785 canonical serialization")]
    NonCanonicalBody,

    /// An error occurred during RFC 8785 serialization.
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
}

impl JcsError {
    /// Returns the exact reason code used for API problem details and signer audits.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidBase64(_) => "invalid_request",
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnknownVersion(_) => "unknown_version",
            Self::NonCanonicalBody => "non_canonical_body",
            Self::Canonicalization(_) => "invalid_request",
        }
    }

    /// Returns the top-level RFC 9457 error code (`"invalid_request"`).
    pub const fn error_code(&self) -> &'static str {
        "invalid_request"
    }
}

/// Operation type specified in a [`RequestBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    /// Create a new wallet root seed wrapped by the HSM.
    CreateWallet,
    /// Derive a public key at a BIP32 / SLIP10 derivation path.
    DerivePublic,
    /// Sign a payload (digest, raw message, or transaction).
    Sign,
}

impl RequestType {
    /// Returns the wire string representation (`"create_wallet"`, `"derive_public"`, or `"sign"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CreateWallet => "create_wallet",
            Self::DerivePublic => "derive_public",
            Self::Sign => "sign",
        }
    }
}

impl std::fmt::Display for RequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Payload encoding for signing requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadEncoding {
    /// Pre-hashed 32-byte digest (ECDSA secp256k1). Blind signing.
    Digest,
    /// Raw message bytes (Ed25519). Blind signing.
    Message,
    /// Raw serialized transaction (decoded and verified by chain codecs). Non-blind signing.
    Tx,
}

impl PayloadEncoding {
    /// Returns the wire string representation (`"digest"`, `"message"`, or `"tx"`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Message => "message",
            Self::Tx => "tx",
        }
    }
}

impl std::fmt::Display for PayloadEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strongly typed request body deserialized strictly (`#[serde(deny_unknown_fields)]`)
/// from base64url-decoded canonical JSON bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    /// Envelope version (must be `1`).
    pub v: u32,

    /// Request operation type (`create_wallet`, `derive_public`, or `sign`).
    #[serde(rename = "type")]
    pub request_type: RequestType,

    /// Replay prevention UUID.
    pub request_id: String,

    /// Replay prevention 16-byte random hex string.
    pub nonce: String,

    /// Target signer ID (e.g., `"signer-local-1"`).
    pub audience: String,

    /// UTC RFC 3339 expiration timestamp (maximum lifetime 10 minutes).
    pub expires_at: String,

    /// Policy engine decision identifier copied to audit logs and signed responses.
    pub decision_id: String,

    /// Wallet identifier.
    pub wallet_id: String,

    /// Key derivation scheme (`bip32` or `slip10`).
    pub scheme: Scheme,

    /// Elliptic curve (`secp256k1` or `ed25519`).
    pub curve: Curve,

    /// Derivation path for single-key operations (`derive_public` or single-path `sign`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<u32>>,

    /// Multi-input derivation paths for multi-input Bitcoin transactions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_paths: Option<Vec<Vec<u32>>>,

    /// Payload encoding (`digest`, `message`, or `tx`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_encoding: Option<PayloadEncoding>,

    /// Payload content (digest hex, raw message bytes, or raw transaction hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    /// CAIP-2 chain identifier (e.g., `"eip155:1"`). Required when `payload_encoding == "tx"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,

    /// Seed version for AEAD Associated Authenticated Data (defaults to `1` if omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_version: Option<u32>,

    /// HSM KEK label for AEAD Associated Authenticated Data (defaults to `"kek-v1"` if omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_label: Option<String>,
}

impl RequestBody {
    /// Returns the effective seed version (`self.seed_version` or default `1`).
    pub fn effective_seed_version(&self) -> u32 {
        self.seed_version.unwrap_or(DEFAULT_SEED_VERSION)
    }

    /// Returns the effective KEK label (`self.kek_label` or default `"kek-v1"`).
    pub fn effective_kek_label(&self) -> &str {
        self.kek_label.as_deref().unwrap_or(DEFAULT_KEK_LABEL)
    }

    /// Computes the SHA-256 hash of the canonical request body bytes.
    pub fn canonical_hash(&self) -> Result<[u8; 32], JcsError> {
        let canonical_bytes = to_canonical_json_bytes(self)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        Ok(hasher.finalize().into())
    }

    /// Builds the canonical AEAD Associated Authenticated Data (AAD) bytes strictly
    /// from this verified request body:
    /// `"{wallet_id}|{scheme}|{curve}|{seed_version}|{kek_label}"`
    pub fn build_aad(&self) -> Result<Vec<u8>, BackendError> {
        build_aad_checked(
            &self.wallet_id,
            self.scheme,
            self.curve,
            self.effective_seed_version(),
            self.effective_kek_label(),
        )
    }
}

/// Generic envelope structure on the wire: `{ body, authorization }`.
///
/// `body` contains the unpadded base64url-encoded RFC 8785 canonical bytes of the request.
/// `authorization` carries policy engine authentication (`Ed25519` or `ES256`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T = serde_json::Value> {
    /// Base64url-encoded canonical JSON request body.
    pub body: String,
    /// Policy engine authorization payload.
    pub authorization: T,
}

impl<T> Envelope<T> {
    /// Decodes the base64url-encoded body into raw bytes.
    pub fn decode_body_bytes(&self) -> Result<Vec<u8>, JcsError> {
        decode_base64url(&self.body)
    }

    /// Verifies the envelope's body: decodes base64url, strictly parses the [`RequestBody`],
    /// validates version `v == 1`, re-encodes to RFC 8785 canonical bytes, and asserts byte-for-byte equality.
    ///
    /// Returns the verified [`RequestBody`] and the verified canonical body bytes.
    pub fn verify_canonical_body(&self) -> Result<(RequestBody, Vec<u8>), JcsError> {
        let raw_bytes = self.decode_body_bytes()?;
        let (body, canonical_bytes) = verify_request_body_bytes(&raw_bytes)?;
        Ok((body, canonical_bytes))
    }
}

/// Canonicalizes any serializable value according to RFC 8785 (JCS) and returns raw UTF-8 bytes.
pub fn to_canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| JcsError::Canonicalization(e.to_string()))
}

/// Canonicalizes any serializable value according to RFC 8785 (JCS) and returns a UTF-8 string.
pub fn to_canonical_json_string<T: Serialize>(value: &T) -> Result<String, JcsError> {
    serde_json_canonicalizer::to_string(value).map_err(|e| JcsError::Canonicalization(e.to_string()))
}

/// Strictly parses and canonical-verifies raw request body bytes:
/// 1. Deserializes with strict `deny_unknown_fields`.
/// 2. Validates envelope version `v == 1` (rejecting unknown versions).
/// 3. Re-encodes using RFC 8785 JCS canonical serialization.
/// 4. Asserts byte-for-byte equality with the input bytes.
///
/// Returns the parsed [`RequestBody`] and its verified canonical bytes.
pub fn verify_request_body_bytes(body_bytes: &[u8]) -> Result<(RequestBody, Vec<u8>), JcsError> {
    let body: RequestBody = serde_json::from_slice(body_bytes)
        .map_err(|e| JcsError::InvalidRequest(e.to_string()))?;

    if body.v != 1 {
        return Err(JcsError::UnknownVersion(body.v));
    }

    let canonical = to_canonical_json_bytes(&body)?;
    if canonical.as_slice() != body_bytes {
        return Err(JcsError::NonCanonicalBody);
    }

    Ok((body, canonical))
}

/// Strictly parses a JSON envelope string, decodes its base64url body, and verifies canonical equality.
pub fn verify_envelope_json(json_str: &str) -> Result<(Envelope, RequestBody, Vec<u8>), JcsError> {
    let env: Envelope = serde_json::from_str(json_str)
        .map_err(|e| JcsError::InvalidRequest(e.to_string()))?;
    let (body, canonical_bytes) = env.verify_canonical_body()?;
    Ok((env, body, canonical_bytes))
}

/// Decodes an unpadded base64url string into bytes.
pub fn decode_base64url(s: &str) -> Result<Vec<u8>, JcsError> {
    Base64UrlUnpadded::decode_vec(s.trim())
        .map_err(|e| JcsError::InvalidBase64(e.to_string()))
}

/// Encodes raw bytes into an unpadded base64url string.
pub fn encode_base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Curve, Scheme};

    #[test]
    fn test_rfc8785_spec_section_3_2_2_and_3_2_3() {
        // Test example from RFC 8785 Section 3.2.2 and 3.2.3
        let input: serde_json::Value = serde_json::json!({
            "numbers": [333333333.3333333, 1e30, 4.50, 2e-3, 1e-27],
            "string": "\u{20ac}$\u{000f}\nA'B\"\\\"/",
            "literals": [null, true, false]
        });

        let canonical = to_canonical_json_string(&input).expect("canonicalization succeeds");
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\"}";
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_utf16_code_unit_sorting() {
        // UTF-16 surrogate pairs (supplementary characters like U+1F600 😀) sort before U+FFF0 in UTF-16
        // whereas in UTF-8 code point ordering, U+1F600 (0xF0) > U+FFF0 (0xEF).
        let input: serde_json::Value = serde_json::json!({
            "\u{fff0}": "bmp_high",
            "\u{1f600}": "emoji_surrogate"
        });

        let canonical = to_canonical_json_string(&input).expect("canonicalization succeeds");
        // In UTF-16: 😀 is 0xD83D, 0xDE00. U+FFF0 is 0xFFF0.
        // 0xD83D < 0xFFF0, so 😀 must appear FIRST.
        assert_eq!(canonical, "{\"😀\":\"emoji_surrogate\",\"\u{fff0}\":\"bmp_high\"}");
    }

    #[test]
    fn test_request_body_canonical_roundtrip_and_verification() {
        let body = RequestBody {
            v: 1,
            request_type: RequestType::Sign,
            request_id: "7b47e4dc-10a3-4a11-a836-ecbf31dfdc07".to_string(),
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
            audience: "signer-local-1".to_string(),
            expires_at: "2026-10-16T12:10:00Z".to_string(),
            decision_id: "dec_8f3a".to_string(),
            wallet_id: "w_01HZABCDEF1234567890".to_string(),
            scheme: Scheme::Bip32,
            curve: Curve::Secp256k1,
            path: Some(vec![2147483692, 2147483648, 2147483648, 0, 5]),
            input_paths: None,
            payload_encoding: Some(PayloadEncoding::Digest),
            payload: Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string()),
            chain: None,
            seed_version: None,
            kek_label: None,
        };

        let canonical_bytes = to_canonical_json_bytes(&body).expect("canonical serialize");
        let (verified_body, verified_bytes) = verify_request_body_bytes(&canonical_bytes).expect("verify passes");
        assert_eq!(verified_body, body);
        assert_eq!(verified_bytes, canonical_bytes);

        // Build AAD
        let aad = verified_body.build_aad().expect("build aad");
        assert_eq!(
            aad,
            b"w_01HZABCDEF1234567890|bip32|secp256k1|1|kek-v1"
        );
    }

    #[test]
    fn test_envelope_verification_happy_path() {
        let body = RequestBody {
            v: 1,
            request_type: RequestType::CreateWallet,
            request_id: "a1b2c3d4-0000-0000-0000-000000000001".to_string(),
            nonce: "deadbeefcafebabe0123456789abcdef".to_string(),
            audience: "signer-local-1".to_string(),
            expires_at: "2026-10-16T12:10:00Z".to_string(),
            decision_id: "dec_001".to_string(),
            wallet_id: "w_new_01".to_string(),
            scheme: Scheme::Bip32,
            curve: Curve::Secp256k1,
            path: None,
            input_paths: None,
            payload_encoding: None,
            payload: None,
            chain: None,
            seed_version: Some(1),
            kek_label: Some("kek-v1".to_string()),
        };

        let canonical_bytes = to_canonical_json_bytes(&body).unwrap();
        let body_b64 = encode_base64url(&canonical_bytes);

        let env = Envelope {
            body: body_b64.clone(),
            authorization: serde_json::json!({
                "kid": "pe-dev-1",
                "alg": "ed25519",
                "sig": "placeholder"
            }),
        };

        let (verified_body, verified_bytes) = env.verify_canonical_body().unwrap();
        assert_eq!(verified_body, body);
        assert_eq!(verified_bytes, canonical_bytes);
    }

    #[test]
    fn test_reject_non_canonical_whitespace() {
        // Space after colon: `{"v": 1, ...}` instead of `{"v":1,...}`
        let non_canonical_json = br#"{"audience":"signer-local-1","curve":"secp256k1","decision_id":"dec_1","expires_at":"2026-10-16T12:10:00Z","nonce":"0123456789abcdef0123456789abcdef","request_id":"7b47e4dc-10a3-4a11-a836-ecbf31dfdc07","scheme":"bip32","type":"create_wallet","v": 1,"wallet_id":"w_1"}"#;

        let err = verify_request_body_bytes(non_canonical_json).unwrap_err();
        assert_eq!(err, JcsError::NonCanonicalBody);
        assert_eq!(err.reason_code(), "non_canonical_body");
    }

    #[test]
    fn test_reject_reordered_keys() {
        // "v" placed before "type" when canonical order puts "type" before "v"
        let reordered_json = br#"{"audience":"signer-local-1","curve":"secp256k1","decision_id":"dec_1","expires_at":"2026-10-16T12:10:00Z","nonce":"0123456789abcdef0123456789abcdef","request_id":"7b47e4dc-10a3-4a11-a836-ecbf31dfdc07","scheme":"bip32","v":1,"type":"create_wallet","wallet_id":"w_1"}"#;

        let err = verify_request_body_bytes(reordered_json).unwrap_err();
        assert_eq!(err, JcsError::NonCanonicalBody);
        assert_eq!(err.reason_code(), "non_canonical_body");
    }

    #[test]
    fn test_reject_unknown_fields() {
        // Body with extraneous field `malicious_injection`
        let body_with_unknown = br#"{"audience":"signer-local-1","curve":"secp256k1","decision_id":"dec_1","expires_at":"2026-10-16T12:10:00Z","malicious_injection":true,"nonce":"0123456789abcdef0123456789abcdef","request_id":"7b47e4dc-10a3-4a11-a836-ecbf31dfdc07","scheme":"bip32","type":"create_wallet","v":1,"wallet_id":"w_1"}"#;

        let err = verify_request_body_bytes(body_with_unknown).unwrap_err();
        match err {
            JcsError::InvalidRequest(ref msg) => {
                assert!(msg.contains("unknown field `malicious_injection`"), "msg was: {msg}");
            }
            other => panic!("expected InvalidRequest, got {:?}", other),
        }
        assert_eq!(err.reason_code(), "invalid_request");
    }

    #[test]
    fn test_reject_unknown_version() {
        // Envelope version v == 2
        let body_v2 = br#"{"audience":"signer-local-1","curve":"secp256k1","decision_id":"dec_1","expires_at":"2026-10-16T12:10:00Z","nonce":"0123456789abcdef0123456789abcdef","request_id":"7b47e4dc-10a3-4a11-a836-ecbf31dfdc07","scheme":"bip32","type":"create_wallet","v":2,"wallet_id":"w_1"}"#;

        let err = verify_request_body_bytes(body_v2).unwrap_err();
        assert_eq!(err, JcsError::UnknownVersion(2));
        assert_eq!(err.reason_code(), "unknown_version");
    }

    #[test]
    fn test_reject_invalid_base64url_in_envelope() {
        let env = Envelope {
            body: "invalid!@#base64==".to_string(),
            authorization: serde_json::json!({}),
        };

        let err = env.verify_canonical_body().unwrap_err();
        match err {
            JcsError::InvalidBase64(_) => {}
            other => panic!("expected InvalidBase64, got {:?}", other),
        }
    }
}
