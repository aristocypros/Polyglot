//! 9-step verification checklist, response signing, and envelope processor (Section 5 of `Specs.md`).
//!
//! This module implements the complete 9-step verification checklist in the exact order
//! mandated by Section 5 of `Specs.md`:
//!
//! 1. **Strict parse**: `deny_unknown_fields`, check `v == 1`, and re-encode to RFC 8785 JCS
//!    to confirm canonical bytes (`invalid_request`, `unknown_version`, `non_canonical_body`).
//! 2. **Audience check**: Check `audience == config.signer_id` (`audience_mismatch` on failure).
//! 3. **Lifetime & clock skew**: Verify not expired (`expires_at > now - 30s`), lifetime `<= 10 minutes`,
//!    and clock skew within `30s` (`request_expired` / `invalid_lifetime`).
//! 4. **Policy engine authorization**: Verify `authorization` against pinned policy engine key
//!    (`kid`, validity window, pinned `alg`, cryptographic signature over canonical body).
//! 5. **Replay prevention**: Check `ReplayStore`: return cached signed result if present in
//!    `signer.results`, otherwise insert `(request_id, nonce)` into `signer.replay` **before**
//!    executing the operation (`replayed`).
//! 6. **Derivation path check**: Validate derivation path(s) (`path` or `input_paths` for Bitcoin)
//!    against scheme (`ed25519` hardened-only, depth `<= 255`).
//! 7. **Payload check**:
//!    - If `payload_encoding == "tx"`: decode with chain codec for `chain`, verify internal network
//!      ID matches `chain`, verify Bitcoin prevout scripts belong to derived keys, compute signing
//!      input(s), set `blind_sign = false`.
//!    - If `payload_encoding == "digest" | "message"`: require `config.allow_digest_signing == true`
//!      (reject with `digest_signing_disabled` when off in prod profile), set `blind_sign = true`.
//! 8. **AEAD AAD verification**: Build AEAD AAD (`wallet_id | scheme | curve | seed_version | kek_label`)
//!    strictly from the verified request body (never from unverified DB columns) and unwrap seed via `Backend`.
//! 9. **Execution, zeroization & response signing**: Execute `create_wallet`, `derive_public`, or `sign`
//!    via `Backend`, destroy session object, zeroize buffers, build response:
//!    `{ request_id, decision_id, request_hash, status: "completed", result, parsed, protection_level, backend, signing_in_hsm, blind_sign, signed_at }`,
//!    sign canonical response with signer's Ed25519 identity key, and store in `signer.results` + `signer.signer_audit`.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{
    validate_scheme_curve, Backend, BackendError, Curve, ProtectionLevel, Scheme,
    SigningInput as BackendSigningInput, WalletRef, DEFAULT_KEK_LABEL, DEFAULT_SEED_VERSION,
};
use crate::chains::{ChainError, CodecDispatcher, DerivedKeys, ParsedTx};
use crate::derive::{DerivationPath, MAX_DEPTH};
use crate::envelope::auth::{
    verify_authorization_at, AuthError, RawAuthorization, SignerConfig,
};
use crate::envelope::jcs::{
    decode_base64url, to_canonical_json_bytes,
    verify_request_body_bytes, JcsError, PayloadEncoding, RequestBody, RequestType,
};
use crate::store::{
    compute_audit_entry_hash, compute_audit_hash, format_audit_ts, AuditEntry, IntoRequestId,
    ReplayOutcome, SignerStore, StoreError, StoredResult, GENESIS_PREV_HASH,
};

/// Errors arising during processor verification or execution.
#[derive(Debug, Error)]
pub enum ProcessorError {
    /// Step 1: JCS canonicalization or strict parse error.
    #[error(transparent)]
    Jcs(#[from] JcsError),

    /// Step 2: Audience mismatch (`audience != config.signer_id`).
    #[error("audience mismatch: request intended for '{actual}', this signer is '{expected}'")]
    AudienceMismatch { expected: String, actual: String },

    /// Step 3: Request expired (`expires_at <= now - clock_skew`).
    #[error("request expired: expires_at ({expires_at}) is in the past")]
    RequestExpired { expires_at: String },

    /// Step 3: Request lifetime exceeds maximum allowed duration.
    #[error("invalid lifetime: request lifetime exceeds maximum of {max_seconds}s")]
    InvalidLifetime { max_seconds: u64 },

    /// Step 4: Policy engine authorization verification failure.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// Step 5: Request or nonce was replayed without a stored result.
    #[error("replayed request: {0}")]
    Replayed(String),

    /// Step 5: Database store error.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// Step 6: Derivation path validation failure.
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    /// Step 7: Digest/message signing disabled in current profile.
    #[error("blind digest signing is disabled in current signer configuration/profile")]
    DigestSigningDisabled,

    /// Step 7: Chain codec or payload verification failure.
    #[error(transparent)]
    Chain(#[from] ChainError),

    /// Step 7: Invalid payload format (e.g. malformed hex for digest).
    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    /// Step 8: Missing wallet seed for derivation/signing.
    #[error("unknown wallet: wallet '{0}' does not exist or has not been created")]
    UnknownWallet(String),

    /// Step 8: AEAD AAD mismatch or unwrapping failure.
    #[error("AEAD authentication failed: {0}")]
    AeadMismatch(String),

    /// Step 9: Backend cryptographic operation failure.
    #[error(transparent)]
    Backend(#[from] BackendError),

    /// General internal processing error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ProcessorError {
    /// Returns the exact reason code string used for RFC 9457 Problem Details and audits.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Jcs(e) => e.reason_code(),
            Self::AudienceMismatch { .. } => "audience_mismatch",
            Self::RequestExpired { .. } => "request_expired",
            Self::InvalidLifetime { .. } => "invalid_lifetime",
            Self::Auth(e) => e.reason_code(),
            Self::Replayed(_) => "replayed",
            Self::Store(StoreError::Replayed(_)) => "replayed",
            Self::Store(_) => "store_error",
            Self::InvalidPath(_) => "invalid_path",
            Self::DigestSigningDisabled => "digest_signing_disabled",
            Self::Chain(e) => e.reason_code(),
            Self::InvalidPayload(_) => "invalid_payload",
            Self::UnknownWallet(_) => "unknown_wallet",
            Self::AeadMismatch(_) => "aead_mismatch",
            Self::Backend(BackendError::UnwrapFailed(_)) => "aead_mismatch",
            Self::Backend(_) => "backend_error",
            Self::Internal(_) => "internal_error",
        }
    }

    /// Returns the top-level RFC 9457 error code.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::Jcs(e) => e.error_code(),
            Self::AudienceMismatch { .. } => "signer_rejected",
            Self::RequestExpired { .. } => "request_expired",
            Self::InvalidLifetime { .. } => "signer_rejected",
            Self::Auth(e) => e.error_code(),
            Self::Replayed(_) | Self::Store(StoreError::Replayed(_)) => "replayed",
            Self::Store(_) => "signer_unavailable",
            Self::InvalidPath(_) => "signer_rejected",
            Self::DigestSigningDisabled => "signer_rejected",
            Self::Chain(_) => "signer_rejected",
            Self::InvalidPayload(_) => "signer_rejected",
            Self::UnknownWallet(_) => "unknown_wallet",
            Self::AeadMismatch(_) | Self::Backend(BackendError::UnwrapFailed(_)) => "signer_rejected",
            Self::Backend(_) => "signer_rejected",
            Self::Internal(_) => "signer_rejected",
        }
    }
}

/// Helper module for serializing/deserializing wrapped seed bytes across JSON boundaries.
pub mod wrapped_seed_serde {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WrappedSeedVisitor;

        impl<'de> serde::de::Visitor<'de> for WrappedSeedVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a hex string, base64/base64url string, or byte array")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let clean = v.trim();
                let hex_str = clean.strip_prefix("0x").unwrap_or(clean);
                if hex_str.len() % 2 == 0 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(b) = hex::decode(hex_str) {
                        return Ok(b);
                    }
                }
                if let Ok(b) = Base64UrlUnpadded::decode_vec(clean) {
                    return Ok(b);
                }
                if let Ok(b) = Base64::decode_vec(clean) {
                    return Ok(b);
                }
                Err(E::custom("invalid wrapped seed string encoding"))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(WrappedSeedVisitor)
    }
}

/// Metadata and encrypted seed blob for an existing wallet provided in [`ClaimedWork`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedWallet {
    /// Unique wallet identifier (e.g. `"w_01HZ..."`).
    pub wallet_id: String,

    /// Descriptive user label.
    #[serde(default)]
    pub label: String,

    /// Key derivation scheme (`bip32` or `slip10`).
    pub scheme: Scheme,

    /// Elliptic curve (`secp256k1` or `ed25519`).
    pub curve: Curve,

    /// Seed version for AEAD Associated Authenticated Data (default: 1).
    #[serde(default = "default_seed_version")]
    pub seed_version: u32,

    /// HSM KEK label used for seed encryption (default: `"kek-v1"`).
    #[serde(default = "default_kek_label")]
    pub kek_label: String,

    /// Wrapped 92-byte seed blob (`IV || ciphertext || tag`).
    #[serde(with = "wrapped_seed_serde")]
    pub wrapped_seed: Vec<u8>,
}

const fn default_seed_version() -> u32 {
    DEFAULT_SEED_VERSION
}

fn default_kek_label() -> String {
    DEFAULT_KEK_LABEL.to_string()
}

/// Work item returned by `/internal/claim` and passed to [`EnvelopeProcessor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedWork {
    /// Unique request identifier (UUID).
    pub request_id: String,

    /// Canonical request body encoded as base64url (or raw canonical JSON string).
    pub body_canonical: String,

    /// Policy engine authorization payload (`RawAuthorization` or `{ kid, alg, sig / jws }`).
    pub authorization: serde_json::Value,

    /// Optional unsigned user label passed during `create_wallet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Existing wallet record retrieved from `app.wallets` (required for `derive_public` and `sign`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<ClaimedWallet>,
}

/// Metadata and wrapped seed produced during a successful `create_wallet` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedWalletData {
    pub wallet_id: String,
    pub label: String,
    pub scheme: Scheme,
    pub curve: Curve,
    pub seed_version: u32,
    pub kek_label: String,
    #[serde(with = "wrapped_seed_serde")]
    pub wrapped_seed: Vec<u8>,
}

/// Canonical signed response payload as specified in Section 5 of `Specs.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerResponse {
    /// Replay prevention UUID matching request body.
    pub request_id: String,

    /// Policy engine decision ID copied into response.
    pub decision_id: String,

    /// SHA-256 hash of the canonical request body bytes (lowercase hex).
    pub request_hash: String,

    /// Operation status (`"completed"`).
    pub status: String,

    /// Operation-specific result payload.
    pub result: serde_json::Value,

    /// Decoded common transaction summary (present for `tx` signing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<ParsedTx>,

    /// Signer protection level (`"generic-dev"`, `"generic-hsm"`, or `"native"`).
    pub protection_level: ProtectionLevel,

    /// Backend identifier (e.g. `"softhsm-generic"`).
    pub backend: String,

    /// True if all cryptographic signing executed inside the HSM token.
    pub signing_in_hsm: bool,

    /// True if payload was a blind digest or raw message without transaction decoding.
    pub blind_sign: bool,

    /// RFC 3339 UTC timestamp when response was signed.
    pub signed_at: String,
}

/// Submission payload posted by the worker to `/internal/results` upon completion or rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSubmission {
    /// Replay prevention request UUID.
    pub request_id: String,

    /// Status of the request (`"completed"` or `"failed"`).
    pub status: String,

    /// Canonical signer response payload (present if `status == "completed"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<SignerResponse>,

    /// Signer Ed25519 identity signature over `to_canonical_json_bytes(&response)` (hex string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sig: Option<String>,

    /// Top-level RFC 9457 error code (present if `status == "failed"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Detailed signer reason code (present if `status == "failed"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,

    /// Created wallet record to be inserted into `app.wallets` (present for `create_wallet`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<CreatedWalletData>,
}

/// Signer Ed25519 identity key used to sign canonical response bodies.
#[derive(Clone)]
pub struct SignerIdentity {
    signing_key: Arc<Ed25519SigningKey>,
    public_key: [u8; 32],
    public_key_hex: String,
}

impl SignerIdentity {
    /// Creates a [`SignerIdentity`] from an [`Ed25519SigningKey`].
    pub fn new(signing_key: Ed25519SigningKey) -> Self {
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();
        let public_key_hex = hex::encode(public_key);
        Self {
            signing_key: Arc::new(signing_key),
            public_key,
            public_key_hex,
        }
    }

    /// Creates a [`SignerIdentity`] from 32 raw private seed bytes.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let signing_key = Ed25519SigningKey::from_bytes(seed);
        Self::new(signing_key)
    }

    /// Parses a 64-character hex-encoded Ed25519 private seed string.
    pub fn from_hex(hex_str: &str) -> Result<Self, ProcessorError> {
        let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let bytes = hex::decode(clean)
            .map_err(|e| ProcessorError::Internal(format!("invalid hex identity key: {e}")))?;
        if bytes.len() != 32 {
            return Err(ProcessorError::Internal(format!(
                "invalid identity key length {}, expected 32 bytes",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&seed))
    }

    /// Loads a 32-byte Ed25519 identity key from a file (accepting hex or raw bytes).
    pub fn from_file(path: &Path) -> Result<Self, ProcessorError> {
        let mut file = File::open(path).map_err(|e| {
            ProcessorError::Internal(format!("failed to open identity key '{}': {e}", path.display()))
        })?;
        let mut raw = Vec::with_capacity(128);
        file.read_to_end(&mut raw).map_err(|e| {
            ProcessorError::Internal(format!("failed to read identity key '{}': {e}", path.display()))
        })?;

        if raw.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            return Ok(Self::from_bytes(&seed));
        }

        let str_val = String::from_utf8_lossy(&raw);
        Self::from_hex(&str_val)
    }

    /// Generates a random Ephemeral [`SignerIdentity`] (primarily for testing).
    pub fn generate() -> Self {
        let mut rng = p256::elliptic_curve::rand_core::OsRng;
        let signing_key = Ed25519SigningKey::generate(&mut rng);
        Self::new(signing_key)
    }

    /// Signs `canonical_bytes` with the signer's Ed25519 identity key.
    pub fn sign(&self, canonical_bytes: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(canonical_bytes).to_bytes()
    }

    /// Returns the raw 32-byte Ed25519 identity public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the hex-encoded 32-byte Ed25519 identity public key string.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
}

/// Abstract replay and results persistence interface matching `SignerStore`.
pub trait ReplayStore: Send + Sync {
    /// Step 5: Checks whether `request_id` has a stored completed result, or inserts
    /// `(request_id, nonce)` into the replay table before execution.
    fn check_or_record_replay(
        &self,
        request_id: &str,
        nonce: &str,
    ) -> Result<ReplayOutcome, StoreError>;

    /// Stores canonical response JSON and Ed25519 signer signature into `signer.results`.
    fn store_signed_result(
        &self,
        request_id: &str,
        response_json: &serde_json::Value,
        response_sig: &str,
    ) -> Result<(), StoreError>;

    /// Fetches a stored completed result, if present.
    fn get_result(&self, request_id: &str) -> Result<Option<StoredResult>, StoreError>;

    /// Appends a hash-chained audit row to `signer.signer_audit`.
    fn append_audit(
        &self,
        actor: &str,
        event: &str,
        request_id: Option<&str>,
        decision_id: Option<&str>,
    ) -> Result<AuditEntry, StoreError>;
}

impl ReplayStore for SignerStore {
    fn check_or_record_replay(
        &self,
        request_id: &str,
        nonce: &str,
    ) -> Result<ReplayOutcome, StoreError> {
        SignerStore::check_or_record_replay(self, request_id, nonce)
    }

    fn store_signed_result(
        &self,
        request_id: &str,
        response_json: &serde_json::Value,
        response_sig: &str,
    ) -> Result<(), StoreError> {
        SignerStore::store_signed_result(self, request_id, response_json, response_sig)
    }

    fn get_result(&self, request_id: &str) -> Result<Option<StoredResult>, StoreError> {
        SignerStore::get_result(self, request_id)
    }

    fn append_audit(
        &self,
        actor: &str,
        event: &str,
        request_id: Option<&str>,
        decision_id: Option<&str>,
    ) -> Result<AuditEntry, StoreError> {
        SignerStore::append_audit(self, actor, event, request_id, decision_id)
    }
}

/// Thread-safe in-memory implementation of [`ReplayStore`] for testing and standalone operation.
#[derive(Default, Clone)]
pub struct InMemorySignerStore {
    replay: Arc<Mutex<HashMap<String, String>>>,
    nonces: Arc<Mutex<HashSet<String>>>,
    results: Arc<Mutex<HashMap<String, StoredResult>>>,
    audit: Arc<Mutex<Vec<AuditEntry>>>,
}

impl InMemorySignerStore {
    /// Constructs a fresh, empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies cryptographic hash chain integrity across all audit entries.
    pub fn verify_audit_chain(&self) -> Result<usize, StoreError> {
        let audit = self.audit.lock().unwrap();
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (i, entry) in audit.iter().enumerate() {
            let seq = (i + 1) as i64;
            if entry.seq != seq {
                return Err(StoreError::AuditChainIntegrity {
                    seq: entry.seq,
                    reason: format!("expected seq {seq}, found {}", entry.seq),
                });
            }
            if entry.prev_hash != expected_prev {
                return Err(StoreError::AuditChainIntegrity {
                    seq: entry.seq,
                    reason: format!(
                        "prev_hash mismatch: expected '{expected_prev}', got '{}'",
                        entry.prev_hash
                    ),
                });
            }
            let computed = compute_audit_entry_hash(entry);
            if entry.hash != computed {
                return Err(StoreError::AuditChainIntegrity {
                    seq: entry.seq,
                    reason: format!("hash mismatch: expected '{computed}', got '{}'", entry.hash),
                });
            }
            expected_prev = entry.hash.clone();
        }
        Ok(audit.len())
    }
}

impl ReplayStore for InMemorySignerStore {
    fn check_or_record_replay(
        &self,
        request_id: &str,
        nonce: &str,
    ) -> Result<ReplayOutcome, StoreError> {
        let req_uuid = request_id.into_request_id()?;
        let results = self.results.lock().unwrap();
        if let Some(stored) = results.get(&req_uuid.to_string()) {
            return Ok(ReplayOutcome::Stored(stored.clone()));
        }
        drop(results);

        let mut replay = self.replay.lock().unwrap();
        let mut nonces = self.nonces.lock().unwrap();

        if replay.contains_key(&req_uuid.to_string()) {
            return Err(StoreError::Replayed(format!(
                "request_id '{req_uuid}' has already been processed or claimed"
            )));
        }
        if nonces.contains(nonce) {
            return Err(StoreError::Replayed(format!(
                "nonce '{nonce}' has already been recorded"
            )));
        }

        replay.insert(req_uuid.to_string(), nonce.to_string());
        nonces.insert(nonce.to_string());

        Ok(ReplayOutcome::Recorded)
    }

    fn store_signed_result(
        &self,
        request_id: &str,
        response_json: &serde_json::Value,
        response_sig: &str,
    ) -> Result<(), StoreError> {
        let req_uuid = request_id.into_request_id()?;
        let mut results = self.results.lock().unwrap();
        results.insert(
            req_uuid.to_string(),
            StoredResult {
                response: response_json.clone(),
                response_sig: response_sig.to_string(),
                created_at: Some(Utc::now()),
            },
        );
        Ok(())
    }

    fn get_result(&self, request_id: &str) -> Result<Option<StoredResult>, StoreError> {
        let req_uuid = request_id.into_request_id()?;
        let results = self.results.lock().unwrap();
        Ok(results.get(&req_uuid.to_string()).cloned())
    }

    fn append_audit(
        &self,
        actor: &str,
        event: &str,
        request_id: Option<&str>,
        decision_id: Option<&str>,
    ) -> Result<AuditEntry, StoreError> {
        let mut audit = self.audit.lock().unwrap();
        let seq = (audit.len() + 1) as i64;
        let prev_hash = if let Some(last) = audit.last() {
            last.hash.clone()
        } else {
            GENESIS_PREV_HASH.to_string()
        };
        let ts = Utc::now();
        let ts_str = format_audit_ts(&ts);
        let req_id_parsed = match request_id {
            Some(r) => Some(r.into_request_id()?),
            None => None,
        };
        let req_id_str = req_id_parsed.map(|u| u.to_string());

        let hash = compute_audit_hash(
            &prev_hash,
            seq,
            &ts_str,
            actor,
            event,
            req_id_str.as_deref(),
            decision_id,
        );

        let entry = AuditEntry {
            seq,
            ts,
            actor: actor.to_string(),
            event: event.to_string(),
            request_id: req_id_parsed,
            decision_id: decision_id.map(|d| d.to_string()),
            prev_hash,
            hash,
        };
        audit.push(entry.clone());
        Ok(entry)
    }
}

/// Signer envelope verification and execution processor implementing the complete 9-step checklist.
pub struct EnvelopeProcessor {
    config: SignerConfig,
    backend: Arc<dyn Backend>,
    store: Arc<dyn ReplayStore>,
    identity: SignerIdentity,
    dispatcher: CodecDispatcher,
}

impl EnvelopeProcessor {
    /// Constructs a new [`EnvelopeProcessor`].
    pub fn new(
        config: SignerConfig,
        backend: Arc<dyn Backend>,
        store: Arc<dyn ReplayStore>,
        identity: SignerIdentity,
    ) -> Self {
        Self {
            config,
            backend,
            store,
            identity,
            dispatcher: CodecDispatcher::with_builtin_codecs(),
        }
    }

    /// Constructs an [`EnvelopeProcessor`] with a custom [`CodecDispatcher`].
    pub fn with_dispatcher(
        config: SignerConfig,
        backend: Arc<dyn Backend>,
        store: Arc<dyn ReplayStore>,
        identity: SignerIdentity,
        dispatcher: CodecDispatcher,
    ) -> Self {
        Self {
            config,
            backend,
            store,
            identity,
            dispatcher,
        }
    }

    /// Returns a reference to the read-only signer configuration.
    pub fn config(&self) -> &SignerConfig {
        &self.config
    }

    /// Returns a reference to the backend.
    pub fn backend(&self) -> &dyn Backend {
        self.backend.as_ref()
    }

    /// Returns a reference to the replay store.
    pub fn store(&self) -> &dyn ReplayStore {
        self.store.as_ref()
    }

    /// Returns a reference to the signer's identity key.
    pub fn identity(&self) -> &SignerIdentity {
        &self.identity
    }

    /// Executes the 9-step verification checklist and produces a [`SignerSubmission`].
    ///
    /// If any check fails, returns `Err(ProcessorError)` with exact reason code.
    pub fn process_claimed_work(
        &self,
        claimed: &ClaimedWork,
        reference_time: Option<DateTime<Utc>>,
    ) -> Result<SignerSubmission, ProcessorError> {
        let now = reference_time.unwrap_or_else(Utc::now);

        // ---------------------------------------------------------------------
        // Step 1: Strict parse (`deny_unknown_fields`), check `v == 1`, and
        //         re-encode to RFC 8785 JCS to confirm canonical bytes.
        // ---------------------------------------------------------------------
        let body_bytes = decode_claimed_body_bytes(&claimed.body_canonical)?;
        let (body, canonical_body_bytes) = verify_request_body_bytes(&body_bytes)?;

        // Ensure claimed.request_id matches body.request_id
        if claimed.request_id != body.request_id {
            return Err(ProcessorError::Jcs(JcsError::InvalidRequest(format!(
                "claimed request_id '{}' does not match body request_id '{}'",
                claimed.request_id, body.request_id
            ))));
        }

        // ---------------------------------------------------------------------
        // Step 2: Check `audience == config.signer_id` (`audience_mismatch` on failure).
        // ---------------------------------------------------------------------
        if body.audience != self.config.signer_id {
            return Err(ProcessorError::AudienceMismatch {
                expected: self.config.signer_id.clone(),
                actual: body.audience.clone(),
            });
        }

        // ---------------------------------------------------------------------
        // Step 3: Verify not expired (`expires_at > now - 30s`), lifetime `<= 10 minutes`,
        //         and clock skew within `30s` (`request_expired` / `invalid_lifetime`).
        // ---------------------------------------------------------------------
        let expires_at_dt = DateTime::parse_from_rfc3339(&body.expires_at)
            .map_err(|e| ProcessorError::RequestExpired {
                expires_at: format!("invalid RFC 3339 timestamp '{}': {e}", body.expires_at),
            })?
            .with_timezone(&Utc);

        let clock_skew = Duration::seconds(self.config.clock_skew_seconds as i64);
        let max_lifetime = Duration::seconds(self.config.max_lifetime_seconds as i64);

        // Not expired: expires_at must be strictly greater than now - clock_skew
        // (i.e. if expires_at + clock_skew <= now, the request is expired)
        if expires_at_dt + clock_skew <= now {
            return Err(ProcessorError::RequestExpired {
                expires_at: body.expires_at.clone(),
            });
        }

        // Lifetime <= maximum allowed lifetime (default 10 minutes = 600 seconds)
        // If expires_at is further in the future than now + max_lifetime + clock_skew, reject
        if expires_at_dt > now + max_lifetime + clock_skew {
            return Err(ProcessorError::InvalidLifetime {
                max_seconds: self.config.max_lifetime_seconds,
            });
        }

        // ---------------------------------------------------------------------
        // Step 4: Verify `authorization` against pinned policy engine key
        //         (`kid`, validity window, pinned `alg`, cryptographic signature
        //         over canonical body).
        // ---------------------------------------------------------------------
        let raw_auth: RawAuthorization = serde_json::from_value(claimed.authorization.clone())
            .map_err(|e| AuthError::InvalidAuthorization(e.to_string()))?;

        verify_authorization_at(&self.config, &raw_auth, &canonical_body_bytes, now)?;

        // ---------------------------------------------------------------------
        // Step 5: Replay check via `SignerStore`: return cached signed result if
        //         present in `signer.results`, otherwise insert `(request_id, nonce)`
        //         into `signer.replay` before executing the operation.
        // ---------------------------------------------------------------------
        match self
            .store
            .check_or_record_replay(&body.request_id, &body.nonce)?
        {
            ReplayOutcome::Stored(cached) => {
                let response: SignerResponse = serde_json::from_value(cached.response)
                    .map_err(|e| ProcessorError::Store(StoreError::Json(e)))?;
                return Ok(SignerSubmission {
                    request_id: body.request_id,
                    status: "completed".to_string(),
                    response: Some(response),
                    response_sig: Some(cached.response_sig),
                    error_code: None,
                    reason_code: None,
                    wallet: None,
                });
            }
            ReplayOutcome::Recorded => {
                // Successfully recorded in signer.replay before execution
            }
        }

        // ---------------------------------------------------------------------
        // Step 6: Validate derivation path(s) (`path` or `input_paths` for Bitcoin)
        //         against scheme (`ed25519` hardened-only, depth `<= 255`).
        // ---------------------------------------------------------------------
        validate_scheme_curve(body.scheme, body.curve)?;

        match body.request_type {
            RequestType::CreateWallet => {
                // For wallet creation, path is optional (typically none)
                if let Some(ref p) = body.path {
                    validate_derivation_path(p, body.scheme)?;
                }
            }
            RequestType::DerivePublic => {
                let path = body.path.as_deref().ok_or_else(|| {
                    ProcessorError::InvalidPath("missing 'path' for derive_public".to_string())
                })?;
                validate_derivation_path(path, body.scheme)?;
            }
            RequestType::Sign => {
                if let Some(ref input_paths) = body.input_paths {
                    if input_paths.is_empty() {
                        return Err(ProcessorError::InvalidPath(
                            "input_paths array must not be empty".to_string(),
                        ));
                    }
                    for p in input_paths {
                        validate_derivation_path(p, body.scheme)?;
                    }
                } else if let Some(ref p) = body.path {
                    validate_derivation_path(p, body.scheme)?;
                } else {
                    return Err(ProcessorError::InvalidPath(
                        "sign request requires either 'path' or 'input_paths'".to_string(),
                    ));
                }
            }
        }

        // ---------------------------------------------------------------------
        // Step 8 (AAD Calculation): Build AEAD AAD strictly from the verified
        //         request body (never from unverified DB columns).
        // ---------------------------------------------------------------------
        let verified_aad = body.build_aad()?;

        // Retrieve capabilities for protection level and backend info
        let caps = self.backend.capabilities()?;

        // ---------------------------------------------------------------------
        // Step 7 & 8 & 9: Payload check, unwrap seed via Backend, execute operation,
        //                 destroy session object, zeroize buffers, sign canonical
        //                 response, store result and audit log.
        // ---------------------------------------------------------------------
        let request_hash = hex::encode(Sha256::digest(&canonical_body_bytes));

        let (result_value, parsed_summary, signing_in_hsm, blind_sign, created_wallet) =
            match body.request_type {
                RequestType::CreateWallet => {
                    // Create wallet root seed inside the backend and wrap under KEK + verified AAD
                    let spec = crate::backend::Spec::new(body.scheme, body.curve);
                    let wrapped_seed = self.backend.create_wallet(&spec, &verified_aad)?;

                    let created_data = CreatedWalletData {
                        wallet_id: body.wallet_id.clone(),
                        label: claimed.label.clone().unwrap_or_default(),
                        scheme: body.scheme,
                        curve: body.curve,
                        seed_version: body.effective_seed_version(),
                        kek_label: body.effective_kek_label().to_string(),
                        wrapped_seed: wrapped_seed.clone(),
                    };

                    let result_json = serde_json::json!({
                        "wallet_id": body.wallet_id,
                        "scheme": body.scheme.as_str(),
                        "curve": body.curve.as_str(),
                        "seed_version": body.effective_seed_version(),
                        "kek_label": body.effective_kek_label(),
                        "wrapped_seed": hex::encode(&wrapped_seed),
                    });

                    (result_json, None, true, false, Some(created_data))
                }
                RequestType::DerivePublic => {
                    let claimed_wallet = claimed.wallet.as_ref().ok_or_else(|| {
                        ProcessorError::UnknownWallet(body.wallet_id.clone())
                    })?;

                    let wallet_ref = WalletRef::new(
                        &claimed_wallet.wrapped_seed,
                        &verified_aad,
                        body.scheme,
                        body.curve,
                    );

                    let path = body.path.as_deref().unwrap();
                    let pubkey_bytes = self.backend.public_key(&wallet_ref, path)?;

                    let result_json = serde_json::json!({
                        "public_key": hex::encode(&pubkey_bytes),
                    });

                    (result_json, None, true, false, None)
                }
                RequestType::Sign => {
                    let claimed_wallet = claimed.wallet.as_ref().ok_or_else(|| {
                        ProcessorError::UnknownWallet(body.wallet_id.clone())
                    })?;

                    let wallet_ref = WalletRef::new(
                        &claimed_wallet.wrapped_seed,
                        &verified_aad,
                        body.scheme,
                        body.curve,
                    );

                    let payload_encoding = body.payload_encoding.ok_or_else(|| {
                        ProcessorError::InvalidPayload("missing 'payload_encoding'".to_string())
                    })?;
                    let payload_str = body.payload.as_deref().ok_or_else(|| {
                        ProcessorError::InvalidPayload("missing 'payload'".to_string())
                    })?;

                    match payload_encoding {
                        PayloadEncoding::Digest | PayloadEncoding::Message => {
                            // Enforce config.allow_digest_signing
                            if !self.config.allow_digest_signing() {
                                return Err(ProcessorError::DigestSigningDisabled);
                            }

                            let path = body.path.as_deref().ok_or_else(|| {
                                ProcessorError::InvalidPath(
                                    "missing 'path' for digest/message signing".to_string(),
                                )
                            })?;

                            let signature = if payload_encoding == PayloadEncoding::Digest {
                                let clean = payload_str.trim().strip_prefix("0x").unwrap_or(payload_str.trim());
                                let digest_bytes = hex::decode(clean).map_err(|e| {
                                    ProcessorError::InvalidPayload(format!("invalid hex digest: {e}"))
                                })?;
                                if digest_bytes.len() != 32 {
                                    return Err(ProcessorError::InvalidPayload(format!(
                                        "digest must be exactly 32 bytes, got {}",
                                        digest_bytes.len()
                                    )));
                                }
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&digest_bytes);
                                self.backend.sign(
                                    &wallet_ref,
                                    path,
                                    BackendSigningInput::Digest32(&arr),
                                )?
                            } else {
                                let clean = payload_str.trim().strip_prefix("0x").unwrap_or(payload_str.trim());
                                let msg_bytes = if clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                                    hex::decode(clean).unwrap_or_else(|_| payload_str.as_bytes().to_vec())
                                } else {
                                    payload_str.as_bytes().to_vec()
                                };
                                self.backend.sign(
                                    &wallet_ref,
                                    path,
                                    BackendSigningInput::Message(&msg_bytes),
                                )?
                            };

                            let mut res_map = serde_json::Map::new();
                            res_map.insert("signature".to_string(), serde_json::json!(hex::encode(signature.as_bytes())));
                            if let Some(ref r) = signature.r {
                                res_map.insert("r".to_string(), serde_json::json!(hex::encode(r)));
                            }
                            if let Some(ref s) = signature.s {
                                res_map.insert("s".to_string(), serde_json::json!(hex::encode(s)));
                            }
                            if let Some(v) = signature.recovery_id {
                                res_map.insert("recovery_id".to_string(), serde_json::json!(v));
                            }
                            if let Some(ref der) = signature.der {
                                res_map.insert("der".to_string(), serde_json::json!(hex::encode(der)));
                            }

                            (
                                serde_json::Value::Object(res_map),
                                None,
                                signature.signing_in_hsm,
                                true, // blind_sign = true
                                None,
                            )
                        }
                        PayloadEncoding::Tx => {
                            let chain = body.chain.as_deref().ok_or_else(|| {
                                ProcessorError::InvalidPayload("missing 'chain' for tx signing".to_string())
                            })?;

                            let raw_tx_bytes = decode_tx_payload(payload_str)?;

                            // Multi-input Bitcoin transaction path vs single-key path
                            let is_multi_path = body.input_paths.is_some();
                            let paths: Vec<&[u32]> = if let Some(ref multi) = body.input_paths {
                                multi.iter().map(|p| p.as_slice()).collect()
                            } else {
                                vec![body.path.as_deref().unwrap()]
                            };

                            // Derive public keys for each path
                            let mut derived_keys = Vec::with_capacity(paths.len());
                            for p in &paths {
                                let pk = self.backend.public_key(&wallet_ref, p)?;
                                derived_keys.push(pk);
                            }

                            let keys = DerivedKeys::Multiple(&derived_keys);

                            // Step 7: Decode with chain codec, verify network ID, verify prevouts, compute signing inputs
                            let decoded_tx = self.dispatcher.decode(chain, &raw_tx_bytes, &keys)?;

                            // Sign all signing inputs
                            let all_inputs = decoded_tx.all_signing_inputs();
                            if all_inputs.len() != paths.len() {
                                return Err(ProcessorError::Chain(ChainError::MalformedTransaction(
                                    format!(
                                        "signing input count ({}) does not match derivation path count ({})",
                                        all_inputs.len(),
                                        paths.len()
                                    ),
                                )));
                            }

                            let mut signatures = Vec::with_capacity(all_inputs.len());
                            let mut all_in_hsm = true;

                            for (i, signing_input) in all_inputs.iter().enumerate() {
                                let sig = self.backend.sign(
                                    &wallet_ref,
                                    paths[i],
                                    signing_input.to_backend_input(),
                                )?;
                                if !sig.signing_in_hsm {
                                    all_in_hsm = false;
                                }
                                signatures.push(sig);
                            }

                            let first_sig = &signatures[0];
                            let mut res_map = serde_json::Map::new();
                            res_map.insert("signature".to_string(), serde_json::json!(hex::encode(first_sig.as_bytes())));
                            res_map.insert("signer_address".to_string(), serde_json::json!(decoded_tx.signer_address));

                            if is_multi_path || signatures.len() > 1 {
                                let hex_sigs: Vec<String> = signatures
                                    .iter()
                                    .map(|s| {
                                        if let Some(ref der) = s.der {
                                            hex::encode(der)
                                        } else {
                                            hex::encode(s.as_bytes())
                                        }
                                    })
                                    .collect();
                                res_map.insert("signatures".to_string(), serde_json::json!(hex_sigs));
                            }

                            if let Some(ref r) = first_sig.r {
                                res_map.insert("r".to_string(), serde_json::json!(hex::encode(r)));
                            }
                            if let Some(ref s) = first_sig.s {
                                res_map.insert("s".to_string(), serde_json::json!(hex::encode(s)));
                            }
                            if let Some(v) = first_sig.recovery_id {
                                res_map.insert("recovery_id".to_string(), serde_json::json!(v));
                            }
                            if let Some(ref der) = first_sig.der {
                                res_map.insert("der".to_string(), serde_json::json!(hex::encode(der)));
                            }

                            (
                                serde_json::Value::Object(res_map),
                                Some(decoded_tx.parsed),
                                all_in_hsm,
                                false, // blind_sign = false
                                None,
                            )
                        }
                    }
                }
            };

        // Build canonical response
        let signed_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let response = SignerResponse {
            request_id: body.request_id.clone(),
            decision_id: body.decision_id.clone(),
            request_hash,
            status: "completed".to_string(),
            result: result_value,
            parsed: parsed_summary,
            protection_level: caps.protection_level,
            backend: caps.backend,
            signing_in_hsm,
            blind_sign,
            signed_at,
        };

        // Sign canonical response bytes with signer's Ed25519 identity key
        let canonical_resp_bytes = to_canonical_json_bytes(&response)?;
        let response_sig_bytes = self.identity.sign(&canonical_resp_bytes);
        let response_sig = hex::encode(response_sig_bytes);

        // Store signed result in signer.results
        let response_json = serde_json::to_value(&response)
            .map_err(|e| ProcessorError::Internal(format!("serialize response json: {e}")))?;
        self.store
            .store_signed_result(&body.request_id, &response_json, &response_sig)?;

        // Append audit log event in signer.signer_audit
        let event_name = format!("{}:completed", body.request_type.as_str());
        let _ = self.store.append_audit(
            &self.config.signer_id,
            &event_name,
            Some(&body.request_id),
            Some(&body.decision_id),
        );

        Ok(SignerSubmission {
            request_id: body.request_id,
            status: "completed".to_string(),
            response: Some(response),
            response_sig: Some(response_sig),
            error_code: None,
            reason_code: None,
            wallet: created_wallet,
        })
    }

    /// End-to-end execution wrapper that catches any rejection and builds a completed or
    /// structured failed [`SignerSubmission`] ready to post to `/internal/results`.
    pub fn process_and_submit(
        &self,
        claimed: &ClaimedWork,
        reference_time: Option<DateTime<Utc>>,
    ) -> SignerSubmission {
        match self.process_claimed_work(claimed, reference_time) {
            Ok(submission) => submission,
            Err(err) => {
                let reason = err.reason_code();
                let error_code = err.error_code();

                // Append audit log for the rejection
                let _ = self.store.append_audit(
                    &self.config.signer_id,
                    &format!("rejected:{reason}"),
                    Some(&claimed.request_id),
                    None,
                );

                SignerSubmission {
                    request_id: claimed.request_id.clone(),
                    status: "failed".to_string(),
                    response: None,
                    response_sig: None,
                    error_code: Some(error_code.to_string()),
                    reason_code: Some(reason.to_string()),
                    wallet: None,
                }
            }
        }
    }

    /// Parses and processes a raw JSON envelope string `{ "body": "...", "authorization": { ... } }`.
    pub fn process_envelope_json(
        &self,
        envelope_json: &str,
        wallet: Option<ClaimedWallet>,
        reference_time: Option<DateTime<Utc>>,
    ) -> Result<SignerSubmission, ProcessorError> {
        let env_value: serde_json::Value = serde_json::from_str(envelope_json)
            .map_err(|e| JcsError::InvalidRequest(e.to_string()))?;

        let body_b64 = env_value
            .get("body")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JcsError::InvalidRequest("missing 'body' field in envelope".into()))?;

        let auth_val = env_value
            .get("authorization")
            .cloned()
            .ok_or_else(|| JcsError::InvalidRequest("missing 'authorization' in envelope".into()))?;

        // Extract request_id from body
        let body_bytes = decode_claimed_body_bytes(body_b64)?;
        let parsed_body: RequestBody = serde_json::from_slice(&body_bytes)
            .map_err(|e| JcsError::InvalidRequest(e.to_string()))?;

        let claimed = ClaimedWork {
            request_id: parsed_body.request_id,
            body_canonical: body_b64.to_string(),
            authorization: auth_val,
            label: None,
            wallet,
        };

        self.process_claimed_work(&claimed, reference_time)
    }
}

/// Decodes base64url or accepts raw UTF-8 JSON bytes.
fn decode_claimed_body_bytes(body_str: &str) -> Result<Vec<u8>, JcsError> {
    let clean = body_str.trim();
    if clean.starts_with('{') {
        return Ok(clean.as_bytes().to_vec());
    }
    decode_base64url(clean)
}

/// Decodes raw transaction payload from hex string or raw bytes.
fn decode_tx_payload(payload_str: &str) -> Result<Vec<u8>, ProcessorError> {
    let clean = payload_str.trim().strip_prefix("0x").unwrap_or(payload_str.trim());
    if clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(clean)
            .map_err(|e| ProcessorError::InvalidPayload(format!("invalid hex tx: {e}")))
    } else if let Ok(b) = Base64UrlUnpadded::decode_vec(clean) {
        Ok(b)
    } else if let Ok(b) = Base64::decode_vec(clean) {
        Ok(b)
    } else {
        Ok(payload_str.as_bytes().to_vec())
    }
}

/// Validates a single derivation path against scheme rules.
fn validate_derivation_path(path: &[u32], scheme: Scheme) -> Result<(), ProcessorError> {
    if path.len() > MAX_DEPTH {
        return Err(ProcessorError::InvalidPath(format!(
            "path depth {} exceeds maximum allowed depth of {MAX_DEPTH}",
            path.len()
        )));
    }

    if scheme.hardened_only() {
        for (i, &idx) in path.iter().enumerate() {
            if idx < 0x8000_0000 {
                return Err(ProcessorError::InvalidPath(format!(
                    "non-hardened index {idx} at position {i} rejected for scheme '{scheme}' (hardened only)"
                )));
            }
        }
    }

    let parsed = DerivationPath::from_slice(path)
        .map_err(|e| ProcessorError::InvalidPath(e.to_string()))?;
    parsed
        .validate_for_scheme(scheme.into())
        .map_err(|e| ProcessorError::InvalidPath(e.to_string()))?;

    Ok(())
}

/// Verifies a canonical [`SignerResponse`] against the signer's Ed25519 public key.
pub fn verify_signer_response(
    signer_pubkey: &[u8; 32],
    response: &SignerResponse,
    response_sig: &str,
) -> Result<(), ProcessorError> {
    let verifying_key = Ed25519VerifyingKey::from_bytes(signer_pubkey)
        .map_err(|e| ProcessorError::Internal(format!("invalid verifying key: {e}")))?;

    let clean = response_sig.trim().strip_prefix("0x").unwrap_or(response_sig.trim());
    let sig_bytes: [u8; 64] = if clean.len() == 128 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = hex::decode(clean).map_err(|e| ProcessorError::Internal(format!("hex sig decode: {e}")))?;
        b.try_into().unwrap()
    } else if let Ok(b) = Base64UrlUnpadded::decode_vec(clean) {
        b.try_into().map_err(|_| ProcessorError::Internal("invalid b64url sig length".into()))?
    } else {
        return Err(ProcessorError::Internal("unrecognized signature encoding".into()));
    };

    let sig = Ed25519Signature::from_bytes(&sig_bytes);
    let canonical_bytes = to_canonical_json_bytes(response)?;

    verifying_key
        .verify_strict(&canonical_bytes, &sig)
        .map_err(|e| ProcessorError::Internal(format!("signer signature verification failed: {e}")))?;

    Ok(())
}
