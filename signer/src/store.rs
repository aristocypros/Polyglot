//! Signer Database Store: Replay Table, Idempotent Results & Hash-Chained Audit.
//!
//! This module provides PostgreSQL persistence for the signer connecting as `signer_role`:
//! - [`SignerStore::check_or_record_replay`]:
//!   1. First checks `signer.results` for `request_id`; if found, returns [`ReplayOutcome::Stored`]
//!      with the cached response and signature so retries return identical signed answers.
//!   2. Otherwise inserts `(request_id, nonce)` into `signer.replay`. If a unique constraint fails
//!      (either `request_id` or `nonce` already seen without a stored result), rejects with
//!      [`StoreError::Replayed`].
//! - [`SignerStore::store_signed_result`]:
//!   Persists `{ request_id, response, response_sig }` into `signer.results`.
//! - [`SignerStore::append_audit`]:
//!   Appends an immutable audit entry into `signer.signer_audit`, calculating:
//!   `hash = SHA256(prev_hash || seq || ts || actor || event || request_id || decision_id)`.
//! - [`SignerStore::verify_audit_chain`]:
//!   Cryptographically validates the hash chain across all entries in `signer.signer_audit`.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Timelike, Utc};
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Initial hash when the audit log table is empty (64 hex zeros).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Advisory lock ID used to serialize audit appends and prevent hash forks.
const AUDIT_ADVISORY_LOCK_ID: i64 = 742189421;

/// Errors arising from database store operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Request ID or nonce was already seen without a stored completed result.
    #[error("replayed request or nonce: {0}")]
    Replayed(String),

    /// Underlying PostgreSQL database driver error.
    #[error("database error: {0}")]
    Database(#[from] postgres::Error),

    /// JSON serialization or deserialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// UUID parsing error.
    #[error("invalid uuid: {0}")]
    InvalidUuid(#[from] uuid::Error),

    /// Internal mutex lock acquisition error.
    #[error("client lock error: {0}")]
    Lock(String),

    /// Hash chain integrity failure during audit log verification.
    #[error("audit chain integrity violation at seq {seq}: {reason}")]
    AuditChainIntegrity { seq: i64, reason: String },

    /// Configuration or connection error.
    #[error("configuration error: {0}")]
    Config(String),
}

impl StoreError {
    /// Returns true if this error represents a replayed request or duplicate nonce.
    pub fn is_replayed(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }

    /// Stable error code matching RFC 9457 error categories.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Replayed(_) => "replayed",
            Self::Database(_) => "database_error",
            Self::Json(_) => "invalid_json",
            Self::InvalidUuid(_) => "invalid_uuid",
            Self::Lock(_) => "internal_error",
            Self::AuditChainIntegrity { .. } => "audit_chain_integrity_violation",
            Self::Config(_) => "config_error",
        }
    }
}

/// Cached signed response returned when a request is retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredResult {
    /// Verified canonical response JSON payload.
    pub response: serde_json::Value,
    /// Ed25519 signer identity signature over the canonical response.
    pub response_sig: String,
    /// Timestamp when the result was first stored.
    pub created_at: Option<DateTime<Utc>>,
}

/// Outcome of checking or recording a request in the replay store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// Request was not seen before; successfully recorded in `signer.replay`.
    Recorded,
    /// Request was already completed; returns the identical cached signed answer.
    Stored(StoredResult),
}

impl ReplayOutcome {
    /// Returns true if this request was newly recorded.
    pub fn is_recorded(&self) -> bool {
        matches!(self, Self::Recorded)
    }

    /// Returns true if a cached signed result was found.
    pub fn is_stored(&self) -> bool {
        matches!(self, Self::Stored(_))
    }

    /// Extracts the stored result, if present.
    pub fn stored_result(&self) -> Option<&StoredResult> {
        match self {
            Self::Stored(res) => Some(res),
            Self::Recorded => None,
        }
    }
}

/// An entry in `signer.signer_audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub seq: i64,
    /// Timestamp of audit entry creation.
    pub ts: DateTime<Utc>,
    /// Identity of the actor (e.g. `"signer"`, `"signer-worker-1"`).
    pub actor: String,
    /// Event name (e.g. `"claim"`, `"signed"`, `"rejected"`).
    pub event: String,
    /// Associated request ID, if applicable.
    pub request_id: Option<Uuid>,
    /// Associated policy engine decision ID, if applicable.
    pub decision_id: Option<String>,
    /// Hash of the immediately preceding audit row (`GENESIS_PREV_HASH` for first entry).
    pub prev_hash: String,
    /// SHA256(prev_hash || seq || ts || actor || event || request_id || decision_id).
    pub hash: String,
}

/// Trait allowing functions to accept `Uuid`, `&str`, `String`, or `&String` as request IDs.
pub trait IntoRequestId {
    fn into_request_id(self) -> Result<Uuid, StoreError>;
}

impl IntoRequestId for Uuid {
    fn into_request_id(self) -> Result<Uuid, StoreError> {
        Ok(self)
    }
}

impl IntoRequestId for &str {
    fn into_request_id(self) -> Result<Uuid, StoreError> {
        Uuid::parse_str(self).map_err(StoreError::InvalidUuid)
    }
}

impl IntoRequestId for &String {
    fn into_request_id(self) -> Result<Uuid, StoreError> {
        Uuid::parse_str(self.as_str()).map_err(StoreError::InvalidUuid)
    }
}

impl IntoRequestId for String {
    fn into_request_id(self) -> Result<Uuid, StoreError> {
        Uuid::parse_str(&self).map_err(StoreError::InvalidUuid)
    }
}

/// Formats a `DateTime<Utc>` into RFC 3339 with microsecond precision to match Postgres TIMESTAMPTZ.
pub fn format_audit_ts(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Computes the SHA-256 hash for an audit log entry:
/// `SHA256(prev_hash || seq || ts || actor || event || request_id || decision_id)`.
pub fn compute_audit_hash(
    prev_hash: &str,
    seq: i64,
    ts: &str,
    actor: &str,
    event: &str,
    request_id: Option<&str>,
    decision_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(seq.to_string().as_bytes());
    hasher.update(ts.as_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(event.as_bytes());
    if let Some(r) = request_id {
        hasher.update(r.as_bytes());
    }
    if let Some(d) = decision_id {
        hasher.update(d.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Computes the expected hash for a given [`AuditEntry`].
pub fn compute_audit_entry_hash(entry: &AuditEntry) -> String {
    let ts_str = format_audit_ts(&entry.ts);
    let req_id_str = entry.request_id.map(|id| id.to_string());
    compute_audit_hash(
        &entry.prev_hash,
        entry.seq,
        &ts_str,
        &entry.actor,
        &entry.event,
        req_id_str.as_deref(),
        entry.decision_id.as_deref(),
    )
}

/// Thread-safe client store for signer operations against PostgreSQL.
#[derive(Clone)]
pub struct SignerStore {
    client: Arc<Mutex<Client>>,
}

impl SignerStore {
    /// Creates a new `SignerStore` from an existing PostgreSQL client.
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }

    /// Connects to PostgreSQL using a connection string (e.g. `postgres://signer_role:signer_pass@127.0.0.1:5432/postgres`).
    pub fn connect(url: &str) -> Result<Self, StoreError> {
        let client = Client::connect(url, NoTls)?;
        Ok(Self::new(client))
    }

    /// Step 5 Replay verification:
    /// 1. First checks `signer.results` for `request_id`; if found, returns [`ReplayOutcome::Stored`]
    ///    so retries of a completed request return the identical signed answer.
    /// 2. Otherwise executes `INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ($1, $2, now())`.
    ///    If unique constraint fails (either `request_id` or `nonce` already seen without a stored result),
    ///    rejects as [`StoreError::Replayed`].
    pub fn check_or_record_replay(
        &self,
        request_id: impl IntoRequestId,
        nonce: &str,
    ) -> Result<ReplayOutcome, StoreError> {
        let req_id = request_id.into_request_id()?;
        let mut client = self
            .client
            .lock()
            .map_err(|e| StoreError::Lock(e.to_string()))?;

        // 1. Check signer.results first
        let row_opt = client.query_opt(
            "SELECT response::text, response_sig, created_at FROM signer.results WHERE request_id = $1",
            &[&req_id],
        )?;

        if let Some(row) = row_opt {
            let resp_text: String = row.get(0);
            let resp_sig: String = row.get(1);
            let created_at: DateTime<Utc> = row.get(2);
            let resp_val: serde_json::Value = serde_json::from_str(&resp_text)?;
            return Ok(ReplayOutcome::Stored(StoredResult {
                response: resp_val,
                response_sig: resp_sig,
                created_at: Some(created_at),
            }));
        }

        // 2. Insert into signer.replay
        match client.execute(
            "INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ($1, $2, now())",
            &[&req_id, &nonce],
        ) {
            Ok(_) => Ok(ReplayOutcome::Recorded),
            Err(err) => {
                if err.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                    Err(StoreError::Replayed(format!(
                        "request_id {} or nonce '{}' already seen without a stored result",
                        req_id, nonce
                    )))
                } else {
                    Err(StoreError::Database(err))
                }
            }
        }
    }

    /// Stores a signed response payload into `signer.results`.
    pub fn store_signed_result(
        &self,
        request_id: impl IntoRequestId,
        response_json: &serde_json::Value,
        response_sig: &str,
    ) -> Result<(), StoreError> {
        let req_id = request_id.into_request_id()?;
        let resp_str = serde_json::to_string(response_json)?;
        let mut client = self
            .client
            .lock()
            .map_err(|e| StoreError::Lock(e.to_string()))?;

        client.execute(
            "INSERT INTO signer.results (request_id, response, response_sig, created_at)
             VALUES ($1, $2::text::jsonb, $3, now())
             ON CONFLICT (request_id) DO NOTHING",
            &[&req_id, &resp_str, &response_sig],
        )?;

        Ok(())
    }

    /// Retrieves a cached signed result from `signer.results`, if present.
    pub fn get_result(
        &self,
        request_id: impl IntoRequestId,
    ) -> Result<Option<StoredResult>, StoreError> {
        let req_id = request_id.into_request_id()?;
        let mut client = self
            .client
            .lock()
            .map_err(|e| StoreError::Lock(e.to_string()))?;

        let row_opt = client.query_opt(
            "SELECT response::text, response_sig, created_at FROM signer.results WHERE request_id = $1",
            &[&req_id],
        )?;

        match row_opt {
            Some(row) => {
                let resp_text: String = row.get(0);
                let resp_sig: String = row.get(1);
                let created_at: DateTime<Utc> = row.get(2);
                let resp_val: serde_json::Value = serde_json::from_str(&resp_text)?;
                Ok(Some(StoredResult {
                    response: resp_val,
                    response_sig: resp_sig,
                    created_at: Some(created_at),
                }))
            }
            None => Ok(None),
        }
    }

    /// Appends an immutable audit row into `signer.signer_audit`, calculating:
    /// `hash = SHA256(prev_hash || seq || ts || actor || event || request_id || decision_id)`.
    pub fn append_audit(
        &self,
        actor: &str,
        event: &str,
        request_id: Option<impl IntoRequestId>,
        decision_id: Option<&str>,
    ) -> Result<AuditEntry, StoreError> {
        let req_id: Option<Uuid> = request_id.map(|r| r.into_request_id()).transpose()?;
        let mut client = self
            .client
            .lock()
            .map_err(|e| StoreError::Lock(e.to_string()))?;

        let mut tx = client.transaction()?;

        // Acquire advisory transaction lock to serialize audit appends
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&AUDIT_ADVISORY_LOCK_ID],
        )?;

        // Determine prev_hash from the last recorded row in signer.signer_audit
        let prev_row = tx.query_opt(
            "SELECT seq, hash FROM signer.signer_audit ORDER BY seq DESC LIMIT 1",
            &[],
        )?;
        let prev_hash = match &prev_row {
            Some(row) => row.get::<_, String>("hash"),
            None => GENESIS_PREV_HASH.to_string(),
        };

        // Fetch next monotonically increasing sequence number
        let next_seq_row = tx.query_one("SELECT nextval('signer.signer_audit_seq_seq')", &[])?;
        let seq: i64 = next_seq_row.get(0);

        // Truncate timestamp to microsecond resolution matching PostgreSQL TIMESTAMPTZ
        let now = Utc::now();
        let nanos = now.timestamp_subsec_nanos();
        let micros = (nanos / 1_000) * 1_000;
        let ts = now.with_nanosecond(micros).unwrap_or(now);
        let ts_str = format_audit_ts(&ts);

        // Compute hash
        let req_id_str = req_id.map(|id| id.to_string());
        let hash = compute_audit_hash(
            &prev_hash,
            seq,
            &ts_str,
            actor,
            event,
            req_id_str.as_deref(),
            decision_id,
        );

        tx.execute(
            "INSERT INTO signer.signer_audit (seq, ts, actor, event, request_id, decision_id, prev_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&seq, &ts, &actor, &event, &req_id, &decision_id, &prev_hash, &hash],
        )?;

        tx.commit()?;

        Ok(AuditEntry {
            seq,
            ts,
            actor: actor.to_string(),
            event: event.to_string(),
            request_id: req_id,
            decision_id: decision_id.map(|d| d.to_string()),
            prev_hash,
            hash,
        })
    }

    /// Fetches all audit entries in ascending sequence order.
    pub fn fetch_audit_entries(&self, limit: Option<i64>) -> Result<Vec<AuditEntry>, StoreError> {
        let mut client = self
            .client
            .lock()
            .map_err(|e| StoreError::Lock(e.to_string()))?;

        let query = match limit {
            Some(lim) => format!(
                "SELECT seq, ts, actor, event, request_id, decision_id, prev_hash, hash
                 FROM signer.signer_audit
                 ORDER BY seq ASC
                 LIMIT {}",
                lim
            ),
            None => "SELECT seq, ts, actor, event, request_id, decision_id, prev_hash, hash
                     FROM signer.signer_audit
                     ORDER BY seq ASC"
                .to_string(),
        };

        let rows = client.query(&query, &[])?;
        let mut entries = Vec::with_capacity(rows.len());

        for row in rows {
            entries.push(AuditEntry {
                seq: row.get("seq"),
                ts: row.get("ts"),
                actor: row.get("actor"),
                event: row.get("event"),
                request_id: row.get("request_id"),
                decision_id: row.get("decision_id"),
                prev_hash: row.get("prev_hash"),
                hash: row.get("hash"),
            });
        }

        Ok(entries)
    }

    /// Cryptographically verifies that the audit log in `signer.signer_audit` forms a continuous,
    /// untampered hash chain from genesis to the latest record. Returns the number of verified entries.
    pub fn verify_audit_chain(&self) -> Result<usize, StoreError> {
        let entries = self.fetch_audit_entries(None)?;
        let mut expected_prev_hash: Option<String> = None;
        let mut count = 0;

        for entry in &entries {
            // Check prev_hash matches the prior row's computed hash
            if let Some(prev) = &expected_prev_hash {
                if entry.prev_hash != *prev {
                    return Err(StoreError::AuditChainIntegrity {
                        seq: entry.seq,
                        reason: format!(
                            "prev_hash mismatch: expected {}, got {}",
                            prev, entry.prev_hash
                        ),
                    });
                }
            } else if entry.seq == 1 && entry.prev_hash != GENESIS_PREV_HASH {
                // If this is the very first entry, verify genesis hash
                return Err(StoreError::AuditChainIntegrity {
                    seq: entry.seq,
                    reason: format!(
                        "genesis prev_hash mismatch: expected {}, got {}",
                        GENESIS_PREV_HASH, entry.prev_hash
                    ),
                });
            }

            // Verify the entry's hash matches SHA256(...)
            let calculated = compute_audit_entry_hash(entry);
            if entry.hash != calculated {
                return Err(StoreError::AuditChainIntegrity {
                    seq: entry.seq,
                    reason: format!(
                        "hash mismatch at seq {}: expected {}, calculated {}",
                        entry.seq, entry.hash, calculated
                    ),
                });
            }

            expected_prev_hash = Some(entry.hash.clone());
            count += 1;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_audit_hash_deterministic() {
        let prev_hash = GENESIS_PREV_HASH;
        let seq = 1;
        let ts = "2026-10-19T12:00:00.000000Z";
        let actor = "signer";
        let event = "claim";
        let request_id = Some("11111111-1111-1111-1111-111111111111");
        let decision_id = Some("dec-001");

        let hash1 = compute_audit_hash(prev_hash, seq, ts, actor, event, request_id, decision_id);
        let hash2 = compute_audit_hash(prev_hash, seq, ts, actor, event, request_id, decision_id);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);

        // Changing any single field changes the hash
        let hash_diff_actor =
            compute_audit_hash(prev_hash, seq, ts, "api", event, request_id, decision_id);
        assert_ne!(hash1, hash_diff_actor);

        let hash_diff_seq =
            compute_audit_hash(prev_hash, 2, ts, actor, event, request_id, decision_id);
        assert_ne!(hash1, hash_diff_seq);

        let hash_diff_ts = compute_audit_hash(
            prev_hash,
            seq,
            "2026-10-19T12:00:00.000001Z",
            actor,
            event,
            request_id,
            decision_id,
        );
        assert_ne!(hash1, hash_diff_ts);

        let hash_diff_event =
            compute_audit_hash(prev_hash, seq, ts, actor, "signed", request_id, decision_id);
        assert_ne!(hash1, hash_diff_event);

        let hash_no_req = compute_audit_hash(prev_hash, seq, ts, actor, event, None, decision_id);
        assert_ne!(hash1, hash_no_req);

        let hash_no_dec = compute_audit_hash(prev_hash, seq, ts, actor, event, request_id, None);
        assert_ne!(hash1, hash_no_dec);
    }

    #[test]
    fn test_audit_entry_hash_verification() {
        let entry = AuditEntry {
            seq: 1,
            ts: DateTime::parse_from_rfc3339("2026-10-19T12:00:00.123456Z")
                .unwrap()
                .with_timezone(&Utc),
            actor: "signer".to_string(),
            event: "signed".to_string(),
            request_id: Some(Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()),
            decision_id: Some("dec-002".to_string()),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            hash: String::new(),
        };

        let hash = compute_audit_entry_hash(&entry);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_into_request_id_conversions() {
        let uuid_val = Uuid::new_v4();
        let uuid_str = uuid_val.to_string();

        assert_eq!(uuid_val.into_request_id().unwrap(), uuid_val);
        assert_eq!(uuid_str.as_str().into_request_id().unwrap(), uuid_val);
        assert_eq!((&uuid_str).into_request_id().unwrap(), uuid_val);
        assert_eq!(uuid_str.clone().into_request_id().unwrap(), uuid_val);

        assert!(matches!(
            "invalid-uuid".into_request_id(),
            Err(StoreError::InvalidUuid(_))
        ));
    }

    #[test]
    fn test_reason_codes_and_error_helpers() {
        let replayed = StoreError::Replayed("dup".to_string());
        assert!(replayed.is_replayed());
        assert_eq!(replayed.reason_code(), "replayed");

        let uuid_err = StoreError::InvalidUuid(Uuid::parse_str("invalid").unwrap_err());
        assert!(!uuid_err.is_replayed());
        assert_eq!(uuid_err.reason_code(), "invalid_uuid");
    }

    #[test]
    fn test_replay_outcome_helpers() {
        let rec = ReplayOutcome::Recorded;
        assert!(rec.is_recorded());
        assert!(!rec.is_stored());
        assert!(rec.stored_result().is_none());

        let res = StoredResult {
            response: serde_json::json!({"status": "ok"}),
            response_sig: "sig123".to_string(),
            created_at: Some(Utc::now()),
        };
        let stored = ReplayOutcome::Stored(res.clone());
        assert!(!stored.is_recorded());
        assert!(stored.is_stored());
        assert_eq!(stored.stored_result(), Some(&res));
    }

    // Database integration tests run against PostgreSQL when available
    fn test_pg_url() -> Option<String> {
        if let Ok(url) = std::env::var("DATABASE_URL") {
            return Some(url);
        }
        if let Ok(url) = std::env::var("POLYGLOT_TEST_PG_URL") {
            return Some(url);
        }
        // Try common test ports: 5433 then 5432
        for port in [5433, 5432] {
            let url = format!("postgres://signer_role:signer_pass@127.0.0.1:{}/postgres", port);
            if Client::connect(&url, NoTls).is_ok() {
                return Some(url);
            }
        }
        None
    }

    #[test]
    fn test_signer_store_integration() {
        let Some(url) = test_pg_url() else {
            eprintln!("SKIPPING test_signer_store_integration: Postgres not reachable at 127.0.0.1:5432");
            return;
        };

        let store = SignerStore::connect(&url).expect("Failed to connect as signer_role");

        // Generate fresh test parameters
        let req_id_1 = Uuid::new_v4();
        let nonce_1 = format!("nonce_{}", hex::encode(req_id_1.as_bytes()));

        let req_id_2 = Uuid::new_v4();
        let _nonce_2 = format!("nonce_{}", hex::encode(req_id_2.as_bytes()));

        // 1. Initial check on brand new request returns Recorded
        let outcome = store
            .check_or_record_replay(req_id_1, &nonce_1)
            .expect("First check_or_record_replay should succeed");
        assert!(outcome.is_recorded(), "Expected Recorded, got {:?}", outcome);

        // 2. Duplicate request_id without stored result rejects as replayed
        let err_dup_id = store
            .check_or_record_replay(req_id_1, "nonce_different")
            .expect_err("Duplicate request_id without result must reject as replayed");
        assert!(
            err_dup_id.is_replayed(),
            "Expected replayed error, got: {:?}",
            err_dup_id
        );

        // 3. Duplicate nonce with new request_id rejects as replayed
        let err_dup_nonce = store
            .check_or_record_replay(req_id_2, &nonce_1)
            .expect_err("Duplicate nonce with new request_id must reject as replayed");
        assert!(
            err_dup_nonce.is_replayed(),
            "Expected replayed error, got: {:?}",
            err_dup_nonce
        );

        // 4. Store signed result for req_id_1
        let sample_response = serde_json::json!({
            "request_id": req_id_1.to_string(),
            "status": "completed",
            "result": { "public_key": "02abcdef" },
            "signing_in_hsm": true
        });
        let sample_sig = "sample_ed25519_signature_hex";

        store
            .store_signed_result(req_id_1, &sample_response, sample_sig)
            .expect("store_signed_result should succeed");

        // 5. Duplicate request_id WITH stored result returns the stored result
        let outcome_retry = store
            .check_or_record_replay(req_id_1, &nonce_1)
            .expect("Retry of completed request must succeed");

        match outcome_retry {
            ReplayOutcome::Stored(stored) => {
                assert_eq!(stored.response, sample_response);
                assert_eq!(stored.response_sig, sample_sig);
            }
            ReplayOutcome::Recorded => {
                panic!("Expected ReplayOutcome::Stored for completed request retry");
            }
        }

        // Also test get_result directly
        let fetched = store
            .get_result(req_id_1)
            .expect("get_result should succeed")
            .expect("Result should be found");
        assert_eq!(fetched.response, sample_response);
        assert_eq!(fetched.response_sig, sample_sig);

        // Non-existent request returns None
        let not_found = store
            .get_result(Uuid::new_v4())
            .expect("get_result should succeed");
        assert!(not_found.is_none());

        // 6. Test append_audit and hash chain verification
        let entry1 = store
            .append_audit("signer", "claim", Some(req_id_1), Some("dec-001"))
            .expect("append_audit 1 should succeed");
        assert_eq!(entry1.actor, "signer");
        assert_eq!(entry1.event, "claim");
        assert_eq!(entry1.request_id, Some(req_id_1));
        assert_eq!(entry1.decision_id, Some("dec-001".to_string()));
        assert_eq!(compute_audit_entry_hash(&entry1), entry1.hash);

        let entry2 = store
            .append_audit("signer", "signed", Some(req_id_1), Some("dec-001"))
            .expect("append_audit 2 should succeed");
        assert_eq!(compute_audit_entry_hash(&entry2), entry2.hash);

        let entry3 = store
            .append_audit("signer", "completed", Option::<Uuid>::None, None)
            .expect("append_audit 3 should succeed");
        assert_eq!(compute_audit_entry_hash(&entry3), entry3.hash);

        // Verify that entry2 and entry3 chained to the immediately preceding sequence entry
        let all_entries = store.fetch_audit_entries(None).expect("fetch_audit_entries failed");
        let prev_of_entry2 = all_entries.iter().find(|e| e.seq == entry2.seq - 1).unwrap();
        assert_eq!(entry2.prev_hash, prev_of_entry2.hash);

        let prev_of_entry3 = all_entries.iter().find(|e| e.seq == entry3.seq - 1).unwrap();
        assert_eq!(entry3.prev_hash, prev_of_entry3.hash);

        // 7. Verify the complete audit chain in the database
        let count = store
            .verify_audit_chain()
            .expect("verify_audit_chain should succeed");
        assert!(count >= 3, "Expected at least 3 verified entries");
    }

    #[test]
    fn test_duplicate_request_id_with_stored_result_returns_stored_result() {
        let Some(url) = test_pg_url() else { return; };
        let store = SignerStore::connect(&url).expect("connect failed");

        let req_id = Uuid::new_v4();
        let nonce = format!("nonce_{}", Uuid::new_v4());

        // 1. Initial record
        let outcome = store.check_or_record_replay(req_id, &nonce).expect("initial check failed");
        assert!(outcome.is_recorded());

        // 2. Store result
        let resp = serde_json::json!({
            "request_id": req_id.to_string(),
            "status": "completed",
            "result": { "signature": "01020304" }
        });
        let sig = "ed25519_valid_signature_string";
        store.store_signed_result(req_id, &resp, sig).expect("store result failed");

        // 3. Retry with same request_id must return the stored result
        let retry_outcome = store.check_or_record_replay(req_id, &nonce).expect("retry check failed");
        match retry_outcome {
            ReplayOutcome::Stored(cached) => {
                assert_eq!(cached.response, resp);
                assert_eq!(cached.response_sig, sig);
            }
            ReplayOutcome::Recorded => panic!("Expected Stored result on retry"),
        }
    }

    #[test]
    fn test_duplicate_request_id_without_stored_result_rejects_as_replayed() {
        let Some(url) = test_pg_url() else { return; };
        let store = SignerStore::connect(&url).expect("connect failed");

        let req_id = Uuid::new_v4();
        let nonce = format!("nonce_{}", Uuid::new_v4());

        // 1. Initial record
        let outcome = store.check_or_record_replay(req_id, &nonce).expect("initial check failed");
        assert!(outcome.is_recorded());

        // 2. Immediate duplicate with new nonce (before result stored)
        let new_nonce = format!("nonce_{}", Uuid::new_v4());
        let err = store.check_or_record_replay(req_id, &new_nonce).expect_err("must reject duplicate request_id");
        assert!(err.is_replayed(), "Expected Replayed error, got: {:?}", err);
        assert_eq!(err.reason_code(), "replayed");
    }

    #[test]
    fn test_duplicate_nonce_with_new_request_id_rejects_as_replayed() {
        let Some(url) = test_pg_url() else { return; };
        let store = SignerStore::connect(&url).expect("connect failed");

        let req_id_1 = Uuid::new_v4();
        let shared_nonce = format!("nonce_shared_{}", Uuid::new_v4());

        // 1. Record req_id_1 with shared_nonce
        let outcome = store.check_or_record_replay(req_id_1, &shared_nonce).expect("initial check failed");
        assert!(outcome.is_recorded());

        // 2. Submit new req_id_2 with same shared_nonce
        let req_id_2 = Uuid::new_v4();
        let err = store.check_or_record_replay(req_id_2, &shared_nonce).expect_err("must reject duplicate nonce");
        assert!(err.is_replayed(), "Expected Replayed error, got: {:?}", err);
        assert_eq!(err.reason_code(), "replayed");
    }

    #[test]
    fn test_audit_log_hashes_chain_properly() {
        let Some(url) = test_pg_url() else { return; };
        let store = SignerStore::connect(&url).expect("connect failed");

        let req_id = Uuid::new_v4();
        let e1 = store.append_audit("signer", "step_1_canonicalized", Some(req_id), Some("dec-100")).unwrap();
        let e2 = store.append_audit("signer", "step_4_auth_verified", Some(req_id), Some("dec-100")).unwrap();
        let e3 = store.append_audit("signer", "step_5_replay_checked", Some(req_id), Some("dec-100")).unwrap();
        let e4 = store.append_audit("signer", "step_9_signed_in_hsm", Some(req_id), Some("dec-100")).unwrap();

        // Verify that each entry's prev_hash matches the hash of entry at seq - 1
        let all_entries = store.fetch_audit_entries(None).expect("fetch_audit_entries failed");
        for entry in [&e1, &e2, &e3, &e4] {
            if entry.seq > 1 {
                let prev = all_entries.iter().find(|e| e.seq == entry.seq - 1).expect("prev entry missing");
                assert_eq!(entry.prev_hash, prev.hash);
            }
            // Verify each individual hash matches preimage
            assert_eq!(compute_audit_entry_hash(entry), entry.hash);
        }

        // Entire audit log in DB verifies
        let total = store.verify_audit_chain().expect("audit chain verification failed");
        assert!(total >= 4);
    }
}
