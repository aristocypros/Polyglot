//! Queue resilience and worker concurrency integration tests (Milestone 5 Gate).
//!
//! Covers Section 10's `Queue` row:
//! 1. Two signer workers claiming concurrently against the API (exactly one claim per request, no double signing).
//! 2. Signer killed mid-request before posting results: lease expires after timeout, second claim checks
//!    `signer.replay` / `signer.results` (returns stored result if step 9 completed before crash, or marks `failed`
//!    if crashed between step 5 and step 9).
//! 3. Worker HTTP communication round-trip over standard TCP stream.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hex;

use signer::backend::{
    Backend, BackendError, Capabilities, Curve, ProtectionLevel, Scheme, Signature,
    SigningInput as BackendSigningInput, SigningLocation, Spec, WalletRef, WRAPPED_SEED_LEN,
};
use signer::envelope::auth::{
    sign_ed25519_authorization, PinnedKey, PolicyAlg, Profile, SignerConfig,
};
use signer::envelope::jcs::{to_canonical_json_bytes, RequestBody, RequestType};
use signer::envelope::processor::{
    ClaimedWork, EnvelopeProcessor, InMemorySignerStore, ReplayStore, SignerIdentity,
    SignerSubmission,
};
use signer::store::ReplayOutcome;
use signer::worker::{
    HttpClient, HttpResponse, SimpleHttpClient, StepOutcome, Worker, WorkerConfig, WorkerError,
};

const SIGNER_ID: &str = "signer-local-1";
const PINNED_KID: &str = "pe-dev-1";

/// Test harness backend simulating HSM wrapping and signing.
#[derive(Clone)]
struct TestHarnessBackend {
    caps: Capabilities,
}

impl TestHarnessBackend {
    fn new() -> Self {
        Self {
            caps: Capabilities::new_generic(
                "softhsm-generic",
                ProtectionLevel::GenericDev,
                SigningLocation::Hsm,
                SigningLocation::Hsm,
            ),
        }
    }
}

impl Backend for TestHarnessBackend {
    fn capabilities(&self) -> Result<Capabilities, BackendError> {
        Ok(self.caps.clone())
    }

    fn create_wallet(&self, _spec: &Spec, _aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        Ok(vec![0x77; WRAPPED_SEED_LEN])
    }

    fn public_key(&self, _w: &WalletRef, _path: &[u32]) -> Result<Vec<u8>, BackendError> {
        Ok(vec![0x02; 33])
    }

    fn sign(
        &self,
        _w: &WalletRef,
        _path: &[u32],
        _input: BackendSigningInput,
    ) -> Result<Signature, BackendError> {
        Ok(Signature::new_ecdsa([0x12; 32], [0x34; 32], 0, None, vec![0x02; 33], true))
    }
}

/// Simulated shared HTTP queue client between concurrent workers.
struct SharedQueueHttpClient {
    pending_work: Mutex<Vec<ClaimedWork>>,
    claims_count: Mutex<HashMap<String, usize>>,
    signed_submissions: Mutex<Vec<SignerSubmission>>,
}

impl SharedQueueHttpClient {
    fn new(work_items: Vec<ClaimedWork>) -> Self {
        Self {
            pending_work: Mutex::new(work_items),
            claims_count: Mutex::new(HashMap::new()),
            signed_submissions: Mutex::new(Vec::new()),
        }
    }
}

impl HttpClient for SharedQueueHttpClient {
    fn post_json(
        &self,
        url: &str,
        _bearer_token: Option<&str>,
        body: &[u8],
        _timeout: Duration,
    ) -> Result<HttpResponse, WorkerError> {
        if url.ends_with("/internal/claim") {
            let mut queue = self.pending_work.lock().unwrap();
            if queue.is_empty() {
                return Ok(HttpResponse {
                    status: 204,
                    status_text: "No Content".to_string(),
                    headers: HashMap::new(),
                    body: Vec::new(),
                });
            }
            let item = queue.remove(0);
            let mut counts = self.claims_count.lock().unwrap();
            *counts.entry(item.request_id.clone()).or_insert(0) += 1;
            drop(counts);
            drop(queue);

            let body_bytes = serde_json::to_vec(&item)?;
            return Ok(HttpResponse {
                status: 200,
                status_text: "OK".to_string(),
                headers: HashMap::new(),
                body: body_bytes,
            });
        }

        if url.ends_with("/internal/results") {
            let sub: SignerSubmission = serde_json::from_slice(body)?;
            self.signed_submissions.lock().unwrap().push(sub);
            return Ok(HttpResponse {
                status: 200,
                status_text: "OK".to_string(),
                headers: HashMap::new(),
                body: br#"{"status":"ok"}"#.to_vec(),
            });
        }

        Err(WorkerError::Http(format!("unexpected URL: {url}")))
    }
}

fn create_test_processor(
    signer_id: &str,
    pe_key: &Ed25519SigningKey,
    store: Arc<dyn ReplayStore>,
) -> EnvelopeProcessor {
    let pubkey_hex = hex::encode(pe_key.verifying_key().to_bytes());
    let cfg = SignerConfig {
        signer_id: signer_id.to_string(),
        policy_engine_keys: vec![PinnedKey {
            kid: PINNED_KID.to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: pubkey_hex,
            not_before: None,
            not_after: None,
        }],
        max_lifetime_seconds: 600,
        clock_skew_seconds: 30,
        profile: Profile::Dev,
        allow_digest_signing: Some(true),
    };
    let backend = Arc::new(TestHarnessBackend::new());
    let identity = SignerIdentity::generate();
    EnvelopeProcessor::new(cfg, backend, store, identity)
}

fn create_test_request(
    req_id: &str,
    nonce: &str,
    pe_key: &Ed25519SigningKey,
) -> ClaimedWork {
    let body = RequestBody {
        v: 1,
        request_id: req_id.to_string(),
        decision_id: format!("dec-{req_id}"),
        audience: SIGNER_ID.to_string(),
        expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        nonce: nonce.to_string(),
        request_type: RequestType::CreateWallet,
        scheme: Scheme::Bip32,
        curve: Curve::Secp256k1,
        wallet_id: format!("w_{}", &req_id[..8]),
        path: None,
        input_paths: None,
        payload: None,
        payload_encoding: None,
        chain: None,
        seed_version: None,
        kek_label: None,
    };

    let canonical_bytes = to_canonical_json_bytes(&body).unwrap();
    let auth_raw = sign_ed25519_authorization(pe_key, PINNED_KID, &canonical_bytes);
    let auth_val = serde_json::to_value(&auth_raw).unwrap();

    ClaimedWork {
        request_id: req_id.to_string(),
        body_canonical: String::from_utf8(canonical_bytes).unwrap(),
        authorization: auth_val,
        label: Some("Concurrent Test Label".to_string()),
        wallet: None,
    }
}

#[test]
fn test_concurrent_workers_no_double_signing() {
    let pe_key = Ed25519SigningKey::from_bytes(&[0x11; 32]);
    let store = Arc::new(InMemorySignerStore::new());

    const NUM_REQUESTS: usize = 20;
    let mut work_items = Vec::with_capacity(NUM_REQUESTS);
    let mut expected_ids = Vec::with_capacity(NUM_REQUESTS);

    for i in 0..NUM_REQUESTS {
        let req_id = format!("00000000-0000-0000-0000-{:012x}", i + 1);
        let nonce = format!("nonce-{:016x}", i + 1);
        expected_ids.push(req_id.clone());
        work_items.push(create_test_request(&req_id, &nonce, &pe_key));
    }

    let shared_http = Arc::new(SharedQueueHttpClient::new(work_items));

    // Create 2 concurrent workers sharing the same queue and store
    let proc1 = Arc::new(create_test_processor(SIGNER_ID, &pe_key, store.clone()));
    let proc2 = Arc::new(create_test_processor(SIGNER_ID, &pe_key, store.clone()));

    let mut cfg1 = WorkerConfig::default();
    cfg1.bearer_token = Some("signer-secret-token".to_string());
    let mut cfg2 = WorkerConfig::default();
    cfg2.bearer_token = Some("signer-secret-token".to_string());

    let worker1 = Arc::new(Worker::with_client(cfg1, proc1, shared_http.clone()));
    let worker2 = Arc::new(Worker::with_client(cfg2, proc2, shared_http.clone()));

    let processed_w1 = Arc::new(AtomicUsize::new(0));
    let processed_w2 = Arc::new(AtomicUsize::new(0));

    let w1_clone = worker1.clone();
    let p1_clone = processed_w1.clone();
    let handle1 = thread::spawn(move || {
        loop {
            match w1_clone.step() {
                Ok(StepOutcome::Processed(_)) => {
                    p1_clone.fetch_add(1, Ordering::SeqCst);
                }
                Ok(StepOutcome::Idle) => break,
                Ok(StepOutcome::Rejected { .. }) => {}
                Err(e) => panic!("worker 1 unexpected error: {e}"),
            }
        }
    });

    let w2_clone = worker2.clone();
    let p2_clone = processed_w2.clone();
    let handle2 = thread::spawn(move || {
        loop {
            match w2_clone.step() {
                Ok(StepOutcome::Processed(_)) => {
                    p2_clone.fetch_add(1, Ordering::SeqCst);
                }
                Ok(StepOutcome::Idle) => break,
                Ok(StepOutcome::Rejected { .. }) => {}
                Err(e) => panic!("worker 2 unexpected error: {e}"),
            }
        }
    });

    handle1.join().unwrap();
    handle2.join().unwrap();

    // Verify all 20 requests were processed exactly once
    let total_processed = processed_w1.load(Ordering::SeqCst) + processed_w2.load(Ordering::SeqCst);
    assert_eq!(
        total_processed, NUM_REQUESTS,
        "expected {NUM_REQUESTS} total requests processed across both workers, got {total_processed}"
    );

    let claims = shared_http.claims_count.lock().unwrap();
    assert_eq!(claims.len(), NUM_REQUESTS);
    for (id, count) in claims.iter() {
        assert_eq!(*count, 1, "request {id} was claimed {count} times (must be exactly 1)");
    }

    let submissions = shared_http.signed_submissions.lock().unwrap();
    assert_eq!(submissions.len(), NUM_REQUESTS);
    for sub in submissions.iter() {
        assert_eq!(sub.status, "completed");
        assert!(sub.response.is_some());
        assert!(sub.response_sig.is_some());
    }

    // Verify cryptographic audit log integrity in store
    assert_eq!(store.verify_audit_chain().unwrap(), NUM_REQUESTS);
}

#[test]
fn test_signer_killed_mid_request_recovery_after_step9() {
    let pe_key = Ed25519SigningKey::from_bytes(&[0x22; 32]);
    let store = Arc::new(InMemorySignerStore::new());

    let req_id = "00000000-0000-0000-0000-0000000000aa";
    let nonce = "nonce-mid-crash-step9";
    let work = create_test_request(req_id, nonce, &pe_key);

    // Worker 1 processes work up to Step 9, saving result into store, but crashes before results POST
    let proc1 = create_test_processor(SIGNER_ID, &pe_key, store.clone());
    let submission1 = proc1.process_claimed_work(&work, None).unwrap();
    assert_eq!(submission1.status, "completed");
    let original_sig = submission1.response_sig.clone().unwrap();

    // Worker 1 crashes (never calls /internal/results)

    // Lease expires -> Worker 2 claims the exact same request
    let proc2 = create_test_processor(SIGNER_ID, &pe_key, store.clone());
    let submission2 = proc2.process_claimed_work(&work, None).unwrap();

    // Worker 2 should return the cached completed result with identical signature
    assert_eq!(submission2.status, "completed");
    assert_eq!(submission2.request_id, req_id);
    assert_eq!(submission2.response_sig.as_ref(), Some(&original_sig));
}

#[test]
fn test_signer_killed_mid_request_failed_before_step9() {
    let pe_key = Ed25519SigningKey::from_bytes(&[0x33; 32]);
    let store = Arc::new(InMemorySignerStore::new());

    let req_id = "00000000-0000-0000-0000-0000000000bb";
    let nonce = "nonce-mid-crash-step5";
    let work = create_test_request(req_id, nonce, &pe_key);

    // Worker 1 executes Step 5 only: records (request_id, nonce) in replay table, then crashes before Step 9
    let outcome = store.check_or_record_replay(req_id, nonce).unwrap();
    assert_eq!(outcome, ReplayOutcome::Recorded);

    // Lease expires -> Worker 2 claims the exact same request
    let proc2 = create_test_processor(SIGNER_ID, &pe_key, store.clone());
    let err = proc2.process_claimed_work(&work, None).unwrap_err();

    // Worker 2 must reject as replayed
    assert_eq!(err.error_code(), "replayed");
    assert_eq!(err.reason_code(), "replayed");
}

#[test]
fn test_simple_http_client_roundtrip_over_tcp() {
    // Start local TCP listener on random port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_url = format!("http://127.0.0.1:{port}/internal/claim");

    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap();
        let req_str = String::from_utf8_lossy(&buf[..n]);

        assert!(req_str.starts_with("POST /internal/claim HTTP/1.1"));
        assert!(req_str.contains("Authorization: Bearer secret-signer-token"));
        assert!(req_str.contains("Content-Type: application/json"));

        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        stream.write_all(resp.as_bytes()).unwrap();
        stream.flush().unwrap();
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut discard = [0u8; 128];
        while let Ok(n) = stream.read(&mut discard) {
            if n == 0 {
                break;
            }
        }
    });

    let client = SimpleHttpClient::new();
    let res = client
        .post_json(
            &server_url,
            Some("secret-signer-token"),
            br#"{"signer_id":"test-1"}"#,
            Duration::from_secs(5),
        )
        .unwrap();

    assert_eq!(res.status, 200);
    assert_eq!(res.body, br#"{"status":"ok"}"#);

    server_handle.join().unwrap();
}
