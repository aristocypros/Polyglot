//! Outbound HTTP polling worker for the signer service (Task 28 of Milestone 5).
//!
//! The worker continuously calls `POST http://api:8081/internal/claim` with the signer
//! bearer token, reports signer capabilities and Ed25519 identity public key in the
//! heartbeat payload, processes each claimed envelope through the 9-step verification
//! processor ([`EnvelopeProcessor`]), and posts the signed result (or structured rejection)
//! to `POST http://api:8081/internal/results`.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::backend::{Capabilities, ProtectionLevel};
use crate::envelope::processor::{
    ClaimedWork, EnvelopeProcessor, ProcessorError, SignerSubmission,
};

/// Default internal API base URL.
pub const DEFAULT_INTERNAL_API_URL: &str = "http://api:8081";

/// Default bearer token secret file path.
pub const DEFAULT_SIGNER_TOKEN_FILE: &str = "/run/secrets/signer_token";

/// Default request timeout for HTTP calls (must exceed server's 25-second poll timeout).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(35);

/// Default poll interval between claim attempts when queue was idle.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Errors arising during worker execution or communication with the internal API.
#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("unauthorized (HTTP {0}): {1}")]
    Unauthorized(u16, String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("processor error: {0}")]
    Processor(#[from] ProcessorError),

    #[error("bearer token error: {0}")]
    Token(String),

    #[error("worker configuration error: {0}")]
    Config(String),
}

/// Signer heartbeat and capability registration payload sent on `POST /internal/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerHeartbeat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_level: Option<ProtectionLevel>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
}

/// Configuration for the outbound HTTP polling worker.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Base URL of the internal API (e.g. `"http://api:8081"` or `"http://127.0.0.1:8081"`).
    pub api_url: String,

    /// Explicit bearer token string (takes priority over token file).
    pub bearer_token: Option<String>,

    /// Path to file containing bearer token (e.g. `/run/secrets/signer_token`).
    pub token_path: Option<PathBuf>,

    /// Timeout for claim and result HTTP requests.
    pub request_timeout: Duration,

    /// Delay between polling attempts when `/internal/claim` returns 204 No Content.
    pub poll_interval: Duration,

    /// Delay between retries after network or server errors.
    pub error_retry_delay: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            api_url: DEFAULT_INTERNAL_API_URL.to_string(),
            bearer_token: None,
            token_path: Some(PathBuf::from(DEFAULT_SIGNER_TOKEN_FILE)),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
            error_retry_delay: Duration::from_secs(1),
        }
    }
}

impl WorkerConfig {
    /// Resolves the bearer token from the explicit string, configured file, or environment.
    pub fn resolve_bearer_token(&self) -> Result<String, WorkerError> {
        if let Some(token) = &self.bearer_token {
            let clean = token.trim();
            if !clean.is_empty() {
                return Ok(clean.to_string());
            }
        }

        if let Ok(env_token) = env::var("SIGNER_TOKEN") {
            let clean = env_token.trim();
            if !clean.is_empty() {
                return Ok(clean.to_string());
            }
        }

        if let Ok(env_token) = env::var("SIGNER_BEARER_TOKEN") {
            let clean = env_token.trim();
            if !clean.is_empty() {
                return Ok(clean.to_string());
            }
        }

        let token_path = self.token_path.as_deref().or_else(|| {
            env::var("SIGNER_TOKEN_FILE")
                .ok()
                .map(|p| Path::new(p.leak()))
        });

        if let Some(path) = token_path {
            if path.exists() {
                let content = fs::read_to_string(path).map_err(|e| {
                    WorkerError::Token(format!(
                        "failed to read bearer token from '{}': {e}",
                        path.display()
                    ))
                })?;
                let clean = content.trim();
                if !clean.is_empty() {
                    return Ok(clean.to_string());
                }
            }
        }

        Err(WorkerError::Token(
            "no bearer token found (set --token, --token-file, SIGNER_TOKEN, or mount /run/secrets/signer_token)"
                .to_string(),
        ))
    }
}

/// Raw HTTP response representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Abstract HTTP client interface used by [`Worker`] for outbound API communication.
pub trait HttpClient: Send + Sync {
    /// Performs an HTTP POST request with an optional Bearer token and JSON body.
    fn post_json(
        &self,
        url: &str,
        bearer_token: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, WorkerError>;
}

/// Built-in standard library HTTP/1.1 client using [`TcpStream`].
#[derive(Debug, Default, Clone)]
pub struct SimpleHttpClient;

impl SimpleHttpClient {
    pub fn new() -> Self {
        Self
    }
}

impl HttpClient for SimpleHttpClient {
    fn post_json(
        &self,
        url: &str,
        bearer_token: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, WorkerError> {
        let (host, port, path) = parse_http_url(url)?;

        let addrs = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| WorkerError::Http(format!("failed to resolve host '{host}:{port}': {e}")))?;

        let mut stream_opt = None;
        let mut last_err = None;

        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    stream_opt = Some(stream);
                    break;
                }
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        let mut stream = stream_opt.ok_or_else(|| {
            WorkerError::Http(format!(
                "failed to connect to '{host}:{port}': {}",
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no addresses resolved".to_string())
            ))
        })?;

        stream
            .set_read_timeout(Some(timeout))
            .map_err(WorkerError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(WorkerError::Io)?;

        let mut req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}:{port}\r\n\
             User-Agent: polyglot-signer/0.1.0\r\n\
             Content-Type: application/json\r\n\
             Accept: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n",
            body.len()
        );

        if let Some(token) = bearer_token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", token.trim()));
        }

        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).map_err(WorkerError::Io)?;
        if !body.is_empty() {
            stream.write_all(body).map_err(WorkerError::Io)?;
        }
        stream.flush().map_err(WorkerError::Io)?;

        // Read complete response until EOF
        let mut resp_bytes = Vec::new();
        stream
            .read_to_end(&mut resp_bytes)
            .map_err(WorkerError::Io)?;

        parse_http_response(&resp_bytes)
    }
}

/// Parses an HTTP URL into `(host, port, path)`.
fn parse_http_url(url: &str) -> Result<(String, u16, String), WorkerError> {
    let clean = url.trim();
    let rest = clean.strip_prefix("http://").ok_or_else(|| {
        WorkerError::Config(format!(
            "unsupported or invalid URL '{url}': only plain 'http://' is supported for internal API"
        ))
    })?;

    let (host_port, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part.to_string()
    };

    let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
        let h = &host_port[..colon_idx];
        let p_str = &host_port[colon_idx + 1..];
        let p: u16 = p_str.parse().map_err(|e| {
            WorkerError::Config(format!("invalid port '{p_str}' in URL '{url}': {e}"))
        })?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };

    if host.is_empty() {
        return Err(WorkerError::Config(format!("empty host in URL '{url}'")));
    }

    Ok((host, port, path))
}

/// Parses raw HTTP response bytes into [`HttpResponse`].
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, WorkerError> {
    if raw.is_empty() {
        return Err(WorkerError::Http("empty response received from server".to_string()));
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| (idx, idx + 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|idx| (idx, idx + 2)))
        .ok_or_else(|| WorkerError::Http("malformed HTTP response: missing header terminator".to_string()))?;

    let header_str = std::str::from_utf8(&raw[..header_end.0])
        .map_err(|e| WorkerError::Http(format!("invalid UTF-8 in response headers: {e}")))?;

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| WorkerError::Http("missing HTTP status line".to_string()))?;

    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(WorkerError::Http(format!(
            "malformed HTTP status line '{status_line}'"
        )));
    }

    let status: u16 = parts[1]
        .parse()
        .map_err(|e| WorkerError::Http(format!("invalid status code in '{status_line}': {e}")))?;

    let status_text = parts[2..].join(" ");

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let raw_body = &raw[header_end.1..];

    // Decode chunked transfer encoding if present
    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let body = if is_chunked {
        decode_chunked_body(raw_body)?
    } else if let Some(len_str) = headers.get("content-length") {
        if let Ok(expected_len) = len_str.parse::<usize>() {
            let actual_len = raw_body.len().min(expected_len);
            raw_body[..actual_len].to_vec()
        } else {
            raw_body.to_vec()
        }
    } else {
        raw_body.to_vec()
    };

    Ok(HttpResponse {
        status,
        status_text,
        headers,
        body,
    })
}

/// Decodes HTTP/1.1 chunked transfer encoding.
fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, WorkerError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| WorkerError::Http("malformed chunked transfer header".to_string()))?;

        let hex_str = std::str::from_utf8(&data[..line_end])
            .map_err(|e| WorkerError::Http(format!("invalid chunk size hex UTF-8: {e}")))?
            .trim();

        // Optional chunk extensions may follow ';'
        let clean_hex = hex_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(clean_hex, 16).map_err(|e| {
            WorkerError::Http(format!("invalid chunk size hex '{clean_hex}': {e}"))
        })?;

        if chunk_size == 0 {
            break;
        }

        let chunk_start = line_end + 2;
        let chunk_end = chunk_start + chunk_size;
        if data.len() < chunk_end {
            return Err(WorkerError::Http("truncated chunked payload".to_string()));
        }

        out.extend_from_slice(&data[chunk_start..chunk_end]);
        data = &data[chunk_end..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

/// Outcome of a single worker polling step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// No work was available on `/internal/claim` (204 No Content).
    Idle,

    /// A claimed request was successfully verified, executed, and signed.
    Processed(String),

    /// A claimed request failed verification and a structured rejection was posted.
    Rejected {
        request_id: String,
        error_code: String,
        reason_code: String,
    },
}

/// Outbound HTTP polling worker communicating with the Polyglot API internal listener.
pub struct Worker {
    config: WorkerConfig,
    processor: Arc<EnvelopeProcessor>,
    client: Arc<dyn HttpClient>,
    heartbeat: SignerHeartbeat,
}

impl Worker {
    /// Constructs a [`Worker`] using the default [`SimpleHttpClient`].
    pub fn new(config: WorkerConfig, processor: Arc<EnvelopeProcessor>) -> Self {
        let client = Arc::new(SimpleHttpClient::new());
        Self::with_client(config, processor, client)
    }

    /// Constructs a [`Worker`] with a custom [`HttpClient`].
    pub fn with_client(
        config: WorkerConfig,
        processor: Arc<EnvelopeProcessor>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        let caps = processor.backend().capabilities().ok();
        let protection_level = caps.as_ref().map(|c| c.protection_level);
        let heartbeat = SignerHeartbeat {
            signer_id: Some(processor.config().signer_id.clone()),
            public_key: Some(processor.identity().public_key_hex().to_string()),
            protection_level,
            capabilities: caps,
        };

        Self {
            config,
            processor,
            client,
            heartbeat,
        }
    }

    /// Returns a reference to the worker configuration.
    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Returns a reference to the inner envelope processor.
    pub fn processor(&self) -> &EnvelopeProcessor {
        &self.processor
    }

    /// Returns a reference to the active heartbeat metadata.
    pub fn heartbeat(&self) -> &SignerHeartbeat {
        &self.heartbeat
    }

    /// Executes a single polling and execution cycle:
    /// 1. Calls `POST /internal/claim` with the signer bearer token and heartbeat payload.
    /// 2. If 204 No Content, returns [`StepOutcome::Idle`].
    /// 3. If 200 OK with [`ClaimedWork`], runs the 9-step verification processor.
    /// 4. Posts the result (or structured rejection) to `POST /internal/results`.
    pub fn step(&self) -> Result<StepOutcome, WorkerError> {
        let token = self.config.resolve_bearer_token()?;

        // 1. Call POST /internal/claim
        let claim_url = format!("{}/internal/claim", self.config.api_url.trim_end_matches('/'));
        let hb_json = serde_json::to_vec(&self.heartbeat)?;

        let resp = self.client.post_json(
            &claim_url,
            Some(&token),
            &hb_json,
            self.config.request_timeout,
        )?;

        if resp.status == 204 {
            return Ok(StepOutcome::Idle);
        }

        if resp.status == 401 || resp.status == 403 {
            return Err(WorkerError::Unauthorized(
                resp.status,
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }

        if resp.status != 200 {
            return Err(WorkerError::Http(format!(
                "POST /internal/claim returned status {}: {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            )));
        }

        let claimed: ClaimedWork = serde_json::from_slice(&resp.body).map_err(|e| {
            WorkerError::Http(format!(
                "failed to parse ClaimedWork JSON from /internal/claim: {e} (body: {})",
                String::from_utf8_lossy(&resp.body)
            ))
        })?;

        let request_id = claimed.request_id.clone();

        // 2. Process claimed envelope through the 9-step verification processor
        let (submission, outcome) = match self.processor.process_claimed_work(&claimed, None) {
            Ok(sub) => (sub, StepOutcome::Processed(request_id.clone())),
            Err(err) => {
                let error_code = err.error_code().to_string();
                let reason_code = err.reason_code().to_string();
                let sub = SignerSubmission {
                    request_id: request_id.clone(),
                    status: "failed".to_string(),
                    response: None,
                    response_sig: None,
                    error_code: Some(error_code.clone()),
                    reason_code: Some(reason_code.clone()),
                    wallet: None,
                };
                (
                    sub,
                    StepOutcome::Rejected {
                        request_id: request_id.clone(),
                        error_code,
                        reason_code,
                    },
                )
            }
        };

        // 3. Post submission to POST /internal/results
        let results_url = format!(
            "{}/internal/results",
            self.config.api_url.trim_end_matches('/')
        );
        let sub_json = serde_json::to_vec(&submission)?;

        let res_resp = self.client.post_json(
            &results_url,
            Some(&token),
            &sub_json,
            self.config.request_timeout,
        )?;

        if res_resp.status == 401 || res_resp.status == 403 {
            return Err(WorkerError::Unauthorized(
                res_resp.status,
                String::from_utf8_lossy(&res_resp.body).into_owned(),
            ));
        }

        if res_resp.status != 200 {
            return Err(WorkerError::Http(format!(
                "POST /internal/results returned status {}: {}",
                res_resp.status,
                String::from_utf8_lossy(&res_resp.body)
            )));
        }

        Ok(outcome)
    }

    /// Runs the polling worker loop until `shutdown_signal` is set to `true`.
    pub fn run(&self, shutdown_signal: Arc<AtomicBool>) -> Result<(), WorkerError> {
        while !shutdown_signal.load(Ordering::Relaxed) {
            match self.step() {
                Ok(StepOutcome::Processed(req_id)) => {
                    eprintln!("signer: processed and signed request '{req_id}'");
                    // Immediately check queue for next pending request
                }
                Ok(StepOutcome::Rejected {
                    request_id,
                    error_code,
                    reason_code,
                }) => {
                    eprintln!(
                        "signer: rejected request '{request_id}' with {error_code} ({reason_code})"
                    );
                    // Immediately check queue for next pending request
                }
                Ok(StepOutcome::Idle) => {
                    thread::sleep(self.config.poll_interval);
                }
                Err(err) => {
                    eprintln!("signer worker error: {err}");
                    thread::sleep(self.config.error_retry_delay);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use crate::backend::{Curve, Scheme, SigningLocation, Spec, WalletRef};
    use crate::envelope::auth::{
        sign_ed25519_authorization, PinnedKey, PolicyAlg, Profile, SignerConfig,
    };
    use crate::envelope::jcs::{to_canonical_json_bytes, RequestBody, RequestType};
    use crate::envelope::processor::{InMemorySignerStore, SignerIdentity};
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    /// Mock HTTP client for isolated worker testing.
    struct MockHttpClient {
        claim_responses: Mutex<Vec<HttpResponse>>,
        posted_results: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockHttpClient {
        fn new(claim_responses: Vec<HttpResponse>) -> Self {
            Self {
                claim_responses: Mutex::new(claim_responses),
                posted_results: Mutex::new(Vec::new()),
            }
        }

        fn get_posted_results(&self) -> Vec<(String, Vec<u8>)> {
            self.posted_results.lock().unwrap().clone()
        }
    }

    impl HttpClient for MockHttpClient {
        fn post_json(
            &self,
            url: &str,
            _bearer_token: Option<&str>,
            body: &[u8],
            _timeout: Duration,
        ) -> Result<HttpResponse, WorkerError> {
            if url.ends_with("/internal/claim") {
                let mut claims = self.claim_responses.lock().unwrap();
                if claims.is_empty() {
                    return Ok(HttpResponse {
                        status: 204,
                        status_text: "No Content".to_string(),
                        headers: HashMap::new(),
                        body: Vec::new(),
                    });
                }
                return Ok(claims.remove(0));
            }

            if url.ends_with("/internal/results") {
                self.posted_results
                    .lock()
                    .unwrap()
                    .push((url.to_string(), body.to_vec()));
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

    /// Minimal test backend simulating wallet creation and derivation.
    #[derive(Clone)]
    struct DummyBackend {
        caps: Capabilities,
    }

    impl DummyBackend {
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

    impl crate::backend::Backend for DummyBackend {
        fn capabilities(&self) -> Result<Capabilities, crate::backend::BackendError> {
            Ok(self.caps.clone())
        }

        fn create_wallet(
            &self,
            _spec: &Spec,
            _aad: &[u8],
        ) -> Result<Vec<u8>, crate::backend::BackendError> {
            Ok(vec![0x42; 92])
        }

        fn public_key(
            &self,
            _w: &WalletRef,
            _path: &[u32],
        ) -> Result<Vec<u8>, crate::backend::BackendError> {
            Ok(vec![0x02; 33])
        }

        fn sign(
            &self,
            _w: &WalletRef,
            _path: &[u32],
            _input: crate::backend::SigningInput,
        ) -> Result<crate::backend::Signature, crate::backend::BackendError> {
            Ok(crate::backend::Signature::new_ecdsa(
                [0x11; 32],
                [0x22; 32],
                0,
                None,
                vec![0x02; 33],
                true,
            ))
        }
    }

    #[test]
    fn test_parse_http_url() {
        let (host, port, path) = parse_http_url("http://api:8081/internal/claim").unwrap();
        assert_eq!(host, "api");
        assert_eq!(port, 8081);
        assert_eq!(path, "/internal/claim");

        let (host, port, path) = parse_http_url("http://127.0.0.1:9000/").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9000);
        assert_eq!(path, "/");

        let (host, port, path) = parse_http_url("http://localhost/path").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");

        assert!(parse_http_url("https://secure.example.com").is_err());
    }

    #[test]
    fn test_parse_http_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        let res = parse_http_response(raw).unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.status_text, "OK");
        assert_eq!(res.body, br#"{"status":"ok"}"#);
    }

    #[test]
    fn test_parse_http_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let res = parse_http_response(raw).unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"Wikipedia");
    }

    #[test]
    fn test_worker_idle_claim() {
        let mut config = WorkerConfig::default();
        config.bearer_token = Some("test-signer-token".to_string());

        let pe_signing_key = Ed25519SigningKey::from_bytes(&[0xaa; 32]);
        let pe_pubkey_hex = hex::encode(pe_signing_key.verifying_key().to_bytes());
        let signer_cfg = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-dev-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pe_pubkey_hex,
                not_before: None,
                not_after: None,
            }],
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
        };

        let backend = Arc::new(DummyBackend::new());
        let store = Arc::new(InMemorySignerStore::new());
        let identity = SignerIdentity::generate();
        let processor = Arc::new(EnvelopeProcessor::new(signer_cfg, backend, store, identity));

        let mock_client = Arc::new(MockHttpClient::new(vec![HttpResponse {
            status: 204,
            status_text: "No Content".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }]));

        let worker = Worker::with_client(config, processor, mock_client.clone());
        let outcome = worker.step().unwrap();
        assert_eq!(outcome, StepOutcome::Idle);
        assert_eq!(mock_client.get_posted_results().len(), 0);
    }

    #[test]
    fn test_worker_claim_process_and_submit_completed() {
        let mut config = WorkerConfig::default();
        config.bearer_token = Some("test-signer-token".to_string());

        let pe_signing_key = Ed25519SigningKey::from_bytes(&[0xaa; 32]);
        let pe_pubkey_hex = hex::encode(pe_signing_key.verifying_key().to_bytes());
        let signer_cfg = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-dev-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pe_pubkey_hex,
                not_before: None,
                not_after: None,
            }],
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
        };

        let backend = Arc::new(DummyBackend::new());
        let store = Arc::new(InMemorySignerStore::new());
        let identity = SignerIdentity::generate();
        let processor = Arc::new(EnvelopeProcessor::new(signer_cfg, backend, store, identity));

        // Create a valid create_wallet request body
        let req_id = "3fa85f64-5717-4562-b3fc-2c963f66afa6".to_string();
        let req_body = RequestBody {
            v: 1,
            request_id: req_id.clone(),
            decision_id: "dec-1001".to_string(),
            audience: "signer-local-1".to_string(),
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            nonce: "nonce-abc-123".to_string(),
            request_type: RequestType::CreateWallet,
            scheme: Scheme::Bip32,
            curve: Curve::Secp256k1,
            wallet_id: "w_test_01".to_string(),
            path: None,
            input_paths: None,
            payload: None,
            payload_encoding: None,
            chain: None,
            seed_version: None,
            kek_label: None,
        };

        let canonical_bytes = to_canonical_json_bytes(&req_body).unwrap();
        let auth_raw = sign_ed25519_authorization(&pe_signing_key, "pe-dev-1", &canonical_bytes);
        let auth_json = serde_json::to_value(&auth_raw).unwrap();

        let claimed_work = ClaimedWork {
            request_id: req_id.clone(),
            body_canonical: String::from_utf8(canonical_bytes).unwrap(),
            authorization: auth_json,
            label: Some("Test Label".to_string()),
            wallet: None,
        };

        let claim_resp = HttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: serde_json::to_vec(&claimed_work).unwrap(),
        };

        let mock_client = Arc::new(MockHttpClient::new(vec![claim_resp]));
        let worker = Worker::with_client(config, processor, mock_client.clone());

        let outcome = worker.step().unwrap();
        assert_eq!(outcome, StepOutcome::Processed(req_id.clone()));

        let posted = mock_client.get_posted_results();
        assert_eq!(posted.len(), 1);
        let (url, body) = &posted[0];
        assert!(url.ends_with("/internal/results"));

        let submission: SignerSubmission = serde_json::from_slice(body).unwrap();
        assert_eq!(submission.request_id, req_id);
        assert_eq!(submission.status, "completed");
        assert!(submission.response.is_some());
        assert!(submission.response_sig.is_some());
        assert!(submission.wallet.is_some());
    }

    #[test]
    fn test_worker_claim_process_and_submit_rejected() {
        let mut config = WorkerConfig::default();
        config.bearer_token = Some("test-signer-token".to_string());

        let pe_signing_key = Ed25519SigningKey::from_bytes(&[0xaa; 32]);
        let pe_pubkey_hex = hex::encode(pe_signing_key.verifying_key().to_bytes());
        let signer_cfg = SignerConfig {
            signer_id: "signer-local-1".to_string(),
            policy_engine_keys: vec![PinnedKey {
                kid: "pe-dev-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: pe_pubkey_hex,
                not_before: None,
                not_after: None,
            }],
            max_lifetime_seconds: 600,
            clock_skew_seconds: 30,
            profile: Profile::Dev,
            allow_digest_signing: Some(true),
        };

        let backend = Arc::new(DummyBackend::new());
        let store = Arc::new(InMemorySignerStore::new());
        let identity = SignerIdentity::generate();
        let processor = Arc::new(EnvelopeProcessor::new(signer_cfg, backend, store, identity));

        // Create a request with audience mismatch
        let req_id = "3fa85f64-5717-4562-b3fc-2c963f66afa6".to_string();
        let req_body = RequestBody {
            v: 1,
            request_id: req_id.clone(),
            decision_id: "dec-1002".to_string(),
            audience: "wrong-audience-node".to_string(),
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            nonce: "nonce-xyz-456".to_string(),
            request_type: RequestType::CreateWallet,
            scheme: Scheme::Bip32,
            curve: Curve::Secp256k1,
            wallet_id: "w_test_02".to_string(),
            path: None,
            input_paths: None,
            payload: None,
            payload_encoding: None,
            chain: None,
            seed_version: None,
            kek_label: None,
        };

        let canonical_bytes = to_canonical_json_bytes(&req_body).unwrap();
        let auth_raw = sign_ed25519_authorization(&pe_signing_key, "pe-dev-1", &canonical_bytes);
        let auth_json = serde_json::to_value(&auth_raw).unwrap();

        let claimed_work = ClaimedWork {
            request_id: req_id.clone(),
            body_canonical: String::from_utf8(canonical_bytes).unwrap(),
            authorization: auth_json,
            label: None,
            wallet: None,
        };

        let claim_resp = HttpResponse {
            status: 200,
            status_text: "OK".to_string(),
            headers: HashMap::new(),
            body: serde_json::to_vec(&claimed_work).unwrap(),
        };

        let mock_client = Arc::new(MockHttpClient::new(vec![claim_resp]));
        let worker = Worker::with_client(config, processor, mock_client.clone());

        let outcome = worker.step().unwrap();
        assert_eq!(
            outcome,
            StepOutcome::Rejected {
                request_id: req_id.clone(),
                error_code: "signer_rejected".to_string(),
                reason_code: "audience_mismatch".to_string(),
            }
        );

        let posted = mock_client.get_posted_results();
        assert_eq!(posted.len(), 1);
        let (url, body) = &posted[0];
        assert!(url.ends_with("/internal/results"));

        let submission: SignerSubmission = serde_json::from_slice(body).unwrap();
        assert_eq!(submission.request_id, req_id);
        assert_eq!(submission.status, "failed");
        assert_eq!(submission.error_code.as_deref(), Some("signer_rejected"));
        assert_eq!(submission.reason_code.as_deref(), Some("audience_mismatch"));
        assert!(submission.response.is_none());
    }
}

