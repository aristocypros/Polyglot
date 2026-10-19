//! JCS cross-check CLI tool used by Python verification scripts and test harnesses.
//!
//! Supports batch canonicalization and body verification via stdin or direct vector files.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer::envelope::jcs::{
    decode_base64url, encode_base64url, to_canonical_json_string, verify_request_body_bytes,
};
use std::io::{self, Read};

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum ActionRequest {
    /// Canonicalize arbitrary JSON value according to RFC 8785.
    Canonicalize {
        id: String,
        value: serde_json::Value,
    },
    /// Verify whether raw JSON bytes represent a strictly canonical request body.
    VerifyBody {
        id: String,
        raw_bytes_utf8: String,
    },
    /// Decode base64url and verify envelope body.
    VerifyEnvelopeBody {
        id: String,
        body_b64url: String,
    },
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_b64url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input_str = String::new();
    io::stdin().read_to_string(&mut input_str)?;

    if input_str.trim().is_empty() {
        eprintln!("jcs_crosscheck: empty input on stdin. Pass JSON array of actions.");
        std::process::exit(1);
    }

    let actions: Vec<ActionRequest> = serde_json::from_str(&input_str)?;
    let mut responses: Vec<ActionResponse> = Vec::with_capacity(actions.len());

    for action in actions {
        match action {
            ActionRequest::Canonicalize { id, value } => {
                match to_canonical_json_string(&value) {
                    Ok(canonical) => {
                        let mut hasher = Sha256::new();
                        hasher.update(canonical.as_bytes());
                        let sha = hex::encode(hasher.finalize());
                        let b64 = encode_base64url(canonical.as_bytes());
                        responses.push(ActionResponse {
                            id,
                            canonical: Some(canonical),
                            body_b64url: Some(b64),
                            sha256: Some(sha),
                            valid: true,
                            error: None,
                            reason_code: None,
                        });
                    }
                    Err(e) => {
                        responses.push(ActionResponse {
                            id,
                            canonical: None,
                            body_b64url: None,
                            sha256: None,
                            valid: false,
                            error: Some(e.to_string()),
                            reason_code: Some(e.reason_code().to_string()),
                        });
                    }
                }
            }
            ActionRequest::VerifyBody { id, raw_bytes_utf8 } => {
                match verify_request_body_bytes(raw_bytes_utf8.as_bytes()) {
                    Ok((_body, canonical_bytes)) => {
                        let canonical = String::from_utf8(canonical_bytes)?;
                        let mut hasher = Sha256::new();
                        hasher.update(canonical.as_bytes());
                        let sha = hex::encode(hasher.finalize());
                        let b64 = encode_base64url(canonical.as_bytes());
                        responses.push(ActionResponse {
                            id,
                            canonical: Some(canonical),
                            body_b64url: Some(b64),
                            sha256: Some(sha),
                            valid: true,
                            error: None,
                            reason_code: None,
                        });
                    }
                    Err(e) => {
                        responses.push(ActionResponse {
                            id,
                            canonical: None,
                            body_b64url: None,
                            sha256: None,
                            valid: false,
                            error: Some(e.to_string()),
                            reason_code: Some(e.reason_code().to_string()),
                        });
                    }
                }
            }
            ActionRequest::VerifyEnvelopeBody { id, body_b64url } => {
                match decode_base64url(&body_b64url) {
                    Ok(raw_bytes) => {
                        match verify_request_body_bytes(&raw_bytes) {
                            Ok((_body, canonical_bytes)) => {
                                let canonical = String::from_utf8(canonical_bytes)?;
                                let mut hasher = Sha256::new();
                                hasher.update(canonical.as_bytes());
                                let sha = hex::encode(hasher.finalize());
                                responses.push(ActionResponse {
                                    id,
                                    canonical: Some(canonical),
                                    body_b64url: Some(body_b64url),
                                    sha256: Some(sha),
                                    valid: true,
                                    error: None,
                                    reason_code: None,
                                });
                            }
                            Err(e) => {
                                responses.push(ActionResponse {
                                    id,
                                    canonical: None,
                                    body_b64url: Some(body_b64url),
                                    sha256: None,
                                    valid: false,
                                    error: Some(e.to_string()),
                                    reason_code: Some(e.reason_code().to_string()),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        responses.push(ActionResponse {
                            id,
                            canonical: None,
                            body_b64url: Some(body_b64url),
                            sha256: None,
                            valid: false,
                            error: Some(e.to_string()),
                            reason_code: Some(e.reason_code().to_string()),
                        });
                    }
                }
            }
        }
    }

    let out_json = serde_json::to_string(&responses)?;
    println!("{}", out_json);
    Ok(())
}
