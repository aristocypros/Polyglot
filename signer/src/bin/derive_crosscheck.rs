//! Derivation cross-check CLI tool.
//!
//! Supports batch derivation over stdin (JSON or NDJSON) and command-line arguments.
//! Used by `dev/crosscheck_derive.py` and test harnesses.

use serde::{Deserialize, Serialize};
use signer::derive::{derive_bip32_str, derive_slip10_str, run_derivation_self_test};
use std::io::{self, BufRead, Read};

#[derive(Debug, Deserialize, Serialize)]
struct DerivationRequest {
    #[serde(default)]
    id: Option<u64>,
    scheme: String,
    seed: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DerivationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn handle_request(req: DerivationRequest) -> DerivationResponse {
    let seed_bytes = match hex::decode(&req.seed) {
        Ok(b) => b,
        Err(e) => {
            return DerivationResponse {
                id: req.id,
                public_key: None,
                private_key: None,
                error: Some(format!("invalid hex seed: {e}")),
            };
        }
    };

    match req.scheme.to_lowercase().as_str() {
        "bip32" | "secp256k1" => match derive_bip32_str(&seed_bytes, &req.path) {
            Ok(key) => DerivationResponse {
                id: req.id,
                public_key: Some(hex::encode(key.public_key())),
                private_key: Some(hex::encode(&**key.private_key())),
                error: None,
            },
            Err(e) => DerivationResponse {
                id: req.id,
                public_key: None,
                private_key: None,
                error: Some(format!("BIP32 derivation error: {e}")),
            },
        },
        "slip10" | "ed25519" => match derive_slip10_str(&seed_bytes, &req.path) {
            Ok(key) => DerivationResponse {
                id: req.id,
                public_key: Some(hex::encode(key.public_key())),
                private_key: Some(hex::encode(&**key.private_key())),
                error: None,
            },
            Err(e) => DerivationResponse {
                id: req.id,
                public_key: None,
                private_key: None,
                error: Some(format!("SLIP10 derivation error: {e}")),
            },
        },
        other => DerivationResponse {
            id: req.id,
            public_key: None,
            private_key: None,
            error: Some(format!("unknown derivation scheme: {other}")),
        },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--self-test") {
        match run_derivation_self_test() {
            Ok(()) => {
                println!("Derivation self-test passed.");
                return Ok(());
            }
            Err(err) => {
                eprintln!("Derivation self-test failed: {err}");
                std::process::exit(1);
            }
        }
    }

    // Single request via CLI arguments
    // e.g. --scheme bip32 --seed <hex> --path <path>
    if args.len() >= 7 {
        let mut scheme = String::new();
        let mut seed = String::new();
        let mut path = String::new();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--scheme" if i + 1 < args.len() => {
                    scheme = args[i + 1].clone();
                    i += 2;
                }
                "--seed" if i + 1 < args.len() => {
                    seed = args[i + 1].clone();
                    i += 2;
                }
                "--path" if i + 1 < args.len() => {
                    path = args[i + 1].clone();
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }

        if !scheme.is_empty() && !seed.is_empty() && !path.is_empty() {
            let resp = handle_request(DerivationRequest {
                id: None,
                scheme,
                seed,
                path,
            });
            println!("{}", serde_json::to_string(&resp)?);
            return Ok(());
        }
    }

    // Default: read from stdin (NDJSON or full JSON array)
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    // Check first non-whitespace character
    let mut first_line = String::new();
    if handle.read_line(&mut first_line)? == 0 {
        return Ok(());
    }

    let trimmed = first_line.trim();
    if trimmed.starts_with('[') {
        // Full JSON array mode
        let mut rest = String::new();
        handle.read_to_string(&mut rest)?;
        let full = format!("{first_line}{rest}");
        let requests: Vec<DerivationRequest> = serde_json::from_str(&full)?;
        let responses: Vec<DerivationResponse> =
            requests.into_iter().map(handle_request).collect();
        println!("{}", serde_json::to_string(&responses)?);
    } else if !trimmed.is_empty() {
        // Line-delimited JSON (NDJSON) mode
        let req: DerivationRequest = serde_json::from_str(trimmed)?;
        let resp = handle_request(req);
        println!("{}", serde_json::to_string(&resp)?);

        let mut line = String::new();
        while handle.read_line(&mut line)? > 0 {
            let t = line.trim();
            if !t.is_empty() {
                let req: DerivationRequest = serde_json::from_str(t)?;
                let resp = handle_request(req);
                println!("{}", serde_json::to_string(&resp)?);
            }
            line.clear();
        }
    }

    Ok(())
}
