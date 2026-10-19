//! Integration tests validating RFC 8785 JCS canonicalization and envelope verification against `vectors/jcs.json`.

use serde::Deserialize;
use sha2::Digest;
use signer::envelope::jcs::{
    encode_base64url, to_canonical_json_string, verify_envelope_json, verify_request_body_bytes,
    Envelope,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct JcsFile {
    standard_vectors: Vec<StandardVector>,
    polyglot_bodies: Vec<PolyglotBodyVector>,
    rejection_vectors: Vec<RejectionVector>,
}

#[derive(Debug, Deserialize)]
struct StandardVector {
    id: String,
    input: serde_json::Value,
    canonical: String,
}

#[derive(Debug, Deserialize)]
struct PolyglotBodyVector {
    id: String,
    input: serde_json::Value,
    canonical: String,
    body_b64url: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct RejectionVector {
    id: String,
    raw_bytes_utf8: String,
    expected_error: String,
}

fn get_vectors_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().unwrap().join("vectors").join("jcs.json")
}

#[test]
fn test_standard_jcs_vectors_from_file() {
    let path = get_vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let file: JcsFile = serde_json::from_str(&content).expect("parse jcs.json");

    for vec in file.standard_vectors {
        let canonical = to_canonical_json_string(&vec.input).expect("canonicalize");
        assert_eq!(
            canonical, vec.canonical,
            "mismatch on standard vector {}",
            vec.id
        );
    }
}

#[test]
fn test_polyglot_request_bodies_from_file() {
    let path = get_vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let file: JcsFile = serde_json::from_str(&content).expect("parse jcs.json");

    for vec in file.polyglot_bodies {
        // 1. Canonicalize input value
        let canonical_str = to_canonical_json_string(&vec.input).expect("canonicalize");
        assert_eq!(canonical_str, vec.canonical, "canonical string mismatch for {}", vec.id);

        // 2. Verify base64url encoding
        let b64 = encode_base64url(canonical_str.as_bytes());
        assert_eq!(b64, vec.body_b64url, "base64url mismatch for {}", vec.id);

        // 3. Verify SHA-256 hash
        let hash = hex::encode(sha2::Sha256::digest(canonical_str.as_bytes()));
        assert_eq!(hash, vec.sha256, "sha256 mismatch for {}", vec.id);

        // 4. Verify request body bytes via strict verify_request_body_bytes
        let (body, verified_bytes) = verify_request_body_bytes(canonical_str.as_bytes())
            .unwrap_or_else(|e| panic!("failed to verify request body {}: {e:?}", vec.id));
        assert_eq!(verified_bytes, canonical_str.as_bytes());
        assert_eq!(body.v, 1);

        // 5. Test Envelope wrap and verify
        let env = Envelope {
            body: vec.body_b64url.clone(),
            authorization: serde_json::json!({
                "kid": "pe-dev-1",
                "alg": "ed25519"
            }),
        };
        let (env_body, env_bytes) = env.verify_canonical_body()
            .unwrap_or_else(|e| panic!("envelope verify failed for {}: {e:?}", vec.id));
        assert_eq!(env_body, body);
        assert_eq!(env_bytes, verified_bytes);

        // 6. Test full JSON envelope string verification
        let env_json = serde_json::to_string(&env).expect("serialize envelope");
        let (_parsed_env, parsed_body, _parsed_bytes) = verify_envelope_json(&env_json)
            .expect("verify envelope json");
        assert_eq!(parsed_body, body);
    }
}

#[test]
fn test_rejection_vectors_from_file() {
    let path = get_vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let file: JcsFile = serde_json::from_str(&content).expect("parse jcs.json");

    for vec in file.rejection_vectors {
        let res = verify_request_body_bytes(vec.raw_bytes_utf8.as_bytes());
        assert!(res.is_err(), "expected rejection for {}, got ok", vec.id);
        let err = res.unwrap_err();
        assert_eq!(
            err.reason_code(),
            vec.expected_error,
            "reason code mismatch for {}",
            vec.id
        );
    }
}
