//! Integration tests for Policy Engine Stand-In CLI Tool (`pe-sim`).
//!
//! Validates:
//! - Keypair generation via `pe-sim keygen` for both Ed25519 and ES256.
//! - Canonical request body signing via `pe-sim sign` producing envelopes.
//! - Cryptographic verification against Rust signer's `envelope::auth` module.
//! - Negative test cases: bad signature, wrong key ID, algorithm mismatch.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use signer::envelope::auth::{
    verify_envelope_and_auth, PinnedKey, PolicyAlg, Profile, SignerConfig,
};

struct TempDir(PathBuf);
impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pe-sim-{name}-{}-{}", std::process::id(), nanos));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pe_sim_bin() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rel_bin = manifest_dir.join("target").join("release").join("pe-sim");
    if rel_bin.exists() {
        return rel_bin;
    }
    let dbg_bin = manifest_dir.join("target").join("debug").join("pe-sim");
    if dbg_bin.exists() {
        return dbg_bin;
    }
    manifest_dir.join("pe-sim")
}

fn sample_create_wallet_body() -> Value {
    json!({
        "v": 1,
        "type": "create_wallet",
        "request_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "nonce": "0123456789abcdef0123456789abcdef",
        "audience": "signer-local-1",
        "expires_at": "2026-10-19T20:00:00Z",
        "decision_id": "dec-test-001",
        "wallet_id": "w_test_100",
        "scheme": "bip32",
        "curve": "secp256k1"
    })
}

fn sample_derive_public_body() -> Value {
    json!({
        "v": 1,
        "type": "derive_public",
        "request_id": "4fa85f64-5717-4562-b3fc-2c963f66afa7",
        "nonce": "fedcba9876543210fedcba9876543210",
        "audience": "signer-local-1",
        "expires_at": "2026-10-19T20:00:00Z",
        "decision_id": "dec-test-002",
        "wallet_id": "w_test_100",
        "scheme": "bip32",
        "curve": "secp256k1",
        "path": [2147483692u32, 2147483708u32, 2147483648u32, 0u32, 0u32]
    })
}

#[test]
fn test_cli_keygen_and_sign_both_algorithms_end_to_end() {
    let temp = TempDir::new("e2e");
    let secrets_dir = temp.path().join("secrets");
    let bin = pe_sim_bin();

    // 1. Generate Ed25519 key (pe-dev-1)
    let output1 = Command::new(&bin)
        .args([
            "keygen",
            "--alg",
            "ed25519",
            "--kid",
            "pe-dev-1",
            "--out",
            secrets_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run pe-sim keygen ed25519");
    assert!(output1.status.success(), "keygen ed25519 failed: {:?}", output1);

    let ed_yaml = fs::read_to_string(secrets_dir.join("pe-dev-1.yaml")).unwrap();
    assert!(ed_yaml.contains("kid: \"pe-dev-1\""));
    assert!(ed_yaml.contains("alg: \"ed25519\""));
    let ed_pub_hex = ed_yaml
        .lines()
        .find(|l| l.contains("public_key:"))
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap()
        .to_string();

    // 2. Generate ES256 key (pe-dev-2)
    let output2 = Command::new(&bin)
        .args([
            "keygen",
            "--alg",
            "es256",
            "--kid",
            "pe-dev-2",
            "--out",
            secrets_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run pe-sim keygen es256");
    assert!(output2.status.success(), "keygen es256 failed: {:?}", output2);

    let es_yaml = fs::read_to_string(secrets_dir.join("pe-dev-2.yaml")).unwrap();
    assert!(es_yaml.contains("kid: \"pe-dev-2\""));
    assert!(es_yaml.contains("alg: \"ES256\""));
    let es_pub_hex = es_yaml
        .lines()
        .find(|l| l.contains("public_key:"))
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap()
        .to_string();

    // 3. Configure signer trust with both pinned keys
    let mut signer_config = SignerConfig::new("signer-local-1", Profile::Dev);
    signer_config.policy_engine_keys = vec![
        PinnedKey {
            kid: "pe-dev-1".to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: ed_pub_hex.clone(),
            not_before: None,
            not_after: None,
        },
        PinnedKey {
            kid: "pe-dev-2".to_string(),
            alg: PolicyAlg::Es256,
            public_key: es_pub_hex.clone(),
            not_before: None,
            not_after: None,
        },
    ];

    // 4. Test Ed25519 sign and verify
    let body1_path = temp.path().join("body1.json");
    fs::write(&body1_path, serde_json::to_string_pretty(&sample_create_wallet_body()).unwrap()).unwrap();

    let env1_path = temp.path().join("env1.json");
    let sign1 = Command::new(&bin)
        .args([
            "sign",
            "--key",
            secrets_dir.join("pe-dev-1.key").to_str().unwrap(),
            "--kid",
            "pe-dev-1",
            "--alg",
            "ed25519",
            "--in",
            body1_path.to_str().unwrap(),
            "--out",
            env1_path.to_str().unwrap(),
        ])
        .output()
        .expect("run pe-sim sign ed25519");
    assert!(sign1.status.success(), "sign ed25519 failed: {:?}", sign1);

    let env1_json = fs::read_to_string(&env1_path).unwrap();
    let (body1, _, key1) = verify_envelope_and_auth(&signer_config, &env1_json, None)
        .expect("signer auth verification for ed25519 envelope failed");
    assert_eq!(body1.request_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6");
    assert_eq!(key1.kid, "pe-dev-1");
    assert_eq!(key1.alg, PolicyAlg::Ed25519);

    // 5. Test ES256 sign and verify
    let body2_path = temp.path().join("body2.json");
    fs::write(&body2_path, serde_json::to_string_pretty(&sample_derive_public_body()).unwrap()).unwrap();

    let env2_path = temp.path().join("env2.json");
    let sign2 = Command::new(&bin)
        .args([
            "sign",
            "--key",
            secrets_dir.join("pe-dev-2.key").to_str().unwrap(),
            "--kid",
            "pe-dev-2",
            "--alg",
            "es256",
            "--in",
            body2_path.to_str().unwrap(),
            "--out",
            env2_path.to_str().unwrap(),
        ])
        .output()
        .expect("run pe-sim sign es256");
    assert!(sign2.status.success(), "sign es256 failed: {:?}", sign2);

    let env2_json = fs::read_to_string(&env2_path).unwrap();
    let (body2, _, key2) = verify_envelope_and_auth(&signer_config, &env2_json, None)
        .expect("signer auth verification for ES256 envelope failed");
    assert_eq!(body2.request_id, "4fa85f64-5717-4562-b3fc-2c963f66afa7");
    assert_eq!(key2.kid, "pe-dev-2");
    assert_eq!(key2.alg, PolicyAlg::Es256);

    // 6. Adversarial checks on generated envelopes:
    // Case 6a: Corrupted signature
    let mut tampered_env: Value = serde_json::from_str(&env1_json).unwrap();
    tampered_env["authorization"]["sig"] = json!("AAAAAA_corrupted_signature_bytes_here_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let err = verify_envelope_and_auth(&signer_config, &tampered_env.to_string(), None).unwrap_err();
    assert_eq!(err.reason_code(), "bad_signature");

    // Case 6b: Unknown kid
    let mut unknown_kid_env: Value = serde_json::from_str(&env1_json).unwrap();
    unknown_kid_env["authorization"]["kid"] = json!("unpinned-kid-999");
    let err = verify_envelope_and_auth(&signer_config, &unknown_kid_env.to_string(), None).unwrap_err();
    assert_eq!(err.reason_code(), "unknown_kid");

    // Case 6c: Alg mismatch (wire declared ES256 for an Ed25519 key)
    let mut alg_mismatch_env: Value = serde_json::from_str(&env1_json).unwrap();
    alg_mismatch_env["authorization"]["alg"] = json!("ES256");
    let err = verify_envelope_and_auth(&signer_config, &alg_mismatch_env.to_string(), None).unwrap_err();
    assert_eq!(err.reason_code(), "alg_mismatch");
}
