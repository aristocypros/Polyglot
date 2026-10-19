//! Policy Engine Stand-In CLI Tool (`pe-sim`).
//!
//! A development stand-in for the client's policy engine supporting:
//! - `pe-sim keygen --alg ed25519|es256 --kid <id> --out <dir>`
//!   Generates development keypairs on the host and outputs the public key block ready for `signer.yaml`.
//! - `pe-sim sign --key <private_key_file> --kid <id> --alg ed25519|es256 --in <body.json>`
//!   Canonicalizes request bodies according to RFC 8785 (JCS), base64url-encodes the canonical bytes,
//!   produces authorization signatures (Ed25519 or ES256 detached JWS), and outputs the complete
//!   `{ "body": "...", "authorization": { ... } }` envelope ready for `POST /v1/requests`.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use ed25519_dalek::pkcs8::spki::EncodePublicKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey as P256EncodePrivateKey, LineEnding};
use serde_json::Value;

use signer::envelope::{
    encode_base64url, sign_ed25519_authorization, sign_es256_authorization,
    to_canonical_json_bytes, RawAuthorization,
};

pub mod demo;

const DEFAULT_NOT_BEFORE: &str = "2026-01-01T00:00:00Z";
const DEFAULT_NOT_AFTER: &str = "2027-01-01T00:00:00Z";

fn print_usage() {
    eprintln!(
        r#"Policy Engine Stand-In Tool (pe-sim)

USAGE:
    pe-sim <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    keygen    Generate a development policy engine keypair and output signer.yaml config
    sign      Canonicalize a request body (RFC 8785 JCS) and sign it into an envelope
    demo      Run the end-to-end demo suite across all 5 chains
    help      Print this help message

SUBCOMMAND OPTIONS:
    keygen:
        --alg <ed25519|es256>   Algorithm to generate (required)
        --kid <id>              Key ID, e.g. pe-dev-1 or pe-dev-2 (required)
        --out <dir>             Directory to save keypair files (required)
        --not-before <rfc3339>  Optional not-before timestamp (default: {DEFAULT_NOT_BEFORE})
        --not-after <rfc3339>   Optional not-after expiration timestamp (default: {DEFAULT_NOT_AFTER})

    sign:
        --key <path>            Path to private key file (.key) (required)
        --kid <id>              Key ID matching the pinned key (required)
        --alg <ed25519|es256>   Algorithm used to sign (required)
        --in <path>             Path to input request body JSON file or '-' for stdin (required)
        --out <path>            Optional output file path (default: stdout)
        --label <string>        Optional label to attach to the envelope

EXAMPLES:
    # 1. Generate Ed25519 and ES256 development keypairs
    pe-sim keygen --alg ed25519 --kid pe-dev-1 --out ./secrets
    pe-sim keygen --alg es256 --kid pe-dev-2 --out ./secrets

    # 2. Sign a request body using Ed25519
    pe-sim sign --key ./secrets/pe-dev-1.key --kid pe-dev-1 --alg ed25519 --in body.json

    # 3. Sign a request body using ES256 and post directly to API
    pe-sim sign --key ./secrets/pe-dev-2.key --kid pe-dev-2 --alg es256 --in body.json \
      | curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <key>" -d @- http://127.0.0.1:8080/v1/requests
"#
    );
}

fn parse_cli_flags(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut flags = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(flag) = arg.strip_prefix("--") {
            if let Some(pos) = flag.find('=') {
                let key = flag[..pos].to_string();
                let val = flag[pos + 1..].to_string();
                flags.insert(key, val);
                i += 1;
            } else if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                flags.insert(flag.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                flags.insert(flag.to_string(), "true".to_string());
                i += 1;
            }
        } else {
            return Err(format!("unexpected positional argument: '{arg}'"));
        }
    }
    Ok(flags)
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    let flags = parse_cli_flags(args)?;

    let alg_raw = flags
        .get("alg")
        .ok_or_else(|| "missing required flag: --alg <ed25519|es256>".to_string())?;
    let kid = flags
        .get("kid")
        .ok_or_else(|| "missing required flag: --kid <id>".to_string())?;
    let out_dir_str = flags
        .get("out")
        .ok_or_else(|| "missing required flag: --out <dir>".to_string())?;

    let not_before = flags
        .get("not-before")
        .cloned()
        .unwrap_or_else(|| DEFAULT_NOT_BEFORE.to_string());
    let not_after = flags
        .get("not-after")
        .cloned()
        .unwrap_or_else(|| DEFAULT_NOT_AFTER.to_string());

    let out_dir = PathBuf::from(out_dir_str);
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("failed to create output directory {}: {e}", out_dir.display()))?;

    let alg_lower = alg_raw.to_lowercase();

    let (alg_canonical, pub_hex, priv_pem, pub_pem) = match alg_lower.as_str() {
        "ed25519" => {
            let signing_key = Ed25519SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let priv_pem = signing_key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("failed to encode Ed25519 PKCS#8 private key: {e}"))?
                .to_string();
            let pub_pem = verifying_key
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| format!("failed to encode Ed25519 SPKI public key: {e}"))?;
            let pub_hex = format!("0x{}", hex::encode(verifying_key.to_bytes()));
            ("ed25519".to_string(), pub_hex, priv_pem, pub_pem)
        }
        "es256" => {
            let signing_key = P256SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let priv_pem = P256EncodePrivateKey::to_pkcs8_pem(
                &signing_key,
                LineEnding::LF,
            )
            .map_err(|e| format!("failed to encode ES256 PKCS#8 private key: {e}"))?
            .to_string();
            let pub_pem = verifying_key
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| format!("failed to encode ES256 SPKI public key: {e}"))?;
            // Compressed SEC1 hex representation (33 bytes: 0x02... or 0x03...)
            let pub_hex = format!(
                "0x{}",
                hex::encode(verifying_key.to_encoded_point(true).as_bytes())
            );
            ("ES256".to_string(), pub_hex, priv_pem, pub_pem)
        }
        other => {
            return Err(format!(
                "unsupported algorithm '{other}': expected 'ed25519' or 'es256'"
            ));
        }
    };

    // Write private key file (<out>/<kid>.key)
    let key_path = out_dir.join(format!("{kid}.key"));
    fs::write(&key_path, priv_pem)
        .map_err(|e| format!("failed to write private key to {}: {e}", key_path.display()))?;

    // Write public key PEM file (<out>/<kid>.pub)
    let pub_path = out_dir.join(format!("{kid}.pub"));
    fs::write(&pub_path, pub_pem)
        .map_err(|e| format!("failed to write public key to {}: {e}", pub_path.display()))?;

    // Build YAML snippet ready for signer.yaml
    let yaml_block = format!(
        "  - kid: \"{kid}\"\n    alg: \"{alg_canonical}\"\n    public_key: \"{pub_hex}\"\n    not_before: \"{not_before}\"\n    not_after: \"{not_after}\"\n"
    );

    let yaml_path = out_dir.join(format!("{kid}.yaml"));
    fs::write(&yaml_path, &yaml_block)
        .map_err(|e| format!("failed to write YAML snippet to {}: {e}", yaml_path.display()))?;

    // Output to stdout as required by specification
    print!("{yaml_block}");

    eprintln!(
        "[pe-sim] Successfully generated {alg_canonical} keypair for kid '{kid}':\n  Private key: {}\n  Public key:  {}\n  YAML block:  {}",
        key_path.display(),
        pub_path.display(),
        yaml_path.display()
    );

    Ok(())
}

fn load_ed25519_private_key(path: &Path) -> Result<Ed25519SigningKey, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read Ed25519 key file {}: {e}", path.display()))?;
    let clean = content.trim();

    // Try PKCS#8 PEM
    if clean.starts_with("-----BEGIN") {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        if let Ok(key) = Ed25519SigningKey::from_pkcs8_pem(clean) {
            return Ok(key);
        }
    }

    // Try hex (32-byte seed = 64 hex chars, or 64-byte keypair = 128 hex chars)
    let hex_clean = clean.strip_prefix("0x").unwrap_or(clean);
    if hex_clean.len() == 64 || hex_clean.len() == 128 {
        if let Ok(bytes) = hex::decode(hex_clean) {
            let seed: [u8; 32] = bytes[..32]
                .try_into()
                .map_err(|_| "invalid seed slice".to_string())?;
            return Ok(Ed25519SigningKey::from_bytes(&seed));
        }
    }

    // Try raw 32-byte binary
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() == 32 {
            let seed: [u8; 32] = bytes.as_slice().try_into().unwrap();
            return Ok(Ed25519SigningKey::from_bytes(&seed));
        }
    }

    Err(format!(
        "unrecognized Ed25519 private key in {}: expected PKCS#8 PEM or 32-byte hex",
        path.display()
    ))
}

fn load_es256_private_key(path: &Path) -> Result<P256SigningKey, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read ES256 key file {}: {e}", path.display()))?;
    let clean = content.trim();

    // Try PKCS#8 PEM
    if clean.starts_with("-----BEGIN") {
        use p256::pkcs8::DecodePrivateKey;
        if let Ok(key) = P256SigningKey::from_pkcs8_pem(clean) {
            return Ok(key);
        }
        // Try SEC1 PEM
        if let Ok(secret) = p256::SecretKey::from_sec1_pem(clean) {
            return Ok(P256SigningKey::from(secret));
        }
    }

    // Try hex (32-byte scalar = 64 hex chars)
    let hex_clean = clean.strip_prefix("0x").unwrap_or(clean);
    if hex_clean.len() == 64 {
        if let Ok(bytes) = hex::decode(hex_clean) {
            if let Ok(key) = P256SigningKey::from_slice(&bytes) {
                return Ok(key);
            }
        }
    }

    // Try raw 32-byte binary
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() == 32 {
            if let Ok(key) = P256SigningKey::from_slice(&bytes) {
                return Ok(key);
            }
        }
    }

    Err(format!(
        "unrecognized ES256 (P-256) private key in {}: expected PKCS#8 PEM, SEC1 PEM, or 32-byte hex",
        path.display()
    ))
}

fn read_input_payload(in_arg: &str) -> Result<String, String> {
    if in_arg == "-" {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("failed to read from stdin: {e}"))?;
        Ok(buffer)
    } else {
        fs::read_to_string(in_arg)
            .map_err(|e| format!("failed to read input file '{in_arg}': {e}"))
    }
}

fn run_sign(args: &[String]) -> Result<(), String> {
    let flags = parse_cli_flags(args)?;

    let key_path_str = flags
        .get("key")
        .ok_or_else(|| "missing required flag: --key <path>".to_string())?;
    let kid = flags
        .get("kid")
        .ok_or_else(|| "missing required flag: --kid <id>".to_string())?;
    let alg_raw = flags
        .get("alg")
        .ok_or_else(|| "missing required flag: --alg <ed25519|es256>".to_string())?;
    let in_arg = flags
        .get("in")
        .ok_or_else(|| "missing required flag: --in <body.json>".to_string())?;

    let out_file = flags.get("out");
    let explicit_label = flags.get("label").cloned();

    let input_raw = read_input_payload(in_arg)?;
    let parsed_json: Value = serde_json::from_str(&input_raw)
        .map_err(|e| format!("invalid JSON in input '{in_arg}': {e}"))?;

    // Determine the actual request body object to canonicalize and any attached label
    let mut attached_label = explicit_label;
    let body_value = if let Some(map) = parsed_json.as_object() {
        if map.contains_key("body") && !map.contains_key("v") {
            if attached_label.is_none() {
                attached_label = map.get("label").and_then(|v| v.as_str()).map(|s| s.to_string());
            }
            map.get("body").unwrap().clone()
        } else {
            parsed_json
        }
    } else {
        parsed_json
    };

    // Canonicalize request body according to RFC 8785 (JCS)
    let canonical_body_bytes = to_canonical_json_bytes(&body_value)
        .map_err(|e| format!("RFC 8785 JSON canonicalization error: {e}"))?;

    // Base64url-encode canonical body bytes
    let body_b64 = encode_base64url(&canonical_body_bytes);

    // Sign according to algorithm
    let alg_lower = alg_raw.to_lowercase();
    let auth: RawAuthorization = match alg_lower.as_str() {
        "ed25519" => {
            let key = load_ed25519_private_key(Path::new(key_path_str))?;
            sign_ed25519_authorization(&key, kid, &canonical_body_bytes)
        }
        "es256" => {
            let key = load_es256_private_key(Path::new(key_path_str))?;
            sign_es256_authorization(&key, kid, &canonical_body_bytes)
        }
        other => {
            return Err(format!(
                "unsupported algorithm '{other}': expected 'ed25519' or 'es256'"
            ));
        }
    };

    // Construct final envelope payload ready for POST /v1/requests:
    // { "body": "...", "authorization": { ... }, "label": "..." }
    let mut envelope_map = serde_json::Map::new();
    envelope_map.insert("body".to_string(), Value::String(body_b64));
    envelope_map.insert(
        "authorization".to_string(),
        serde_json::to_value(&auth)
            .map_err(|e| format!("failed to serialize authorization: {e}"))?,
    );
    if let Some(lbl) = attached_label {
        envelope_map.insert("label".to_string(), Value::String(lbl));
    }

    let envelope_json = serde_json::to_string_pretty(&Value::Object(envelope_map))
        .map_err(|e| format!("failed to format envelope JSON: {e}"))?;

    if let Some(out_path) = out_file {
        fs::write(out_path, &envelope_json)
            .map_err(|e| format!("failed to write output envelope to '{out_path}': {e}"))?;
        eprintln!("[pe-sim] Successfully wrote signed envelope to '{out_path}'");
    } else {
        println!("{envelope_json}");
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let subcommand = args[1].as_str();
    let sub_args = &args[2..];

    let result = match subcommand {
        "keygen" => run_keygen(sub_args),
        "sign" => run_sign(sub_args),
        "demo" => demo::run_demo(sub_args),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        unknown => {
            eprintln!("Error: unknown subcommand '{unknown}'\n");
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use signer::envelope::auth::{verify_envelope_and_auth, PinnedKey, PolicyAlg, Profile, SignerConfig};

    struct TempTestDir(PathBuf);
    impl TempTestDir {
        fn new() -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let ctr = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("pe-sim-test-{}-{}-{}", std::process::id(), nanos, ctr));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_body_json() -> Value {
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

    #[test]
    fn test_keygen_and_sign_ed25519_acceptance() {
        let dir = TempTestDir::new();
        let out_dir = dir.path().to_str().unwrap();

        // 1. Run keygen
        run_keygen(&[
            "--alg".into(),
            "ed25519".into(),
            "--kid".into(),
            "pe-dev-1".into(),
            "--out".into(),
            out_dir.into(),
        ])
        .unwrap();

        let key_file = dir.path().join("pe-dev-1.key");
        let pub_file = dir.path().join("pe-dev-1.pub");
        let yaml_file = dir.path().join("pe-dev-1.yaml");

        assert!(key_file.exists());
        assert!(pub_file.exists());
        assert!(yaml_file.exists());

        // Parse yaml snippet
        let yaml_content = fs::read_to_string(&yaml_file).unwrap();
        assert!(yaml_content.contains("kid: \"pe-dev-1\""));
        assert!(yaml_content.contains("alg: \"ed25519\""));
        assert!(yaml_content.contains("public_key: \"0x"));

        // Extract public key hex from yaml
        let pub_hex_line = yaml_content
            .lines()
            .find(|l| l.contains("public_key:"))
            .unwrap();
        let pub_hex = pub_hex_line
            .split('"')
            .nth(1)
            .unwrap()
            .to_string();

        // 2. Sign sample body
        let body_path = dir.path().join("body.json");
        fs::write(&body_path, serde_json::to_string(&sample_body_json()).unwrap()).unwrap();

        let env_path = dir.path().join("envelope.json");
        run_sign(&[
            "--key".into(),
            key_file.to_str().unwrap().into(),
            "--kid".into(),
            "pe-dev-1".into(),
            "--alg".into(),
            "ed25519".into(),
            "--in".into(),
            body_path.to_str().unwrap().into(),
            "--out".into(),
            env_path.to_str().unwrap().into(),
        ])
        .unwrap();

        let env_json = fs::read_to_string(&env_path).unwrap();

        // 3. Verify with Rust signer's envelope::auth
        let pinned_key = PinnedKey {
            kid: "pe-dev-1".to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: pub_hex,
            not_before: None,
            not_after: None,
        };

        let mut config = SignerConfig::new("signer-local-1", Profile::Dev);
        config.policy_engine_keys.push(pinned_key);

        let (verified_body, verified_bytes, verified_key) =
            verify_envelope_and_auth(&config, &env_json, None).unwrap();

        assert_eq!(verified_body.request_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6");
        assert_eq!(verified_key.kid, "pe-dev-1");
        assert_eq!(verified_key.alg, PolicyAlg::Ed25519);
        assert!(!verified_bytes.is_empty());
    }

    #[test]
    fn test_keygen_and_sign_es256_acceptance() {
        let dir = TempTestDir::new();
        let out_dir = dir.path().to_str().unwrap();

        // 1. Run keygen
        run_keygen(&[
            "--alg".into(),
            "es256".into(),
            "--kid".into(),
            "pe-dev-2".into(),
            "--out".into(),
            out_dir.into(),
        ])
        .unwrap();

        let key_file = dir.path().join("pe-dev-2.key");
        let pub_file = dir.path().join("pe-dev-2.pub");
        let yaml_file = dir.path().join("pe-dev-2.yaml");

        assert!(key_file.exists());
        assert!(pub_file.exists());
        assert!(yaml_file.exists());

        // Parse yaml snippet
        let yaml_content = fs::read_to_string(&yaml_file).unwrap();
        assert!(yaml_content.contains("kid: \"pe-dev-2\""));
        assert!(yaml_content.contains("alg: \"ES256\""));
        assert!(yaml_content.contains("public_key: \"0x"));

        // Extract public key hex from yaml
        let pub_hex_line = yaml_content
            .lines()
            .find(|l| l.contains("public_key:"))
            .unwrap();
        let pub_hex = pub_hex_line
            .split('"')
            .nth(1)
            .unwrap()
            .to_string();

        // 2. Sign sample body
        let body_path = dir.path().join("body.json");
        fs::write(&body_path, serde_json::to_string(&sample_body_json()).unwrap()).unwrap();

        let env_path = dir.path().join("envelope.json");
        run_sign(&[
            "--key".into(),
            key_file.to_str().unwrap().into(),
            "--kid".into(),
            "pe-dev-2".into(),
            "--alg".into(),
            "es256".into(),
            "--in".into(),
            body_path.to_str().unwrap().into(),
            "--out".into(),
            env_path.to_str().unwrap().into(),
        ])
        .unwrap();

        let env_json = fs::read_to_string(&env_path).unwrap();

        // 3. Verify with Rust signer's envelope::auth
        let pinned_key = PinnedKey {
            kid: "pe-dev-2".to_string(),
            alg: PolicyAlg::Es256,
            public_key: pub_hex,
            not_before: None,
            not_after: None,
        };

        let mut config = SignerConfig::new("signer-local-1", Profile::Dev);
        config.policy_engine_keys.push(pinned_key);

        let (verified_body, verified_bytes, verified_key) =
            verify_envelope_and_auth(&config, &env_json, None).unwrap();

        assert_eq!(verified_body.request_id, "3fa85f64-5717-4562-b3fc-2c963f66afa6");
        assert_eq!(verified_key.kid, "pe-dev-2");
        assert_eq!(verified_key.alg, PolicyAlg::Es256);
        assert!(!verified_bytes.is_empty());
    }

    #[test]
    fn test_sign_with_label_option() {
        let dir = TempTestDir::new();
        let out_dir = dir.path().to_str().unwrap();

        run_keygen(&[
            "--alg".into(),
            "ed25519".into(),
            "--kid".into(),
            "pe-dev-1".into(),
            "--out".into(),
            out_dir.into(),
        ])
        .unwrap();

        let key_file = dir.path().join("pe-dev-1.key");
        let body_path = dir.path().join("body.json");
        fs::write(&body_path, serde_json::to_string(&sample_body_json()).unwrap()).unwrap();

        let env_path = dir.path().join("envelope.json");
        run_sign(&[
            "--key".into(),
            key_file.to_str().unwrap().into(),
            "--kid".into(),
            "pe-dev-1".into(),
            "--alg".into(),
            "ed25519".into(),
            "--in".into(),
            body_path.to_str().unwrap().into(),
            "--out".into(),
            env_path.to_str().unwrap().into(),
            "--label".into(),
            "my-custom-wallet-label".into(),
        ])
        .unwrap();

        let env_json = fs::read_to_string(&env_path).unwrap();
        let val: Value = serde_json::from_str(&env_json).unwrap();
        assert_eq!(val["label"], "my-custom-wallet-label");
        assert!(val["body"].is_string());
        assert_eq!(val["authorization"]["kid"], "pe-dev-1");
    }
}
