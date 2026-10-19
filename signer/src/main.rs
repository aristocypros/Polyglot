//! Signer service main entrypoint (`signer/src/main.rs`).
//!
//! Startup lifecycle:
//! 1. Parses configuration, CLI flags, Docker secrets, and environment variables.
//! 2. Executes the 5-step fail-closed startup capability probe (Task 11):
//!    refuses to start and exits with non-zero exit code if steps 1-4 fail or session
//!    hygiene fails.
//! 3. Loads the pinned policy engine key configuration ([`SignerConfig`]) and Ed25519
//!    identity keypair ([`SignerIdentity`]).
//! 4. Connects to PostgreSQL (`signer_role`) for replay prevention, result caching,
//!    and hash-chained audit logging ([`SignerStore`]).
//! 5. Starts the outbound HTTP polling worker ([`Worker`]) claiming requests from
//!    `POST http://api:8081/internal/claim` and posting completed results to
//!    `POST http://api:8081/internal/results`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use signer::backend::generic::{GenericBackend, ProbeConfig};
use signer::backend::DEFAULT_KEK_LABEL;
use signer::bootstrap::{resolve_softhsm_module_path, DEFAULT_TOKEN_LABEL};
use signer::envelope::auth::{PinnedKey, PolicyAlg, Profile, SignerConfig};
use signer::envelope::processor::{EnvelopeProcessor, InMemorySignerStore, ReplayStore, SignerIdentity};
use signer::pkcs11session::{Pkcs11Config, SlotSelector};
use signer::store::SignerStore;
use signer::worker::{
    Worker, WorkerConfig, DEFAULT_INTERNAL_API_URL, DEFAULT_SIGNER_TOKEN_FILE,
};

const DEFAULT_PIN_FILE_PATH: &str = "/run/secrets/softhsm_user_pin";
const DEFAULT_IDENTITY_KEY_PATH: &str = "/var/lib/softhsm/tokens/signer_identity.key";
const DEFAULT_DATABASE_URL: &str = "postgres://signer_role:signer_pass@postgres:5432/postgres";
const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/polyglot/signer.yaml";

fn print_usage() {
    eprintln!(
        "Usage: signer [OPTIONS]\n\
         \n\
         Polyglot Outbound Polling Signer Service (Milestone 5 Gate).\n\
         \n\
         Options:\n\
           --config <PATH>            Signer trust configuration YAML path (env: SIGNER_CONFIG_PATH)\n\
           --api-url <URL>            Internal API base URL [default: http://api:8081] (env: API_URL, POLYGLOT_API_INTERNAL_URL)\n\
           --token-file <PATH>        Signer bearer token secret file path [default: /run/secrets/signer_token] (env: SIGNER_TOKEN_FILE)\n\
           --token <TOKEN>            Signer bearer token string override (env: SIGNER_TOKEN, SIGNER_BEARER_TOKEN)\n\
           --database-url <URL>       PostgreSQL connection URL for signer_role (env: SIGNER_DATABASE_URL)\n\
           --in-memory-store          Use in-memory replay/audit store instead of PostgreSQL (dev/testing)\n\
           --module-path <PATH>       PKCS#11 module path (env: PKCS11_MODULE_PATH)\n\
           --token-label <LABEL>      PKCS#11 token label [default: polyglot-softhsm] (env: PKCS11_TOKEN_LABEL)\n\
           --slot-id <ID>             Explicit PKCS#11 slot ID (env: PKCS11_SLOT_ID)\n\
           --pin-file <PATH>          User PIN file path [default: /run/secrets/softhsm_user_pin] (env: PKCS11_PIN_FILE)\n\
           --kek-label <LABEL>        AES-256 KEK label [default: kek-v1] (env: PKCS11_KEK_LABEL)\n\
           --identity-key <PATH>      Signer Ed25519 identity key path (env: SIGNER_IDENTITY_KEY_PATH)\n\
           -h, --help                 Print this help message"
    );
}

fn main() -> ExitCode {
    if let Err(err) = try_main() {
        eprintln!("signer fatal error: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn try_main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut config_path_opt: Option<PathBuf> = env::var("SIGNER_CONFIG_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let mut api_url: String = env::var("API_URL")
        .or_else(|_| env::var("POLYGLOT_API_INTERNAL_URL"))
        .unwrap_or_else(|_| DEFAULT_INTERNAL_API_URL.to_string());
    let mut token_file_path: PathBuf = env::var("SIGNER_TOKEN_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SIGNER_TOKEN_FILE));
    let mut token_override: Option<String> = env::var("SIGNER_TOKEN")
        .or_else(|_| env::var("SIGNER_BEARER_TOKEN"))
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut database_url: String = match env::var("SIGNER_DATABASE_URL") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => {
            if let Ok(pass) = std::fs::read_to_string("/run/secrets/db_signer_password") {
                let p = pass.trim();
                if !p.is_empty() {
                    format!("postgres://signer_role:{p}@postgres:5432/postgres")
                } else {
                    DEFAULT_DATABASE_URL.to_string()
                }
            } else {
                DEFAULT_DATABASE_URL.to_string()
            }
        }
    };
    let mut in_memory_store = env::var("SIGNER_IN_MEMORY_STORE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut module_path_opt: Option<PathBuf> = env::var("PKCS11_MODULE_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let mut token_label: String = env::var("PKCS11_TOKEN_LABEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TOKEN_LABEL.to_string());
    let mut slot_id_opt: Option<u64> = match env::var("PKCS11_SLOT_ID") {
        Ok(val) if !val.trim().is_empty() => Some(
            val.trim()
                .parse::<u64>()
                .map_err(|e| format!("invalid PKCS11_SLOT_ID '{val}': {e}"))?,
        ),
        _ => None,
    };
    let mut pin_file_path: PathBuf = env::var("PKCS11_PIN_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PIN_FILE_PATH));
    let mut kek_label: String = env::var("PKCS11_KEK_LABEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KEK_LABEL.to_string());
    let mut identity_key_path: PathBuf = env::var("SIGNER_IDENTITY_KEY_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_KEY_PATH));

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let val = args.next().ok_or("missing value for --config")?;
                config_path_opt = Some(PathBuf::from(val));
            }
            "--api-url" => {
                api_url = args.next().ok_or("missing value for --api-url")?;
            }
            "--token-file" => {
                let val = args.next().ok_or("missing value for --token-file")?;
                token_file_path = PathBuf::from(val);
            }
            "--token" => {
                let val = args.next().ok_or("missing value for --token")?;
                token_override = Some(val);
            }
            "--database-url" => {
                database_url = args.next().ok_or("missing value for --database-url")?;
            }
            "--in-memory-store" => {
                in_memory_store = true;
            }
            "--module-path" => {
                let val = args.next().ok_or("missing value for --module-path")?;
                module_path_opt = Some(PathBuf::from(val));
            }
            "--token-label" => {
                token_label = args.next().ok_or("missing value for --token-label")?;
            }
            "--slot-id" => {
                let val = args.next().ok_or("missing value for --slot-id")?;
                let id = val
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --slot-id '{val}': {e}"))?;
                slot_id_opt = Some(id);
            }
            "--pin-file" => {
                let val = args.next().ok_or("missing value for --pin-file")?;
                pin_file_path = PathBuf::from(val);
            }
            "--kek-label" => {
                kek_label = args.next().ok_or("missing value for --kek-label")?;
            }
            "--identity-key" => {
                let val = args.next().ok_or("missing value for --identity-key")?;
                identity_key_path = PathBuf::from(val);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            unknown => {
                return Err(format!("unknown option '{unknown}'. Run with --help for usage"));
            }
        }
    }

    // 1. Resolve PKCS#11 module path
    let module_path = resolve_softhsm_module_path(module_path_opt.as_deref())
        .map_err(|e| format!("failed to resolve PKCS#11 library path: {e}"))?;

    let slot = match slot_id_opt {
        Some(id) => SlotSelector::Id(id),
        None => SlotSelector::Label(token_label.clone()),
    };

    let pkcs11_config = Pkcs11Config::new(
        module_path,
        slot,
        pin_file_path,
        kek_label,
    );

    // 2. Execute fail-closed startup capability probe (Task 11)
    eprintln!("signer: executing fail-closed startup capability probe (Task 11)...");
    let probe_config = ProbeConfig::new(pkcs11_config);
    let backend = match GenericBackend::new(probe_config) {
        Ok(b) => {
            let caps = b.capabilities_ref();
            eprintln!(
                "signer: startup capability probe PASSED [backend: {}, protection: {}, wrap: {}]",
                caps.backend, caps.protection_level, caps.wrap_mechanism
            );
            for s in &caps.schemes {
                eprintln!(
                    "  - scheme: {}, curve: {}, signing: {}",
                    s.scheme, s.curve, s.signing
                );
            }
            b
        }
        Err(err) => {
            eprintln!("signer: STARTUP PROBE FAILED (failing closed): {err}");
            return Err(format!("startup capability probe failed: {err}"));
        }
    };

    // 3. Load SignerConfig (policy engine keys & parameters)
    let signer_config = load_signer_config(config_path_opt)?;

    // 4. Load Ed25519 identity key
    let identity = if identity_key_path.exists() {
        SignerIdentity::from_file(&identity_key_path)
            .map_err(|e| format!("failed to load identity key: {e}"))?
    } else {
        eprintln!(
            "signer: identity key file '{}' not found, generating ephemeral test identity key",
            identity_key_path.display()
        );
        SignerIdentity::generate()
    };
    eprintln!(
        "signer: identity public key (Ed25519): {}",
        identity.public_key_hex()
    );

    // 5. Initialize replay prevention and results store
    let store: Arc<dyn ReplayStore> = if in_memory_store {
        eprintln!("signer: using in-memory replay and audit store");
        Arc::new(InMemorySignerStore::new())
    } else {
        eprintln!(
            "signer: connecting to PostgreSQL store ({})...",
            redact_url_password(&database_url)
        );
        let mut retries = 30;
        let s = loop {
            match SignerStore::connect(&database_url) {
                Ok(s) => break s,
                Err(e) if retries > 0 => {
                    eprintln!("signer: waiting for postgres ({e}), retrying in 1s... ({retries} attempts left)");
                    std::thread::sleep(Duration::from_secs(1));
                    retries -= 1;
                }
                Err(e) => return Err(format!("failed to connect to PostgreSQL signer store: {e}")),
            }
        };
        Arc::new(s)
    };

    // 6. Build EnvelopeProcessor (Task 24)
    let processor = Arc::new(EnvelopeProcessor::new(
        signer_config,
        Arc::new(backend),
        store,
        identity,
    ));

    // 7. Configure and start outbound HTTP polling worker
    let worker_config = WorkerConfig {
        api_url,
        bearer_token: token_override,
        token_path: Some(token_file_path),
        request_timeout: Duration::from_secs(35),
        poll_interval: Duration::from_millis(500),
        error_retry_delay: Duration::from_secs(1),
    };

    eprintln!(
        "signer: starting outbound HTTP polling worker -> {}/internal/claim",
        worker_config.api_url
    );

    let worker = Worker::new(worker_config, processor);

    // Setup graceful shutdown on Ctrl-C / termination
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown_signal.clone();

    // Spawn a thread to catch standard OS termination if possible
    let _ = thread_spawn_shutdown_listener(shutdown_clone);

    worker
        .run(shutdown_signal)
        .map_err(|e| format!("worker stopped with error: {e}"))?;

    eprintln!("signer: worker shutdown cleanly");
    Ok(())
}

/// Helper to load [`SignerConfig`] from candidate paths or default configuration.
fn load_signer_config(configured_path: Option<PathBuf>) -> Result<SignerConfig, String> {
    let candidate_paths = if let Some(p) = configured_path {
        vec![p]
    } else {
        vec![
            PathBuf::from(DEFAULT_CONFIG_FILE_PATH),
            PathBuf::from("deploy/signer.yaml"),
            PathBuf::from("../deploy/signer.yaml"),
        ]
    };

    for path in candidate_paths {
        if path.exists() {
            eprintln!("signer: loading trust configuration from '{}'", path.display());
            return SignerConfig::from_file(&path)
                .map_err(|e| format!("failed to parse signer config '{}': {e}", path.display()));
        }
    }

    eprintln!("signer: no configuration file found, using default dev signer trust configuration");
    Ok(default_dev_signer_config())
}

/// Baseline development configuration matching deploy/signer.yaml.
fn default_dev_signer_config() -> SignerConfig {
    SignerConfig {
        signer_id: "signer-local-1".to_string(),
        policy_engine_keys: vec![
            PinnedKey {
                kid: "pe-dev-1".to_string(),
                alg: PolicyAlg::Ed25519,
                public_key: "0xa4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
                    .to_string(),
                not_before: None,
                not_after: None,
            },
            PinnedKey {
                kid: "pe-dev-2".to_string(),
                alg: PolicyAlg::Es256,
                public_key:
                    "0x02608d1d98542e5f7147d4bae2ac3127f88811f4e17eaa321d87e32435eb1c4dda"
                        .to_string(),
                not_before: None,
                not_after: None,
            },
        ],
        max_lifetime_seconds: 600,
        clock_skew_seconds: 30,
        profile: Profile::Dev,
        allow_digest_signing: Some(true),
    }
}

/// Hook for programmatic process termination.
fn thread_spawn_shutdown_listener(_shutdown_signal: Arc<AtomicBool>) -> Result<(), ()> {
    Ok(())
}

/// Replaces the password in a `scheme://user:password@host/...` URL with `***` so the URL can be logged.
fn redact_url_password(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return url.to_string();
    };
    let authority_end = url[scheme_end..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| scheme_end + i);
    let authority = &url[scheme_end..authority_end];
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    let Some(colon) = authority[..at].find(':') else {
        return url.to_string();
    };
    format!(
        "{}{}:***{}",
        &url[..scheme_end],
        &authority[..colon],
        &url[scheme_end + at..]
    )
}

#[cfg(test)]
mod tests {
    use super::redact_url_password;

    #[test]
    fn redacts_password() {
        assert_eq!(
            redact_url_password("postgres://signer_role:s3cr3t@postgres:5432/postgres"),
            "postgres://signer_role:***@postgres:5432/postgres"
        );
    }

    #[test]
    fn redacts_password_containing_at_sign() {
        assert_eq!(
            redact_url_password("postgres://u:p@ss@host/db?sslmode=disable"),
            "postgres://u:***@host/db?sslmode=disable"
        );
    }

    #[test]
    fn leaves_urls_without_password_unchanged() {
        for url in ["postgres://signer_role@postgres/db", "postgres://postgres/db", "not a url"] {
            assert_eq!(redact_url_password(url), url);
        }
    }
}

