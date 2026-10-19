//! `bootstrap` binary / subcommand for initializing the SoftHSMv2 token, creating the
//! non-extractable 256-bit AES KEK (`"kek-v1"`), generating the signer's Ed25519 identity
//! keypair, and running the 5-step fail-closed startup capability probe.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use signer::backend::DEFAULT_KEK_LABEL;
use signer::bootstrap::{
    resolve_softhsm_module_path, run_bootstrap, BootstrapConfig, DEFAULT_TOKEN_LABEL,
};

const DEFAULT_PIN_FILE_PATH: &str = "/run/secrets/softhsm_user_pin";
const DEFAULT_IDENTITY_KEY_PATH: &str = "/var/lib/softhsm/tokens/signer_identity.key";

fn print_usage() {
    eprintln!(
        "Usage: bootstrap [OPTIONS]\n\
         \n\
         Initializes the SoftHSMv2 token, creates the non-extractable 256-bit AES KEK ('kek-v1'),\n\
         generates the signer's Ed25519 identity keypair, and runs the 5-step startup probe.\n\
         \n\
         Options:\n\
           --module-path <PATH>       PKCS#11 shared library path (env: PKCS11_MODULE_PATH)\n\
           --token-label <LABEL>      PKCS#11 token label [default: polyglot-softhsm] (env: PKCS11_TOKEN_LABEL)\n\
           --slot-id <ID>             Optional explicit PKCS#11 slot ID (env: PKCS11_SLOT_ID)\n\
           --pin-file <PATH>          User PIN secret file path [default: /run/secrets/softhsm_user_pin] (env: PKCS11_PIN_FILE)\n\
           --so-pin-file <PATH>       Optional SO PIN file path (defaults to --pin-file) (env: PKCS11_SO_PIN_FILE)\n\
           --kek-label <LABEL>        AES-256 KEK label [default: kek-v1] (env: PKCS11_KEK_LABEL)\n\
           --identity-key <PATH>      Signer Ed25519 identity private key path (env: SIGNER_IDENTITY_KEY_PATH)\n\
           --identity-pubkey <PATH>   Signer Ed25519 identity public key path (env: SIGNER_IDENTITY_PUBKEY_PATH)\n\
           -h, --help                 Print this help message"
    );
}

fn main() -> ExitCode {
    if let Err(err) = try_main() {
        eprintln!("bootstrap error: {err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn try_main() -> Result<(), String> {
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
    let mut so_pin_file_opt: Option<PathBuf> = env::var("PKCS11_SO_PIN_FILE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let mut kek_label: String = env::var("PKCS11_KEK_LABEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_KEK_LABEL.to_string());
    let mut identity_key_path: PathBuf = env::var("SIGNER_IDENTITY_KEY_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_KEY_PATH));
    let mut identity_pubkey_opt: Option<PathBuf> = env::var("SIGNER_IDENTITY_PUBKEY_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);

    let mut args = env::args().skip(1).peekable();
    if matches!(args.peek().map(String::as_str), Some("bootstrap")) {
        args.next();
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "--module-path" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--module-path requires a value".to_string())?;
                module_path_opt = Some(PathBuf::from(v));
            }
            "--token-label" => {
                token_label = args
                    .next()
                    .ok_or_else(|| "--token-label requires a value".to_string())?;
            }
            "--slot-id" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--slot-id requires a value".to_string())?;
                slot_id_opt = Some(
                    v.parse::<u64>()
                        .map_err(|e| format!("invalid --slot-id '{v}': {e}"))?,
                );
            }
            "--pin-file" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--pin-file requires a value".to_string())?;
                pin_file_path = PathBuf::from(v);
            }
            "--so-pin-file" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--so-pin-file requires a value".to_string())?;
                so_pin_file_opt = Some(PathBuf::from(v));
            }
            "--kek-label" => {
                kek_label = args
                    .next()
                    .ok_or_else(|| "--kek-label requires a value".to_string())?;
            }
            "--identity-key" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--identity-key requires a value".to_string())?;
                identity_key_path = PathBuf::from(v);
            }
            "--identity-pubkey" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--identity-pubkey requires a value".to_string())?;
                identity_pubkey_opt = Some(PathBuf::from(v));
            }
            other => {
                return Err(format!("unknown argument '{other}' (use --help for usage)"));
            }
        }
    }

    let module_path = resolve_softhsm_module_path(module_path_opt.as_deref())
        .map_err(|e| e.to_string())?;

    let mut cfg = BootstrapConfig::with_pin_file(
        module_path,
        token_label,
        pin_file_path,
        kek_label,
        identity_key_path,
    );
    cfg.slot_id = slot_id_opt;
    cfg.so_pin_path = so_pin_file_opt;
    if let Some(pub_path) = identity_pubkey_opt {
        cfg.identity_pubkey_path = Some(pub_path);
    }

    let report = run_bootstrap(cfg).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("failed to serialize bootstrap report: {e}"))?;
    println!("{json}");
    Ok(())
}
