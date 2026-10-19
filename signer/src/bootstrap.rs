//! SoftHSMv2 token initialization, AES-256 KEK (`"kek-v1"`) provisioning, and signer Ed25519
//! identity keypair generation (`signer/src/bootstrap.rs`).
//!
//! Implements the `bootstrap` component of Task 12 (Section 8 and Section 9 of `Specs.md`):
//! 1. Locates the PKCS#11 module (e.g. `/usr/lib/softhsm/libsofthsm2.so`) and initializes the
//!    SoftHSM token (`"polyglot-softhsm"`) if not already initialized.
//! 2. Creates the non-extractable 256-bit AES KEK (`"kek-v1"`) with `CKA_CLASS = CKO_SECRET_KEY`,
//!    `CKA_KEY_TYPE = CKK_AES`, `CKA_TOKEN = true`, `CKA_PRIVATE = true`, `CKA_SENSITIVE = true`,
//!    `CKA_EXTRACTABLE = false`, `CKA_ENCRYPT = true`, `CKA_DECRYPT = true`, and all other usage
//!    flags (`CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`) set to `false`.
//! 3. Generates the signer's 32-byte Ed25519 identity keypair using 32 random bytes from the HSM's
//!    `C_GenerateRandom`, persisting the private seed with `0600` file permissions and writing
//!    the hex-encoded 32-byte Ed25519 public key.
//! 4. Runs the 5-step fail-closed startup capability probe ([`run_startup_probe`]) to confirm the
//!    bootstrapped token is ready for the signer service.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::generic::{
    run_startup_probe, ProbeConfig, DEFAULT_GENERIC_BACKEND_NAME,
};
use crate::backend::{
    BackendError, Capabilities, ProtectionLevel, DEFAULT_KEK_LABEL,
};
use crate::pkcs11session::{
    load_pin_from_file, map_pkcs11_err, validate_kek_label, validate_pin_str, KekMetadata,
    Pkcs11Config, Pkcs11Library, Pkcs11Session, SlotSelector, AES_256_KEY_LEN, SELF_MODULE_PATH,
};

/// Default SoftHSMv2 token label created by `bootstrap`.
pub const DEFAULT_TOKEN_LABEL: &str = "polyglot-softhsm";

/// Candidate filesystem paths searched when locating `libsofthsm2` if not explicitly configured.
pub const CANDIDATE_SOFTHSM_PATHS: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.dylib",
];

/// Configuration for the `bootstrap` job / subcommand.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// Path to the PKCS#11 shared library (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
    pub module_path: PathBuf,
    /// Token label to initialize / locate (default: `"polyglot-softhsm"`).
    pub token_label: String,
    /// Optional explicit slot ID when targeting an already-initialized slot.
    pub slot_id: Option<u64>,
    /// Path to the user PIN secret file.
    pub user_pin_path: Option<PathBuf>,
    /// Pre-loaded user PIN in a zeroizing buffer (for unit/integration tests).
    user_pin: Option<Zeroizing<String>>,
    /// Optional path to the Security Officer (SO) PIN secret file (defaults to user PIN if omitted).
    pub so_pin_path: Option<PathBuf>,
    /// Pre-loaded SO PIN in a zeroizing buffer.
    so_pin: Option<Zeroizing<String>>,
    /// KEK label to create and verify on the token (default: `"kek-v1"`).
    pub kek_label: String,
    /// File path where the signer's 32-byte Ed25519 identity private key seed (hex) is written.
    pub identity_key_path: PathBuf,
    /// Optional file path where the signer's 32-byte Ed25519 identity public key (hex) is written.
    pub identity_pubkey_path: Option<PathBuf>,
    /// Backend identifier passed to the post-bootstrap capability probe (default: `"softhsm-generic"`).
    pub backend_name: String,
    /// Protection level passed to the post-bootstrap capability probe (default: `ProtectionLevel::GenericDev`).
    pub protection_level: ProtectionLevel,
}

impl std::fmt::Debug for BootstrapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapConfig")
            .field("module_path", &self.module_path)
            .field("token_label", &self.token_label)
            .field("slot_id", &self.slot_id)
            .field("user_pin_path", &self.user_pin_path)
            .field("user_pin", &self.user_pin.as_ref().map(|_| "<redacted>"))
            .field("so_pin_path", &self.so_pin_path)
            .field("so_pin", &self.so_pin.as_ref().map(|_| "<redacted>"))
            .field("kek_label", &self.kek_label)
            .field("identity_key_path", &self.identity_key_path)
            .field("identity_pubkey_path", &self.identity_pubkey_path)
            .field("backend_name", &self.backend_name)
            .field("protection_level", &self.protection_level)
            .finish()
    }
}

impl BootstrapConfig {
    /// Creates a new [`BootstrapConfig`] reading the user PIN from `user_pin_path`.
    pub fn with_pin_file(
        module_path: impl Into<PathBuf>,
        token_label: impl Into<String>,
        user_pin_path: impl Into<PathBuf>,
        kek_label: impl Into<String>,
        identity_key_path: impl Into<PathBuf>,
    ) -> Self {
        let id_path = identity_key_path.into();
        let pub_path = default_pubkey_companion_path(&id_path);
        Self {
            module_path: module_path.into(),
            token_label: token_label.into(),
            slot_id: None,
            user_pin_path: Some(user_pin_path.into()),
            user_pin: None,
            so_pin_path: None,
            so_pin: None,
            kek_label: kek_label.into(),
            identity_key_path: id_path,
            identity_pubkey_path: Some(pub_path),
            backend_name: DEFAULT_GENERIC_BACKEND_NAME.to_string(),
            protection_level: ProtectionLevel::GenericDev,
        }
    }

    /// Creates a [`BootstrapConfig`] with an in-memory [`Zeroizing<String>`] user PIN (for tests).
    pub fn with_loaded_pin(
        module_path: impl Into<PathBuf>,
        token_label: impl Into<String>,
        user_pin: Zeroizing<String>,
        kek_label: impl Into<String>,
        identity_key_path: impl Into<PathBuf>,
    ) -> Self {
        let id_path = identity_key_path.into();
        let pub_path = default_pubkey_companion_path(&id_path);
        Self {
            module_path: module_path.into(),
            token_label: token_label.into(),
            slot_id: None,
            user_pin_path: None,
            user_pin: Some(user_pin),
            so_pin_path: None,
            so_pin: None,
            kek_label: kek_label.into(),
            identity_key_path: id_path,
            identity_pubkey_path: Some(pub_path),
            backend_name: DEFAULT_GENERIC_BACKEND_NAME.to_string(),
            protection_level: ProtectionLevel::GenericDev,
        }
    }

    /// Resolves the user PIN into a [`Zeroizing<String>`].
    pub fn resolve_user_pin(&self) -> Result<Zeroizing<String>, BackendError> {
        if let Some(pin) = &self.user_pin {
            let trimmed = pin
                .as_str()
                .trim_matches(|c: char| c == '\r' || c == '\n' || c == ' ' || c == '\t');
            validate_pin_str(trimmed)?;
            return Ok(Zeroizing::new(trimmed.to_string()));
        }
        if let Some(path) = &self.user_pin_path {
            return load_pin_from_file(path);
        }
        Err(BackendError::Config(
            "bootstrap requires user_pin_path".to_string(),
        ))
    }

    /// Resolves the Security Officer (SO) PIN into a [`Zeroizing<String>`] (defaults to the user
    /// PIN if no separate SO PIN is configured).
    pub fn resolve_so_pin(&self) -> Result<Zeroizing<String>, BackendError> {
        if let Some(pin) = &self.so_pin {
            let trimmed = pin
                .as_str()
                .trim_matches(|c: char| c == '\r' || c == '\n' || c == ' ' || c == '\t');
            validate_pin_str(trimmed)?;
            return Ok(Zeroizing::new(trimmed.to_string()));
        }
        if let Some(path) = &self.so_pin_path {
            return load_pin_from_file(path);
        }
        self.resolve_user_pin()
    }
}

/// Summary report produced by a successful [`run_bootstrap`] execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapReport {
    /// Resolved PKCS#11 slot ID (`CK_SLOT_ID`).
    pub slot_id: u64,
    /// Token label (`"polyglot-softhsm"`).
    pub token_label: String,
    /// `true` if the token was initialized during this bootstrap run; `false` if already initialized.
    pub token_initialized_now: bool,
    /// Verified KEK label (`"kek-v1"`).
    pub kek_label: String,
    /// `true` if the KEK was generated during this bootstrap run; `false` if already present and valid.
    pub kek_created_now: bool,
    /// Hex-encoded 32-byte Ed25519 identity public key of the signer.
    pub identity_public_key_hex: String,
    /// `true` if the signer Ed25519 identity keypair was generated during this run; `false` if loaded.
    pub identity_key_created_now: bool,
    /// Capabilities returned by the post-bootstrap 5-step startup probe.
    pub capabilities: Capabilities,
}

fn default_pubkey_companion_path(priv_path: &Path) -> PathBuf {
    let mut os = priv_path.as_os_str().to_os_string();
    os.push(".pub");
    PathBuf::from(os)
}

/// Resolves the SoftHSMv2 PKCS#11 shared library path by checking `explicit_path` (if provided)
/// or searching [`CANDIDATE_SOFTHSM_PATHS`].
pub fn resolve_softhsm_module_path(explicit_path: Option<&Path>) -> Result<PathBuf, BackendError> {
    if let Some(p) = explicit_path {
        if p == Path::new(SELF_MODULE_PATH) || p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(BackendError::Config(format!(
            "configured PKCS#11 module '{}' does not exist",
            p.display()
        )));
    }

    for candidate in CANDIDATE_SOFTHSM_PATHS {
        let p = Path::new(candidate);
        if p.exists() {
            return Ok(p.to_path_buf());
        }
    }

    Err(BackendError::Config(format!(
        "could not locate libsofthsm2.so in any standard location ({})",
        CANDIDATE_SOFTHSM_PATHS.join(", ")
    )))
}

/// Executes the complete idempotent bootstrap workflow:
/// 1. Initializes the SoftHSM token (if not already initialized).
/// 2. Creates and verifies the non-extractable 256-bit AES KEK (`"kek-v1"`).
/// 3. Generates or loads the signer's 32-byte Ed25519 identity keypair.
/// 4. Executes the 5-step fail-closed startup capability probe and returns [`BootstrapReport`].
pub fn run_bootstrap(config: BootstrapConfig) -> Result<BootstrapReport, BackendError> {
    validate_kek_label(&config.kek_label)?;
    let trimmed_token_label = config.token_label.trim();
    if trimmed_token_label.is_empty() || trimmed_token_label.contains('\0') {
        return Err(BackendError::Config(
            "bootstrap token_label must be non-empty and contain no NUL bytes".to_string(),
        ));
    }

    let user_pin = config.resolve_user_pin()?;
    let so_pin = config.resolve_so_pin()?;

    // 1. Ensure the token is initialized.
    let token_initialized_now = ensure_token_initialized(
        &config.module_path,
        trimmed_token_label,
        config.slot_id,
        &so_pin,
        &user_pin,
    )?;

    // Open the PKCS#11 library against the initialized token.
    let slot_selector = match config.slot_id {
        Some(id) => SlotSelector::from_id_and_label(id, trimmed_token_label),
        None => SlotSelector::from_label(trimmed_token_label),
    };
    let pkcs11_config = Pkcs11Config::with_loaded_pin(
        &config.module_path,
        slot_selector,
        user_pin,
        &config.kek_label,
    );
    let library = Pkcs11Library::open(pkcs11_config.clone())?;

    // 2. Ensure the non-extractable 256-bit AES KEK (`kek-v1`) exists and passes verification.
    let (kek_meta, kek_created_now, identity_pubkey, identity_key_created_now) = {
        let session = library.open_rw_session()?;
        let (kek_meta, kek_created) = ensure_kek_created(&session, &config.kek_label)?;

        // 3. Ensure the signer's 32-byte Ed25519 identity keypair exists.
        let (id_pub, id_created) = ensure_identity_keypair(
            &session,
            &config.identity_key_path,
            config.identity_pubkey_path.as_deref(),
        )?;

        session.assert_no_session_objects()?;
        session.close();
        (kek_meta, kek_created, id_pub, id_created)
    };

    // 4. Execute the 5-step fail-closed startup capability probe.
    let probe_report = run_startup_probe(ProbeConfig::with_backend_and_protection(
        pkcs11_config,
        &config.backend_name,
        config.protection_level,
    ))?;

    Ok(BootstrapReport {
        slot_id: probe_report.library.slot().id(),
        token_label: probe_report.token_label,
        token_initialized_now,
        kek_label: kek_meta.label,
        kek_created_now,
        identity_public_key_hex: hex::encode(identity_pubkey),
        identity_key_created_now,
        capabilities: probe_report.capabilities,
    })
}

/// Ensures that a token with `token_label` (and optional `slot_id`) is initialized.
///
/// Returns `Ok(false)` if the token was already initialized, or `Ok(true)` if this call
/// initialized the token.
pub fn ensure_token_initialized(
    module_path: &Path,
    token_label: &str,
    slot_id: Option<u64>,
    so_pin: &Zeroizing<String>,
    user_pin: &Zeroizing<String>,
) -> Result<bool, BackendError> {
    let selector = match slot_id {
        Some(id) => SlotSelector::from_id_and_label(id, token_label),
        None => SlotSelector::from_label(token_label),
    };

    // Check if the token is already initialized via PKCS#11.
    let check_cfg = Pkcs11Config::with_loaded_pin(
        module_path,
        selector,
        Zeroizing::new(user_pin.as_str().to_string()),
        DEFAULT_KEK_LABEL,
    );
    if Pkcs11Library::open(check_cfg).is_ok() {
        return Ok(false);
    }

    // Attempt PKCS#11 C_InitToken + C_InitPIN directly on the first uninitialized slot with a token.
    if try_pkcs11_init_token(module_path, token_label, slot_id, so_pin, user_pin).is_ok() {
        return Ok(true);
    }

    // Fallback to `softhsm2-util --init-token --free` if available on PATH.
    let mut cmd = Command::new("softhsm2-util");
    cmd.arg("--init-token")
        .arg("--free")
        .arg("--label")
        .arg(token_label)
        .arg("--so-pin")
        .arg(so_pin.as_str())
        .arg("--pin")
        .arg(user_pin.as_str());

    let output = cmd.output().map_err(|err| {
        BackendError::Pkcs11(format!(
            "failed to initialize token '{token_label}' via PKCS#11 or softhsm2-util: {err}"
        ))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(BackendError::Pkcs11(format!(
            "softhsm2-util --init-token failed (status {}): {} {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }

    Ok(true)
}

fn try_pkcs11_init_token(
    module_path: &Path,
    token_label: &str,
    slot_id: Option<u64>,
    so_pin: &Zeroizing<String>,
    user_pin: &Zeroizing<String>,
) -> Result<Slot, BackendError> {
    let client = Pkcs11Library::load_client(module_path)?;

    let slots = client
        .get_slots_with_token()
        .map_err(|e| map_pkcs11_err("C_GetSlotList", e))?;

    let target_slot = if let Some(wanted_id) = slot_id {
        let s = Slot::try_from(wanted_id)
            .map_err(|e| BackendError::Config(format!("invalid slot_id {wanted_id}: {e}")))?;
        if !slots.contains(&s) {
            return Err(BackendError::Pkcs11(format!("slot {wanted_id} not found")));
        }
        s
    } else {
        // Pick the first uninitialized slot, or the first slot if none report initialized=false.
        let mut chosen = None;
        for &s in &slots {
            if let Ok(info) = client.get_token_info(s) {
                if !info.token_initialized() {
                    chosen = Some(s);
                    break;
                }
            }
        }
        chosen
            .or_else(|| slots.first().copied())
            .ok_or_else(|| BackendError::Pkcs11("no PKCS#11 slots with token present".to_string()))?
    };

    let mut so_pin_copy = so_pin.as_str().to_string();
    let so_auth = AuthPin::new(so_pin_copy.clone());
    so_pin_copy.zeroize();

    client
        .init_token(target_slot, &so_auth, token_label)
        .map_err(|e| map_pkcs11_err("C_InitToken", e))?;

    // SoftHSMv2 may assign a new slot ID when initializing a free slot; resolve the slot
    // whose token label matches `token_label`, falling back to `target_slot`.
    let post_init_slots = client
        .get_slots_with_token()
        .map_err(|e| map_pkcs11_err("C_GetSlotList (post-init)", e))?;
    let initialized_slot = post_init_slots
        .into_iter()
        .find(|&s| {
            client
                .get_token_info(s)
                .map(|info| info.label().trim() == token_label)
                .unwrap_or(false)
        })
        .unwrap_or(target_slot);

    let session = client
        .open_rw_session(initialized_slot)
        .map_err(|e| map_pkcs11_err("C_OpenSession (init_pin)", e))?;

    session
        .login(UserType::So, Some(&so_auth))
        .map_err(|e| map_pkcs11_err("C_Login (CKU_SO)", e))?;

    let mut user_pin_copy = user_pin.as_str().to_string();
    let user_auth = AuthPin::new(user_pin_copy.clone());
    user_pin_copy.zeroize();

    session
        .init_pin(&user_auth)
        .map_err(|e| map_pkcs11_err("C_InitPIN", e))?;

    let _ = session.logout();
    session.close();

    Ok(initialized_slot)
}

/// Ensures that a non-extractable 256-bit AES KEK with `kek_label` (`"kek-v1"`) exists on `session`
/// and passes all security attribute checks (`CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`,
/// encrypt/decrypt only).
///
/// Returns `(KekMetadata, created_now)`.
pub fn ensure_kek_created(
    session: &Pkcs11Session,
    kek_label: &str,
) -> Result<(KekMetadata, bool), BackendError> {
    validate_kek_label(kek_label)?;

    match session.verify_kek_by_label(kek_label) {
        Ok(existing) => return Ok((existing, false)),
        Err(BackendError::KekNotFound(_)) => {
            // Proceed to create the KEK below.
        }
        Err(other_err) => return Err(other_err),
    }

    let base_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Wrap(false),
        Attribute::Unwrap(false),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
        Attribute::Label(kek_label.as_bytes().to_vec()),
    ];

    let mut keygen_template = base_template.clone();
    keygen_template.push(Attribute::ValueLen((AES_256_KEY_LEN as u64).into()));

    // Try C_GenerateKey (CKM_AES_KEY_GEN) first; fall back to C_GenerateRandom + C_CreateObject
    // if the token does not implement C_GenerateKey (e.g. minimal mock PKCS#11 test provider).
    if session
        .raw()
        .generate_key(&Mechanism::AesKeyGen, &keygen_template)
        .is_err()
    {
        let random_key: Zeroizing<[u8; AES_256_KEY_LEN]> = session.generate_random_array()?;
        let mut create_template = base_template;
        let mut key_vec = Vec::with_capacity(AES_256_KEY_LEN);
        key_vec.extend_from_slice(&*random_key);
        create_template.push(Attribute::Value(key_vec));

        let create_res = session.raw().create_object(&create_template);
        for attr in create_template.iter_mut() {
            if let Attribute::Value(bytes) = attr {
                let cap = bytes.capacity();
                bytes.resize(cap, 0);
                bytes.zeroize();
            }
        }
        create_res.map_err(|err| map_pkcs11_err("C_CreateObject (AES-256 KEK)", err))?;
    }

    let verified = session.verify_kek_by_label(kek_label)?;
    Ok((verified, true))
}

/// Ensures that the signer's 32-byte Ed25519 identity keypair exists at `private_key_path`
/// (and writes the hex-encoded 32-byte public key to `public_key_path` if provided).
///
/// Returns `([u8; 32] public_key, created_now)`.
pub fn ensure_identity_keypair(
    session: &Pkcs11Session,
    private_key_path: &Path,
    public_key_path: Option<&Path>,
) -> Result<([u8; 32], bool), BackendError> {
    if private_key_path.as_os_str().is_empty() {
        return Err(BackendError::Config(
            "identity_key_path must not be empty".to_string(),
        ));
    }

    let (seed_bytes, created_now) = if private_key_path.exists() {
        let existing_seed = load_identity_private_seed(private_key_path)?;
        (existing_seed, false)
    } else {
        let generated_seed: Zeroizing<[u8; 32]> = session.generate_random_array()?;
        write_secret_hex_file(private_key_path, &*generated_seed)?;
        (generated_seed, true)
    };

    let signing_key = Ed25519SigningKey::from_bytes(&seed_bytes);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    drop(signing_key);
    drop(seed_bytes);

    if let Some(pub_path) = public_key_path {
        if let Some(parent) = pub_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    BackendError::Config(format!(
                        "failed to create directory '{}' for identity public key: {err}",
                        parent.display()
                    ))
                })?;
            }
        }
        let pub_hex = format!("{}\n", hex::encode(pubkey_bytes));
        fs::write(pub_path, pub_hex.as_bytes()).map_err(|err| {
            BackendError::Config(format!(
                "failed to write signer identity public key '{}': {err}",
                pub_path.display()
            ))
        })?;
    }

    Ok((pubkey_bytes, created_now))
}

/// Loads a 32-byte Ed25519 identity private seed from `path` (accepting either 64-character hex
/// or raw 32 bytes) into a [`Zeroizing<[u8; 32]>`] buffer.
pub fn load_identity_private_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, BackendError> {
    let mut file = File::open(path).map_err(|err| {
        BackendError::Config(format!(
            "failed to open signer identity key '{}': {err}",
            path.display()
        ))
    })?;

    let mut raw = Zeroizing::new(Vec::with_capacity(128));
    file.read_to_end(&mut raw).map_err(|err| {
        BackendError::Config(format!(
            "failed to read signer identity key '{}': {err}",
            path.display()
        ))
    })?;

    if raw.len() == 32 {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&raw);
        return Ok(out);
    }

    let utf8 = std::str::from_utf8(&raw).map_err(|_| {
        BackendError::Config(format!(
            "signer identity key '{}' is neither 32 raw bytes nor valid UTF-8 hex",
            path.display()
        ))
    })?;
    let trimmed = utf8.trim();
    let decoded = Zeroizing::new(hex::decode(trimmed).map_err(|err| {
        BackendError::Config(format!(
            "signer identity key '{}' contains invalid hex: {err}",
            path.display()
        ))
    })?);

    if decoded.len() != 32 {
        return Err(BackendError::Config(format!(
            "signer identity key '{}' decoded to {} bytes; expected 32 bytes",
            path.display(),
            decoded.len()
        )));
    }

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn write_secret_hex_file(path: &Path, secret: &[u8; 32]) -> Result<(), BackendError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                BackendError::Config(format!(
                    "failed to create parent directory '{}' for secret file: {err}",
                    parent.display()
                ))
            })?;
        }
    }

    let hex_line = Zeroizing::new(format!("{}\n", hex::encode(secret)));

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| {
                BackendError::Config(format!(
                    "failed to create secret file '{}': {err}",
                    path.display()
                ))
            })?
    };

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|err| {
            BackendError::Config(format!(
                "failed to create secret file '{}': {err}",
                path.display()
            ))
        })?;

    file.write_all(hex_line.as_bytes()).map_err(|err| {
        BackendError::Config(format!(
            "failed to write secret file '{}': {err}",
            path.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        BackendError::Config(format!(
            "failed to sync secret file '{}': {err}",
            path.display()
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs11session::tests::{mock_state, mock_test_lock, C_GetFunctionList, MOCK_SLOT_ID};
    use std::sync::atomic::{AtomicU64, Ordering};

    static BOOTSTRAP_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn temp_identity_path(label: &str) -> PathBuf {
        let id = BOOTSTRAP_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "polyglot_bootstrap_{label}_{}_{}.key",
            std::process::id(),
            id
        ))
    }

    #[test]
    fn test_bootstrap_creates_kek_and_identity_key_idempotently() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();
        // Start with no KEK on the token so bootstrap creates it
        mock_state().lock().unwrap().objects.clear();

        let _keep_sym = C_GetFunctionList as usize;
        let id_path = temp_identity_path("idempotent");
        let pub_path = default_pubkey_companion_path(&id_path);

        let mut cfg = BootstrapConfig::with_loaded_pin(
            SELF_MODULE_PATH,
            "polyglot-softhsm",
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
            &id_path,
        );
        cfg.slot_id = Some(MOCK_SLOT_ID as u64);

        // First bootstrap run: creates KEK and generates Ed25519 identity keypair
        let report1 = run_bootstrap(cfg.clone()).expect("first bootstrap run");
        assert!(!report1.token_initialized_now);
        assert!(report1.kek_created_now);
        assert!(report1.identity_key_created_now);
        assert_eq!(report1.kek_label, DEFAULT_KEK_LABEL);
        assert_eq!(report1.identity_public_key_hex.len(), 64);
        assert!(id_path.exists());
        assert!(pub_path.exists());

        // Second bootstrap run: idempotent (reuses existing KEK and identity keypair)
        let report2 = run_bootstrap(cfg).expect("second bootstrap run");
        assert!(!report2.kek_created_now);
        assert!(!report2.identity_key_created_now);
        assert_eq!(
            report1.identity_public_key_hex,
            report2.identity_public_key_hex
        );

        let _ = fs::remove_file(&id_path);
        let _ = fs::remove_file(&pub_path);
    }
}
