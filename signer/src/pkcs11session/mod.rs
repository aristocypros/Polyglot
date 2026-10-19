//! PKCS#11 session management, library wrapper, PIN loading, and HSM RNG (`C_GenerateRandom`).
//!
//! Implements Task 07 of the generic PKCS#11 backend (Section 4 and Section 8 of `Specs.md`):
//! - [`Pkcs11Config`] and [`SlotSelector`] for module path, slot ID/label, user PIN file path,
//!   and KEK label (`"kek-v1"`).
//! - [`load_pin_from_file`] reading the user PIN from a Docker secret / file path into a trimmed
//!   [`Zeroizing<String>`] buffer (never from environment variables in production) and wiping raw
//!   intermediate bytes.
//! - [`Pkcs11Library`] managing the initialized `cryptoki::context::Pkcs11` instance and resolved
//!   token [`Slot`].
//! - [`Pkcs11Session`] implementing the one-session-per-request lifecycle (`open_rw_session`,
//!   automatic `CKU_USER` login when needed, tracked ephemeral session-object cleanup, and
//!   automatic `C_CloseSession` on drop).
//! - [`Pkcs11Session::generate_random`] and typed helpers (`generate_seed`, `generate_aes_gcm_iv`)
//!   backed by `C_GenerateRandom` writing directly into [`Zeroizing`] buffers.

pub mod sign;
pub mod wrap;

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, Function, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use cryptoki::session::{Session, SessionInfo, SessionState, UserType};
use cryptoki::slot::{Slot, SlotInfo, TokenInfo};
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{
    BackendError, Curve, AAD_DELIMITER, AES_GCM_IV_LEN, DEFAULT_KEK_LABEL, WALLET_SEED_LEN,
};

pub use sign::{
    assert_no_session_objects, count_session_objects, find_session_objects,
    import_ed25519_session_key, import_ed25519_session_key_with_format,
    import_secp256k1_session_key, import_session_key, sign_ed25519_message_in_hsm,
    sign_secp256k1_digest_in_hsm, verify_session_key_attributes, Ed25519EcParamsFormat,
    Ed25519ValueFormat, SessionKeyGuard, DER_OCTET_STRING_32_PREFIX, ECDSA_RAW_SIGNATURE_LEN,
    ED25519_CURVE_NAME_DER, ED25519_OID_DER, ED25519_SIGNATURE_LEN, SECP256K1_DIGEST_LEN,
    SECP256K1_OID_DER,
};
pub use wrap::{
    find_and_validate_kek, find_and_validate_kek_by_label, find_kek, find_kek_by_label,
    parse_wrapped_seed, unwrap_seed, unwrap_seed_with_kek_label, validate_kek_label,
    verify_kek_attributes, wrap_seed, wrap_seed_with_kek_label, KekMetadata, WrappedSeedBlob,
    AES_256_KEY_LEN, AES_GCM_CIPHERTEXT_AND_TAG_LEN, AES_GCM_TAG_BITS,
};

/// Upper bound on a single `generate_random` request (64 KiB) to guard against accidental
/// unbounded allocations while easily accommodating 64-byte seeds and 12-byte AES-GCM IVs.
pub const MAX_RANDOM_BYTES: usize = 65_536;

/// Special in-process module path identifier used by unit and integration tests to bind `Pkcs11::new_from_self()`.
pub const SELF_MODULE_PATH: &str = ":self:";

/// Global registry of initialized [`Pkcs11`] library contexts keyed by module path.
///
/// In PKCS#11 (`cryptoki`), `C_Initialize` and `C_Finalize` are process-global per loaded module.
/// Caching the `Pkcs11` context per module path prevents `Drop` on an earlier `Pkcs11Library`
/// instance from calling `C_Finalize` while another instance or test in the same process is active,
/// and avoids redundant `C_Initialize` calls.
fn pkcs11_registry() -> &'static Mutex<HashMap<PathBuf, Pkcs11>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl From<CryptokiError> for BackendError {
    fn from(err: CryptokiError) -> Self {
        BackendError::Pkcs11(err.to_string())
    }
}

/// Maps a [`CryptokiError`] with contextual operation details into a [`BackendError::Pkcs11`].
pub fn map_pkcs11_err(context: &str, err: CryptokiError) -> BackendError {
    BackendError::Pkcs11(format!("{context}: {err}"))
}

/// Specifies how to select the target PKCS#11 token slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotSelector {
    /// Select slot by its numeric PKCS#11 slot ID (`CK_SLOT_ID`).
    Id(u64),
    /// Select slot by matching `CK_TOKEN_INFO.label` (trimmed of trailing spaces).
    Label(String),
    /// Require both the numeric slot ID and the initialized token's label to match.
    IdAndLabel { id: u64, label: String },
}

impl SlotSelector {
    /// Creates a [`SlotSelector::Id`] for the given numeric slot ID.
    pub const fn from_id(id: u64) -> Self {
        Self::Id(id)
    }

    /// Creates a [`SlotSelector::Label`] for the given token label.
    pub fn from_label(label: impl Into<String>) -> Self {
        Self::Label(label.into())
    }

    /// Creates a [`SlotSelector::IdAndLabel`] requiring both slot ID and token label to match.
    pub fn from_id_and_label(id: u64, label: impl Into<String>) -> Self {
        Self::IdAndLabel {
            id,
            label: label.into(),
        }
    }

    /// Builds a [`SlotSelector`] from optional `slot_id` and `token_label` configuration fields.
    pub fn from_options(
        slot_id: Option<u64>,
        token_label: Option<String>,
    ) -> Result<Self, BackendError> {
        match (slot_id, token_label) {
            (Some(id), Some(label)) => {
                let selector = Self::IdAndLabel { id, label };
                selector.validate()?;
                Ok(selector)
            }
            (Some(id), None) => Ok(Self::Id(id)),
            (None, Some(label)) => {
                let selector = Self::Label(label);
                selector.validate()?;
                Ok(selector)
            }
            (None, None) => Err(BackendError::Config(
                "PKCS#11 slot configuration requires either slot_id or token_label".to_string(),
            )),
        }
    }

    /// Validates that any label in this [`SlotSelector`] is non-empty after trimming and
    /// does not contain NUL bytes.
    pub fn validate(&self) -> Result<(), BackendError> {
        match self {
            SlotSelector::Id(_) => Ok(()),
            SlotSelector::Label(label) | SlotSelector::IdAndLabel { label, .. } => {
                let trimmed = label.trim();
                if trimmed.is_empty() {
                    return Err(BackendError::Config(
                        "PKCS#11 token label must not be empty".to_string(),
                    ));
                }
                if label.contains('\0') {
                    return Err(BackendError::Config(
                        "PKCS#11 token label must not contain NUL bytes".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Validates an in-memory user PIN string (must be non-empty after trimming and contain no NUL bytes).
pub fn validate_pin_str(pin: &str) -> Result<(), BackendError> {
    if pin.is_empty() {
        return Err(BackendError::Config(
            "PKCS#11 user PIN must not be empty".to_string(),
        ));
    }
    if pin.contains('\0') {
        return Err(BackendError::Config(
            "PKCS#11 user PIN must not contain NUL bytes".to_string(),
        ));
    }
    Ok(())
}

/// Reads a PKCS#11 user PIN from a filesystem path (such as a Docker secret file),
/// trims leading and trailing ASCII whitespace (`\r`, `\n`, `' '`, `\t`), validates it,
/// and returns it inside a [`Zeroizing<String>`].
///
/// All intermediate raw byte buffers read from the file are wrapped in [`Zeroizing`]
/// so they are wiped on every return and error path.
pub fn load_pin_from_file(path: impl AsRef<Path>) -> Result<Zeroizing<String>, BackendError> {
    let path_ref = path.as_ref();
    if path_ref.as_os_str().is_empty() {
        return Err(BackendError::Config(
            "PKCS#11 user PIN file path must not be empty".to_string(),
        ));
    }

    let mut file = File::open(path_ref).map_err(|err| {
        BackendError::Config(format!(
            "failed to open PKCS#11 user PIN file '{}': {err}",
            path_ref.display()
        ))
    })?;

    let mut raw_bytes = Zeroizing::new(Vec::with_capacity(64));
    file.read_to_end(&mut raw_bytes).map_err(|err| {
        BackendError::Config(format!(
            "failed to read PKCS#11 user PIN file '{}': {err}",
            path_ref.display()
        ))
    })?;

    let raw_str = std::str::from_utf8(&raw_bytes).map_err(|_| {
        BackendError::Config(format!(
            "PKCS#11 user PIN file '{}' does not contain valid UTF-8",
            path_ref.display()
        ))
    })?;

    let trimmed = raw_str.trim_matches(|c: char| c == '\r' || c == '\n' || c == ' ' || c == '\t');
    if trimmed.is_empty() {
        return Err(BackendError::Config(format!(
            "PKCS#11 user PIN file '{}' is empty after trimming whitespace",
            path_ref.display()
        )));
    }
    validate_pin_str(trimmed)?;

    Ok(Zeroizing::new(trimmed.to_string()))
}

/// Configuration for loading a PKCS#11 module and opening authenticated sessions.
///
/// Per Section 8 and Section 9 of `Specs.md`, the user PIN is loaded from a secret file
/// (`user_pin_path`), trimmed, and held in [`Zeroizing<String>`] (never read from environment
/// variables in production).
#[derive(Clone, PartialEq, Eq)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 shared library (e.g., `/usr/lib/softhsm/libsofthsm2.so`).
    pub module_path: PathBuf,
    /// Target token slot selector (by slot ID, token label, or both).
    pub slot: SlotSelector,
    /// Path to the file containing the PKCS#11 user PIN (e.g., `/run/secrets/softhsm_user_pin`).
    pub user_pin_path: Option<PathBuf>,
    /// Pre-loaded user PIN stored in a zeroizing buffer (used when already loaded from file or in tests).
    user_pin: Option<Zeroizing<String>>,
    /// Label of the non-extractable AES-256 KEK on the token (default: `"kek-v1"`).
    pub kek_label: String,
}

impl fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("module_path", &self.module_path)
            .field("slot", &self.slot)
            .field("user_pin_path", &self.user_pin_path)
            .field(
                "user_pin",
                &self.user_pin.as_ref().map(|_| "<redacted>"),
            )
            .field("kek_label", &self.kek_label)
            .finish()
    }
}

impl Pkcs11Config {
    /// Creates a new [`Pkcs11Config`] that reads the user PIN from `user_pin_path`.
    pub fn new(
        module_path: impl Into<PathBuf>,
        slot: SlotSelector,
        user_pin_path: impl Into<PathBuf>,
        kek_label: impl Into<String>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            slot,
            user_pin_path: Some(user_pin_path.into()),
            user_pin: None,
            kek_label: kek_label.into(),
        }
    }

    /// Creates a new [`Pkcs11Config`] using [`DEFAULT_KEK_LABEL`] (`"kek-v1"`) and a PIN file path.
    pub fn with_pin_file(
        module_path: impl Into<PathBuf>,
        slot: SlotSelector,
        user_pin_path: impl Into<PathBuf>,
    ) -> Self {
        Self::new(module_path, slot, user_pin_path, DEFAULT_KEK_LABEL)
    }

    /// Creates a [`Pkcs11Config`] with an already-loaded [`Zeroizing<String>`] user PIN.
    pub fn with_loaded_pin(
        module_path: impl Into<PathBuf>,
        slot: SlotSelector,
        user_pin: Zeroizing<String>,
        kek_label: impl Into<String>,
    ) -> Self {
        Self {
            module_path: module_path.into(),
            slot,
            user_pin_path: None,
            user_pin: Some(user_pin),
            kek_label: kek_label.into(),
        }
    }

    /// Validates all configuration fields without opening the PKCS#11 library.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.module_path.as_os_str().is_empty() {
            return Err(BackendError::Config(
                "PKCS#11 module_path must not be empty".to_string(),
            ));
        }
        if self
            .module_path
            .to_string_lossy()
            .contains('\0')
        {
            return Err(BackendError::Config(
                "PKCS#11 module_path must not contain NUL bytes".to_string(),
            ));
        }

        self.slot.validate()?;

        if self.kek_label.is_empty() {
            return Err(BackendError::Config(
                "PKCS#11 kek_label must not be empty".to_string(),
            ));
        }
        if self.kek_label.contains(AAD_DELIMITER) || self.kek_label.contains('\0') {
            return Err(BackendError::Config(
                "PKCS#11 kek_label must not contain '|' or NUL bytes".to_string(),
            ));
        }

        match (&self.user_pin, &self.user_pin_path) {
            (Some(pin), _) => validate_pin_str(pin.as_str())?,
            (None, Some(path)) => {
                if path.as_os_str().is_empty() {
                    return Err(BackendError::Config(
                        "PKCS#11 user_pin_path must not be empty".to_string(),
                    ));
                }
            }
            (None, None) => {
                return Err(BackendError::Config(
                    "PKCS#11 configuration requires user_pin_path".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Resolves and returns the trimmed user PIN in a [`Zeroizing<String>`], reading it from
    /// `user_pin_path` if not already loaded in memory.
    pub fn resolve_user_pin(&self) -> Result<Zeroizing<String>, BackendError> {
        self.validate()?;
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
            "PKCS#11 user PIN is not configured".to_string(),
        ))
    }
}

struct Pkcs11LibraryInner {
    client: Pkcs11,
    module_path: PathBuf,
    slot: Slot,
    slot_selector: SlotSelector,
    user_pin: Zeroizing<String>,
    kek_label: String,
}

/// Thread-safe handle to an initialized PKCS#11 library and resolved token slot.
///
/// `Pkcs11Library` loads and initializes the PKCS#11 module once, resolves the target
/// token [`Slot`], holds the trimmed user PIN in a [`Zeroizing<String>`], and opens
/// fresh per-request [`Pkcs11Session`]s via [`Pkcs11Library::open_rw_session`].
#[derive(Clone)]
pub struct Pkcs11Library {
    inner: Arc<Pkcs11LibraryInner>,
}

impl fmt::Debug for Pkcs11Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Library")
            .field("module_path", &self.inner.module_path)
            .field("slot", &self.inner.slot)
            .field("slot_selector", &self.inner.slot_selector)
            .field("user_pin", &"<redacted>")
            .field("kek_label", &self.inner.kek_label)
            .finish()
    }
}

impl Pkcs11Library {
    /// Loads and initializes the PKCS#11 library specified by `config`, resolves the configured
    /// token slot, and stores the user PIN in a [`Zeroizing<String>`].
    pub fn open(config: Pkcs11Config) -> Result<Self, BackendError> {
        let user_pin = config.resolve_user_pin()?;
        let client = Self::load_and_init_client(&config.module_path)?;
        Self::from_initialized_client(client, config, user_pin)
    }

    /// Alias for [`Pkcs11Library::open`].
    pub fn new(config: Pkcs11Config) -> Result<Self, BackendError> {
        Self::open(config)
    }

    /// Constructs a [`Pkcs11Library`] from an existing [`Pkcs11`] context and [`Pkcs11Config`].
    ///
    /// If `client` is not yet initialized, calls `client.initialize(CInitializeArgs::OsThreads)`
    /// (tolerating `AlreadyInitialized` / `CryptokiAlreadyInitialized`).
    pub fn from_client(client: Pkcs11, config: Pkcs11Config) -> Result<Self, BackendError> {
        let user_pin = config.resolve_user_pin()?;
        Self::ensure_initialized(&client, &config.module_path)?;
        Self::from_initialized_client(client, config, user_pin)
    }

    fn from_initialized_client(
        client: Pkcs11,
        config: Pkcs11Config,
        user_pin: Zeroizing<String>,
    ) -> Result<Self, BackendError> {
        let slot = Self::resolve_slot(&client, &config.slot)?;
        Ok(Self {
            inner: Arc::new(Pkcs11LibraryInner {
                client,
                module_path: config.module_path,
                slot,
                slot_selector: config.slot,
                user_pin,
                kek_label: config.kek_label,
            }),
        })
    }

    /// Loads (or retrieves from the process-wide registry) and initializes a [`Pkcs11`] client
    /// for `module_path`.
    pub fn load_client(module_path: &Path) -> Result<Pkcs11, BackendError> {
        Self::load_and_init_client(module_path)
    }

    fn load_and_init_client(module_path: &Path) -> Result<Pkcs11, BackendError> {
        let mut guard = pkcs11_registry()
            .lock()
            .map_err(|_| BackendError::Pkcs11("PKCS#11 registry mutex poisoned".to_string()))?;

        let lookup_key = std::fs::canonicalize(module_path)
            .unwrap_or_else(|_| module_path.to_path_buf());

        if let Some(existing) = guard.get(&lookup_key) {
            Self::ensure_initialized(existing, module_path)?;
            return Ok(existing.clone());
        }

        let client = if module_path == Path::new(SELF_MODULE_PATH) {
            Pkcs11::new_from_self().map_err(|err| {
                BackendError::Pkcs11(format!(
                    "failed to load in-process PKCS#11 module '{}': {err}",
                    module_path.display()
                ))
            })?
        } else {
            Pkcs11::new(module_path).map_err(|err| {
                BackendError::Pkcs11(format!(
                    "failed to load PKCS#11 library '{}': {err}",
                    module_path.display()
                ))
            })?
        };

        Self::ensure_initialized(&client, module_path)?;
        guard.insert(lookup_key, client.clone());
        Ok(client)
    }

    fn ensure_initialized(client: &Pkcs11, module_path: &Path) -> Result<(), BackendError> {
        if client.is_initialized() {
            return Ok(());
        }
        match client.initialize(CInitializeArgs::OsThreads) {
            Ok(()) => Ok(()),
            Err(CryptokiError::AlreadyInitialized)
            | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => {
                Ok(())
            }
            Err(err) => Err(BackendError::Pkcs11(format!(
                "failed to initialize PKCS#11 module '{}': {err}",
                module_path.display()
            ))),
        }
    }

    /// Resolves a [`SlotSelector`] against the initialized slots of `client` and verifies that
    /// the selected slot has an initialized token present.
    pub fn resolve_slot(client: &Pkcs11, selector: &SlotSelector) -> Result<Slot, BackendError> {
        selector.validate()?;

        let initialized_slots = client
            .get_slots_with_initialized_token()
            .map_err(|err| map_pkcs11_err("C_GetSlotList (initialized tokens)", err))?;

        match selector {
            SlotSelector::Id(target_id) => {
                let target_slot = Slot::try_from(*target_id).map_err(|err| {
                    BackendError::Config(format!("invalid PKCS#11 slot ID {target_id}: {err}"))
                })?;

                if !initialized_slots.contains(&target_slot) {
                    return Err(BackendError::Pkcs11(format!(
                        "PKCS#11 slot {target_id} not found or token is not initialized"
                    )));
                }
                Ok(target_slot)
            }
            SlotSelector::Label(target_label) => {
                let wanted = target_label.trim();
                for slot in initialized_slots {
                    let info = client
                        .get_token_info(slot)
                        .map_err(|err| map_pkcs11_err("C_GetTokenInfo", err))?;
                    if info.label().trim() == wanted {
                        return Ok(slot);
                    }
                }
                Err(BackendError::Pkcs11(format!(
                    "PKCS#11 token with label '{wanted}' not found in any initialized slot"
                )))
            }
            SlotSelector::IdAndLabel { id, label } => {
                let target_slot = Slot::try_from(*id).map_err(|err| {
                    BackendError::Config(format!("invalid PKCS#11 slot ID {id}: {err}"))
                })?;

                if !initialized_slots.contains(&target_slot) {
                    return Err(BackendError::Pkcs11(format!(
                        "PKCS#11 slot {id} not found or token is not initialized"
                    )));
                }

                let info = client
                    .get_token_info(target_slot)
                    .map_err(|err| map_pkcs11_err("C_GetTokenInfo", err))?;
                let actual_label = info.label().trim();
                let wanted_label = label.trim();
                if actual_label != wanted_label {
                    return Err(BackendError::Pkcs11(format!(
                        "PKCS#11 slot {id} token label mismatch: expected '{wanted_label}', got '{actual_label}'"
                    )));
                }
                Ok(target_slot)
            }
        }
    }

    /// Returns a reference to the underlying [`cryptoki::context::Pkcs11`] client.
    pub fn client(&self) -> &Pkcs11 {
        &self.inner.client
    }

    /// Returns the configured PKCS#11 module filesystem path.
    pub fn module_path(&self) -> &Path {
        &self.inner.module_path
    }

    /// Returns the resolved PKCS#11 [`Slot`].
    pub fn slot(&self) -> Slot {
        self.inner.slot
    }

    /// Returns the [`SlotSelector`] used to resolve [`Pkcs11Library::slot`].
    pub fn slot_selector(&self) -> &SlotSelector {
        &self.inner.slot_selector
    }

    /// Returns the configured KEK label (e.g., `"kek-v1"`).
    pub fn kek_label(&self) -> &str {
        &self.inner.kek_label
    }

    /// Queries `C_GetSlotInfo` for the resolved slot.
    pub fn slot_info(&self) -> Result<SlotInfo, BackendError> {
        self.inner
            .client
            .get_slot_info(self.inner.slot)
            .map_err(|err| map_pkcs11_err("C_GetSlotInfo", err))
    }

    /// Queries `C_GetTokenInfo` for the resolved slot.
    pub fn token_info(&self) -> Result<TokenInfo, BackendError> {
        self.inner
            .client
            .get_token_info(self.inner.slot)
            .map_err(|err| map_pkcs11_err("C_GetTokenInfo", err))
    }

    /// Queries `C_GetMechanismList` for the resolved slot.
    pub fn mechanism_list(&self) -> Result<Vec<MechanismType>, BackendError> {
        self.inner
            .client
            .get_mechanism_list(self.inner.slot)
            .map_err(|err| map_pkcs11_err("C_GetMechanismList", err))
    }

    /// Returns `true` if `mechanism` is advertised by `C_GetMechanismList` on the resolved slot.
    pub fn supports_mechanism(&self, mechanism: MechanismType) -> Result<bool, BackendError> {
        let mechanisms = self.mechanism_list()?;
        Ok(mechanisms.contains(&mechanism))
    }

    /// Opens a new per-request read-write PKCS#11 session (`CKF_SERIAL_SESSION | CKF_RW_SESSION`)
    /// on the resolved token slot and logs in as `CKU_USER` if the session is not already in a
    /// user-authenticated state.
    pub fn open_rw_session(&self) -> Result<Pkcs11Session, BackendError> {
        let session = self
            .inner
            .client
            .open_rw_session(self.inner.slot)
            .map_err(|err| map_pkcs11_err("C_OpenSession (RW)", err))?;

        let info = session
            .get_session_info()
            .map_err(|err| map_pkcs11_err("C_GetSessionInfo", err))?;

        match info.session_state() {
            SessionState::RwUser | SessionState::RoUser => {
                // Already logged in as normal user (PKCS#11 login state is token-wide per process).
            }
            SessionState::RwPublic | SessionState::RoPublic => {
                let mut pin_copy = self.inner.user_pin.as_str().to_string();
                let auth_pin = AuthPin::new(pin_copy.clone());
                pin_copy.zeroize();

                match session.login(UserType::User, Some(&auth_pin)) {
                    Ok(()) => {}
                    Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, Function::Login)) => {
                        // A concurrent session in this process logged in first.
                    }
                    Err(err) => {
                        return Err(map_pkcs11_err("C_Login (CKU_USER)", err));
                    }
                }
            }
            SessionState::RwSecurityOfficer => {
                return Err(BackendError::Pkcs11(
                    "PKCS#11 token has an active Security Officer (SO) session; cannot authenticate as normal user"
                        .to_string(),
                ));
            }
        }

        Ok(Pkcs11Session {
            tracked_objects: Mutex::new(Vec::new()),
            session,
            slot: self.inner.slot,
            kek_label: self.inner.kek_label.clone(),
        })
    }

    /// Opens a per-request session and generates `len` random bytes via `C_GenerateRandom`.
    pub fn generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let session = self.open_rw_session()?;
        session.generate_random(len)
    }

    /// Opens a per-request session and generates `N` random bytes via `C_GenerateRandom`.
    pub fn generate_random_array<const N: usize>(&self) -> Result<Zeroizing<[u8; N]>, BackendError> {
        let session = self.open_rw_session()?;
        session.generate_random_array::<N>()
    }

    /// Opens a per-request session and generates a 64-byte wallet seed via `C_GenerateRandom`.
    pub fn generate_seed(&self) -> Result<Zeroizing<[u8; WALLET_SEED_LEN]>, BackendError> {
        let session = self.open_rw_session()?;
        session.generate_seed()
    }

    /// Opens a per-request session and generates a 12-byte (96-bit) AES-GCM IV via `C_GenerateRandom`.
    pub fn generate_aes_gcm_iv(&self) -> Result<Zeroizing<[u8; AES_GCM_IV_LEN]>, BackendError> {
        let session = self.open_rw_session()?;
        session.generate_aes_gcm_iv()
    }

    /// Opens a per-request session and verifies that the configured KEK exists on the token
    /// with valid security attributes (`CKA_CLASS=CKO_SECRET_KEY`, `CKA_KEY_TYPE=CKK_AES`,
    /// `CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`, `CKA_ENCRYPT=true`, `CKA_DECRYPT=true`).
    pub fn verify_kek(&self) -> Result<KekMetadata, BackendError> {
        let session = self.open_rw_session()?;
        session.verify_kek()
    }

    /// Opens a per-request session and wraps a 64-byte wallet `seed` under the configured KEK
    /// with `CKM_AES_GCM` and the caller-supplied `aad`.
    pub fn wrap_seed(&self, seed: &[u8], aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        let session = self.open_rw_session()?;
        session.wrap_seed(seed, aad)
    }

    /// Opens a per-request session and unwraps a 92-byte `wrapped` seed blob under the configured KEK
    /// with `CKM_AES_GCM` and the caller-supplied `aad` into a [`Zeroizing<[u8; WALLET_SEED_LEN]>`] buffer.
    pub fn unwrap_seed(
        &self,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; WALLET_SEED_LEN]>, BackendError> {
        let session = self.open_rw_session()?;
        session.unwrap_seed(wrapped, aad)
    }

    /// Opens a per-request session, loads `private_key` as a short-lived `secp256k1` (`CKK_EC`)
    /// session object, signs `digest` with `CKM_ECDSA`, destroys the session object, and returns
    /// the raw 64-byte `(r || s)` signature.
    pub fn sign_secp256k1_digest(
        &self,
        private_key: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<[u8; ECDSA_RAW_SIGNATURE_LEN], BackendError> {
        let session = self.open_rw_session()?;
        session.sign_secp256k1_digest(private_key, digest)
    }

    /// Opens a per-request session, loads `private_key` as a short-lived `ed25519` (`CKK_EC_EDWARDS`)
    /// session object, signs `message` with `CKM_EDDSA`, destroys the session object, and returns
    /// the 64-byte Ed25519 signature.
    pub fn sign_ed25519_message(
        &self,
        private_key: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], BackendError> {
        let session = self.open_rw_session()?;
        session.sign_ed25519_message(private_key, message)
    }
}

/// Per-request read-write PKCS#11 session wrapper.
///
/// Implements the one-session-per-request lifecycle from Section 4 and Section 8 of `Specs.md`:
/// - Opened via [`Pkcs11Library::open_rw_session`] and logged in as `CKU_USER` if needed.
/// - Generates random bytes from the HSM RNG (`C_GenerateRandom`) directly into [`Zeroizing`] buffers.
/// - Tracks any ephemeral session objects (`CKA_TOKEN=false`) registered on the session so they are
///   explicitly destroyed via `C_DestroyObject` before the session closes.
/// - Automatically closes the session via `C_CloseSession` on [`Drop`], which also destroys any
///   remaining session objects in the token.
pub struct Pkcs11Session {
    tracked_objects: Mutex<Vec<ObjectHandle>>,
    session: Session,
    slot: Slot,
    kek_label: String,
}

impl fmt::Debug for Pkcs11Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tracked_count = self
            .tracked_objects
            .lock()
            .map(|objs| objs.len())
            .unwrap_or(0);
        f.debug_struct("Pkcs11Session")
            .field("slot", &self.slot)
            .field("kek_label", &self.kek_label)
            .field("tracked_session_objects", &tracked_count)
            .finish()
    }
}

impl Pkcs11Session {
    /// Returns a reference to the underlying `cryptoki` [`Session`].
    pub fn raw(&self) -> &Session {
        &self.session
    }

    /// Returns the PKCS#11 [`Slot`] associated with this session.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Returns the configured KEK label (`"kek-v1"`) associated with this session.
    pub fn kek_label(&self) -> &str {
        &self.kek_label
    }

    /// Queries `C_GetSessionInfo` for this session.
    pub fn session_info(&self) -> Result<SessionInfo, BackendError> {
        self.session
            .get_session_info()
            .map_err(|err| map_pkcs11_err("C_GetSessionInfo", err))
    }

    /// Returns `true` if the session is currently in an authenticated user state
    /// (`CKS_RW_USER_FUNCTIONS` or `CKS_RO_USER_FUNCTIONS`).
    pub fn is_user_logged_in(&self) -> Result<bool, BackendError> {
        let info = self.session_info()?;
        Ok(matches!(
            info.session_state(),
            SessionState::RwUser | SessionState::RoUser
        ))
    }

    /// Generates `len` random bytes using the HSM's `C_GenerateRandom` mechanism directly into
    /// a [`Zeroizing<Vec<u8>>`] buffer.
    ///
    /// Rejects `len == 0` or `len > MAX_RANDOM_BYTES` with [`BackendError::Pkcs11`].
    pub fn generate_random(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        if len == 0 {
            return Err(BackendError::Pkcs11(
                "C_GenerateRandom requested length must be >= 1".to_string(),
            ));
        }
        if len > MAX_RANDOM_BYTES {
            return Err(BackendError::Pkcs11(format!(
                "C_GenerateRandom requested length {len} exceeds maximum {MAX_RANDOM_BYTES}"
            )));
        }

        let mut buf = Zeroizing::new(vec![0u8; len]);
        self.session
            .generate_random_slice(buf.as_mut_slice())
            .map_err(|err| map_pkcs11_err("C_GenerateRandom", err))?;
        Ok(buf)
    }

    /// Generates `N` random bytes using the HSM's `C_GenerateRandom` mechanism directly into
    /// a fixed-size [`Zeroizing<[u8; N]>`] buffer.
    pub fn generate_random_array<const N: usize>(&self) -> Result<Zeroizing<[u8; N]>, BackendError> {
        if N == 0 {
            return Err(BackendError::Pkcs11(
                "C_GenerateRandom requested array length must be >= 1".to_string(),
            ));
        }
        if N > MAX_RANDOM_BYTES {
            return Err(BackendError::Pkcs11(format!(
                "C_GenerateRandom requested array length {N} exceeds maximum {MAX_RANDOM_BYTES}"
            )));
        }

        let mut buf = Zeroizing::new([0u8; N]);
        self.session
            .generate_random_slice(buf.as_mut_slice())
            .map_err(|err| map_pkcs11_err("C_GenerateRandom", err))?;
        Ok(buf)
    }

    /// Generates a fresh 64-byte wallet seed (`WALLET_SEED_LEN`) using `C_GenerateRandom`.
    pub fn generate_seed(&self) -> Result<Zeroizing<[u8; WALLET_SEED_LEN]>, BackendError> {
        self.generate_random_array::<WALLET_SEED_LEN>()
    }

    /// Generates a fresh 12-byte (96-bit) AES-GCM initialization vector (`AES_GCM_IV_LEN`)
    /// using `C_GenerateRandom`.
    pub fn generate_aes_gcm_iv(&self) -> Result<Zeroizing<[u8; AES_GCM_IV_LEN]>, BackendError> {
        self.generate_random_array::<AES_GCM_IV_LEN>()
    }

    /// Locates and validates the KEK configured on this session (`self.kek_label()`, e.g., `"kek-v1"`),
    /// returning its [`ObjectHandle`].
    pub fn find_kek(&self) -> Result<ObjectHandle, BackendError> {
        wrap::find_kek(self)
    }

    /// Locates and validates a KEK by `label`, returning its [`ObjectHandle`].
    pub fn find_kek_by_label(&self, label: &str) -> Result<ObjectHandle, BackendError> {
        wrap::find_kek_by_label(self, label)
    }

    /// Locates and validates the KEK configured on this session (`self.kek_label()`),
    /// returning its verified [`KekMetadata`].
    pub fn verify_kek(&self) -> Result<KekMetadata, BackendError> {
        wrap::find_and_validate_kek(self)
    }

    /// Locates and validates a KEK by `label`, returning its verified [`KekMetadata`].
    pub fn verify_kek_by_label(&self, label: &str) -> Result<KekMetadata, BackendError> {
        wrap::find_and_validate_kek_by_label(self, label)
    }

    /// Wraps a 64-byte wallet `seed` under this session's configured KEK (`self.kek_label()`)
    /// using `CKM_AES_GCM` with a fresh 12-byte IV from `C_GenerateRandom`, the caller-supplied
    /// `aad`, and a 128-bit authentication tag.
    ///
    /// Returns the 92-byte wrapped seed blob: `IV (12B) || ciphertext (64B) || tag (16B)`.
    pub fn wrap_seed(&self, seed: &[u8], aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        wrap::wrap_seed(self, seed, aad)
    }

    /// Unwraps a 92-byte `wrapped` seed blob (`IV (12B) || ciphertext (64B) || tag (16B)`)
    /// under this session's configured KEK (`self.kek_label()`) using `C_Decrypt` (`CKM_AES_GCM`)
    /// and the caller-supplied `aad`.
    ///
    /// Outputs the decrypted 64-byte seed into a [`Zeroizing<[u8; WALLET_SEED_LEN]>`] buffer.
    pub fn unwrap_seed(
        &self,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; WALLET_SEED_LEN]>, BackendError> {
        wrap::unwrap_seed(self, wrapped, aad)
    }

    /// Imports a derived 32-byte `secp256k1` child private key into this session as a short-lived
    /// PKCS#11 session object (`CKK_EC`, `CKA_EC_PARAMS = 06 05 2b 81 04 00 0a`, `CKA_TOKEN = false`)
    /// and returns a [`SessionKeyGuard`] that destroys the object on drop.
    pub fn import_secp256k1_session_key(
        &self,
        private_key: &[u8; 32],
    ) -> Result<SessionKeyGuard<'_>, BackendError> {
        sign::import_secp256k1_session_key(self, private_key)
    }

    /// Imports a derived 32-byte `ed25519` child private key into this session as a short-lived
    /// PKCS#11 session object (`CKK_EC_EDWARDS`, `CKA_TOKEN = false`) and returns a
    /// [`SessionKeyGuard`] that destroys the object on drop.
    pub fn import_ed25519_session_key(
        &self,
        private_key: &[u8; 32],
    ) -> Result<SessionKeyGuard<'_>, BackendError> {
        sign::import_ed25519_session_key(self, private_key)
    }

    /// Imports a derived 32-byte child private key for `curve` into this session as a short-lived
    /// PKCS#11 session object and returns its [`SessionKeyGuard`].
    pub fn import_session_key(
        &self,
        curve: Curve,
        private_key: &[u8; 32],
    ) -> Result<SessionKeyGuard<'_>, BackendError> {
        sign::import_session_key(self, curve, private_key)
    }

    /// Loads `private_key` as a short-lived `secp256k1` (`CKK_EC`) session object, signs the
    /// 32-byte `digest` with `CKM_ECDSA`, and immediately destroys the session object before
    /// returning the raw 64-byte `(r || s)` signature.
    pub fn sign_secp256k1_digest(
        &self,
        private_key: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<[u8; ECDSA_RAW_SIGNATURE_LEN], BackendError> {
        sign::sign_secp256k1_digest_in_hsm(self, private_key, digest)
    }

    /// Loads `private_key` as a short-lived `ed25519` (`CKK_EC_EDWARDS`) session object, signs
    /// `message` with `CKM_EDDSA`, and immediately destroys the session object before returning
    /// the 64-byte Ed25519 signature.
    pub fn sign_ed25519_message(
        &self,
        private_key: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], BackendError> {
        sign::sign_ed25519_message_in_hsm(self, private_key, message)
    }

    /// Queries `C_FindObjects` (`CKA_TOKEN = false`) on this session and returns all session
    /// object handles currently present.
    pub fn find_session_objects(&self) -> Result<Vec<ObjectHandle>, BackendError> {
        sign::find_session_objects(self)
    }

    /// Queries `C_FindObjects` (`CKA_TOKEN = false`) on this session and returns the number of
    /// session objects currently present.
    pub fn count_session_objects(&self) -> Result<usize, BackendError> {
        sign::count_session_objects(self)
    }

    /// Verifies that zero session objects (`CKA_TOKEN = false`) remain on this session,
    /// returning [`BackendError::SessionObjectHygieneFailed`] if any leftover object is found.
    pub fn assert_no_session_objects(&self) -> Result<(), BackendError> {
        sign::assert_no_session_objects(self)
    }

    /// Registers an ephemeral session [`ObjectHandle`] to be automatically destroyed via
    /// `C_DestroyObject` if not explicitly destroyed before this [`Pkcs11Session`] is dropped.
    pub fn track_session_object(&self, handle: ObjectHandle) {
        if let Ok(mut guard) = self.tracked_objects.lock() {
            if !guard.contains(&handle) {
                guard.push(handle);
            }
        }
    }

    /// Removes `handle` from the tracked session-object list after explicit destruction.
    pub fn untrack_session_object(&self, handle: ObjectHandle) {
        if let Ok(mut guard) = self.tracked_objects.lock() {
            guard.retain(|&h| h != handle);
        }
    }

    /// Destroys a PKCS#11 object via `C_DestroyObject` and removes it from the tracked object list.
    pub fn destroy_object(&self, handle: ObjectHandle) -> Result<(), BackendError> {
        let res = self
            .session
            .destroy_object(handle)
            .map_err(|err| map_pkcs11_err("C_DestroyObject", err));
        self.untrack_session_object(handle);
        res
    }

    /// Returns the number of currently tracked ephemeral session objects on this wrapper.
    pub fn tracked_object_count(&self) -> usize {
        self.tracked_objects
            .lock()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }

    /// Explicitly closes the session, destroying any tracked session objects first.
    ///
    /// Note: Dropping [`Pkcs11Session`] performs the exact same cleanup automatically.
    pub fn close(self) {
        drop(self);
    }

    fn destroy_tracked_objects_best_effort(&self) {
        if let Ok(mut guard) = self.tracked_objects.lock() {
            while let Some(handle) = guard.pop() {
                let _ = self.session.destroy_object(handle);
            }
        }
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        // Explicitly destroy any tracked session objects before `self.session` drops
        // and invokes `C_CloseSession`.
        self.destroy_tracked_objects_best_effort();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn unique_temp_pin_file(prefix: &str, contents: &[u8]) -> PathBuf {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "polyglot_pkcs11_{prefix}_{}_{}.pin",
            std::process::id(),
            id
        ));
        let mut file = File::create(&path).expect("create temp pin file");
        file.write_all(contents).expect("write temp pin file");
        path
    }

    #[test]
    fn test_load_pin_from_file_trims_whitespace_and_newlines() {
        let path = unique_temp_pin_file("trim", b"  my-secret-pin-1234 \r\n\n ");
        let pin = load_pin_from_file(&path).expect("load pin from file");
        assert_eq!(pin.as_str(), "my-secret-pin-1234");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_pin_from_file_rejects_missing_empty_and_nul() {
        // Missing file
        let missing_err = load_pin_from_file("/nonexistent/path/to/softhsm_user.pin").unwrap_err();
        assert!(matches!(missing_err, BackendError::Config(_)));

        // Empty path
        let empty_path_err = load_pin_from_file("").unwrap_err();
        assert!(matches!(empty_path_err, BackendError::Config(_)));

        // Whitespace-only file
        let ws_path = unique_temp_pin_file("whitespace", b"  \r\n\t  ");
        let ws_err = load_pin_from_file(&ws_path).unwrap_err();
        assert!(matches!(ws_err, BackendError::Config(_)));
        let _ = std::fs::remove_file(&ws_path);

        // NUL byte inside PIN
        let nul_path = unique_temp_pin_file("nul", b"pin\0secret\n");
        let nul_err = load_pin_from_file(&nul_path).unwrap_err();
        assert!(matches!(nul_err, BackendError::Config(_)));
        let _ = std::fs::remove_file(&nul_path);

        // Invalid UTF-8 bytes
        let utf8_path = unique_temp_pin_file("utf8", &[0xff, 0xfe, 0xfd]);
        let utf8_err = load_pin_from_file(&utf8_path).unwrap_err();
        assert!(matches!(utf8_err, BackendError::Config(_)));
        let _ = std::fs::remove_file(&utf8_path);
    }

    #[test]
    fn test_slot_selector_and_config_validation() {
        assert_eq!(
            SlotSelector::from_options(Some(0), None).unwrap(),
            SlotSelector::Id(0)
        );
        assert_eq!(
            SlotSelector::from_options(None, Some("polyglot-token".to_string())).unwrap(),
            SlotSelector::Label("polyglot-token".to_string())
        );
        assert_eq!(
            SlotSelector::from_options(Some(2), Some("polyglot-token".to_string())).unwrap(),
            SlotSelector::IdAndLabel {
                id: 2,
                label: "polyglot-token".to_string()
            }
        );
        assert!(SlotSelector::from_options(None, None).is_err());
        assert!(SlotSelector::from_label("   ").validate().is_err());
        assert!(SlotSelector::from_label("bad\0label").validate().is_err());

        let pin_path = unique_temp_pin_file("cfg", b"123456\n");
        let cfg = Pkcs11Config::with_pin_file(
            "/usr/lib/softhsm/libsofthsm2.so",
            SlotSelector::from_id(0),
            &pin_path,
        );
        assert_eq!(cfg.kek_label, DEFAULT_KEK_LABEL);
        assert_eq!(cfg.resolve_user_pin().unwrap().as_str(), "123456");

        // Ensure Debug output redacts the PIN
        let inline_cfg = Pkcs11Config::with_loaded_pin(
            "/usr/lib/softhsm/libsofthsm2.so",
            SlotSelector::from_label("softhsm-token"),
            Zeroizing::new("super-secret-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        let debug_str = format!("{inline_cfg:?}");
        assert!(!debug_str.contains("super-secret-pin"));
        assert!(debug_str.contains("<redacted>"));

        // Invalid KEK label with delimiter '|' or empty module path
        let bad_kek_cfg = Pkcs11Config::with_loaded_pin(
            "/usr/lib/softhsm/libsofthsm2.so",
            SlotSelector::from_id(0),
            Zeroizing::new("1234".to_string()),
            "kek|injected",
        );
        assert!(bad_kek_cfg.validate().is_err());

        let empty_mod_cfg = Pkcs11Config::with_loaded_pin(
            "",
            SlotSelector::from_id(0),
            Zeroizing::new("1234".to_string()),
            DEFAULT_KEK_LABEL,
        );
        assert!(empty_mod_cfg.validate().is_err());

        let _ = std::fs::remove_file(&pin_path);
    }

    #[test]
    fn test_missing_pkcs11_library_fails_closed() {
        let cfg = Pkcs11Config::with_loaded_pin(
            "/nonexistent/path/to/libsofthsm2.so",
            SlotSelector::from_id(0),
            Zeroizing::new("123456".to_string()),
            DEFAULT_KEK_LABEL,
        );
        let err = Pkcs11Library::open(cfg).unwrap_err();
        assert!(matches!(err, BackendError::Pkcs11(_)));
    }

    // -------------------------------------------------------------------------
    // In-process mock PKCS#11 provider for unit-testing session, RNG & AES-GCM
    // -------------------------------------------------------------------------

    use cryptoki_sys::{
        CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_EXTRACTABLE,
        CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP,
        CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKA_WRAP, CKF_RW_SESSION, CKF_SERIAL_SESSION,
        CKF_TOKEN_INITIALIZED, CKF_USER_PIN_INITIALIZED, CKK_AES, CKK_EC, CKK_EC_EDWARDS,
        CKM_AES_GCM, CKM_ECDSA, CKM_EDDSA, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKR_ARGUMENTS_BAD,
        CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL,
        CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
        CKR_FUNCTION_FAILED, CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT,
        CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_OBJECT_HANDLE_INVALID, CKR_OK,
        CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_SLOT_ID_INVALID,
        CKS_RW_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CKU_USER,
        CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR,
        CK_FUNCTION_LIST_PTR_PTR, CK_GCM_PARAMS, CK_KEY_TYPE, CK_MECHANISM_PTR, CK_MECHANISM_TYPE,
        CK_MECHANISM_TYPE_PTR, CK_NOTIFY, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR,
        CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR, CK_SESSION_INFO, CK_SESSION_INFO_PTR,
        CK_SLOT_ID, CK_SLOT_ID_PTR, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
        CK_UNAVAILABLE_INFORMATION, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
    };
    use ed25519_dalek::{Signer as DalekSigner, SigningKey as DalekSigningKey};
    use hmac::{Hmac, Mac};
    use k256::ecdsa::{
        signature::hazmat::PrehashSigner, Signature as K256Signature, SigningKey as K256SigningKey,
    };
    use sha2::Sha256;

    pub(crate) const MOCK_SLOT_ID: CK_SLOT_ID = 7;
    pub(crate) const MOCK_TOKEN_LABEL: &[u8] = b"polyglot-softhsm";
    pub(crate) const MOCK_EXPECTED_PIN: &[u8] = b"correct-user-pin";
    pub(crate) const MOCK_KEK_HANDLE: CK_OBJECT_HANDLE = 1;

    #[derive(Clone, Debug)]
    pub(crate) struct MockPkcs11Object {
        pub(crate) handle: CK_OBJECT_HANDLE,
        pub(crate) label: Vec<u8>,
        pub(crate) class: Option<CK_OBJECT_CLASS>,
        pub(crate) key_type: Option<CK_KEY_TYPE>,
        pub(crate) token: bool,
        pub(crate) private: Option<bool>,
        pub(crate) extractable: Option<bool>,
        pub(crate) sensitive: Option<bool>,
        pub(crate) encrypt: Option<bool>,
        pub(crate) decrypt: Option<bool>,
        pub(crate) value_len: Option<CK_ULONG>,
        pub(crate) wrap: Option<bool>,
        pub(crate) unwrap: Option<bool>,
        pub(crate) sign: Option<bool>,
        pub(crate) verify: Option<bool>,
        pub(crate) derive: Option<bool>,
        pub(crate) ec_params: Option<Vec<u8>>,
        pub(crate) key_material: [u8; 32],
    }

    impl MockPkcs11Object {
        pub(crate) fn valid_kek(handle: CK_OBJECT_HANDLE, label: &[u8], key_material: [u8; 32]) -> Self {
            Self {
                handle,
                label: label.to_vec(),
                class: Some(CKO_SECRET_KEY),
                key_type: Some(CKK_AES),
                token: true,
                private: Some(true),
                extractable: Some(false),
                sensitive: Some(true),
                encrypt: Some(true),
                decrypt: Some(true),
                value_len: Some(32),
                wrap: Some(false),
                unwrap: Some(false),
                sign: Some(false),
                verify: Some(false),
                derive: Some(false),
                ec_params: None,
                key_material,
            }
        }

        fn encode_attribute(&self, attr_type: CK_ULONG) -> Option<Vec<u8>> {
            match attr_type {
                CKA_CLASS => self.class.map(|v| v.to_ne_bytes().to_vec()),
                CKA_KEY_TYPE => self.key_type.map(|v| v.to_ne_bytes().to_vec()),
                CKA_LABEL => Some(self.label.clone()),
                CKA_TOKEN => Some(vec![u8::from(self.token)]),
                CKA_PRIVATE => self.private.map(|v| vec![u8::from(v)]),
                CKA_EXTRACTABLE => self.extractable.map(|v| vec![u8::from(v)]),
                CKA_SENSITIVE => self.sensitive.map(|v| vec![u8::from(v)]),
                CKA_ENCRYPT => self.encrypt.map(|v| vec![u8::from(v)]),
                CKA_DECRYPT => self.decrypt.map(|v| vec![u8::from(v)]),
                CKA_VALUE_LEN => self.value_len.map(|v| v.to_ne_bytes().to_vec()),
                CKA_WRAP => self.wrap.map(|v| vec![u8::from(v)]),
                CKA_UNWRAP => self.unwrap.map(|v| vec![u8::from(v)]),
                CKA_SIGN => self.sign.map(|v| vec![u8::from(v)]),
                CKA_VERIFY => self.verify.map(|v| vec![u8::from(v)]),
                CKA_DERIVE => self.derive.map(|v| vec![u8::from(v)]),
                CKA_EC_PARAMS => self.ec_params.clone(),
                _ => None,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub(crate) struct MockGcmOperation {
        pub(crate) key_handle: CK_OBJECT_HANDLE,
        pub(crate) iv: Vec<u8>,
        pub(crate) aad: Vec<u8>,
        pub(crate) tag_len: usize,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct MockSignOperation {
        pub(crate) key_handle: CK_OBJECT_HANDLE,
        pub(crate) mechanism: CK_MECHANISM_TYPE,
    }

    pub(crate) struct MockPkcs11State {
        pub(crate) session_state: CK_ULONG,
        pub(crate) next_session_handle: CK_SESSION_HANDLE,
        pub(crate) next_object_handle: CK_OBJECT_HANDLE,
        pub(crate) open_sessions: Vec<CK_SESSION_HANDLE>,
        pub(crate) closed_sessions: Vec<CK_SESSION_HANDLE>,
        pub(crate) destroyed_objects: Vec<CK_OBJECT_HANDLE>,
        pub(crate) objects: Vec<MockPkcs11Object>,
        pub(crate) supported_mechanisms: Vec<CK_MECHANISM_TYPE>,
        pub(crate) find_matches: Vec<CK_OBJECT_HANDLE>,
        pub(crate) find_cursor: usize,
        pub(crate) active_encrypt: Option<MockGcmOperation>,
        pub(crate) active_decrypt: Option<MockGcmOperation>,
        pub(crate) active_sign: Option<MockSignOperation>,
        pub(crate) login_calls: usize,
        pub(crate) rng_calls: usize,
        pub(crate) force_so_state: bool,
        pub(crate) force_zero_iv: bool,
        pub(crate) force_encrypt_len_override: Option<usize>,
        pub(crate) force_decrypt_len_override: Option<usize>,
        pub(crate) force_sign_error: bool,
        pub(crate) reject_secp256k1_import: bool,
        pub(crate) reject_ed25519_import: bool,
        pub(crate) reject_ed25519_oid_params: bool,
        pub(crate) require_ed25519_der_octet_value: bool,
        pub(crate) corrupt_ecdsa_signature: bool,
        pub(crate) corrupt_eddsa_signature: bool,
        pub(crate) corrupt_decrypt_plaintext: bool,
        pub(crate) ignore_aad_on_decrypt: bool,
    }

    impl MockPkcs11State {
        pub(crate) fn new() -> Self {
            Self {
                session_state: CKS_RW_PUBLIC_SESSION,
                next_session_handle: 100,
                next_object_handle: 42,
                open_sessions: Vec::new(),
                closed_sessions: Vec::new(),
                destroyed_objects: Vec::new(),
                objects: vec![MockPkcs11Object::valid_kek(
                    MOCK_KEK_HANDLE,
                    DEFAULT_KEK_LABEL.as_bytes(),
                    [0xA5; 32],
                )],
                supported_mechanisms: vec![CKM_AES_GCM, CKM_ECDSA, CKM_EDDSA],
                find_matches: Vec::new(),
                find_cursor: 0,
                active_encrypt: None,
                active_decrypt: None,
                active_sign: None,
                login_calls: 0,
                rng_calls: 0,
                force_so_state: false,
                force_zero_iv: false,
                force_encrypt_len_override: None,
                force_decrypt_len_override: None,
                force_sign_error: false,
                reject_secp256k1_import: false,
                reject_ed25519_import: false,
                reject_ed25519_oid_params: false,
                require_ed25519_der_octet_value: false,
                corrupt_ecdsa_signature: false,
                corrupt_eddsa_signature: false,
                corrupt_decrypt_plaintext: false,
                ignore_aad_on_decrypt: false,
            }
        }

        pub(crate) fn reset(&mut self) {
            *self = Self::new();
        }
    }

    pub(crate) fn mock_state() -> &'static Mutex<MockPkcs11State> {
        static STATE: OnceLock<Mutex<MockPkcs11State>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(MockPkcs11State::new()))
    }

    pub(crate) fn mock_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn mock_gcm_keystream_xor(key: &[u8; 32], iv: &[u8], input: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; input.len()];
        for (block_idx, chunk) in input.chunks(32).enumerate() {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
            mac.update(b"POLYGLOT-MOCK-GCM-ENC");
            mac.update(iv);
            mac.update(&(block_idx as u32).to_be_bytes());
            let stream = mac.finalize().into_bytes();
            let offset = block_idx * 32;
            for (i, &b) in chunk.iter().enumerate() {
                out[offset + i] = b ^ stream[i];
            }
        }
        out
    }

    fn mock_gcm_compute_tag(
        key: &[u8; 32],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag_len: usize,
    ) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
        mac.update(b"POLYGLOT-MOCK-GCM-TAG");
        mac.update(&(iv.len() as u64).to_be_bytes());
        mac.update(iv);
        mac.update(&(aad.len() as u64).to_be_bytes());
        mac.update(aad);
        mac.update(&(ciphertext.len() as u64).to_be_bytes());
        mac.update(ciphertext);
        let full = mac.finalize().into_bytes();
        full[..tag_len].to_vec()
    }

    unsafe extern "C" fn mock_c_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
        CKR_OK
    }

    unsafe extern "C" fn mock_c_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
        CKR_OK
    }

    unsafe extern "C" fn mock_c_get_slot_list(
        _token_present: CK_BBOOL,
        slot_list: CK_SLOT_ID_PTR,
        count: CK_ULONG_PTR,
    ) -> CK_RV {
        if count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !slot_list.is_null() {
            *slot_list = MOCK_SLOT_ID;
        }
        *count = 1;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_get_token_info(
        slot_id: CK_SLOT_ID,
        info: CK_TOKEN_INFO_PTR,
    ) -> CK_RV {
        if slot_id != MOCK_SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut token_info = CK_TOKEN_INFO::default();
        token_info.label = [b' '; 32];
        token_info.label[..MOCK_TOKEN_LABEL.len()].copy_from_slice(MOCK_TOKEN_LABEL);
        token_info.manufacturerID = [b' '; 32];
        token_info.model = [b' '; 16];
        token_info.serialNumber = [b'0'; 16];
        token_info.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
        *info = token_info;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_get_mechanism_list(
        slot_id: CK_SLOT_ID,
        mech_list: CK_MECHANISM_TYPE_PTR,
        count: CK_ULONG_PTR,
    ) -> CK_RV {
        if slot_id != MOCK_SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let st = mock_state().lock().unwrap();
        let supported = &st.supported_mechanisms;
        if !mech_list.is_null() {
            for (i, &m) in supported.iter().enumerate() {
                *mech_list.add(i) = m;
            }
        }
        *count = supported.len() as CK_ULONG;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_open_session(
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        _application: CK_VOID_PTR,
        _notify: CK_NOTIFY,
        session: CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
        if slot_id != MOCK_SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if (flags & CKF_SERIAL_SESSION) == 0 || (flags & CKF_RW_SESSION) == 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        let handle = st.next_session_handle;
        st.next_session_handle += 1;
        st.open_sessions.push(handle);
        *session = handle;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
        let mut st = mock_state().lock().unwrap();
        st.open_sessions.retain(|&h| h != session);
        st.closed_sessions.push(session);
        CKR_OK
    }

    unsafe extern "C" fn mock_c_get_session_info(
        session: CK_SESSION_HANDLE,
        info: CK_SESSION_INFO_PTR,
    ) -> CK_RV {
        if info.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let st = mock_state().lock().unwrap();
        if !st.open_sessions.contains(&session) {
            return CKR_ARGUMENTS_BAD;
        }
        let state = if st.force_so_state {
            CKS_RW_SO_FUNCTIONS
        } else {
            st.session_state
        };
        *info = CK_SESSION_INFO {
            slotID: MOCK_SLOT_ID,
            state,
            flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ulDeviceError: 0,
        };
        CKR_OK
    }

    unsafe extern "C" fn mock_c_login(
        _session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: CK_UTF8CHAR_PTR,
        pin_len: CK_ULONG,
    ) -> CK_RV {
        if user_type != CKU_USER || pin.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let pin_slice = std::slice::from_raw_parts(pin, pin_len as usize);
        let mut st = mock_state().lock().unwrap();
        st.login_calls += 1;
        if pin_slice != MOCK_EXPECTED_PIN {
            return CKR_PIN_INCORRECT;
        }
        st.session_state = CKS_RW_USER_FUNCTIONS;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_logout(_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut st = mock_state().lock().unwrap();
        st.session_state = CKS_RW_PUBLIC_SESSION;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_create_object(
        _session: CK_SESSION_HANDLE,
        template: CK_ATTRIBUTE_PTR,
        count: CK_ULONG,
        object: CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV {
        if object.is_null() || (count > 0 && template.is_null()) {
            return CKR_ARGUMENTS_BAD;
        }

        let attrs = if count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(template, count as usize)
        };

        let mut class: Option<CK_OBJECT_CLASS> = None;
        let mut key_type: Option<CK_KEY_TYPE> = None;
        let mut label: Vec<u8> = Vec::new();
        let mut token = false;
        let mut private: Option<bool> = None;
        let mut extractable: Option<bool> = None;
        let mut sensitive: Option<bool> = None;
        let mut encrypt: Option<bool> = None;
        let mut decrypt: Option<bool> = None;
        let mut sign: Option<bool> = None;
        let mut verify: Option<bool> = None;
        let mut derive: Option<bool> = None;
        let mut ec_params: Option<Vec<u8>> = None;
        let mut raw_value: Option<Vec<u8>> = None;

        for attr in attrs {
            if attr.pValue.is_null() {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            let bytes =
                std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
            match attr.type_ {
                CKA_CLASS => {
                    if bytes.len() != std::mem::size_of::<CK_OBJECT_CLASS>() {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    let mut arr = [0u8; std::mem::size_of::<CK_OBJECT_CLASS>()];
                    arr.copy_from_slice(bytes);
                    class = Some(CK_OBJECT_CLASS::from_ne_bytes(arr));
                }
                CKA_KEY_TYPE => {
                    if bytes.len() != std::mem::size_of::<CK_KEY_TYPE>() {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    let mut arr = [0u8; std::mem::size_of::<CK_KEY_TYPE>()];
                    arr.copy_from_slice(bytes);
                    key_type = Some(CK_KEY_TYPE::from_ne_bytes(arr));
                }
                CKA_LABEL => label = bytes.to_vec(),
                CKA_TOKEN => token = bytes.first().copied().unwrap_or(0) != 0,
                CKA_PRIVATE => private = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_EXTRACTABLE => extractable = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_SENSITIVE => sensitive = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_ENCRYPT => encrypt = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_DECRYPT => decrypt = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_SIGN => sign = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_VERIFY => verify = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_DERIVE => derive = Some(bytes.first().copied().unwrap_or(0) != 0),
                CKA_EC_PARAMS => ec_params = Some(bytes.to_vec()),
                CKA_VALUE => raw_value = Some(bytes.to_vec()),
                _ => {}
            }
        }

        let mut st = mock_state().lock().unwrap();
        let mut key_material = [0u8; 32];

        if class == Some(CKO_PRIVATE_KEY) {
            match key_type {
                Some(CKK_EC) => {
                    if st.reject_secp256k1_import {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    if ec_params.as_deref() != Some(&SECP256K1_OID_DER[..]) {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    let Some(val) = &raw_value else {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    };
                    if val.len() != 32 {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    key_material.copy_from_slice(val);
                }
                Some(CKK_EC_EDWARDS) => {
                    if st.reject_ed25519_import {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    let Some(params) = ec_params.as_deref() else {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    };
                    if st.reject_ed25519_oid_params && params == ED25519_OID_DER {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                    if params != ED25519_OID_DER && params != ED25519_CURVE_NAME_DER {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }

                    let Some(val) = &raw_value else {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    };
                    if st.require_ed25519_der_octet_value {
                        if val.len() != 34 || &val[..2] != &DER_OCTET_STRING_32_PREFIX {
                            return CKR_ATTRIBUTE_VALUE_INVALID;
                        }
                        key_material.copy_from_slice(&val[2..]);
                    } else if val.len() == 32 {
                        key_material.copy_from_slice(val);
                    } else if val.len() == 34 && &val[..2] == &DER_OCTET_STRING_32_PREFIX {
                        key_material.copy_from_slice(&val[2..]);
                    } else {
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
                _ => return CKR_ATTRIBUTE_VALUE_INVALID,
            }
        }

        let h = st.next_object_handle;
        st.next_object_handle += 1;
        st.objects.push(MockPkcs11Object {
            handle: h,
            label,
            class,
            key_type,
            token,
            private,
            extractable,
            sensitive,
            encrypt,
            decrypt,
            value_len: Some(32),
            wrap: Some(false),
            unwrap: Some(false),
            sign,
            verify,
            derive,
            ec_params,
            key_material,
        });
        *object = h;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_destroy_object(
        _session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        let mut st = mock_state().lock().unwrap();
        st.objects.retain(|o| o.handle != object);
        st.destroyed_objects.push(object);
        CKR_OK
    }

    unsafe extern "C" fn mock_c_get_attribute_value(
        _session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: CK_ATTRIBUTE_PTR,
        count: CK_ULONG,
    ) -> CK_RV {
        if count > 0 && template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let st = mock_state().lock().unwrap();
        let Some(obj) = st.objects.iter().find(|o| o.handle == object) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };

        if count == 0 {
            return CKR_OK;
        }

        let attrs = std::slice::from_raw_parts_mut(template, count as usize);
        let mut status = CKR_OK;

        for attr in attrs.iter_mut() {
            match obj.encode_attribute(attr.type_) {
                None => {
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    status = CKR_ATTRIBUTE_TYPE_INVALID;
                }
                Some(bytes) => {
                    if attr.pValue.is_null() {
                        attr.ulValueLen = bytes.len() as CK_ULONG;
                    } else if (attr.ulValueLen as usize) < bytes.len() {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        status = CKR_BUFFER_TOO_SMALL;
                    } else {
                        let dst =
                            std::slice::from_raw_parts_mut(attr.pValue as *mut u8, bytes.len());
                        dst.copy_from_slice(&bytes);
                        attr.ulValueLen = bytes.len() as CK_ULONG;
                    }
                }
            }
        }

        status
    }

    unsafe extern "C" fn mock_c_find_objects_init(
        _session: CK_SESSION_HANDLE,
        template: CK_ATTRIBUTE_PTR,
        count: CK_ULONG,
    ) -> CK_RV {
        if count > 0 && template.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let filter_attrs = if count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(template, count as usize)
        };

        let mut st = mock_state().lock().unwrap();
        let mut matches = Vec::new();

        'obj_loop: for obj in &st.objects {
            for filter in filter_attrs {
                if filter.pValue.is_null() {
                    continue 'obj_loop;
                }
                let wanted = std::slice::from_raw_parts(
                    filter.pValue as *const u8,
                    filter.ulValueLen as usize,
                );
                let Some(actual) = obj.encode_attribute(filter.type_) else {
                    continue 'obj_loop;
                };
                if actual.as_slice() != wanted {
                    continue 'obj_loop;
                }
            }
            matches.push(obj.handle);
        }

        st.find_matches = matches;
        st.find_cursor = 0;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_find_objects(
        _session: CK_SESSION_HANDLE,
        ph_object: CK_OBJECT_HANDLE_PTR,
        ul_max_object_count: CK_ULONG,
        pul_object_count: CK_ULONG_PTR,
    ) -> CK_RV {
        if ph_object.is_null() || pul_object_count.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        let remaining = st.find_matches.len().saturating_sub(st.find_cursor);
        let to_copy = remaining.min(ul_max_object_count as usize);

        for i in 0..to_copy {
            *ph_object.add(i) = st.find_matches[st.find_cursor + i];
        }
        st.find_cursor += to_copy;
        *pul_object_count = to_copy as CK_ULONG;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_find_objects_final(_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut st = mock_state().lock().unwrap();
        st.find_matches.clear();
        st.find_cursor = 0;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_encrypt_init(
        _session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_PTR,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = &*mechanism;
        if mech.mechanism != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }
        if mech.pParameter.is_null()
            || (mech.ulParameterLen as usize) != std::mem::size_of::<CK_GCM_PARAMS>()
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let gcm = &*(mech.pParameter as *const CK_GCM_PARAMS);
        if gcm.pIv.is_null() || gcm.ulIvLen == 0 || gcm.ulTagBits != 128 {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        let iv = std::slice::from_raw_parts(gcm.pIv, gcm.ulIvLen as usize).to_vec();
        let aad = if gcm.pAAD.is_null() || gcm.ulAADLen == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(gcm.pAAD, gcm.ulAADLen as usize).to_vec()
        };

        let mut st = mock_state().lock().unwrap();
        if !st.supported_mechanisms.contains(&CKM_AES_GCM) {
            return CKR_MECHANISM_INVALID;
        }
        if !st.objects.iter().any(|o| o.handle == key) {
            return CKR_KEY_HANDLE_INVALID;
        }
        st.active_encrypt = Some(MockGcmOperation {
            key_handle: key,
            iv,
            aad,
            tag_len: (gcm.ulTagBits / 8) as usize,
        });
        CKR_OK
    }

    unsafe extern "C" fn mock_c_encrypt(
        _session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_encrypted_data: CK_BYTE_PTR,
        pul_encrypted_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
        if p_data.is_null() || pul_encrypted_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        let Some(op) = st.active_encrypt.clone() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };

        let out_len = st
            .force_encrypt_len_override
            .unwrap_or((ul_data_len as usize) + op.tag_len);

        if p_encrypted_data.is_null() {
            *pul_encrypted_data_len = out_len as CK_ULONG;
            return CKR_OK;
        }
        if (*pul_encrypted_data_len as usize) < out_len {
            *pul_encrypted_data_len = out_len as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }

        st.active_encrypt = None;
        let Some(key_obj) = st.objects.iter().find(|o| o.handle == op.key_handle) else {
            return CKR_KEY_HANDLE_INVALID;
        };

        let plaintext = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ciphertext = mock_gcm_keystream_xor(&key_obj.key_material, &op.iv, plaintext);
        let tag = mock_gcm_compute_tag(
            &key_obj.key_material,
            &op.iv,
            &op.aad,
            &ciphertext,
            op.tag_len,
        );

        let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
        combined.extend_from_slice(&ciphertext);
        combined.extend_from_slice(&tag);
        combined.resize(out_len, 0);

        let dst = std::slice::from_raw_parts_mut(p_encrypted_data, out_len);
        dst.copy_from_slice(&combined);
        *pul_encrypted_data_len = out_len as CK_ULONG;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_decrypt_init(
        _session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_PTR,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = &*mechanism;
        if mech.mechanism != CKM_AES_GCM {
            return CKR_MECHANISM_INVALID;
        }
        if mech.pParameter.is_null()
            || (mech.ulParameterLen as usize) != std::mem::size_of::<CK_GCM_PARAMS>()
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let gcm = &*(mech.pParameter as *const CK_GCM_PARAMS);
        if gcm.pIv.is_null() || gcm.ulIvLen == 0 || gcm.ulTagBits != 128 {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        let iv = std::slice::from_raw_parts(gcm.pIv, gcm.ulIvLen as usize).to_vec();
        let aad = if gcm.pAAD.is_null() || gcm.ulAADLen == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(gcm.pAAD, gcm.ulAADLen as usize).to_vec()
        };

        let mut st = mock_state().lock().unwrap();
        if !st.supported_mechanisms.contains(&CKM_AES_GCM) {
            return CKR_MECHANISM_INVALID;
        }
        if !st.objects.iter().any(|o| o.handle == key) {
            return CKR_KEY_HANDLE_INVALID;
        }
        st.active_decrypt = Some(MockGcmOperation {
            key_handle: key,
            iv,
            aad,
            tag_len: (gcm.ulTagBits / 8) as usize,
        });
        CKR_OK
    }

    unsafe extern "C" fn mock_c_decrypt(
        _session: CK_SESSION_HANDLE,
        p_encrypted_data: CK_BYTE_PTR,
        ul_encrypted_data_len: CK_ULONG,
        p_data: CK_BYTE_PTR,
        pul_data_len: CK_ULONG_PTR,
    ) -> CK_RV {
        if p_encrypted_data.is_null() || pul_data_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        let Some(op) = st.active_decrypt.clone() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };

        if (ul_encrypted_data_len as usize) < op.tag_len {
            st.active_decrypt = None;
            return CKR_ENCRYPTED_DATA_LEN_RANGE;
        }

        let plaintext_len = st
            .force_decrypt_len_override
            .unwrap_or((ul_encrypted_data_len as usize) - op.tag_len);

        if p_data.is_null() {
            *pul_data_len = plaintext_len as CK_ULONG;
            return CKR_OK;
        }
        if (*pul_data_len as usize) < plaintext_len {
            *pul_data_len = plaintext_len as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }

        st.active_decrypt = None;
        let corrupt_plaintext = st.corrupt_decrypt_plaintext;
        let ignore_aad = st.ignore_aad_on_decrypt;
        let Some(key_obj) = st.objects.iter().find(|o| o.handle == op.key_handle) else {
            return CKR_KEY_HANDLE_INVALID;
        };

        let enc_slice =
            std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize);
        let ct_len = enc_slice.len() - op.tag_len;
        let ciphertext = &enc_slice[..ct_len];
        let provided_tag = &enc_slice[ct_len..];

        let expected_tag = mock_gcm_compute_tag(
            &key_obj.key_material,
            &op.iv,
            &op.aad,
            ciphertext,
            op.tag_len,
        );

        if !ignore_aad && provided_tag != expected_tag.as_slice() {
            *pul_data_len = 0;
            return CKR_ENCRYPTED_DATA_INVALID;
        }

        let mut plaintext = mock_gcm_keystream_xor(&key_obj.key_material, &op.iv, ciphertext);
        plaintext.resize(plaintext_len, 0);
        if corrupt_plaintext && !plaintext.is_empty() {
            plaintext[0] ^= 0xff;
        }

        let dst = std::slice::from_raw_parts_mut(p_data, plaintext_len);
        dst.copy_from_slice(&plaintext);
        *pul_data_len = plaintext_len as CK_ULONG;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_sign_init(
        _session: CK_SESSION_HANDLE,
        mechanism: CK_MECHANISM_PTR,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech = &*mechanism;
        if mech.mechanism != CKM_ECDSA && mech.mechanism != CKM_EDDSA {
            return CKR_MECHANISM_INVALID;
        }

        let mut st = mock_state().lock().unwrap();
        if !st.supported_mechanisms.contains(&mech.mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        let Some(key_obj) = st.objects.iter().find(|o| o.handle == key) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if key_obj.class != Some(CKO_PRIVATE_KEY) || key_obj.sign != Some(true) {
            return CKR_KEY_HANDLE_INVALID;
        }
        match (mech.mechanism, key_obj.key_type) {
            (CKM_ECDSA, Some(CKK_EC)) | (CKM_EDDSA, Some(CKK_EC_EDWARDS)) => {}
            _ => return CKR_KEY_TYPE_INCONSISTENT,
        }

        st.active_sign = Some(MockSignOperation {
            key_handle: key,
            mechanism: mech.mechanism,
        });
        CKR_OK
    }

    unsafe extern "C" fn mock_c_sign(
        _session: CK_SESSION_HANDLE,
        p_data: CK_BYTE_PTR,
        ul_data_len: CK_ULONG,
        p_signature: CK_BYTE_PTR,
        pul_signature_len: CK_ULONG_PTR,
    ) -> CK_RV {
        if (ul_data_len > 0 && p_data.is_null()) || pul_signature_len.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        let Some(op) = st.active_sign else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };

        if st.force_sign_error {
            st.active_sign = None;
            return CKR_FUNCTION_FAILED;
        }

        let sig_len = 64usize;
        if p_signature.is_null() {
            *pul_signature_len = sig_len as CK_ULONG;
            return CKR_OK;
        }
        if (*pul_signature_len as usize) < sig_len {
            *pul_signature_len = sig_len as CK_ULONG;
            return CKR_BUFFER_TOO_SMALL;
        }

        st.active_sign = None;
        let corrupt_ecdsa = st.corrupt_ecdsa_signature;
        let corrupt_eddsa = st.corrupt_eddsa_signature;
        let Some(key_obj) = st.objects.iter().find(|o| o.handle == op.key_handle) else {
            return CKR_KEY_HANDLE_INVALID;
        };

        let input = if ul_data_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(p_data, ul_data_len as usize)
        };

        let mut sig_bytes: [u8; 64] = match op.mechanism {
            CKM_ECDSA => {
                if input.len() != 32 {
                    return CKR_DATA_LEN_RANGE;
                }
                let Ok(signing_key) = K256SigningKey::from_bytes((&key_obj.key_material).into())
                else {
                    return CKR_FUNCTION_FAILED;
                };
                let Ok(sig): Result<K256Signature, _> = signing_key.sign_prehash(input) else {
                    return CKR_FUNCTION_FAILED;
                };
                let mut b: [u8; 64] = sig.to_bytes().into();
                if corrupt_ecdsa {
                    b[0] ^= 0xff;
                }
                b
            }
            CKM_EDDSA => {
                let signing_key = DalekSigningKey::from_bytes(&key_obj.key_material);
                let sig = signing_key.sign(input);
                let mut b = sig.to_bytes();
                if corrupt_eddsa {
                    b[0] ^= 0xff;
                }
                b
            }
            _ => return CKR_MECHANISM_INVALID,
        };

        let dst = std::slice::from_raw_parts_mut(p_signature, sig_len);
        dst.copy_from_slice(&sig_bytes);
        sig_bytes.zeroize();
        *pul_signature_len = sig_len as CK_ULONG;
        CKR_OK
    }

    unsafe extern "C" fn mock_c_generate_random(
        _session: CK_SESSION_HANDLE,
        random_data: CK_BYTE_PTR,
        random_len: CK_ULONG,
    ) -> CK_RV {
        if random_data.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut st = mock_state().lock().unwrap();
        st.rng_calls += 1;
        let call_idx = st.rng_calls as u8;
        let out = std::slice::from_raw_parts_mut(random_data, random_len as usize);
        if st.force_zero_iv && random_len as usize == AES_GCM_IV_LEN {
            out.fill(0);
            return CKR_OK;
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = call_idx.wrapping_mul(37).wrapping_add(i as u8) ^ 0x5a;
        }
        CKR_OK
    }

    static mut MOCK_FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
        version: CK_VERSION {
            major: 2,
            minor: 40,
        },
        C_Initialize: Some(mock_c_initialize),
        C_Finalize: Some(mock_c_finalize),
        C_GetInfo: None,
        C_GetFunctionList: Some(C_GetFunctionList),
        C_GetSlotList: Some(mock_c_get_slot_list),
        C_GetSlotInfo: None,
        C_GetTokenInfo: Some(mock_c_get_token_info),
        C_GetMechanismList: Some(mock_c_get_mechanism_list),
        C_GetMechanismInfo: None,
        C_InitToken: None,
        C_InitPIN: None,
        C_SetPIN: None,
        C_OpenSession: Some(mock_c_open_session),
        C_CloseSession: Some(mock_c_close_session),
        C_CloseAllSessions: None,
        C_GetSessionInfo: Some(mock_c_get_session_info),
        C_GetOperationState: None,
        C_SetOperationState: None,
        C_Login: Some(mock_c_login),
        C_Logout: Some(mock_c_logout),
        C_CreateObject: Some(mock_c_create_object),
        C_CopyObject: None,
        C_DestroyObject: Some(mock_c_destroy_object),
        C_GetObjectSize: None,
        C_GetAttributeValue: Some(mock_c_get_attribute_value),
        C_SetAttributeValue: None,
        C_FindObjectsInit: Some(mock_c_find_objects_init),
        C_FindObjects: Some(mock_c_find_objects),
        C_FindObjectsFinal: Some(mock_c_find_objects_final),
        C_EncryptInit: Some(mock_c_encrypt_init),
        C_Encrypt: Some(mock_c_encrypt),
        C_EncryptUpdate: None,
        C_EncryptFinal: None,
        C_DecryptInit: Some(mock_c_decrypt_init),
        C_Decrypt: Some(mock_c_decrypt),
        C_DecryptUpdate: None,
        C_DecryptFinal: None,
        C_DigestInit: None,
        C_Digest: None,
        C_DigestUpdate: None,
        C_DigestKey: None,
        C_DigestFinal: None,
        C_SignInit: Some(mock_c_sign_init),
        C_Sign: Some(mock_c_sign),
        C_SignUpdate: None,
        C_SignFinal: None,
        C_SignRecoverInit: None,
        C_SignRecover: None,
        C_VerifyInit: None,
        C_Verify: None,
        C_VerifyUpdate: None,
        C_VerifyFinal: None,
        C_VerifyRecoverInit: None,
        C_VerifyRecover: None,
        C_DigestEncryptUpdate: None,
        C_DecryptDigestUpdate: None,
        C_SignEncryptUpdate: None,
        C_DecryptVerifyUpdate: None,
        C_GenerateKey: None,
        C_GenerateKeyPair: None,
        C_WrapKey: None,
        C_UnwrapKey: None,
        C_DeriveKey: None,
        C_SeedRandom: None,
        C_GenerateRandom: Some(mock_c_generate_random),
        C_GetFunctionStatus: None,
        C_CancelFunction: None,
        C_WaitForSlotEvent: None,
    };

    #[no_mangle]
    pub unsafe extern "C" fn C_GetFunctionList(
        pp_function_list: CK_FUNCTION_LIST_PTR_PTR,
    ) -> CK_RV {
        if pp_function_list.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        *pp_function_list = std::ptr::addr_of_mut!(MOCK_FUNCTION_LIST) as CK_FUNCTION_LIST_PTR;
        CKR_OK
    }

    #[test]
    fn test_mock_pkcs11_library_slot_resolution_session_lifecycle_and_rng() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        // Keep reference to C_GetFunctionList so the linker retains it
        let _keep_sym = C_GetFunctionList as usize;

        let pin_path = unique_temp_pin_file("mock_ok", b"  correct-user-pin\n");

        // 1. Open library by token label
        let cfg = Pkcs11Config::with_pin_file(
            SELF_MODULE_PATH,
            SlotSelector::from_label("polyglot-softhsm"),
            &pin_path,
        );
        let lib = Pkcs11Library::open(cfg).expect("open mock PKCS#11 library by label");
        assert_eq!(lib.slot().id(), MOCK_SLOT_ID as u64);
        assert_eq!(lib.kek_label(), DEFAULT_KEK_LABEL);
        assert!(lib.supports_mechanism(MechanismType::AES_GCM).unwrap());
        assert!(lib.supports_mechanism(MechanismType::ECDSA).unwrap());
        assert!(!lib.supports_mechanism(MechanismType::RSA_PKCS).unwrap());

        let token_info = lib.token_info().expect("get token info");
        assert_eq!(token_info.label(), "polyglot-softhsm");

        // Debug redacts PIN on Pkcs11Library as well
        let lib_debug = format!("{lib:?}");
        assert!(!lib_debug.contains("correct-user-pin"));
        assert!(lib_debug.contains("<redacted>"));

        // 2. Open RW session -> logs in once when in RwPublic state
        {
            let session = lib.open_rw_session().expect("open first RW session");
            assert!(session.is_user_logged_in().unwrap());
            assert_eq!(mock_state().lock().unwrap().login_calls, 1);
            assert_eq!(mock_state().lock().unwrap().open_sessions.len(), 1);

            // Track two ephemeral session objects; explicitly destroy one, leave one for Drop
            let obj_explicit = session.raw().create_object(&[]).expect("create mock obj 1");
            let obj_on_drop = session.raw().create_object(&[]).expect("create mock obj 2");
            session.track_session_object(obj_explicit);
            session.track_session_object(obj_on_drop);
            assert_eq!(session.tracked_object_count(), 2);

            session
                .destroy_object(obj_explicit)
                .expect("explicit destroy");
            assert_eq!(session.tracked_object_count(), 1);

            // 3. Generate random seed (64B) and AES-GCM IV (12B)
            let seed = session.generate_seed().expect("generate 64B seed");
            assert_eq!(seed.len(), WALLET_SEED_LEN);
            assert!(seed.iter().any(|&b| b != 0));

            let iv = session.generate_aes_gcm_iv().expect("generate 12B IV");
            assert_eq!(iv.len(), AES_GCM_IV_LEN);
            assert_ne!(&seed[..AES_GCM_IV_LEN], iv.as_slice());

            let custom_rand = session.generate_random(32).expect("generate 32B");
            assert_eq!(custom_rand.len(), 32);

            // Reject invalid random lengths (0 or > MAX_RANDOM_BYTES)
            assert!(session.generate_random(0).is_err());
            assert!(session.generate_random(MAX_RANDOM_BYTES + 1).is_err());
        }

        // After session block exits:
        // - `obj_on_drop` (99) was destroyed automatically before closing the session
        // - `C_CloseSession` was called on drop
        {
            let st = mock_state().lock().unwrap();
            assert!(st.open_sessions.is_empty());
            assert_eq!(st.closed_sessions.len(), 1);
            assert_eq!(st.destroyed_objects, vec![42, 43]);
        }

        // 4. Opening a second session when already in RwUser state skips redundant C_Login
        {
            let session2 = lib.open_rw_session().expect("open second RW session");
            assert!(session2.is_user_logged_in().unwrap());
            assert_eq!(mock_state().lock().unwrap().login_calls, 1);
            session2.close();
        }
        assert_eq!(mock_state().lock().unwrap().closed_sessions.len(), 2);

        let _ = std::fs::remove_file(&pin_path);
    }

    #[test]
    fn test_mock_pkcs11_slot_and_login_error_cases() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        // 1. Slot ID not found
        let wrong_slot_cfg = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id(999),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        assert!(Pkcs11Library::open(wrong_slot_cfg).is_err());

        // 2. Token label mismatch on IdAndLabel
        let wrong_label_cfg = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id_and_label(MOCK_SLOT_ID as u64, "wrong-token-label"),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        assert!(Pkcs11Library::open(wrong_label_cfg).is_err());

        // 3. Incorrect user PIN fails C_Login and closes the opened session on drop
        let bad_pin_cfg = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id_and_label(MOCK_SLOT_ID as u64, "polyglot-softhsm"),
            Zeroizing::new("wrong-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        let bad_pin_lib = Pkcs11Library::open(bad_pin_cfg).expect("open library with bad pin");
        let login_err = bad_pin_lib.open_rw_session().unwrap_err();
        assert!(matches!(login_err, BackendError::Pkcs11(_)));
        assert!(mock_state().lock().unwrap().open_sessions.is_empty());

        // 4. Security Officer (SO) active session state is rejected
        mock_state().lock().unwrap().force_so_state = true;
        let ok_pin_cfg = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id(MOCK_SLOT_ID as u64),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        let ok_lib = Pkcs11Library::open(ok_pin_cfg).expect("open library");
        let so_err = ok_lib.open_rw_session().unwrap_err();
        assert!(matches!(so_err, BackendError::Pkcs11(_)));
        assert!(mock_state().lock().unwrap().open_sessions.is_empty());
    }
}

