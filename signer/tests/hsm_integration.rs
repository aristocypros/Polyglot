//! Milestone 2 HSM Integration Tests (`signer/tests/hsm_integration.rs`).
//!
//! Covers all Task 12 and Section 10 (`Wrapping`, `Signing`, `HSM hygiene`, `Probe`) requirements:
//! 1. Bootstrap workflow (`init_token`, non-extractable 256-bit AES KEK `kek-v1`, signer Ed25519
//!    identity keypair) and 5-step startup capability probe against live SoftHSMv2 (when present
//!    in the container/system) and the deterministic PKCS#11 C FFI harness.
//! 2. `GenericBackend` (`Backend` trait) wallet creation, published BIP32/SLIP10 vector derivation,
//!    HSM/software signing (`Digest32`, `Message`, and `TaprootDigest32`), and `signing_in_hsm`
//!    honesty.
//! 3. AEAD wrapping tamper cases: tampered IV, tampered ciphertext, tampered tag, truncated/oversized
//!    blob, wrong AAD, swapped wallet blob (`w_alice` vs `w_bob`), and missing KEK.
//! 4. HSM session-object hygiene: `C_FindObjects` (`CKA_TOKEN = false`) lists zero leftover session
//!    objects after normal requests and after forced-error requests.
//! 5. Fail-closed startup probe failures: missing library, missing `CKM_AES_GCM`, missing KEK,
//!    extractable KEK (`CKA_EXTRACTABLE = true`), non-sensitive KEK, and missing curve fallback
//!    to `SigningLocation::Software`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE,
    CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VALUE,
    CKA_VALUE_LEN, CKA_VERIFY, CKA_WRAP, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKF_TOKEN_INITIALIZED,
    CKF_USER_PIN_INITIALIZED, CKK_AES, CKK_EC, CKK_EC_EDWARDS, CKM_AES_GCM, CKM_AES_KEY_GEN,
    CKM_ECDSA, CKM_EDDSA, CKO_PRIVATE_KEY, CKO_SECRET_KEY, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED, CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_INCORRECT, CKR_SLOT_ID_INVALID, CKS_RW_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS,
    CKS_RW_USER_FUNCTIONS, CKU_SO, CKU_USER, CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_FLAGS,
    CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_FUNCTION_LIST_PTR_PTR, CK_GCM_PARAMS, CK_KEY_TYPE,
    CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_MECHANISM_TYPE_PTR, CK_NOTIFY, CK_OBJECT_CLASS,
    CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR,
    CK_SESSION_INFO, CK_SESSION_INFO_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR, CK_TOKEN_INFO,
    CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR, CK_UNAVAILABLE_INFORMATION, CK_USER_TYPE,
    CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
};
use ed25519_dalek::{Signer as DalekSigner, SigningKey as DalekSigningKey};
use hmac::{Hmac, Mac};
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, Signature as K256Signature, SigningKey as K256SigningKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use signer::backend::generic::{
    extract_probe_failure_code, is_low_s, run_startup_probe_checked, verify_bip340_schnorr,
    verify_ed25519_signature, verify_secp256k1_ecdsa, GenericBackend, ProbeConfig,
    ProbeFailureCode, ProbeStep, DEFAULT_GENERIC_BACKEND_NAME, DEFAULT_WRAP_MECHANISM_NAME,
};
use signer::backend::{
    build_aad_checked, Backend, BackendError, Curve, ProtectionLevel, Scheme, SigningInput,
    SigningLocation, Spec, WalletRef, AES_GCM_IV_LEN, DEFAULT_KEK_LABEL, DEFAULT_SEED_VERSION,
    WALLET_SEED_LEN, WRAPPED_SEED_LEN,
};
use signer::bootstrap::{
    resolve_softhsm_module_path, run_bootstrap, BootstrapConfig, DEFAULT_TOKEN_LABEL,
};
use signer::derive::{
    DerivationPath, COMPRESSED_PUBKEY_LEN, ED25519_PUBKEY_LEN, HARDENED_FLAG, MAX_DEPTH,
};
use signer::pkcs11session::{
    count_session_objects, Pkcs11Config, Pkcs11Library, SlotSelector, DER_OCTET_STRING_32_PREFIX,
    ED25519_CURVE_NAME_DER, ED25519_OID_DER, SECP256K1_OID_DER, SELF_MODULE_PATH,
};

// ============================================================================
// In-process PKCS#11 C FFI test harness (`:self:`) for deterministic fault injection
// and host execution when `libsofthsm2.so` is not installed on the host OS.
// ============================================================================

const HARNESS_SLOT_ID: CK_SLOT_ID = 7;
const HARNESS_DEFAULT_PIN: &[u8] = b"test-softhsm-pin-1234";
const HARNESS_KEK_HANDLE: CK_OBJECT_HANDLE = 1;

#[derive(Clone, Debug)]
struct HarnessPkcs11Object {
    handle: CK_OBJECT_HANDLE,
    label: Vec<u8>,
    class: Option<CK_OBJECT_CLASS>,
    key_type: Option<CK_KEY_TYPE>,
    token: bool,
    private: Option<bool>,
    extractable: Option<bool>,
    sensitive: Option<bool>,
    encrypt: Option<bool>,
    decrypt: Option<bool>,
    value_len: Option<CK_ULONG>,
    wrap: Option<bool>,
    unwrap: Option<bool>,
    sign: Option<bool>,
    verify: Option<bool>,
    derive: Option<bool>,
    ec_params: Option<Vec<u8>>,
    key_material: [u8; 32],
}

impl HarnessPkcs11Object {
    fn valid_kek(handle: CK_OBJECT_HANDLE, label: &[u8], key_material: [u8; 32]) -> Self {
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
struct HarnessGcmOp {
    key_handle: CK_OBJECT_HANDLE,
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag_len: usize,
}

#[derive(Clone, Copy, Debug)]
struct HarnessSignOp {
    key_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
}

struct HarnessState {
    token_initialized: bool,
    token_label: Vec<u8>,
    expected_pin: Vec<u8>,
    session_state: CK_ULONG,
    next_session_handle: CK_SESSION_HANDLE,
    next_object_handle: CK_OBJECT_HANDLE,
    open_sessions: Vec<CK_SESSION_HANDLE>,
    destroyed_objects: Vec<CK_OBJECT_HANDLE>,
    objects: Vec<HarnessPkcs11Object>,
    supported_mechanisms: Vec<CK_MECHANISM_TYPE>,
    find_matches: Vec<CK_OBJECT_HANDLE>,
    find_cursor: usize,
    active_encrypt: Option<HarnessGcmOp>,
    active_decrypt: Option<HarnessGcmOp>,
    active_sign: Option<HarnessSignOp>,
    rng_calls: usize,
    force_sign_error: bool,
    reject_secp256k1_import: bool,
    reject_ed25519_import: bool,
}

impl HarnessState {
    fn new() -> Self {
        Self {
            token_initialized: true,
            token_label: DEFAULT_TOKEN_LABEL.as_bytes().to_vec(),
            expected_pin: HARNESS_DEFAULT_PIN.to_vec(),
            session_state: CKS_RW_PUBLIC_SESSION,
            next_session_handle: 100,
            next_object_handle: 50,
            open_sessions: Vec::new(),
            destroyed_objects: Vec::new(),
            objects: vec![HarnessPkcs11Object::valid_kek(
                HARNESS_KEK_HANDLE,
                DEFAULT_KEK_LABEL.as_bytes(),
                [0x5A; 32],
            )],
            supported_mechanisms: vec![CKM_AES_GCM, CKM_AES_KEY_GEN, CKM_ECDSA, CKM_EDDSA],
            find_matches: Vec::new(),
            find_cursor: 0,
            active_encrypt: None,
            active_decrypt: None,
            active_sign: None,
            rng_calls: 0,
            force_sign_error: false,
            reject_secp256k1_import: false,
            reject_ed25519_import: false,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

fn harness_state() -> &'static Mutex<HarnessState> {
    static STATE: OnceLock<Mutex<HarnessState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HarnessState::new()))
}

fn integration_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn harness_gcm_xor(key: &[u8; 32], iv: &[u8], input: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    for (block_idx, chunk) in input.chunks(32).enumerate() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        mac.update(b"POLYGLOT-ITEST-GCM-ENC");
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

fn harness_gcm_tag(
    key: &[u8; 32],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_len: usize,
) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(b"POLYGLOT-ITEST-GCM-TAG");
    mac.update(&(iv.len() as u64).to_be_bytes());
    mac.update(iv);
    mac.update(&(aad.len() as u64).to_be_bytes());
    mac.update(aad);
    mac.update(&(ciphertext.len() as u64).to_be_bytes());
    mac.update(ciphertext);
    let full = mac.finalize().into_bytes();
    full[..tag_len].to_vec()
}

unsafe extern "C" fn h_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

unsafe extern "C" fn h_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    CKR_OK
}

unsafe extern "C" fn h_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if !slot_list.is_null() {
        *slot_list = HARNESS_SLOT_ID;
    }
    *count = 1;
    CKR_OK
}

unsafe extern "C" fn h_get_token_info(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != HARNESS_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let st = harness_state().lock().unwrap();
    let mut token_info = CK_TOKEN_INFO::default();
    token_info.label = [b' '; 32];
    let copy_len = st.token_label.len().min(32);
    token_info.label[..copy_len].copy_from_slice(&st.token_label[..copy_len]);
    token_info.manufacturerID = [b' '; 32];
    token_info.model = [b' '; 16];
    token_info.serialNumber = [b'0'; 16];
    token_info.flags = if st.token_initialized {
        CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED
    } else {
        0
    };
    *info = token_info;
    CKR_OK
}

unsafe extern "C" fn h_init_token(
    slot_id: CK_SLOT_ID,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
    label: CK_UTF8CHAR_PTR,
) -> CK_RV {
    if slot_id != HARNESS_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if label.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let label_slice = std::slice::from_raw_parts(label, 32);
    let trimmed = std::str::from_utf8(label_slice)
        .unwrap_or(DEFAULT_TOKEN_LABEL)
        .trim();
    let mut st = harness_state().lock().unwrap();
    st.token_label = trimmed.as_bytes().to_vec();
    st.token_initialized = true;
    st.objects.clear();
    CKR_OK
}

unsafe extern "C" fn h_init_pin(
    _session: CK_SESSION_HANDLE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    if pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let pin_slice = std::slice::from_raw_parts(pin, pin_len as usize);
    let mut st = harness_state().lock().unwrap();
    st.expected_pin = pin_slice.to_vec();
    CKR_OK
}

unsafe extern "C" fn h_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mech_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if slot_id != HARNESS_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let st = harness_state().lock().unwrap();
    let mechs = &st.supported_mechanisms;
    if !mech_list.is_null() {
        for (i, &m) in mechs.iter().enumerate() {
            *mech_list.add(i) = m;
        }
    }
    *count = mechs.len() as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn h_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if slot_id != HARNESS_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if (flags & CKF_SERIAL_SESSION) == 0 || (flags & CKF_RW_SESSION) == 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
    let handle = st.next_session_handle;
    st.next_session_handle += 1;
    st.open_sessions.push(handle);
    *session = handle;
    CKR_OK
}

unsafe extern "C" fn h_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = harness_state().lock().unwrap();
    st.open_sessions.retain(|&h| h != session);
    CKR_OK
}

unsafe extern "C" fn h_get_session_info(
    session: CK_SESSION_HANDLE,
    info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let st = harness_state().lock().unwrap();
    if !st.open_sessions.contains(&session) {
        return CKR_ARGUMENTS_BAD;
    }
    *info = CK_SESSION_INFO {
        slotID: HARNESS_SLOT_ID,
        state: st.session_state,
        flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ulDeviceError: 0,
    };
    CKR_OK
}

unsafe extern "C" fn h_login(
    _session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    if pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let pin_slice = std::slice::from_raw_parts(pin, pin_len as usize);
    let mut st = harness_state().lock().unwrap();
    if user_type == CKU_SO {
        st.session_state = CKS_RW_SO_FUNCTIONS;
        return CKR_OK;
    }
    if user_type != CKU_USER {
        return CKR_ARGUMENTS_BAD;
    }
    if pin_slice != st.expected_pin.as_slice() {
        return CKR_PIN_INCORRECT;
    }
    st.session_state = CKS_RW_USER_FUNCTIONS;
    CKR_OK
}

unsafe extern "C" fn h_logout(_session: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = harness_state().lock().unwrap();
    st.session_state = CKS_RW_PUBLIC_SESSION;
    CKR_OK
}

unsafe extern "C" fn h_generate_key(
    _session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
    ph_key: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if mechanism.is_null() || ph_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*mechanism;
    if mech.mechanism != CKM_AES_KEY_GEN {
        return CKR_MECHANISM_INVALID;
    }
    let attrs = if count == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(template, count as usize)
    };
    let mut label = DEFAULT_KEK_LABEL.as_bytes().to_vec();
    for attr in attrs {
        if attr.type_ == CKA_LABEL && !attr.pValue.is_null() {
            let bytes =
                std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
            label = bytes.to_vec();
        }
    }
    let mut st = harness_state().lock().unwrap();
    let h = st.next_object_handle;
    st.next_object_handle += 1;
    st.objects
        .push(HarnessPkcs11Object::valid_kek(h, &label, [0x7C; 32]));
    *ph_key = h;
    CKR_OK
}

unsafe extern "C" fn h_create_object(
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
    let mut wrap: Option<bool> = None;
    let mut unwrap: Option<bool> = None;
    let mut sign: Option<bool> = None;
    let mut verify: Option<bool> = None;
    let mut derive: Option<bool> = None;
    let mut ec_params: Option<Vec<u8>> = None;
    let mut raw_value: Option<Vec<u8>> = None;

    for attr in attrs {
        if attr.pValue.is_null() {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        let bytes = std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize);
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
            CKA_WRAP => wrap = Some(bytes.first().copied().unwrap_or(0) != 0),
            CKA_UNWRAP => unwrap = Some(bytes.first().copied().unwrap_or(0) != 0),
            CKA_SIGN => sign = Some(bytes.first().copied().unwrap_or(0) != 0),
            CKA_VERIFY => verify = Some(bytes.first().copied().unwrap_or(0) != 0),
            CKA_DERIVE => derive = Some(bytes.first().copied().unwrap_or(0) != 0),
            CKA_EC_PARAMS => ec_params = Some(bytes.to_vec()),
            CKA_VALUE => raw_value = Some(bytes.to_vec()),
            _ => {}
        }
    }

    let mut st = harness_state().lock().unwrap();
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
                if params != ED25519_OID_DER && params != ED25519_CURVE_NAME_DER {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                let Some(val) = &raw_value else {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                };
                if val.len() == 32 {
                    key_material.copy_from_slice(val);
                } else if val.len() == 34 && &val[..2] == &DER_OCTET_STRING_32_PREFIX {
                    key_material.copy_from_slice(&val[2..]);
                } else {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
            }
            _ => return CKR_ATTRIBUTE_VALUE_INVALID,
        }
    } else if class == Some(CKO_SECRET_KEY) {
        if let Some(val) = &raw_value {
            if val.len() == 32 {
                key_material.copy_from_slice(val);
            }
        }
    }

    let h = st.next_object_handle;
    st.next_object_handle += 1;
    st.objects.push(HarnessPkcs11Object {
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
        wrap: wrap.or(Some(false)),
        unwrap: unwrap.or(Some(false)),
        sign: sign.or(Some(false)),
        verify: verify.or(Some(false)),
        derive: derive.or(Some(false)),
        ec_params,
        key_material,
    });
    *object = h;
    CKR_OK
}

unsafe extern "C" fn h_destroy_object(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> CK_RV {
    let mut st = harness_state().lock().unwrap();
    st.objects.retain(|o| o.handle != object);
    st.destroyed_objects.push(object);
    CKR_OK
}

unsafe extern "C" fn h_get_attribute_value(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    if count > 0 && template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let st = harness_state().lock().unwrap();
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
                    let dst = std::slice::from_raw_parts_mut(attr.pValue as *mut u8, bytes.len());
                    dst.copy_from_slice(&bytes);
                    attr.ulValueLen = bytes.len() as CK_ULONG;
                }
            }
        }
    }
    status
}

unsafe extern "C" fn h_find_objects_init(
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
    let mut st = harness_state().lock().unwrap();
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

unsafe extern "C" fn h_find_objects(
    _session: CK_SESSION_HANDLE,
    ph_object: CK_OBJECT_HANDLE_PTR,
    ul_max_object_count: CK_ULONG,
    pul_object_count: CK_ULONG_PTR,
) -> CK_RV {
    if ph_object.is_null() || pul_object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
    let remaining = st.find_matches.len().saturating_sub(st.find_cursor);
    let to_copy = remaining.min(ul_max_object_count as usize);
    for i in 0..to_copy {
        *ph_object.add(i) = st.find_matches[st.find_cursor + i];
    }
    st.find_cursor += to_copy;
    *pul_object_count = to_copy as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn h_find_objects_final(_session: CK_SESSION_HANDLE) -> CK_RV {
    let mut st = harness_state().lock().unwrap();
    st.find_matches.clear();
    st.find_cursor = 0;
    CKR_OK
}

unsafe extern "C" fn h_encrypt_init(
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
    let mut st = harness_state().lock().unwrap();
    if !st.supported_mechanisms.contains(&CKM_AES_GCM) {
        return CKR_MECHANISM_INVALID;
    }
    if !st.objects.iter().any(|o| o.handle == key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    st.active_encrypt = Some(HarnessGcmOp {
        key_handle: key,
        iv,
        aad,
        tag_len: (gcm.ulTagBits / 8) as usize,
    });
    CKR_OK
}

unsafe extern "C" fn h_encrypt(
    _session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_encrypted_data: CK_BYTE_PTR,
    pul_encrypted_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_data.is_null() || pul_encrypted_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
    let Some(op) = st.active_encrypt.clone() else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    let out_len = (ul_data_len as usize) + op.tag_len;
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
    let ciphertext = harness_gcm_xor(&key_obj.key_material, &op.iv, plaintext);
    let tag = harness_gcm_tag(
        &key_obj.key_material,
        &op.iv,
        &op.aad,
        &ciphertext,
        op.tag_len,
    );
    let mut combined = Vec::with_capacity(out_len);
    combined.extend_from_slice(&ciphertext);
    combined.extend_from_slice(&tag);
    let dst = std::slice::from_raw_parts_mut(p_encrypted_data, out_len);
    dst.copy_from_slice(&combined);
    *pul_encrypted_data_len = out_len as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn h_decrypt_init(
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
    let mut st = harness_state().lock().unwrap();
    if !st.supported_mechanisms.contains(&CKM_AES_GCM) {
        return CKR_MECHANISM_INVALID;
    }
    if !st.objects.iter().any(|o| o.handle == key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    st.active_decrypt = Some(HarnessGcmOp {
        key_handle: key,
        iv,
        aad,
        tag_len: (gcm.ulTagBits / 8) as usize,
    });
    CKR_OK
}

unsafe extern "C" fn h_decrypt(
    _session: CK_SESSION_HANDLE,
    p_encrypted_data: CK_BYTE_PTR,
    ul_encrypted_data_len: CK_ULONG,
    p_data: CK_BYTE_PTR,
    pul_data_len: CK_ULONG_PTR,
) -> CK_RV {
    if p_encrypted_data.is_null() || pul_data_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
    let Some(op) = st.active_decrypt.clone() else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if (ul_encrypted_data_len as usize) < op.tag_len {
        st.active_decrypt = None;
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    let plaintext_len = (ul_encrypted_data_len as usize) - op.tag_len;
    if p_data.is_null() {
        *pul_data_len = plaintext_len as CK_ULONG;
        return CKR_OK;
    }
    if (*pul_data_len as usize) < plaintext_len {
        *pul_data_len = plaintext_len as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    st.active_decrypt = None;
    let Some(key_obj) = st.objects.iter().find(|o| o.handle == op.key_handle) else {
        return CKR_KEY_HANDLE_INVALID;
    };
    let enc_slice = std::slice::from_raw_parts(p_encrypted_data, ul_encrypted_data_len as usize);
    let ciphertext = &enc_slice[..plaintext_len];
    let provided_tag = &enc_slice[plaintext_len..];
    let expected_tag = harness_gcm_tag(
        &key_obj.key_material,
        &op.iv,
        &op.aad,
        ciphertext,
        op.tag_len,
    );
    if provided_tag != expected_tag.as_slice() {
        *pul_data_len = 0;
        return CKR_ENCRYPTED_DATA_INVALID;
    }
    let plaintext = harness_gcm_xor(&key_obj.key_material, &op.iv, ciphertext);
    let dst = std::slice::from_raw_parts_mut(p_data, plaintext_len);
    dst.copy_from_slice(&plaintext);
    *pul_data_len = plaintext_len as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn h_sign_init(
    _session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = &*mechanism;
    let mut st = harness_state().lock().unwrap();
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
    st.active_sign = Some(HarnessSignOp {
        key_handle: key,
        mechanism: mech.mechanism,
    });
    CKR_OK
}

unsafe extern "C" fn h_sign(
    _session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if (ul_data_len > 0 && p_data.is_null()) || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
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
            let Ok(signing_key) = K256SigningKey::from_bytes((&key_obj.key_material).into()) else {
                return CKR_FUNCTION_FAILED;
            };
            let Ok(sig): Result<K256Signature, _> = signing_key.sign_prehash(input) else {
                return CKR_FUNCTION_FAILED;
            };
            sig.to_bytes().into()
        }
        CKM_EDDSA => {
            let signing_key = DalekSigningKey::from_bytes(&key_obj.key_material);
            signing_key.sign(input).to_bytes()
        }
        _ => return CKR_MECHANISM_INVALID,
    };
    let dst = std::slice::from_raw_parts_mut(p_signature, sig_len);
    dst.copy_from_slice(&sig_bytes);
    sig_bytes.zeroize();
    *pul_signature_len = sig_len as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn h_generate_random(
    _session: CK_SESSION_HANDLE,
    random_data: CK_BYTE_PTR,
    random_len: CK_ULONG,
) -> CK_RV {
    if random_data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut st = harness_state().lock().unwrap();
    st.rng_calls += 1;
    let call_idx = st.rng_calls as u8;
    let out = std::slice::from_raw_parts_mut(random_data, random_len as usize);
    for (i, b) in out.iter_mut().enumerate() {
        *b = call_idx.wrapping_mul(41).wrapping_add(i as u8) ^ 0x3c;
    }
    CKR_OK
}

static mut HARNESS_FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(h_initialize),
    C_Finalize: Some(h_finalize),
    C_GetInfo: None,
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(h_get_slot_list),
    C_GetSlotInfo: None,
    C_GetTokenInfo: Some(h_get_token_info),
    C_GetMechanismList: Some(h_get_mechanism_list),
    C_GetMechanismInfo: None,
    C_InitToken: Some(h_init_token),
    C_InitPIN: Some(h_init_pin),
    C_SetPIN: None,
    C_OpenSession: Some(h_open_session),
    C_CloseSession: Some(h_close_session),
    C_CloseAllSessions: None,
    C_GetSessionInfo: Some(h_get_session_info),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(h_login),
    C_Logout: Some(h_logout),
    C_CreateObject: Some(h_create_object),
    C_CopyObject: None,
    C_DestroyObject: Some(h_destroy_object),
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(h_get_attribute_value),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(h_find_objects_init),
    C_FindObjects: Some(h_find_objects),
    C_FindObjectsFinal: Some(h_find_objects_final),
    C_EncryptInit: Some(h_encrypt_init),
    C_Encrypt: Some(h_encrypt),
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: Some(h_decrypt_init),
    C_Decrypt: Some(h_decrypt),
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(h_sign_init),
    C_Sign: Some(h_sign),
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
    C_GenerateKey: Some(h_generate_key),
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: Some(h_generate_random),
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = std::ptr::addr_of_mut!(HARNESS_FUNCTION_LIST) as CK_FUNCTION_LIST_PTR;
    CKR_OK
}

// ============================================================================
// Test Environment Setup (Live SoftHSMv2 when available, or `:self:` harness)
// ============================================================================

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

struct HsmTestEnv {
    module_path: PathBuf,
    pin_file: PathBuf,
    identity_key_file: PathBuf,
    is_live_softhsm: bool,
}

fn setup_active_hsm_env() -> &'static HsmTestEnv {
    static ENV: OnceLock<HsmTestEnv> = OnceLock::new();
    ENV.get_or_init(|| {
        let _keep = C_GetFunctionList as *const () as usize;
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let base_dir = std::env::temp_dir().join(format!(
            "polyglot_hsm_itest_{}_{}",
            std::process::id(),
            id
        ));
        fs::create_dir_all(&base_dir).expect("create temp test dir");

        let pin_file = base_dir.join("softhsm_user.pin");
        {
            let mut f = File::create(&pin_file).expect("create pin file");
            f.write_all(b"test-softhsm-pin-1234\n")
                .expect("write pin file");
        }
        let identity_key_file = base_dir.join("signer_identity.key");

        let explicit_mod = std::env::var("PKCS11_MODULE_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from);

        if let Ok(real_softhsm_path) = resolve_softhsm_module_path(explicit_mod.as_deref()) {
            // Configure isolated SoftHSMv2 token directory & softhsm2.conf if not already set
            if std::env::var("SOFTHSM2_CONF").is_err() {
                let tokens_dir = base_dir.join("tokens");
                fs::create_dir_all(&tokens_dir).expect("create tokens dir");
                let conf_path = base_dir.join("softhsm2.conf");
                let conf_contents = format!(
                    "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                    tokens_dir.display()
                );
                fs::write(&conf_path, conf_contents).expect("write softhsm2.conf");
                std::env::set_var("SOFTHSM2_CONF", &conf_path);
            }

            HsmTestEnv {
                module_path: real_softhsm_path,
                pin_file,
                identity_key_file,
                is_live_softhsm: true,
            }
        } else {
            HsmTestEnv {
                module_path: PathBuf::from(SELF_MODULE_PATH),
                pin_file,
                identity_key_file,
                is_live_softhsm: false,
            }
        }
    })
}

fn active_pkcs11_config(env: &HsmTestEnv) -> Pkcs11Config {
    Pkcs11Config::with_pin_file(
        &env.module_path,
        SlotSelector::from_label(DEFAULT_TOKEN_LABEL),
        &env.pin_file,
    )
}

#[derive(Debug, Deserialize)]
struct Bip32VectorFile {
    seed: String,
    chains: Vec<VectorChain>,
}

#[derive(Debug, Deserialize)]
struct Slip10VectorFile {
    seed: String,
    chains: Vec<VectorChain>,
}

#[derive(Debug, Deserialize)]
struct VectorChain {
    path: String,
    public_key: String,
}

fn vectors_dir() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let parent_vectors = manifest_dir.parent().unwrap().join("vectors");
    if parent_vectors.exists() {
        parent_vectors
    } else {
        manifest_dir.join("vectors")
    }
}

// ============================================================================
// Integration Test Suite
// ============================================================================

#[test]
fn test_hsm_bootstrap_and_startup_probe_capabilities() {
    let _serial = integration_lock().lock().unwrap();
    let env = setup_active_hsm_env();
    if !env.is_live_softhsm {
        harness_state().lock().unwrap().reset();
        harness_state().lock().unwrap().token_initialized = false;
    }

    let bootstrap_cfg = BootstrapConfig::with_pin_file(
        &env.module_path,
        DEFAULT_TOKEN_LABEL,
        &env.pin_file,
        DEFAULT_KEK_LABEL,
        &env.identity_key_file,
    );

    let report1 = run_bootstrap(bootstrap_cfg.clone()).expect("bootstrap token, KEK, and identity");
    println!(
        "[HSM Integration] Bootstrapped PKCS#11 module '{}' (live_softhsm={}): {:?}",
        env.module_path.display(),
        env.is_live_softhsm,
        report1
    );

    assert_eq!(report1.token_label, DEFAULT_TOKEN_LABEL);
    assert_eq!(report1.kek_label, DEFAULT_KEK_LABEL);
    assert_eq!(report1.identity_public_key_hex.len(), 64);
    assert!(env.identity_key_file.exists());

    // Second run is idempotent
    let report2 = run_bootstrap(bootstrap_cfg).expect("idempotent second bootstrap run");
    assert!(!report2.token_initialized_now);
    assert!(!report2.kek_created_now);
    assert!(!report2.identity_key_created_now);
    assert_eq!(
        report1.identity_public_key_hex,
        report2.identity_public_key_hex
    );

    let backend = GenericBackend::from_pkcs11_config(active_pkcs11_config(env))
        .expect("construct GenericBackend after bootstrap");
    let probe_rep = backend.probe_report();
    println!(
        "[HSM Integration] Probe Report -> secp256k1: {:?} (fallback={:?}), ed25519: {:?} (fallback={:?})",
        probe_rep.secp256k1_outcome.signing_location,
        probe_rep.secp256k1_outcome.hsm_fallback_reason,
        probe_rep.ed25519_outcome.signing_location,
        probe_rep.ed25519_outcome.hsm_fallback_reason
    );

    let caps = backend.capabilities().expect("capabilities");
    assert_eq!(caps.backend, DEFAULT_GENERIC_BACKEND_NAME);
    assert_eq!(caps.protection_level, ProtectionLevel::GenericDev);
    assert_eq!(caps.max_depth, MAX_DEPTH as u8);
    assert_eq!(caps.wrap_mechanism, DEFAULT_WRAP_MECHANISM_NAME);
    assert!(!caps.derives_in_hsm);
    assert_eq!(caps.schemes.len(), 2);
}

#[test]
fn test_hsm_wallet_lifecycle_and_published_vectors_through_backend() {
    let _serial = integration_lock().lock().unwrap();
    let env = setup_active_hsm_env();
    if !env.is_live_softhsm {
        harness_state().lock().unwrap().reset();
    } else {
        let _ = run_bootstrap(BootstrapConfig::with_pin_file(
            &env.module_path,
            DEFAULT_TOKEN_LABEL,
            &env.pin_file,
            DEFAULT_KEK_LABEL,
            &env.identity_key_file,
        ))
        .expect("ensure bootstrapped");
    }

    let backend = GenericBackend::from_pkcs11_config(active_pkcs11_config(env))
        .expect("construct GenericBackend");
    let caps = backend.capabilities().unwrap();
    let expected_secp_in_hsm = caps
        .signing_location(Scheme::Bip32, Curve::Secp256k1)
        .unwrap()
        .is_hsm();
    let expected_ed_in_hsm = caps
        .signing_location(Scheme::Slip10, Curve::Ed25519)
        .unwrap()
        .is_hsm();

    // 1. Create BIP32/secp256k1 wallet & sign Digest32 and TaprootDigest32
    let bip32_aad = build_aad_checked(
        "w_itest_bip32",
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let bip32_wrapped = backend
        .create_wallet(&Spec::new(Scheme::Bip32, Curve::Secp256k1), &bip32_aad)
        .expect("create_wallet bip32");
    assert_eq!(bip32_wrapped.len(), WRAPPED_SEED_LEN);

    let bip32_ref = WalletRef::new(
        &bip32_wrapped,
        &bip32_aad,
        Scheme::Bip32,
        Curve::Secp256k1,
    );
    let path_secp = [
        44 | HARDENED_FLAG,
        60 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0,
        0,
    ];
    let pub_secp = backend
        .public_key(&bip32_ref, &path_secp)
        .expect("derive secp256k1 pubkey");
    assert_eq!(pub_secp.len(), COMPRESSED_PUBKEY_LEN);

    let digest_ga = Sha256::digest(b"milestone-2-hsm-integration-digest");
    let mut digest32 = [0u8; 32];
    digest32.copy_from_slice(&digest_ga);

    let sig_secp = backend
        .sign(&bip32_ref, &path_secp, SigningInput::Digest32(&digest32))
        .expect("sign secp256k1 digest");
    assert_eq!(sig_secp.signing_in_hsm, expected_secp_in_hsm);
    assert!(is_low_s(&sig_secp.s.unwrap()).unwrap());
    let pub_secp_arr: [u8; 33] = pub_secp.try_into().unwrap();
    let sig_secp_arr: [u8; 64] = sig_secp.as_bytes().try_into().unwrap();
    verify_secp256k1_ecdsa(&pub_secp_arr, &digest32, &sig_secp_arr)
        .expect("verify secp256k1 ECDSA signature");

    // Taproot BIP340 Schnorr always signs in software (`signing_in_hsm == false`)
    let taproot_sig = backend
        .sign(
            &bip32_ref,
            &[86 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0, 0],
            SigningInput::TaprootDigest32(&digest32),
        )
        .expect("sign taproot digest");
    assert!(!taproot_sig.signing_in_hsm);
    let tr_pub: [u8; 32] = taproot_sig.public_key.clone().try_into().unwrap();
    let tr_sig: [u8; 64] = taproot_sig.as_bytes().try_into().unwrap();
    verify_bip340_schnorr(&tr_pub, &digest32, &tr_sig).expect("verify Taproot Schnorr signature");

    // 2. Create SLIP10/ed25519 wallet & sign Message
    let slip10_aad = build_aad_checked(
        "w_itest_slip10",
        Scheme::Slip10,
        Curve::Ed25519,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let slip10_wrapped = backend
        .create_wallet(&Spec::new(Scheme::Slip10, Curve::Ed25519), &slip10_aad)
        .expect("create_wallet slip10");
    assert_eq!(slip10_wrapped.len(), WRAPPED_SEED_LEN);

    let slip10_ref = WalletRef::new(
        &slip10_wrapped,
        &slip10_aad,
        Scheme::Slip10,
        Curve::Ed25519,
    );
    let path_ed = [
        44 | HARDENED_FLAG,
        501 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
        0 | HARDENED_FLAG,
    ];
    let pub_ed = backend
        .public_key(&slip10_ref, &path_ed)
        .expect("derive ed25519 pubkey");
    assert_eq!(pub_ed.len(), ED25519_PUBKEY_LEN);

    let msg = b"milestone-2-solana-transfer-message";
    let sig_ed = backend
        .sign(&slip10_ref, &path_ed, SigningInput::Message(msg))
        .expect("sign ed25519 message");
    assert_eq!(sig_ed.signing_in_hsm, expected_ed_in_hsm);
    let pub_ed_arr: [u8; 32] = pub_ed.try_into().unwrap();
    let sig_ed_arr: [u8; 64] = sig_ed.as_bytes().try_into().unwrap();
    verify_ed25519_signature(&pub_ed_arr, msg, &sig_ed_arr).expect("verify Ed25519 signature");

    // 3. Verify published 64-byte BIP32 Vector 2 and SLIP10 Vector 2 seeds wrapped in the HSM
    let bip32_vecs: Vec<Bip32VectorFile> = serde_json::from_str(
        &fs::read_to_string(vectors_dir().join("bip32.json")).expect("read vectors/bip32.json"),
    )
    .expect("parse vectors/bip32.json");

    for (idx, tv) in bip32_vecs.iter().enumerate() {
        let seed_bytes = hex::decode(&tv.seed).unwrap();
        if seed_bytes.len() == WALLET_SEED_LEN {
            let tv_aad = build_aad_checked(
                &format!("w_bip32_tv_{idx}"),
                Scheme::Bip32,
                Curve::Secp256k1,
                DEFAULT_SEED_VERSION,
                DEFAULT_KEK_LABEL,
            )
            .unwrap();
            let wrapped_tv = backend
                .library()
                .wrap_seed(&seed_bytes, &tv_aad)
                .expect("wrap 64B BIP32 vector seed");
            let w_ref = WalletRef::new(&wrapped_tv, &tv_aad, Scheme::Bip32, Curve::Secp256k1);
            for chain in &tv.chains {
                let dp = DerivationPath::parse_str(&chain.path).unwrap();
                let derived_pub = backend
                    .public_key(&w_ref, dp.as_slice())
                    .expect("derive BIP32 vector pubkey via Backend");
                assert_eq!(hex::encode(derived_pub), chain.public_key.to_lowercase());
            }
        }
    }

    let slip10_vecs: Vec<Slip10VectorFile> = serde_json::from_str(
        &fs::read_to_string(vectors_dir().join("slip10.json")).expect("read vectors/slip10.json"),
    )
    .expect("parse vectors/slip10.json");

    for (idx, tv) in slip10_vecs.iter().enumerate() {
        let seed_bytes = hex::decode(&tv.seed).unwrap();
        if seed_bytes.len() == WALLET_SEED_LEN {
            let tv_aad = build_aad_checked(
                &format!("w_slip10_tv_{idx}"),
                Scheme::Slip10,
                Curve::Ed25519,
                DEFAULT_SEED_VERSION,
                DEFAULT_KEK_LABEL,
            )
            .unwrap();
            let wrapped_tv = backend
                .library()
                .wrap_seed(&seed_bytes, &tv_aad)
                .expect("wrap 64B SLIP10 vector seed");
            let w_ref = WalletRef::new(&wrapped_tv, &tv_aad, Scheme::Slip10, Curve::Ed25519);
            for chain in &tv.chains {
                let dp = DerivationPath::parse_str(&chain.path).unwrap();
                let derived_pub = backend
                    .public_key(&w_ref, dp.as_slice())
                    .expect("derive SLIP10 vector pubkey via Backend");
                assert_eq!(hex::encode(derived_pub), chain.public_key.to_lowercase());
            }
        }
    }
}

#[test]
fn test_hsm_wrapping_tamper_cases_fail_closed() {
    let _serial = integration_lock().lock().unwrap();
    let env = setup_active_hsm_env();
    if !env.is_live_softhsm {
        harness_state().lock().unwrap().reset();
    } else {
        let _ = run_bootstrap(BootstrapConfig::with_pin_file(
            &env.module_path,
            DEFAULT_TOKEN_LABEL,
            &env.pin_file,
            DEFAULT_KEK_LABEL,
            &env.identity_key_file,
        ))
        .expect("ensure bootstrapped");
    }

    let backend = GenericBackend::from_pkcs11_config(active_pkcs11_config(env))
        .expect("construct GenericBackend");

    let spec = Spec::new(Scheme::Bip32, Curve::Secp256k1);
    let aad_alice = build_aad_checked(
        "w_alice",
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let aad_bob = build_aad_checked(
        "w_bob",
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();

    let wrapped_alice = backend
        .create_wallet(&spec, &aad_alice)
        .expect("create alice wallet");
    let wrapped_bob = backend
        .create_wallet(&spec, &aad_bob)
        .expect("create bob wallet");

    let path = [44 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0, 0];
    let digest = [0x11u8; 32];

    // 1. Tampered IV (byte 0)
    let mut bad_iv = wrapped_alice.clone();
    bad_iv[0] ^= 0x80;
    let ref_bad_iv = WalletRef::new(&bad_iv, &aad_alice, Scheme::Bip32, Curve::Secp256k1);
    assert!(matches!(
        backend.public_key(&ref_bad_iv, &path),
        Err(BackendError::UnwrapFailed(_))
    ));
    assert!(matches!(
        backend.sign(&ref_bad_iv, &path, SigningInput::Digest32(&digest)),
        Err(BackendError::UnwrapFailed(_))
    ));

    // 2. Tampered ciphertext (byte 20)
    let mut bad_ct = wrapped_alice.clone();
    bad_ct[AES_GCM_IV_LEN + 8] ^= 0x01;
    let ref_bad_ct = WalletRef::new(&bad_ct, &aad_alice, Scheme::Bip32, Curve::Secp256k1);
    assert!(matches!(
        backend.public_key(&ref_bad_ct, &path),
        Err(BackendError::UnwrapFailed(_))
    ));
    assert!(matches!(
        backend.sign(&ref_bad_ct, &path, SigningInput::Digest32(&digest)),
        Err(BackendError::UnwrapFailed(_))
    ));

    // 3. Tampered authentication tag (last byte)
    let mut bad_tag = wrapped_alice.clone();
    bad_tag[WRAPPED_SEED_LEN - 1] ^= 0x01;
    let ref_bad_tag = WalletRef::new(&bad_tag, &aad_alice, Scheme::Bip32, Curve::Secp256k1);
    assert!(matches!(
        backend.public_key(&ref_bad_tag, &path),
        Err(BackendError::UnwrapFailed(_))
    ));

    // 4. Truncated / oversized wrapped seed blob
    let ref_truncated = WalletRef::new(
        &wrapped_alice[..WRAPPED_SEED_LEN - 1],
        &aad_alice,
        Scheme::Bip32,
        Curve::Secp256k1,
    );
    assert!(matches!(
        backend.public_key(&ref_truncated, &path),
        Err(BackendError::InvalidWrappedSeed(_))
    ));

    // 5. Wrong AAD (different seed_version or wallet_id)
    let wrong_version_aad = build_aad_checked(
        "w_alice",
        Scheme::Bip32,
        Curve::Secp256k1,
        2,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let ref_wrong_aad = WalletRef::new(
        &wrapped_alice,
        &wrong_version_aad,
        Scheme::Bip32,
        Curve::Secp256k1,
    );
    assert!(matches!(
        backend.public_key(&ref_wrong_aad, &path),
        Err(BackendError::UnwrapFailed(_))
    ));

    // 6. Swapped wallet blob (Bob's wrapped seed presented with Alice's AAD)
    let ref_swapped = WalletRef::new(&wrapped_bob, &aad_alice, Scheme::Bip32, Curve::Secp256k1);
    assert!(matches!(
        backend.public_key(&ref_swapped, &path),
        Err(BackendError::UnwrapFailed(_))
    ));
    assert!(matches!(
        backend.sign(&ref_swapped, &path, SigningInput::Digest32(&digest)),
        Err(BackendError::UnwrapFailed(_))
    ));

    // 7. Missing KEK on unwrap
    let session = backend.open_session().expect("open session");
    let missing_kek_err = signer::pkcs11session::unwrap_seed_with_kek_label(
        &session,
        "kek-nonexistent-v99",
        &wrapped_alice,
        &aad_alice,
    )
    .unwrap_err();
    assert!(matches!(missing_kek_err, BackendError::KekNotFound(_)));
    session.close();
}

#[test]
fn test_hsm_session_object_hygiene_normal_and_forced_errors() {
    let _serial = integration_lock().lock().unwrap();
    let env = setup_active_hsm_env();
    if !env.is_live_softhsm {
        harness_state().lock().unwrap().reset();
    } else {
        let _ = run_bootstrap(BootstrapConfig::with_pin_file(
            &env.module_path,
            DEFAULT_TOKEN_LABEL,
            &env.pin_file,
            DEFAULT_KEK_LABEL,
            &env.identity_key_file,
        ))
        .expect("ensure bootstrapped");
    }

    let backend = GenericBackend::from_pkcs11_config(active_pkcs11_config(env))
        .expect("construct GenericBackend");

    let bip32_aad = build_aad_checked(
        "w_hygiene_bip32",
        Scheme::Bip32,
        Curve::Secp256k1,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let bip32_wrapped = backend
        .create_wallet(&Spec::new(Scheme::Bip32, Curve::Secp256k1), &bip32_aad)
        .unwrap();
    let bip32_ref = WalletRef::new(
        &bip32_wrapped,
        &bip32_aad,
        Scheme::Bip32,
        Curve::Secp256k1,
    );

    let slip10_aad = build_aad_checked(
        "w_hygiene_slip10",
        Scheme::Slip10,
        Curve::Ed25519,
        DEFAULT_SEED_VERSION,
        DEFAULT_KEK_LABEL,
    )
    .unwrap();
    let slip10_wrapped = backend
        .create_wallet(&Spec::new(Scheme::Slip10, Curve::Ed25519), &slip10_aad)
        .unwrap();
    let slip10_ref = WalletRef::new(
        &slip10_wrapped,
        &slip10_aad,
        Scheme::Slip10,
        Curve::Ed25519,
    );

    let digest = [0x33u8; 32];
    let _ = backend
        .sign(
            &bip32_ref,
            &[44 | HARDENED_FLAG, 0 | HARDENED_FLAG, 0, 0, 0],
            SigningInput::Digest32(&digest),
        )
        .expect("normal secp256k1 sign");
    let _ = backend
        .sign(
            &slip10_ref,
            &[44 | HARDENED_FLAG, 501 | HARDENED_FLAG, 0 | HARDENED_FLAG],
            SigningInput::Message(b"normal ed25519 sign"),
        )
        .expect("normal ed25519 sign");

    // Forced error 1: SLIP10 non-hardened child index
    assert!(backend
        .sign(
            &slip10_ref,
            &[44 | HARDENED_FLAG, 501],
            SigningInput::Message(b"bad path"),
        )
        .is_err());

    // Forced error 2: Depth > 255
    let too_deep = vec![HARDENED_FLAG; 256];
    assert!(backend
        .sign(&bip32_ref, &too_deep, SigningInput::Digest32(&digest))
        .is_err());

    // Forced error 3: Tampered blob during sign
    let mut tampered = bip32_wrapped.clone();
    tampered[25] ^= 0xff;
    let bad_ref = WalletRef::new(&tampered, &bip32_aad, Scheme::Bip32, Curve::Secp256k1);
    assert!(backend
        .sign(
            &bad_ref,
            &[44 | HARDENED_FLAG, 0 | HARDENED_FLAG],
            SigningInput::Digest32(&digest),
        )
        .is_err());

    // Verify on live token session that C_FindObjects (CKA_TOKEN = false) lists 0 session objects
    let check_session = backend.open_session().expect("open hygiene check session");
    assert_eq!(
        count_session_objects(&check_session).expect("count session objects"),
        0,
        "token must have zero leftover session objects after normal and forced-error requests"
    );
    check_session.close();

    // Also test forced C_Sign failure mid-request (after session key object import) on the harness
    harness_state().lock().unwrap().reset();
    let harness_cfg = Pkcs11Config::with_loaded_pin(
        SELF_MODULE_PATH,
        SlotSelector::from_id(HARNESS_SLOT_ID as u64),
        Zeroizing::new(String::from_utf8(HARNESS_DEFAULT_PIN.to_vec()).unwrap()),
        DEFAULT_KEK_LABEL,
    );
    let harness_backend =
        GenericBackend::from_pkcs11_config(harness_cfg).expect("init harness backend");
    let h_wrapped = harness_backend
        .create_wallet(&Spec::new(Scheme::Bip32, Curve::Secp256k1), &bip32_aad)
        .unwrap();
    let h_ref = WalletRef::new(&h_wrapped, &bip32_aad, Scheme::Bip32, Curve::Secp256k1);

    harness_state().lock().unwrap().force_sign_error = true;
    let sign_err = harness_backend
        .sign(
            &h_ref,
            &[44 | HARDENED_FLAG, 0 | HARDENED_FLAG],
            SigningInput::Digest32(&digest),
        )
        .unwrap_err();
    assert!(matches!(sign_err, BackendError::Pkcs11(_)));

    harness_state().lock().unwrap().force_sign_error = false;
    let h_session = harness_backend.open_session().unwrap();
    assert_eq!(count_session_objects(&h_session).unwrap(), 0);
    h_session.close();
}

#[test]
fn test_hsm_startup_probe_failures_and_curve_fallbacks() {
    let _serial = integration_lock().lock().unwrap();
    let env = setup_active_hsm_env();

    // 1. Missing PKCS#11 library -> fail closed at Step 1
    let missing_lib_cfg = ProbeConfig::new(Pkcs11Config::with_loaded_pin(
        "/nonexistent/path/to/libsofthsm2.so",
        SlotSelector::from_id(0),
        Zeroizing::new("pin".to_string()),
        DEFAULT_KEK_LABEL,
    ));
    let err_missing_lib = run_startup_probe_checked(missing_lib_cfg).unwrap_err();
    assert_eq!(err_missing_lib.step, ProbeStep::Step1LibraryAndToken);
    assert_eq!(err_missing_lib.code, ProbeFailureCode::LibraryOrSlotFailed);

    // 2. Missing KEK on live/active PKCS#11 module -> fail closed at Step 3
    let missing_kek_cfg = ProbeConfig::new(Pkcs11Config::new(
        &env.module_path,
        SlotSelector::from_label(DEFAULT_TOKEN_LABEL),
        &env.pin_file,
        "kek-does-not-exist",
    ));
    let err_missing_kek = run_startup_probe_checked(missing_kek_cfg).unwrap_err();
    assert_eq!(err_missing_kek.step, ProbeStep::Step3KekValidation);
    assert_eq!(err_missing_kek.code, ProbeFailureCode::KekNotFound);

    // 3. Extractable KEK (`CKA_EXTRACTABLE = true`) on live/active PKCS#11 module -> fail closed at Step 3
    {
        let extractable_label = "kek-extractable-bad";
        let lib = Pkcs11Library::open(Pkcs11Config::new(
            &env.module_path,
            SlotSelector::from_label(DEFAULT_TOKEN_LABEL),
            &env.pin_file,
            extractable_label,
        ))
        .expect("open library for extractable KEK test");
        let session = lib.open_rw_session().expect("open session");

        // Create an extractable AES key on the token/session and verify probe refuses to start with it
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Label(extractable_label.as_bytes().to_vec()),
            Attribute::Value(vec![0x42u8; 32]),
        ];
        let bad_handle = session
            .raw()
            .create_object(&template)
            .expect("create extractable test KEK object");

        let bad_kek_probe = signer::backend::generic::probe_step3_validate_kek(&session);
        let _ = session.raw().destroy_object(bad_handle);
        session.close();

        let bad_kek_failure = bad_kek_probe.unwrap_err();
        assert_eq!(bad_kek_failure.step, ProbeStep::Step3KekValidation);
        assert_eq!(
            bad_kek_failure.code,
            ProbeFailureCode::InvalidKekAttributes
        );
        assert_eq!(
            extract_probe_failure_code(&bad_kek_failure.to_backend_error()),
            Some(ProbeFailureCode::InvalidKekAttributes)
        );
    }

    // 4. Missing CKM_AES_GCM in C_GetMechanismList -> fail closed at Step 2
    harness_state().lock().unwrap().reset();
    harness_state().lock().unwrap().supported_mechanisms = vec![CKM_ECDSA, CKM_EDDSA];
    let no_gcm_cfg = ProbeConfig::new(Pkcs11Config::with_loaded_pin(
        SELF_MODULE_PATH,
        SlotSelector::from_id(HARNESS_SLOT_ID as u64),
        Zeroizing::new(String::from_utf8(HARNESS_DEFAULT_PIN.to_vec()).unwrap()),
        DEFAULT_KEK_LABEL,
    ));
    let err_no_gcm = run_startup_probe_checked(no_gcm_cfg).unwrap_err();
    assert_eq!(err_no_gcm.step, ProbeStep::Step2AesGcmMechanismAndSelfTest);
    assert_eq!(err_no_gcm.code, ProbeFailureCode::MissingAesGcmMechanism);

    // 5. Missing curve in HSM -> starts cleanly, marks scheme as Software, and signs with signing_in_hsm=false
    harness_state().lock().unwrap().reset();
    harness_state().lock().unwrap().reject_secp256k1_import = true;
    let fallback_backend = GenericBackend::from_pkcs11_config(Pkcs11Config::with_loaded_pin(
        SELF_MODULE_PATH,
        SlotSelector::from_id(HARNESS_SLOT_ID as u64),
        Zeroizing::new(String::from_utf8(HARNESS_DEFAULT_PIN.to_vec()).unwrap()),
        DEFAULT_KEK_LABEL,
    ))
    .expect("GenericBackend must start when a curve falls back to software");

    assert_eq!(
        fallback_backend.signing_location(Scheme::Bip32, Curve::Secp256k1),
        Some(SigningLocation::Software)
    );
    assert_eq!(
        fallback_backend.signing_location(Scheme::Slip10, Curve::Ed25519),
        Some(SigningLocation::Hsm)
    );
}
