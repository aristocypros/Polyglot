//! HSM ephemeral session-object key loading, PKCS#11 signing (`CKM_ECDSA` / `CKM_EDDSA`),
//! and session-object hygiene enforcement (`SessionKeyGuard`, `count_session_objects`).
//!
//! Implements Task 09 of the generic PKCS#11 backend (Section 4, Section 8, and Section 10 of `Specs.md`):
//! - Loads a derived 32-byte child private key into the per-request [`Pkcs11Session`] as a
//!   short-lived, non-extractable session object (`CKA_CLASS = CKO_PRIVATE_KEY`,
//!   `CKA_TOKEN = false`, `CKA_PRIVATE = true`, `CKA_SENSITIVE = true`,
//!   `CKA_EXTRACTABLE = false`, `CKA_SIGN = true`):
//!   - `secp256k1`: `CKK_EC` with ANSI X9.62 OID `1.3.132.0.10` (`06 05 2b 81 04 00 0a`) in
//!     `CKA_EC_PARAMS`, signing a 32-byte digest with `CKM_ECDSA`.
//!   - `ed25519`: `CKK_EC_EDWARDS` with RFC 8410 OID `1.3.101.112` (`06 03 2b 65 70`) or
//!     DER PrintableString curve name `"edwards25519"` (`13 0c 65 64 77 61 72 64 73 32 35 35 31 39`)
//!     in `CKA_EC_PARAMS`, signing raw message bytes with `CKM_EDDSA`.
//! - Provides the [`SessionKeyGuard`] RAII guard that invokes `C_DestroyObject` immediately after
//!   `C_Sign` completes AND on any early return, error path, or panic unwinding before the
//!   PKCS#11 session closes.
//! - Provides [`find_session_objects`], [`count_session_objects`], and [`assert_no_session_objects`]
//!   backed by `C_FindObjects` (`CKA_TOKEN = false`) to verify zero leftover session objects.

use std::fmt;

use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{BackendError, Curve};
use crate::derive::{ED25519_PRIVATE_KEY_LEN, PRIVATE_KEY_LEN};
use crate::pkcs11session::{map_pkcs11_err, Pkcs11Session};

/// ASN.1 DER encoding of ANSI X9.62 / SEC 2 OID `1.3.132.0.10` (`secp256k1`) for `CKA_EC_PARAMS`.
///
/// Exact bytes: `06 05 2b 81 04 00 0a` (`OBJECT IDENTIFIER 1.3.132.0.10`).
pub const SECP256K1_OID_DER: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];

/// ASN.1 DER encoding of RFC 8410 OID `1.3.101.112` (`id-Ed25519`) for `CKA_EC_PARAMS`.
///
/// Exact bytes: `06 03 2b 65 70` (`OBJECT IDENTIFIER 1.3.101.112`).
pub const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// ASN.1 DER PrintableString `"edwards25519"` for `CKA_EC_PARAMS` on `CKK_EC_EDWARDS` objects.
///
/// Exact bytes: `13 0c 65 64 77 61 72 64 73 32 35 35 31 39` (`PrintableString "edwards25519"`).
pub const ED25519_CURVE_NAME_DER: [u8; 14] = [
    0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
];

/// Expected byte length of a 32-byte digest signed with `CKM_ECDSA` on `secp256k1`.
pub const SECP256K1_DIGEST_LEN: usize = 32;

/// Expected byte length of a raw PKCS#11 `CKM_ECDSA` signature (`r (32B) || s (32B)`).
pub const ECDSA_RAW_SIGNATURE_LEN: usize = 64;

/// Expected byte length of a PKCS#11 `CKM_EDDSA` Ed25519 signature (`R (32B) || S (32B)`).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// ASN.1 DER OCTET STRING prefix (`04 20`) for a 32-byte private key value (`34` bytes total).
pub const DER_OCTET_STRING_32_PREFIX: [u8; 2] = [0x04, 0x20];

/// Encoding format for `CKA_EC_PARAMS` when creating a `CKK_EC_EDWARDS` (`ed25519`) key object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519EcParamsFormat {
    /// RFC 8410 OID `1.3.101.112` (`06 03 2b 65 70`).
    OidDer,
    /// ASN.1 DER PrintableString `"edwards25519"` (`13 0c 65 64 77 61 72 64 73 32 35 35 31 39`).
    CurveNamePrintableString,
}

impl Ed25519EcParamsFormat {
    /// Returns the raw `CKA_EC_PARAMS` byte slice for this encoding format.
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Ed25519EcParamsFormat::OidDer => &ED25519_OID_DER,
            Ed25519EcParamsFormat::CurveNamePrintableString => &ED25519_CURVE_NAME_DER,
        }
    }
}

/// Encoding format for `CKA_VALUE` when creating a `CKK_EC_EDWARDS` (`ed25519`) private key object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519ValueFormat {
    /// Raw 32-byte Ed25519 private key seed (PKCS#11 v3.0 standard).
    Raw32,
    /// ASN.1 DER OCTET STRING `04 20 || <32-byte seed>` (used by SoftHSMv2 `DERUtil::der2octet` builds).
    DerOctetString34,
}

/// RAII guard for a short-lived PKCS#11 session private key object (`CKA_TOKEN = false`).
///
/// Guarantees that `C_DestroyObject` is called on the underlying [`ObjectHandle`]:
/// 1. Explicitly via [`SessionKeyGuard::destroy`] immediately after `C_Sign` completes.
/// 2. Automatically in [`Drop`] on any early return, error path, or panic unwinding before
///    the parent [`Pkcs11Session`] closes.
pub struct SessionKeyGuard<'a> {
    session: &'a Pkcs11Session,
    handle: ObjectHandle,
    curve: Curve,
    destroyed: bool,
}

impl fmt::Debug for SessionKeyGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeyGuard")
            .field("handle", &self.handle)
            .field("curve", &self.curve)
            .field("destroyed", &self.destroyed)
            .finish()
    }
}

impl<'a> SessionKeyGuard<'a> {
    /// Wraps an newly created ephemeral session key `handle` in a [`SessionKeyGuard`] and registers
    /// it on `session` so it is tracked until destroyed.
    pub fn new(session: &'a Pkcs11Session, handle: ObjectHandle, curve: Curve) -> Self {
        session.track_session_object(handle);
        Self {
            session,
            handle,
            curve,
            destroyed: false,
        }
    }

    /// Returns the underlying PKCS#11 [`ObjectHandle`].
    pub const fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Returns the elliptic [`Curve`] of this session key (`Secp256k1` or `Ed25519`).
    pub const fn curve(&self) -> Curve {
        self.curve
    }

    /// Returns a reference to the parent [`Pkcs11Session`].
    pub const fn session(&self) -> &'a Pkcs11Session {
        self.session
    }

    /// Returns `true` if `C_DestroyObject` has already been invoked for this key guard.
    pub const fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Signs `input` in the HSM using this session key object (`CKM_ECDSA` for `Secp256k1`,
    /// `CKM_EDDSA` for `Ed25519`) without consuming the guard.
    ///
    /// Callers using this method should still call [`SessionKeyGuard::destroy`] immediately after
    /// signing completes (or rely on [`Drop`] on early return). For one-shot import + sign + destroy,
    /// prefer [`sign_secp256k1_digest_in_hsm`] or [`sign_ed25519_message_in_hsm`].
    pub fn sign_raw(&self, input: &[u8]) -> Result<[u8; 64], BackendError> {
        if self.destroyed {
            return Err(BackendError::Pkcs11(
                "cannot sign with an already-destroyed SessionKeyGuard".to_string(),
            ));
        }

        match self.curve {
            Curve::Secp256k1 => {
                if input.len() != SECP256K1_DIGEST_LEN {
                    return Err(BackendError::Crypto(format!(
                        "CKM_ECDSA on secp256k1 requires a {SECP256K1_DIGEST_LEN}-byte digest, got {} bytes",
                        input.len()
                    )));
                }
                let sig_vec = self
                    .session
                    .raw()
                    .sign(&Mechanism::Ecdsa, self.handle, input)
                    .map_err(|err| map_pkcs11_err("C_Sign (CKM_ECDSA)", err))?;

                if sig_vec.len() != ECDSA_RAW_SIGNATURE_LEN {
                    return Err(BackendError::Pkcs11(format!(
                        "C_Sign (CKM_ECDSA) returned {} bytes; expected {ECDSA_RAW_SIGNATURE_LEN} bytes (r || s)",
                        sig_vec.len()
                    )));
                }

                let mut out = [0u8; ECDSA_RAW_SIGNATURE_LEN];
                out.copy_from_slice(&sig_vec);
                Ok(out)
            }
            Curve::Ed25519 => {
                let eddsa_params = EddsaParams::new(EddsaSignatureScheme::Pure);
                let mechanism = Mechanism::Eddsa(eddsa_params);
                let sig_vec = self
                    .session
                    .raw()
                    .sign(&mechanism, self.handle, input)
                    .map_err(|err| map_pkcs11_err("C_Sign (CKM_EDDSA)", err))?;

                if sig_vec.len() != ED25519_SIGNATURE_LEN {
                    return Err(BackendError::Pkcs11(format!(
                        "C_Sign (CKM_EDDSA) returned {} bytes; expected {ED25519_SIGNATURE_LEN} bytes",
                        sig_vec.len()
                    )));
                }

                let mut out = [0u8; ED25519_SIGNATURE_LEN];
                out.copy_from_slice(&sig_vec);
                Ok(out)
            }
        }
    }

    /// Explicitly destroys the session key object via `C_DestroyObject` in place and untracks it
    /// from the parent [`Pkcs11Session`]. Idempotent if called more than once.
    pub fn destroy_in_place(&mut self) -> Result<(), BackendError> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        self.session.destroy_object(self.handle)
    }

    /// Consumes the guard and explicitly destroys the session key object via `C_DestroyObject`.
    pub fn destroy(mut self) -> Result<(), BackendError> {
        self.destroy_in_place()
    }
}

impl Drop for SessionKeyGuard<'_> {
    fn drop(&mut self) {
        if !self.destroyed {
            self.destroyed = true;
            let _ = self.session.destroy_object(self.handle);
        }
    }
}

/// Wipes any secret key material inside `Attribute::Value` buffers of a PKCS#11 attribute template
/// before the template `Vec<Attribute>` is dropped.
fn zeroize_attribute_template(template: &mut [Attribute]) {
    for attr in template.iter_mut() {
        if let Attribute::Value(bytes) = attr {
            let cap = bytes.capacity();
            bytes.resize(cap, 0);
            bytes.zeroize();
        }
    }
}

/// Builds the PKCS#11 attribute template for a short-lived `secp256k1` (`CKK_EC`) session private key:
/// - `CKA_CLASS = CKO_PRIVATE_KEY`
/// - `CKA_KEY_TYPE = CKK_EC`
/// - `CKA_TOKEN = false`
/// - `CKA_PRIVATE = true`
/// - `CKA_SENSITIVE = true`
/// - `CKA_EXTRACTABLE = false`
/// - `CKA_SIGN = true`
/// - `CKA_EC_PARAMS = 06 05 2b 81 04 00 0a` (OID `1.3.132.0.10`)
/// - `CKA_VALUE = <32-byte private scalar>`
fn build_secp256k1_session_key_template(
    private_key: &[u8; PRIVATE_KEY_LEN],
) -> Vec<Attribute> {
    let mut key_vec = Vec::with_capacity(PRIVATE_KEY_LEN);
    key_vec.extend_from_slice(private_key);

    vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::EcParams(SECP256K1_OID_DER.to_vec()),
        Attribute::Value(key_vec),
    ]
}

/// Builds the PKCS#11 attribute template for a short-lived `ed25519` (`CKK_EC_EDWARDS`) session private key:
/// - `CKA_CLASS = CKO_PRIVATE_KEY`
/// - `CKA_KEY_TYPE = CKK_EC_EDWARDS`
/// - `CKA_TOKEN = false`
/// - `CKA_PRIVATE = true`
/// - `CKA_SENSITIVE = true`
/// - `CKA_EXTRACTABLE = false`
/// - `CKA_SIGN = true`
/// - `CKA_EC_PARAMS = <OidDer (06 03 2b 65 70) or CurveNamePrintableString ("edwards25519")>`
/// - `CKA_VALUE = <32-byte raw seed or 34-byte DER OCTET STRING>`
fn build_ed25519_session_key_template(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    params_format: Ed25519EcParamsFormat,
    value_format: Ed25519ValueFormat,
) -> Vec<Attribute> {
    let key_vec = match value_format {
        Ed25519ValueFormat::Raw32 => {
            let mut v = Vec::with_capacity(ED25519_PRIVATE_KEY_LEN);
            v.extend_from_slice(private_key);
            v
        }
        Ed25519ValueFormat::DerOctetString34 => {
            let mut v = Vec::with_capacity(DER_OCTET_STRING_32_PREFIX.len() + ED25519_PRIVATE_KEY_LEN);
            v.extend_from_slice(&DER_OCTET_STRING_32_PREFIX);
            v.extend_from_slice(private_key);
            v
        }
    };

    vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::EcParams(params_format.as_bytes().to_vec()),
        Attribute::Value(key_vec),
    ]
}

/// Imports a derived 32-byte `secp256k1` child private key into `session` as a short-lived,
/// non-extractable PKCS#11 session object (`CKK_EC`, `CKA_EC_PARAMS = 06 05 2b 81 04 00 0a`,
/// `CKA_TOKEN = false`, `CKA_PRIVATE = true`, `CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = false`,
/// `CKA_SIGN = true`) and returns a [`SessionKeyGuard`] that destroys the object on drop.
pub fn import_secp256k1_session_key<'a>(
    session: &'a Pkcs11Session,
    private_key: &[u8; PRIVATE_KEY_LEN],
) -> Result<SessionKeyGuard<'a>, BackendError> {
    if private_key.iter().all(|&b| b == 0) {
        return Err(BackendError::Crypto(
            "secp256k1 private key must not be all zeros".to_string(),
        ));
    }

    let mut template = build_secp256k1_session_key_template(private_key);
    let create_res = session.raw().create_object(&template);
    zeroize_attribute_template(&mut template);

    let handle = create_res.map_err(|err| {
        map_pkcs11_err("C_CreateObject (secp256k1 CKK_EC session key)", err)
    })?;

    Ok(SessionKeyGuard::new(session, handle, Curve::Secp256k1))
}

/// Imports a derived 32-byte `ed25519` child private key into `session` as a short-lived,
/// non-extractable PKCS#11 session object (`CKK_EC_EDWARDS`, `CKA_TOKEN = false`,
/// `CKA_PRIVATE = true`, `CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = false`, `CKA_SIGN = true`)
/// using the specified `params_format` and `value_format`.
pub fn import_ed25519_session_key_with_format<'a>(
    session: &'a Pkcs11Session,
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    params_format: Ed25519EcParamsFormat,
    value_format: Ed25519ValueFormat,
) -> Result<SessionKeyGuard<'a>, BackendError> {
    let mut template = build_ed25519_session_key_template(private_key, params_format, value_format);
    let create_res = session.raw().create_object(&template);
    zeroize_attribute_template(&mut template);

    let handle = create_res.map_err(|err| {
        map_pkcs11_err("C_CreateObject (ed25519 CKK_EC_EDWARDS session key)", err)
    })?;

    Ok(SessionKeyGuard::new(session, handle, Curve::Ed25519))
}

/// Imports a derived 32-byte `ed25519` child private key into `session` as a short-lived,
/// non-extractable PKCS#11 session object (`CKK_EC_EDWARDS`, `CKA_TOKEN = false`,
/// `CKA_PRIVATE = true`, `CKA_SENSITIVE = true`, `CKA_EXTRACTABLE = false`, `CKA_SIGN = true`)
/// and returns a [`SessionKeyGuard`] that destroys the object on drop.
///
/// Tries RFC 8410 OID `1.3.101.112` (`06 03 2b 65 70`) in `CKA_EC_PARAMS` first, falling back to
/// PrintableString `"edwards25519"` (`13 0c 65 64 77 61 72 64 73 32 35 35 31 39`) and/or DER
/// OCTET STRING `04 20 || key` in `CKA_VALUE` if the PKCS#11 token requires those encodings.
pub fn import_ed25519_session_key<'a>(
    session: &'a Pkcs11Session,
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
) -> Result<SessionKeyGuard<'a>, BackendError> {
    const CANDIDATES: [(Ed25519EcParamsFormat, Ed25519ValueFormat); 4] = [
        (Ed25519EcParamsFormat::OidDer, Ed25519ValueFormat::Raw32),
        (
            Ed25519EcParamsFormat::CurveNamePrintableString,
            Ed25519ValueFormat::Raw32,
        ),
        (
            Ed25519EcParamsFormat::OidDer,
            Ed25519ValueFormat::DerOctetString34,
        ),
        (
            Ed25519EcParamsFormat::CurveNamePrintableString,
            Ed25519ValueFormat::DerOctetString34,
        ),
    ];

    let mut primary_err: Option<BackendError> = None;

    for (params_fmt, val_fmt) in CANDIDATES {
        match import_ed25519_session_key_with_format(session, private_key, params_fmt, val_fmt) {
            Ok(guard) => return Ok(guard),
            Err(err) => {
                if primary_err.is_none() {
                    primary_err = Some(err);
                }
            }
        }
    }

    Err(primary_err.unwrap_or_else(|| {
        BackendError::Pkcs11("C_CreateObject (ed25519 CKK_EC_EDWARDS session key) failed".to_string())
    }))
}

/// Imports a derived 32-byte child private key for `curve` (`Secp256k1` or `Ed25519`) into
/// `session` as a short-lived PKCS#11 session object and returns its [`SessionKeyGuard`].
pub fn import_session_key<'a>(
    session: &'a Pkcs11Session,
    curve: Curve,
    private_key: &[u8; 32],
) -> Result<SessionKeyGuard<'a>, BackendError> {
    match curve {
        Curve::Secp256k1 => import_secp256k1_session_key(session, private_key),
        Curve::Ed25519 => import_ed25519_session_key(session, private_key),
    }
}

/// Loads a derived 32-byte `secp256k1` child private key into `session` as a short-lived
/// session object, signs the 32-byte `digest` with `CKM_ECDSA`, and immediately destroys
/// the session object via `C_DestroyObject` before returning the raw 64-byte `(r || s)` signature.
pub fn sign_secp256k1_digest_in_hsm(
    session: &Pkcs11Session,
    private_key: &[u8; PRIVATE_KEY_LEN],
    digest: &[u8; SECP256K1_DIGEST_LEN],
) -> Result<[u8; ECDSA_RAW_SIGNATURE_LEN], BackendError> {
    let guard = import_secp256k1_session_key(session, private_key)?;
    let sign_res = guard.sign_raw(digest);
    let destroy_res = guard.destroy();
    let sig = sign_res?;
    destroy_res?;
    Ok(sig)
}

/// Loads a derived 32-byte `ed25519` child private key into `session` as a short-lived
/// session object, signs `message` with `CKM_EDDSA`, and immediately destroys the session object
/// via `C_DestroyObject` before returning the 64-byte Ed25519 signature.
pub fn sign_ed25519_message_in_hsm(
    session: &Pkcs11Session,
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_LEN], BackendError> {
    let guard = import_ed25519_session_key(session, private_key)?;
    let sign_res = guard.sign_raw(message);
    let destroy_res = guard.destroy();
    let sig = sign_res?;
    destroy_res?;
    Ok(sig)
}

/// Queries `C_FindObjects` (`CKA_TOKEN = false`) on `session` and returns all session object
/// handles currently present in the session.
pub fn find_session_objects(session: &Pkcs11Session) -> Result<Vec<ObjectHandle>, BackendError> {
    let template = [Attribute::Token(false)];
    session
        .raw()
        .find_objects(&template)
        .map_err(|err| map_pkcs11_err("C_FindObjects (session object hygiene check)", err))
}

/// Queries `C_FindObjects` (`CKA_TOKEN = false`) on `session` and returns the number of
/// session objects currently present in the session.
pub fn count_session_objects(session: &Pkcs11Session) -> Result<usize, BackendError> {
    let handles = find_session_objects(session)?;
    Ok(handles.len())
}

/// Verifies that zero session objects (`CKA_TOKEN = false`) remain on `session`, returning
/// [`BackendError::SessionObjectHygieneFailed`] if any leftover session object is found.
pub fn assert_no_session_objects(session: &Pkcs11Session) -> Result<(), BackendError> {
    let count = count_session_objects(session)?;
    if count != 0 {
        return Err(BackendError::SessionObjectHygieneFailed { count });
    }
    Ok(())
}

/// Verifies via `C_GetAttributeValue` that an imported ephemeral session key object has the
/// required non-extractable, sensitive, private session-object attributes:
/// - `CKA_CLASS == CKO_PRIVATE_KEY`
/// - `CKA_KEY_TYPE == CKK_EC` (for `Secp256k1`) or `CKK_EC_EDWARDS` (for `Ed25519`)
/// - `CKA_TOKEN == false`
/// - `CKA_PRIVATE == true`
/// - `CKA_SENSITIVE == true`
/// - `CKA_EXTRACTABLE == false`
/// - `CKA_SIGN == true`
pub fn verify_session_key_attributes(
    session: &Pkcs11Session,
    handle: ObjectHandle,
    expected_curve: Curve,
) -> Result<(), BackendError> {
    const QUERIED_ATTRS: &[AttributeType] = &[
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Sensitive,
        AttributeType::Extractable,
        AttributeType::Sign,
        AttributeType::EcParams,
    ];

    let attrs = session
        .raw()
        .get_attributes(handle, QUERIED_ATTRS)
        .map_err(|err| map_pkcs11_err("C_GetAttributeValue (session key verification)", err))?;

    let mut class: Option<ObjectClass> = None;
    let mut key_type: Option<KeyType> = None;
    let mut token: Option<bool> = None;
    let mut private: Option<bool> = None;
    let mut sensitive: Option<bool> = None;
    let mut extractable: Option<bool> = None;
    let mut sign: Option<bool> = None;
    let mut ec_params: Option<Zeroizing<Vec<u8>>> = None;

    for attr in attrs {
        match attr {
            Attribute::Class(v) => class = Some(v),
            Attribute::KeyType(v) => key_type = Some(v),
            Attribute::Token(v) => token = Some(v),
            Attribute::Private(v) => private = Some(v),
            Attribute::Sensitive(v) => sensitive = Some(v),
            Attribute::Extractable(v) => extractable = Some(v),
            Attribute::Sign(v) => sign = Some(v),
            Attribute::EcParams(v) => ec_params = Some(Zeroizing::new(v)),
            _ => {}
        }
    }

    if class != Some(ObjectClass::PRIVATE_KEY) {
        return Err(BackendError::Pkcs11(format!(
            "session key CKA_CLASS mismatch: expected CKO_PRIVATE_KEY, got {class:?}"
        )));
    }

    let expected_key_type = match expected_curve {
        Curve::Secp256k1 => KeyType::EC,
        Curve::Ed25519 => KeyType::EC_EDWARDS,
    };
    if key_type != Some(expected_key_type) {
        return Err(BackendError::Pkcs11(format!(
            "session key CKA_KEY_TYPE mismatch for {expected_curve}: expected {expected_key_type}, got {key_type:?}"
        )));
    }

    if token != Some(false) {
        return Err(BackendError::Pkcs11(format!(
            "session key must have CKA_TOKEN=false, got {token:?}"
        )));
    }
    if private != Some(true) {
        return Err(BackendError::Pkcs11(format!(
            "session key must have CKA_PRIVATE=true, got {private:?}"
        )));
    }
    if sensitive != Some(true) {
        return Err(BackendError::Pkcs11(format!(
            "session key must have CKA_SENSITIVE=true, got {sensitive:?}"
        )));
    }
    if extractable != Some(false) {
        return Err(BackendError::Pkcs11(format!(
            "session key must have CKA_EXTRACTABLE=false, got {extractable:?}"
        )));
    }
    if sign != Some(true) {
        return Err(BackendError::Pkcs11(format!(
            "session key must have CKA_SIGN=true, got {sign:?}"
        )));
    }

    if let Some(params) = ec_params {
        match expected_curve {
            Curve::Secp256k1 => {
                if params.as_slice() != SECP256K1_OID_DER {
                    return Err(BackendError::Pkcs11(format!(
                        "secp256k1 session key CKA_EC_PARAMS mismatch: got {:02x?}",
                        params.as_slice()
                    )));
                }
            }
            Curve::Ed25519 => {
                if params.as_slice() != ED25519_OID_DER
                    && params.as_slice() != ED25519_CURVE_NAME_DER
                {
                    return Err(BackendError::Pkcs11(format!(
                        "ed25519 session key CKA_EC_PARAMS mismatch: got {:02x?}",
                        params.as_slice()
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::DEFAULT_KEK_LABEL;
    use crate::derive::{derive_bip32_str, derive_slip10_str};
    use crate::pkcs11session::tests::{
        mock_state, mock_test_lock, C_GetFunctionList, MOCK_SLOT_ID,
    };
    use crate::pkcs11session::{Pkcs11Config, Pkcs11Library, SlotSelector, SELF_MODULE_PATH};
    use ed25519_dalek::{Signature as DalekEdSignature, Verifier, VerifyingKey as DalekVerifyingKey};
    use k256::ecdsa::{
        signature::hazmat::PrehashVerifier, Signature as K256Signature,
        VerifyingKey as K256VerifyingKey,
    };
    use sha2::{Digest, Sha256};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn open_mock_library() -> Pkcs11Library {
        let _keep_sym = C_GetFunctionList as usize;
        let cfg = Pkcs11Config::with_loaded_pin(
            SELF_MODULE_PATH,
            SlotSelector::from_id(MOCK_SLOT_ID as u64),
            Zeroizing::new("correct-user-pin".to_string()),
            DEFAULT_KEK_LABEL,
        );
        Pkcs11Library::open(cfg).expect("open mock PKCS#11 library")
    }

    #[test]
    fn test_oid_and_curve_param_constants() {
        // secp256k1 ANSI X9.62 OID 1.3.132.0.10 -> 06 05 2b 81 04 00 0a
        assert_eq!(
            hex::encode(SECP256K1_OID_DER),
            "06052b8104000a"
        );
        // ed25519 RFC 8410 OID 1.3.101.112 -> 06 03 2b 65 70
        assert_eq!(
            hex::encode(ED25519_OID_DER),
            "06032b6570"
        );
        // ed25519 PrintableString "edwards25519" -> 13 0c 65 64 77 61 72 64 73 32 35 35 31 39
        assert_eq!(
            hex::encode(ED25519_CURVE_NAME_DER),
            "130c656477617264733235353139"
        );
        assert_eq!(
            Ed25519EcParamsFormat::OidDer.as_bytes(),
            &SECP256K1_OID_DER[..0]
                .iter()
                .chain(ED25519_OID_DER.iter())
                .copied()
                .collect::<Vec<u8>>()[..]
        );
    }

    #[test]
    fn test_secp256k1_session_object_signing_and_hygiene() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let lib = open_mock_library();
        let session = lib.open_rw_session().expect("open RW session");

        // Initially zero session objects exist (only the token-resident KEK with CKA_TOKEN=true)
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        assert_no_session_objects(&session).expect("no session objects before signing");

        // Derive a real BIP32 secp256k1 child key from a test seed
        let seed = [0x11u8; 64];
        let derived = derive_bip32_str(&seed, "m/44'/60'/0'/0/0").expect("derive BIP32 key");

        // 1. Verify session object attributes while guard is alive
        {
            let guard = import_secp256k1_session_key(&session, derived.private_key())
                .expect("import secp256k1 session key");
            assert_eq!(guard.curve(), Curve::Secp256k1);
            assert!(!guard.is_destroyed());
            assert_eq!(count_session_objects(&session).unwrap(), 1);
            assert!(matches!(
                assert_no_session_objects(&session),
                Err(BackendError::SessionObjectHygieneFailed { count: 1 })
            ));

            verify_session_key_attributes(&session, guard.handle(), Curve::Secp256k1)
                .expect("session key attributes match spec");

            guard.destroy().expect("explicit guard destroy");
        }
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        assert_no_session_objects(&session).expect("zero session objects after guard destroy");

        // 2. End-to-end sign_secp256k1_digest_in_hsm and verify signature with derived public key
        let digest: [u8; 32] = Sha256::digest(b"polyglot secp256k1 HSM signing test").into();
        let raw_sig = session
            .sign_secp256k1_digest(derived.private_key(), &digest)
            .expect("sign 32B digest with CKM_ECDSA");
        assert_eq!(raw_sig.len(), ECDSA_RAW_SIGNATURE_LEN);

        // Verify with k256 VerifyingKey from the derived 33-byte compressed SEC1 public key
        let verifying_key =
            K256VerifyingKey::from_sec1_bytes(derived.public_key()).expect("valid SEC1 pubkey");
        let k256_sig = K256Signature::from_slice(&raw_sig).expect("valid 64B ECDSA sig");
        verifying_key
            .verify_prehash(&digest, &k256_sig)
            .expect("HSM ECDSA signature must verify against derived public key");

        // Assert zero leftover session objects after signing
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        assert_no_session_objects(&session).unwrap();
    }

    #[test]
    fn test_ed25519_session_object_signing_fallback_formats_and_hygiene() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let lib = open_mock_library();
        let session = lib.open_rw_session().expect("open RW session");

        let seed = [0x22u8; 64];
        let derived = derive_slip10_str(&seed, "m/44'/501'/0'/0'").expect("derive SLIP10 key");
        let message = b"polyglot ed25519 HSM session-object signing test payload";

        // 1. Primary path: OID 1.3.101.112 (06 03 2b 65 70) + raw 32B value
        {
            let guard = import_ed25519_session_key(&session, derived.private_key())
                .expect("import ed25519 session key (OID)");
            assert_eq!(guard.curve(), Curve::Ed25519);
            assert_eq!(count_session_objects(&session).unwrap(), 1);
            verify_session_key_attributes(&session, guard.handle(), Curve::Ed25519)
                .expect("ed25519 session key attributes valid");
            guard.destroy().expect("destroy guard");
        }
        assert_no_session_objects(&session).unwrap();

        let sig_1 = session
            .sign_ed25519_message(derived.private_key(), message)
            .expect("sign ed25519 message in HSM");

        let verifying_key =
            DalekVerifyingKey::from_bytes(derived.public_key()).expect("valid Ed25519 pubkey");
        let dalek_sig_1 = DalekEdSignature::from_bytes(&sig_1);
        verifying_key
            .verify(message, &dalek_sig_1)
            .expect("HSM Ed25519 signature must verify against derived public key");
        assert_no_session_objects(&session).unwrap();

        // 2. Fallback path: token rejects OID 06 03 2b 65 70 and requires PrintableString "edwards25519"
        mock_state().lock().unwrap().reject_ed25519_oid_params = true;
        let sig_2 = session
            .sign_ed25519_message(derived.private_key(), message)
            .expect("sign ed25519 message using PrintableString curve name fallback");
        assert_eq!(sig_2, sig_1);
        assert_no_session_objects(&session).unwrap();

        // 3. Fallback path: token requires DER OCTET STRING (04 20 <32B>) in CKA_VALUE
        mock_state().lock().unwrap().reject_ed25519_oid_params = false;
        mock_state().lock().unwrap().require_ed25519_der_octet_value = true;
        let sig_3 = session
            .sign_ed25519_message(derived.private_key(), message)
            .expect("sign ed25519 message using DER OCTET STRING CKA_VALUE fallback");
        assert_eq!(sig_3, sig_1);
        assert_no_session_objects(&session).unwrap();
        mock_state().lock().unwrap().require_ed25519_der_octet_value = false;
    }

    #[test]
    fn test_session_key_guard_destroys_object_on_sign_error_early_return_and_panic() {
        let _serial = mock_test_lock().lock().unwrap();
        mock_state().lock().unwrap().reset();

        let lib = open_mock_library();
        let session = lib.open_rw_session().expect("open RW session");

        let seed = [0x33u8; 64];
        let secp_key = derive_bip32_str(&seed, "m/44'/0'/0'/0/1").unwrap();
        let ed_key = derive_slip10_str(&seed, "m/44'/501'/0'/0'").unwrap();
        let digest = [0xAAu8; 32];

        // 1. Forced C_Sign failure -> object must still be destroyed immediately
        mock_state().lock().unwrap().force_sign_error = true;
        let err = session
            .sign_secp256k1_digest(secp_key.private_key(), &digest)
            .unwrap_err();
        assert!(matches!(err, BackendError::Pkcs11(_)));
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        assert_no_session_objects(&session).unwrap();

        let ed_err = session
            .sign_ed25519_message(ed_key.private_key(), b"test")
            .unwrap_err();
        assert!(matches!(ed_err, BackendError::Pkcs11(_)));
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        mock_state().lock().unwrap().force_sign_error = false;

        // 2. Early return (implicit Drop without calling guard.destroy())
        {
            let _guard = import_secp256k1_session_key(&session, secp_key.private_key())
                .expect("import session key");
            assert_eq!(count_session_objects(&session).unwrap(), 1);
            // `_guard` drops at block end without explicit `.destroy()`
        }
        assert_eq!(count_session_objects(&session).unwrap(), 0);
        assert_no_session_objects(&session).unwrap();

        // 3. Panic while SessionKeyGuard is in scope -> Drop destroys session object during unwind
        let panic_res = catch_unwind(AssertUnwindSafe(|| {
            let _guard = import_ed25519_session_key(&session, ed_key.private_key())
                .expect("import ed25519 session key before panic");
            assert_eq!(count_session_objects(&session).unwrap(), 1);
            panic!("simulated panic while session key object is loaded in HSM");
        }));
        assert!(panic_res.is_err());
        assert_eq!(
            count_session_objects(&session).unwrap(),
            0,
            "SessionKeyGuard must destroy object on panic unwind before session closes"
        );
        assert_no_session_objects(&session).unwrap();

        // 4. Rejects all-zero secp256k1 private key without creating any object
        let zero_key = [0u8; 32];
        let zero_err = import_secp256k1_session_key(&session, &zero_key).unwrap_err();
        assert!(matches!(zero_err, BackendError::Crypto(_)));
        assert_no_session_objects(&session).unwrap();
    }
}
