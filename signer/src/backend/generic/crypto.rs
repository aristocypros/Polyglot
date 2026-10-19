//! Cryptographic post-processing, normalization, software signing fallbacks,
//! and BIP340/BIP86 Taproot Schnorr signing (`signer/src/backend/generic/crypto.rs`).
//!
//! Implements Task 10 of Milestone 2 (Section 4, Section 5, and Section 8 of `Specs.md`):
//! - **ECDSA Post-Processing (`secp256k1`)**:
//!   - Low-S normalization (`s <= n / 2` on `secp256k1`) for raw 64-byte `(r, s)` signatures
//!     returned by either PKCS#11 `CKM_ECDSA` or software `k256::ecdsa`.
//!   - Recovery ID (`recid` in `0..=1`, y-parity) determination by testing public key recovery
//!     of both parities against the known 33-byte derived compressed SEC1 public key.
//!   - Canonical strict ASN.1 DER encoding (BIP66 / XRP Ledger compliant) and decoding helpers.
//! - **Software Signing Fallback (`signing_in_hsm: false`)**:
//!   - `secp256k1` ECDSA prehash signing via `k256::ecdsa` when HSM curve support is unavailable.
//!   - `ed25519` EdDSA message signing via `ed25519-dalek` when HSM curve support is unavailable.
//! - **BIP340 Taproot Schnorr & BIP86 Key-Path Tweaking (`SigningInput::TaprootDigest32`)**:
//!   - Applies BIP86 Taproot key-path tweak (`t = tagged_hash("TapTweak", internal_x_only_pubkey)`)
//!     to the derived `secp256k1` keypair (and provides public-key-only tweaking for chain codecs).
//!   - Produces a 64-byte BIP340 Schnorr signature in software (`signing_in_hsm: false`),
//!     explicitly zeroizing all intermediate and tweaked scalar material.

use std::fmt;

use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{
    RecoveryId, Signature as K256EcdsaSignature, SigningKey as K256EcdsaSigningKey,
    VerifyingKey as K256EcdsaVerifyingKey,
};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::scalar::IsHigh;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::schnorr::{
    Signature as K256SchnorrSignature, SigningKey as K256SchnorrSigningKey,
    VerifyingKey as K256SchnorrVerifyingKey,
};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{BackendError, Signature};
use crate::derive::bip32::public_key_from_private as secp256k1_pubkey_from_private;
use crate::derive::slip10::public_key_from_private_ed25519;
use crate::derive::{COMPRESSED_PUBKEY_LEN, ED25519_PRIVATE_KEY_LEN, ED25519_PUBKEY_LEN, PRIVATE_KEY_LEN};
use crate::pkcs11session::{ECDSA_RAW_SIGNATURE_LEN, ED25519_SIGNATURE_LEN, SECP256K1_DIGEST_LEN};

/// Byte length of an uncompressed SEC1 `secp256k1` public key (`0x04 || X (32B) || Y (32B)`).
pub const UNCOMPRESSED_PUBKEY_LEN: usize = 65;

/// Byte length of a BIP340 x-only `secp256k1` public key (`32` bytes).
pub const X_ONLY_PUBKEY_LEN: usize = 32;

/// Byte length of a BIP340 Schnorr signature (`R_x (32B) || s (32B)`).
pub const SCHNORR_SIGNATURE_LEN: usize = 64;

/// Domain separation tag for BIP341 / BIP86 Taproot key tweaking (`"TapTweak"`).
pub const TAP_TWEAK_TAG: &str = "TapTweak";

/// `secp256k1` curve order `n` in big-endian bytes:
/// `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Half of `secp256k1` curve order `n / 2` in big-endian bytes (inclusive upper bound for low-S):
/// `0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`.
pub const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

// ============================================================================
// 1. ECDSA Normalization (Low-S, Recovery ID, ASN.1 DER) & Verification
// ============================================================================

/// Splits a 64-byte raw ECDSA signature (`r || s`) into 32-byte `r` and `s` arrays.
pub fn split_ecdsa_rs(sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_64[..32]);
    s.copy_from_slice(&sig_64[32..64]);
    (r, s)
}

/// Checks whether a 32-byte big-endian `secp256k1` scalar `s` is canonical low-S
/// (`1 <= s <= n / 2`).
///
/// Returns `Err(BackendError::Crypto)` if `s == 0` or `s >= n`.
pub fn is_low_s(s_bytes: &[u8; 32]) -> Result<bool, BackendError> {
    let scalar_opt = Option::<Scalar>::from(Scalar::from_repr((*s_bytes).into()));
    let scalar = scalar_opt.ok_or_else(|| {
        BackendError::Crypto("invalid ECDSA s scalar: exceeds or equals secp256k1 curve order n".to_string())
    })?;
    if scalar == Scalar::ZERO {
        return Err(BackendError::Crypto(
            "invalid ECDSA s scalar: s must be non-zero".to_string(),
        ));
    }
    Ok(!bool::from(scalar.is_high()))
}

/// Normalizes a 32-byte `secp256k1` scalar `s` to low-S (`1 <= s <= n / 2`).
///
/// If `s > n / 2`, replaces `s` with `n - s` and returns `(normalized_s, true)`.
/// If `s <= n / 2`, returns `(*s_bytes, false)`.
/// Returns `Err(BackendError::Crypto)` if `s == 0` or `s >= n`.
pub fn normalize_s_scalar(s_bytes: &[u8; 32]) -> Result<([u8; 32], bool), BackendError> {
    let scalar_opt = Option::<Scalar>::from(Scalar::from_repr((*s_bytes).into()));
    let scalar = scalar_opt.ok_or_else(|| {
        BackendError::Crypto("invalid ECDSA s scalar: exceeds or equals secp256k1 curve order n".to_string())
    })?;
    if scalar == Scalar::ZERO {
        return Err(BackendError::Crypto(
            "invalid ECDSA s scalar: s must be non-zero".to_string(),
        ));
    }

    if bool::from(scalar.is_high()) {
        let neg_scalar = -scalar;
        let mut out = [0u8; 32];
        out.copy_from_slice(neg_scalar.to_bytes().as_ref());
        Ok((out, true))
    } else {
        Ok((*s_bytes, false))
    }
}

/// Normalizes a raw 64-byte `(r, s)` `secp256k1` ECDSA signature to low-S (`s <= n / 2`).
///
/// Validates that `1 <= r < n` and `1 <= s < n`.
/// Returns `(normalized_64_bytes, was_normalized)` where `was_normalized` is `true`
/// if `s` was originally in the upper half `(n / 2, n)` and negated to `n - s`.
pub fn normalize_ecdsa_low_s(
    raw_sig: &[u8; ECDSA_RAW_SIGNATURE_LEN],
) -> Result<([u8; ECDSA_RAW_SIGNATURE_LEN], bool), BackendError> {
    let sig = K256EcdsaSignature::from_slice(raw_sig).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid raw 64-byte secp256k1 ECDSA signature (r || s): {e}"
        ))
    })?;

    let (normalized_sig, was_high) = match sig.normalize_s() {
        Some(low_s_sig) => (low_s_sig, true),
        None => (sig, false),
    };

    let mut out = [0u8; ECDSA_RAW_SIGNATURE_LEN];
    out.copy_from_slice(normalized_sig.to_bytes().as_ref());
    Ok((out, was_high))
}

/// Encodes a 64-byte `(r, s)` `secp256k1` ECDSA signature into canonical strict ASN.1 DER
/// (BIP66 and XRP Ledger compliant), normalizing `s` to low-S first if needed.
///
/// Format: `0x30 <total_len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>`
pub fn encode_ecdsa_der(sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN]) -> Result<Vec<u8>, BackendError> {
    let (normalized_bytes, _) = normalize_ecdsa_low_s(sig_64)?;
    let sig = K256EcdsaSignature::from_slice(&normalized_bytes).map_err(|e| {
        BackendError::Crypto(format!(
            "failed to parse normalized ECDSA signature for DER encoding: {e}"
        ))
    })?;
    let der = sig.to_der();
    Ok(der.as_bytes().to_vec())
}

/// Encodes 32-byte `r` and `s` components into canonical strict low-S ASN.1 DER.
pub fn encode_ecdsa_rs_der(r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>, BackendError> {
    let mut raw = [0u8; ECDSA_RAW_SIGNATURE_LEN];
    raw[..32].copy_from_slice(r);
    raw[32..64].copy_from_slice(s);
    encode_ecdsa_der(&raw)
}

/// Strictly decodes a BIP66 canonical ASN.1 DER-encoded `secp256k1` ECDSA signature
/// into its 64-byte `(r, s)` fixed-width big-endian representation.
///
/// Rejects non-minimal integer encodings, negative integers, trailing bytes, or invalid scalars.
pub fn decode_ecdsa_der(der_bytes: &[u8]) -> Result<[u8; ECDSA_RAW_SIGNATURE_LEN], BackendError> {
    validate_bip66_der(der_bytes)?;
    let sig = K256EcdsaSignature::from_der(der_bytes).map_err(|e| {
        BackendError::Crypto(format!("invalid ASN.1 DER ECDSA signature: {e}"))
    })?;
    let mut out = [0u8; ECDSA_RAW_SIGNATURE_LEN];
    out.copy_from_slice(sig.to_bytes().as_ref());
    Ok(out)
}

/// Validates strict BIP66 DER signature encoding rules:
/// `0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]`
fn validate_bip66_der(sig: &[u8]) -> Result<(), BackendError> {
    // Minimum valid DER ECDSA signature is 8 bytes; maximum for 256-bit curve is 72 bytes.
    if sig.len() < 8 || sig.len() > 72 {
        return Err(BackendError::Crypto(format!(
            "BIP66 DER signature length {} out of bounds [8, 72]",
            sig.len()
        )));
    }
    if sig[0] != 0x30 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature must start with compound header 0x30".to_string(),
        ));
    }
    if usize::from(sig[1]) != sig.len() - 2 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature header length does not match actual payload length".to_string(),
        ));
    }
    if sig[2] != 0x02 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature R element must start with integer tag 0x02".to_string(),
        ));
    }
    let len_r = usize::from(sig[3]);
    if len_r == 0 || 5 + len_r >= sig.len() {
        return Err(BackendError::Crypto(
            "BIP66 DER signature R length is zero or out of bounds".to_string(),
        ));
    }
    let r_bytes = &sig[4..4 + len_r];
    if (r_bytes[0] & 0x80) != 0 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature R value is negative".to_string(),
        ));
    }
    if len_r > 1 && r_bytes[0] == 0x00 && (r_bytes[1] & 0x80) == 0 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature R value has non-minimal leading zero padding".to_string(),
        ));
    }

    let s_offset = 4 + len_r;
    if sig[s_offset] != 0x02 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature S element must start with integer tag 0x02".to_string(),
        ));
    }
    let len_s = usize::from(sig[s_offset + 1]);
    if len_s == 0 || s_offset + 2 + len_s != sig.len() {
        return Err(BackendError::Crypto(
            "BIP66 DER signature S length is zero or does not match total signature length"
                .to_string(),
        ));
    }
    let s_bytes = &sig[s_offset + 2..];
    if (s_bytes[0] & 0x80) != 0 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature S value is negative".to_string(),
        ));
    }
    if len_s > 1 && s_bytes[0] == 0x00 && (s_bytes[1] & 0x80) == 0 {
        return Err(BackendError::Crypto(
            "BIP66 DER signature S value has non-minimal leading zero padding".to_string(),
        ));
    }

    Ok(())
}

/// Validates that a 33-byte SEC1 compressed `secp256k1` public key starts with `0x02` or `0x03`.
fn validate_compressed_sec1_prefix(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<(), BackendError> {
    if compressed_pubkey[0] != 0x02 && compressed_pubkey[0] != 0x03 {
        return Err(BackendError::Crypto(format!(
            "invalid SEC1 compressed secp256k1 public key prefix 0x{:02x}: expected 0x02 or 0x03",
            compressed_pubkey[0]
        )));
    }
    Ok(())
}

/// Decompresses a 33-byte SEC1 compressed `secp256k1` public key (`0x02`/`0x03 || X`)
/// into a 65-byte uncompressed SEC1 public key (`0x04 || X || Y`).
///
/// Useful for Ethereum/EVM and Tron address derivation (`Keccak256(uncompressed[1..])[12..]`).
pub fn decompress_secp256k1_pubkey(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<[u8; UNCOMPRESSED_PUBKEY_LEN], BackendError> {
    validate_compressed_sec1_prefix(compressed_pubkey)?;
    let pubkey = PublicKey::from_sec1_bytes(compressed_pubkey).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid 33-byte compressed secp256k1 public key: {e}"
        ))
    })?;
    let encoded = pubkey.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != UNCOMPRESSED_PUBKEY_LEN {
        return Err(BackendError::Crypto(format!(
            "unexpected uncompressed secp256k1 public key length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; UNCOMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Recovers the 33-byte compressed SEC1 `secp256k1` public key from a 32-byte digest,
/// a 64-byte `(r, s)` ECDSA signature, and a recovery ID (`0` or `1`).
pub fn recover_secp256k1_pubkey_compressed(
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN],
    recovery_id: u8,
) -> Result<[u8; COMPRESSED_PUBKEY_LEN], BackendError> {
    if recovery_id > 1 {
        return Err(BackendError::Crypto(format!(
            "invalid ECDSA recovery_id {recovery_id}: expected 0 or 1"
        )));
    }
    let sig = K256EcdsaSignature::from_slice(sig_64).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid 64-byte secp256k1 ECDSA signature for recovery: {e}"
        ))
    })?;
    let recid = RecoveryId::from_byte(recovery_id).ok_or_else(|| {
        BackendError::Crypto(format!("invalid ECDSA recovery_id byte: {recovery_id}"))
    })?;
    let recovered_vk = K256EcdsaVerifyingKey::recover_from_prehash(digest32, &sig, recid).map_err(
        |e| BackendError::Crypto(format!("secp256k1 public key recovery failed: {e}")),
    )?;
    let encoded = recovered_vk.to_encoded_point(true);
    let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Recovers the 65-byte uncompressed SEC1 `secp256k1` public key (`0x04 || X || Y`)
/// from a 32-byte digest, a 64-byte `(r, s)` ECDSA signature, and a recovery ID (`0` or `1`).
pub fn recover_secp256k1_pubkey_uncompressed(
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN],
    recovery_id: u8,
) -> Result<[u8; UNCOMPRESSED_PUBKEY_LEN], BackendError> {
    let compressed = recover_secp256k1_pubkey_compressed(digest32, sig_64, recovery_id)?;
    decompress_secp256k1_pubkey(&compressed)
}

/// Determines the ECDSA recovery ID (`recid` in `0..=1`, y-parity) for a normalized low-S
/// 64-byte `(r, s)` signature by testing public key recovery of both parities (`0` and `1`)
/// against the known 33-byte derived compressed `secp256k1` public key.
///
/// Rejects high-S signatures (`s > n / 2`) or signatures whose recovered public key does not
/// match `expected_pubkey_compressed` under either parity.
pub fn compute_ecdsa_recovery_id(
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    normalized_sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN],
    expected_pubkey_compressed: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<u8, BackendError> {
    validate_compressed_sec1_prefix(expected_pubkey_compressed)?;
    // Validate that expected_pubkey_compressed is a valid SEC1 compressed point.
    let _expected_vk =
        K256EcdsaVerifyingKey::from_sec1_bytes(expected_pubkey_compressed).map_err(|e| {
            BackendError::Crypto(format!(
                "invalid expected 33-byte compressed secp256k1 public key: {e}"
            ))
        })?;

    let sig = K256EcdsaSignature::from_slice(normalized_sig_64).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid 64-byte secp256k1 ECDSA signature: {e}"
        ))
    })?;

    if bool::from(sig.s().is_high()) {
        return Err(BackendError::Crypto(
            "compute_ecdsa_recovery_id requires a low-S normalized ECDSA signature (s <= n/2)"
                .to_string(),
        ));
    }

    for parity in 0u8..=1u8 {
        if let Some(recid) = RecoveryId::from_byte(parity) {
            if let Ok(recovered_vk) =
                K256EcdsaVerifyingKey::recover_from_prehash(digest32, &sig, recid)
            {
                let encoded = recovered_vk.to_encoded_point(true);
                if encoded.as_bytes() == expected_pubkey_compressed {
                    return Ok(parity);
                }
            }
        }
    }

    Err(BackendError::Crypto(
        "ECDSA public key recovery failed: neither parity 0 nor 1 matched the derived secp256k1 public key"
            .to_string(),
    ))
}

/// Verifies a low-S 64-byte `(r, s)` `secp256k1` ECDSA signature over `digest32`
/// against a 33-byte compressed SEC1 public key.
///
/// Rejects high-S signatures (`s > n / 2`) as non-canonical.
pub fn verify_secp256k1_ecdsa(
    pubkey_compressed: &[u8; COMPRESSED_PUBKEY_LEN],
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    sig_64: &[u8; ECDSA_RAW_SIGNATURE_LEN],
) -> Result<(), BackendError> {
    let (_r, s) = split_ecdsa_rs(sig_64);
    if !is_low_s(&s)? {
        return Err(BackendError::Crypto(
            "ECDSA signature verification rejected non-canonical high-S value".to_string(),
        ));
    }
    let _recid = compute_ecdsa_recovery_id(digest32, sig_64, pubkey_compressed)?;
    Ok(())
}

/// Post-processes a raw 64-byte `(r, s)` `secp256k1` ECDSA signature returned by either
/// PKCS#11 `CKM_ECDSA` (`signing_in_hsm = true`) or software `k256::ecdsa` (`signing_in_hsm = false`):
///
/// 1. Normalizes `s` to low-S (`s <= n / 2`).
/// 2. Determines the recovery ID (`recid` in `0..=1`) by testing public key recovery of both
///    parities against `expected_pubkey_compressed` (simultaneously verifying that the signature
///    is valid for `digest32` and `expected_pubkey_compressed`).
/// 3. Encodes the normalized low-S signature as canonical ASN.1 DER (`der`) for Bitcoin and XRPL.
/// 4. Returns a populated [`Signature`] carrying `bytes` (`r || s_low`), `r`, `s`, `recovery_id`,
///    `der`, `public_key`, and `signing_in_hsm`.
pub fn postprocess_ecdsa_signature(
    raw_sig: &[u8; ECDSA_RAW_SIGNATURE_LEN],
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    expected_pubkey_compressed: &[u8; COMPRESSED_PUBKEY_LEN],
    signing_in_hsm: bool,
) -> Result<Signature, BackendError> {
    let (normalized_bytes, _was_high) = normalize_ecdsa_low_s(raw_sig)?;
    let (r, s) = split_ecdsa_rs(&normalized_bytes);
    let recovery_id =
        compute_ecdsa_recovery_id(digest32, &normalized_bytes, expected_pubkey_compressed)?;
    let der = encode_ecdsa_der(&normalized_bytes)?;

    Ok(Signature::new_ecdsa(
        r,
        s,
        recovery_id,
        Some(der),
        expected_pubkey_compressed.to_vec(),
        signing_in_hsm,
    ))
}

// ============================================================================
// 2. Software Signing Fallback (`secp256k1` ECDSA & `ed25519` EdDSA)
// ============================================================================

/// Signs a 32-byte digest in software on `secp256k1` using `k256::ecdsa` (RFC 6979 deterministic
/// ECDSA), normalizes `s` to low-S, and returns the raw 64-byte `(r, s)` signature.
pub fn sign_secp256k1_ecdsa_software_raw(
    private_key: &[u8; PRIVATE_KEY_LEN],
    digest32: &[u8; SECP256K1_DIGEST_LEN],
) -> Result<[u8; ECDSA_RAW_SIGNATURE_LEN], BackendError> {
    let signing_key = K256EcdsaSigningKey::from_slice(private_key).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid secp256k1 private key for software ECDSA signing: {e}"
        ))
    })?;

    let sig: K256EcdsaSignature = signing_key.sign_prehash(digest32).map_err(|e| {
        BackendError::Crypto(format!("software secp256k1 ECDSA prehash signing failed: {e}"))
    })?;

    let normalized = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; ECDSA_RAW_SIGNATURE_LEN];
    out.copy_from_slice(normalized.to_bytes().as_ref());
    Ok(out)
}

/// Signs a 32-byte digest in software on `secp256k1` using `k256::ecdsa` against a known
/// 33-byte derived compressed public key, returning a fully normalized [`Signature`]
/// with `signing_in_hsm: false`.
pub fn sign_secp256k1_ecdsa_software_with_pubkey(
    private_key: &[u8; PRIVATE_KEY_LEN],
    digest32: &[u8; SECP256K1_DIGEST_LEN],
    expected_pubkey_compressed: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<Signature, BackendError> {
    let raw_sig = sign_secp256k1_ecdsa_software_raw(private_key, digest32)?;
    postprocess_ecdsa_signature(&raw_sig, digest32, expected_pubkey_compressed, false)
}

/// Signs a 32-byte digest in software on `secp256k1` using `k256::ecdsa`, deriving the
/// 33-byte compressed SEC1 public key from `private_key`, and returning a fully normalized
/// [`Signature`] with `signing_in_hsm: false`.
pub fn sign_secp256k1_ecdsa_software(
    private_key: &[u8; PRIVATE_KEY_LEN],
    digest32: &[u8; SECP256K1_DIGEST_LEN],
) -> Result<Signature, BackendError> {
    let pubkey = secp256k1_pubkey_from_private(private_key)?;
    sign_secp256k1_ecdsa_software_with_pubkey(private_key, digest32, &pubkey)
}

/// Verifies a 64-byte `ed25519` signature over `message` against a 32-byte compressed
/// Edwards public key using `ed25519_dalek::VerifyingKey::verify_strict`.
pub fn verify_ed25519_signature(
    pubkey: &[u8; ED25519_PUBKEY_LEN],
    message: &[u8],
    sig_64: &[u8; ED25519_SIGNATURE_LEN],
) -> Result<(), BackendError> {
    let verifying_key = Ed25519VerifyingKey::from_bytes(pubkey).map_err(|e| {
        BackendError::Crypto(format!("invalid 32-byte ed25519 public key: {e}"))
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_64);
    verifying_key.verify_strict(message, &sig).map_err(|e| {
        BackendError::Crypto(format!("ed25519 signature verification failed: {e}"))
    })
}

/// Post-processes and verifies a 64-byte `ed25519` signature returned by either
/// PKCS#11 `CKM_EDDSA` (`signing_in_hsm = true`) or software `ed25519-dalek` (`signing_in_hsm = false`).
pub fn postprocess_ed25519_signature(
    raw_sig: &[u8; ED25519_SIGNATURE_LEN],
    message: &[u8],
    expected_pubkey: &[u8; ED25519_PUBKEY_LEN],
    signing_in_hsm: bool,
) -> Result<Signature, BackendError> {
    verify_ed25519_signature(expected_pubkey, message, raw_sig)?;
    Ok(Signature::new_ed25519(
        *raw_sig,
        *expected_pubkey,
        signing_in_hsm,
    ))
}

/// Signs arbitrary message bytes in software on `ed25519` using `ed25519-dalek`,
/// returning the raw 64-byte Ed25519 signature.
pub fn sign_ed25519_software_raw(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    message: &[u8],
) -> [u8; ED25519_SIGNATURE_LEN] {
    let signing_key = Ed25519SigningKey::from_bytes(private_key);
    let sig = signing_key.sign(message);
    sig.to_bytes()
}

/// Signs arbitrary message bytes in software on `ed25519` using `ed25519-dalek` against a
/// known 32-byte derived public key, verifying the signature and returning [`Signature`]
/// with `signing_in_hsm: false`.
pub fn sign_ed25519_software_with_pubkey(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    message: &[u8],
    expected_pubkey: &[u8; ED25519_PUBKEY_LEN],
) -> Result<Signature, BackendError> {
    let derived_pubkey = public_key_from_private_ed25519(private_key);
    if &derived_pubkey != expected_pubkey {
        return Err(BackendError::Crypto(
            "ed25519 software signing public key mismatch against derived key".to_string(),
        ));
    }
    let raw_sig = sign_ed25519_software_raw(private_key, message);
    postprocess_ed25519_signature(&raw_sig, message, expected_pubkey, false)
}

/// Signs arbitrary message bytes in software on `ed25519` using `ed25519-dalek`,
/// deriving the 32-byte public key from `private_key` and returning [`Signature`]
/// with `signing_in_hsm: false`.
pub fn sign_ed25519_software(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
    message: &[u8],
) -> Result<Signature, BackendError> {
    let pubkey = public_key_from_private_ed25519(private_key);
    sign_ed25519_software_with_pubkey(private_key, message, &pubkey)
}

// ============================================================================
// 3. BIP340 Taproot Schnorr & BIP86 Key-Path Tweak (`SigningInput::TaprootDigest32`)
// ============================================================================

/// Result of applying the BIP86 Taproot key-path tweak (`TapTweak`) to a `secp256k1` public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaprootTweakedPubkey {
    /// 32-byte untweaked internal x-only public key ($P_x$).
    pub internal_x_only_pubkey: [u8; X_ONLY_PUBKEY_LEN],
    /// 32-byte tweaked output x-only public key ($Q_x$) committed in `OP_1 <32-byte key>` (`0x5120 || Q_x`).
    pub tweaked_x_only_pubkey: [u8; X_ONLY_PUBKEY_LEN],
    /// Y-parity of the tweaked output point $Q$: `0` if even, `1` if odd.
    pub parity: u8,
}

/// Tweaked BIP86 Taproot keypair holding the zeroized 32-byte tweaked private key scalar
/// and the corresponding internal and tweaked x-only public keys.
#[derive(Clone, PartialEq, Eq)]
pub struct Bip86TweakedKeypair {
    /// 32-byte tweaked private key scalar (normalized for even Y of tweaked point $Q$),
    /// wrapped in [`Zeroizing`] so it is wiped on drop.
    pub tweaked_private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    /// 32-byte untweaked internal x-only public key ($P_x$).
    pub internal_x_only_pubkey: [u8; X_ONLY_PUBKEY_LEN],
    /// 32-byte tweaked output x-only public key ($Q_x$).
    pub tweaked_x_only_pubkey: [u8; X_ONLY_PUBKEY_LEN],
    /// Y-parity of the unnormalized tweaked point $Q = P + t \cdot G$ (`0` for even, `1` for odd).
    pub parity: u8,
}

impl fmt::Debug for Bip86TweakedKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bip86TweakedKeypair")
            .field("tweaked_private_key", &"[REDACTED]")
            .field(
                "internal_x_only_pubkey",
                &hex::encode(self.internal_x_only_pubkey),
            )
            .field(
                "tweaked_x_only_pubkey",
                &hex::encode(self.tweaked_x_only_pubkey),
            )
            .field("parity", &self.parity)
            .finish()
    }
}

/// Computes a BIP340 domain-separated tagged hash:
/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn bip340_tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the BIP341 / BIP86 `TapTweak` hash:
/// `tagged_hash("TapTweak", internal_x_only_pubkey || merkle_root)`.
///
/// For BIP86 key-path spends (empty script tree), pass `merkle_root = None`.
pub fn tap_tweak_hash(
    internal_x_only_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    merkle_root: Option<&[u8; 32]>,
) -> [u8; 32] {
    match merkle_root {
        Some(root) => {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(internal_x_only_pubkey);
            buf[32..64].copy_from_slice(root);
            bip340_tagged_hash(TAP_TWEAK_TAG, &buf)
        }
        None => bip340_tagged_hash(TAP_TWEAK_TAG, internal_x_only_pubkey),
    }
}

/// Computes the BIP86 key-path `TapTweak` hash (`tagged_hash("TapTweak", internal_x_only_pubkey)`)
/// with an empty merkle root.
pub fn bip86_tap_tweak_hash(internal_x_only_pubkey: &[u8; X_ONLY_PUBKEY_LEN]) -> [u8; 32] {
    tap_tweak_hash(internal_x_only_pubkey, None)
}

/// Extracts the 32-byte BIP340 x-only public key from a 33-byte compressed SEC1 `secp256k1`
/// public key after validating that it is a valid curve point.
pub fn extract_x_only_pubkey(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<[u8; X_ONLY_PUBKEY_LEN], BackendError> {
    validate_compressed_sec1_prefix(compressed_pubkey)?;
    let _pubkey = PublicKey::from_sec1_bytes(compressed_pubkey).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid 33-byte compressed secp256k1 public key: {e}"
        ))
    })?;
    let mut x_only = [0u8; X_ONLY_PUBKEY_LEN];
    x_only.copy_from_slice(&compressed_pubkey[1..33]);
    Ok(x_only)
}

/// Applies the BIP86 Taproot key-path tweak (`t = tagged_hash("TapTweak", internal_x_only_pubkey)`)
/// to a 32-byte x-only internal public key $P_x$:
///
/// 1. Lifts $P_x$ to the curve point $P = \text{lift\_x}(P_x)$ with even $Y$ (`0x02 || P_x`).
/// 2. Computes $t = \text{int}(\text{tagged\_hash}(\text{"TapTweak"}, P_x))$ and checks $t < n$.
/// 3. Computes $Q = P + t \cdot G$ and extracts the 32-byte tweaked x-only public key $Q_x$
///    along with the parity of $Y(Q)$.
pub fn bip86_tweak_x_only_pubkey(
    internal_x_only_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
) -> Result<TaprootTweakedPubkey, BackendError> {
    let mut even_sec1 = [0u8; COMPRESSED_PUBKEY_LEN];
    even_sec1[0] = 0x02;
    even_sec1[1..33].copy_from_slice(internal_x_only_pubkey);

    let encoded_p = EncodedPoint::from_bytes(even_sec1).map_err(|e| {
        BackendError::Crypto(format!("invalid x-only internal pubkey encoding: {e}"))
    })?;
    let affine_p = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_p))
        .ok_or_else(|| {
            BackendError::Crypto(
                "invalid 32-byte x-only internal public key: not a valid secp256k1 point"
                    .to_string(),
            )
        })?;

    let t_bytes = bip86_tap_tweak_hash(internal_x_only_pubkey);
    let t_scalar = Option::<Scalar>::from(Scalar::from_repr(t_bytes.into())).ok_or_else(|| {
        BackendError::Crypto("BIP86 TapTweak scalar exceeds secp256k1 curve order n".to_string())
    })?;

    let q_point = ProjectivePoint::from(affine_p) + (ProjectivePoint::GENERATOR * t_scalar);
    let q_affine = q_point.to_affine();
    if bool::from(q_affine.is_identity()) {
        return Err(BackendError::Crypto(
            "BIP86 tweaked public key is the point at infinity".to_string(),
        ));
    }

    let q_encoded = q_affine.to_encoded_point(true);
    let q_bytes = q_encoded.as_bytes();
    if q_bytes.len() != COMPRESSED_PUBKEY_LEN {
        return Err(BackendError::Crypto(
            "BIP86 tweaked public key failed compressed SEC1 encoding".to_string(),
        ));
    }

    let parity = u8::from(q_bytes[0] == 0x03);
    let mut tweaked_x_only_pubkey = [0u8; X_ONLY_PUBKEY_LEN];
    tweaked_x_only_pubkey.copy_from_slice(&q_bytes[1..33]);

    Ok(TaprootTweakedPubkey {
        internal_x_only_pubkey: *internal_x_only_pubkey,
        tweaked_x_only_pubkey,
        parity,
    })
}

/// Applies the BIP86 Taproot key-path tweak to a 33-byte compressed SEC1 `secp256k1`
/// derived public key.
///
/// Chain codecs (e.g., `chains/bitcoin.rs`) can call this directly to verify P2TR
/// `OP_1 <32-byte tweaked_x_only_pubkey>` output scripts against the key derived at `input_paths[i]`.
pub fn bip86_tweak_public_key(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<TaprootTweakedPubkey, BackendError> {
    let internal_x_only = extract_x_only_pubkey(compressed_pubkey)?;
    bip86_tweak_x_only_pubkey(&internal_x_only)
}

/// Convenience helper returning the 32-byte BIP86 tweaked x-only public key ($Q_x$)
/// directly from a 33-byte compressed SEC1 `secp256k1` public key.
pub fn bip86_tweaked_x_only_pubkey(
    compressed_pubkey: &[u8; COMPRESSED_PUBKEY_LEN],
) -> Result<[u8; X_ONLY_PUBKEY_LEN], BackendError> {
    Ok(bip86_tweak_public_key(compressed_pubkey)?.tweaked_x_only_pubkey)
}

/// Applies the BIP86 Taproot key-path tweak (`t = tagged_hash("TapTweak", internal_x_only_pubkey)`)
/// to a 32-byte derived `secp256k1` private key scalar $d'$:
///
/// 1. Validates $1 \le d' < n$ and computes internal point $P = d' \cdot G$.
/// 2. Sets $d = d'$ if $Y(P)$ is even, or $d = n - d'$ if $Y(P)$ is odd.
/// 3. Computes $t = \text{int}(\text{tagged\_hash}(\text{"TapTweak"}, P_x))$ and verifies $t < n$.
/// 4. Computes tweaked scalar $q_0 = (d + t) \pmod n$ and tweaked point $Q = q_0 \cdot G$.
/// 5. Normalizes $q = q_0$ if $Y(Q)$ is even, or $q = n - q_0$ if $Y(Q)$ is odd.
/// 6. Explicitly zeroizes all intermediate scalars and stack buffers before returning.
pub fn bip86_tweak_private_key(
    private_key: &[u8; PRIVATE_KEY_LEN],
) -> Result<Bip86TweakedKeypair, BackendError> {
    let mut d_prime_opt = Option::<Scalar>::from(Scalar::from_repr((*private_key).into()));
    let mut d_prime = match d_prime_opt.take() {
        Some(s) if s != Scalar::ZERO => s,
        Some(mut s) => {
            s.zeroize();
            return Err(BackendError::Crypto(
                "invalid secp256k1 private key for BIP86 tweak: scalar is zero".to_string(),
            ));
        }
        None => {
            return Err(BackendError::Crypto(
                "invalid secp256k1 private key for BIP86 tweak: scalar >= curve order n"
                    .to_string(),
            ));
        }
    };

    // Compute internal public point P = d' * G
    let p_affine = (ProjectivePoint::GENERATOR * d_prime).to_affine();
    let p_encoded = p_affine.to_encoded_point(true);
    let p_bytes = p_encoded.as_bytes();

    let mut internal_x_only_pubkey = [0u8; X_ONLY_PUBKEY_LEN];
    internal_x_only_pubkey.copy_from_slice(&p_bytes[1..33]);

    // If Y(P) is odd (0x03), negate d' -> d = -d' mod n so d * G has even Y
    let mut d = if p_bytes[0] == 0x03 {
        -d_prime
    } else {
        d_prime
    };
    d_prime.zeroize();

    // Compute t = int(tagged_hash("TapTweak", internal_x_only_pubkey))
    let mut t_bytes = Zeroizing::new(bip86_tap_tweak_hash(&internal_x_only_pubkey));
    let mut t_scalar = match Option::<Scalar>::from(Scalar::from_repr((*t_bytes).into())) {
        Some(s) => s,
        None => {
            d.zeroize();
            return Err(BackendError::Crypto(
                "BIP86 TapTweak scalar exceeds secp256k1 curve order n".to_string(),
            ));
        }
    };
    t_bytes.zeroize();

    // Compute tweaked scalar q0 = (d + t) mod n
    let mut q0 = d + t_scalar;
    d.zeroize();
    t_scalar.zeroize();

    if q0 == Scalar::ZERO {
        return Err(BackendError::Crypto(
            "BIP86 tweaked private key scalar is zero".to_string(),
        ));
    }

    // Compute tweaked public point Q = q0 * G
    let q_affine = (ProjectivePoint::GENERATOR * q0).to_affine();
    let q_encoded = q_affine.to_encoded_point(true);
    let q_bytes = q_encoded.as_bytes();
    let parity = u8::from(q_bytes[0] == 0x03);

    let mut tweaked_x_only_pubkey = [0u8; X_ONLY_PUBKEY_LEN];
    tweaked_x_only_pubkey.copy_from_slice(&q_bytes[1..33]);

    // Normalize q for even Y(Q) per BIP340 keypair convention
    let mut q_final = if parity == 1 { -q0 } else { q0 };
    q0.zeroize();

    let mut q_field_bytes = q_final.to_bytes();
    q_final.zeroize();

    let mut tweaked_private_key = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
    tweaked_private_key.copy_from_slice(q_field_bytes.as_ref());
    AsMut::<[u8]>::as_mut(&mut q_field_bytes).zeroize();

    Ok(Bip86TweakedKeypair {
        tweaked_private_key,
        internal_x_only_pubkey,
        tweaked_x_only_pubkey,
        parity,
    })
}

/// Verifies a 64-byte BIP340 Schnorr signature over `msg` (typically a 32-byte BIP341
/// Taproot sighash digest) against a 32-byte x-only public key.
pub fn verify_bip340_schnorr(
    x_only_pubkey: &[u8; X_ONLY_PUBKEY_LEN],
    msg: &[u8],
    sig_64: &[u8; SCHNORR_SIGNATURE_LEN],
) -> Result<(), BackendError> {
    let verifying_key = K256SchnorrVerifyingKey::from_bytes(x_only_pubkey).map_err(|e| {
        BackendError::Crypto(format!("invalid 32-byte BIP340 x-only public key: {e}"))
    })?;
    let sig = K256SchnorrSignature::try_from(&sig_64[..]).map_err(|e| {
        BackendError::Crypto(format!("invalid 64-byte BIP340 Schnorr signature: {e}"))
    })?;
    verifying_key.verify_raw(msg, &sig).map_err(|e| {
        BackendError::Crypto(format!("BIP340 Schnorr signature verification failed: {e}"))
    })
}

/// Signs a 32-byte message/digest using a raw (already-tweaked or untweaked) 32-byte
/// `secp256k1` private key and 32-byte `aux_rand` according to BIP340 (`k256::schnorr::SigningKey::sign_raw`).
///
/// Returns `(sig_64, x_only_pubkey)` and zeroizes intermediate key buffers.
pub fn sign_bip340_schnorr_raw_with_aux(
    private_key: &[u8; PRIVATE_KEY_LEN],
    msg: &[u8],
    aux_rand: &[u8; 32],
) -> Result<([u8; SCHNORR_SIGNATURE_LEN], [u8; X_ONLY_PUBKEY_LEN]), BackendError> {
    let signing_key = K256SchnorrSigningKey::from_bytes(private_key).map_err(|e| {
        BackendError::Crypto(format!(
            "invalid secp256k1 private key for BIP340 Schnorr signing: {e}"
        ))
    })?;
    let verifying_key = signing_key.verifying_key();
    let mut x_only_pubkey = [0u8; X_ONLY_PUBKEY_LEN];
    x_only_pubkey.copy_from_slice(verifying_key.to_bytes().as_ref());

    let sig = signing_key.sign_raw(msg, aux_rand).map_err(|e| {
        BackendError::Crypto(format!("BIP340 Schnorr sign_raw failed: {e}"))
    })?;
    let sig_bytes = sig.to_bytes();

    verify_bip340_schnorr(&x_only_pubkey, msg, &sig_bytes)?;
    Ok((sig_bytes, x_only_pubkey))
}

/// Signs a `SigningInput::TaprootDigest32` (32-byte BIP341 sighash digest) in software
/// with caller-supplied 32-byte `aux_rand`:
///
/// 1. Applies the BIP86 Taproot key-path tweak (`t = tagged_hash("TapTweak", internal_x_only_pubkey)`)
///    to the derived `private_key`.
/// 2. Produces a 64-byte BIP340 Schnorr signature over `taproot_digest32` using `k256::schnorr`.
/// 3. Verifies the signature against the 32-byte tweaked x-only public key.
/// 4. Zeroizes all intermediate and tweaked scalar material.
/// 5. Returns [`Signature::new_schnorr`] with `signing_in_hsm: false` and `public_key` set to
///    the 32-byte tweaked x-only public key.
pub fn sign_taproot_schnorr_with_aux_rand(
    private_key: &[u8; PRIVATE_KEY_LEN],
    taproot_digest32: &[u8; SECP256K1_DIGEST_LEN],
    aux_rand: &[u8; 32],
) -> Result<Signature, BackendError> {
    let tweaked = bip86_tweak_private_key(private_key)?;
    let (sig_bytes, schnorr_x_only) =
        sign_bip340_schnorr_raw_with_aux(&tweaked.tweaked_private_key, taproot_digest32, aux_rand)?;

    if schnorr_x_only != tweaked.tweaked_x_only_pubkey {
        return Err(BackendError::Crypto(
            "internal error: BIP86 tweaked x-only public key mismatch after BIP340 signing"
                .to_string(),
        ));
    }

    Ok(Signature::new_schnorr(
        sig_bytes,
        tweaked.tweaked_x_only_pubkey,
    ))
}

/// Signs a `SigningInput::TaprootDigest32` (32-byte BIP341 sighash digest) in software
/// using `k256::schnorr` with deterministic zero `aux_rand` (`[0u8; 32]`):
///
/// Applies the BIP86 Taproot key-path tweak (`t = tagged_hash("TapTweak", internal_x_only_pubkey)`),
/// produces a 64-byte BIP340 Schnorr signature, verifies it against the tweaked x-only public key,
/// zeroizes tweaked intermediate scalar material, and flags `signing_in_hsm: false`.
pub fn sign_taproot_schnorr_software(
    private_key: &[u8; PRIVATE_KEY_LEN],
    taproot_digest32: &[u8; SECP256K1_DIGEST_LEN],
) -> Result<Signature, BackendError> {
    let zero_aux = [0u8; 32];
    sign_taproot_schnorr_with_aux_rand(private_key, taproot_digest32, &zero_aux)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{derive_bip32_str, derive_slip10_str};

    #[test]
    fn test_secp256k1_half_order_constant_matches_k256() {
        // Verify SECP256K1_HALF_ORDER is Low-S and SECP256K1_HALF_ORDER + 1 is High-S
        assert!(is_low_s(&SECP256K1_HALF_ORDER).unwrap());

        let mut half_plus_one = SECP256K1_HALF_ORDER;
        half_plus_one[31] += 1; // 0xa0 -> 0xa1
        assert!(!is_low_s(&half_plus_one).unwrap());

        // Negating half_plus_one yields SECP256K1_HALF_ORDER
        let (normalized, was_high) = normalize_s_scalar(&half_plus_one).unwrap();
        assert!(was_high);
        assert_eq!(normalized, SECP256K1_HALF_ORDER);
        assert!(is_low_s(&normalized).unwrap());

        // n - 1 is high-S and normalizes to 1
        let mut n_minus_one = SECP256K1_ORDER;
        n_minus_one[31] -= 1; // 0x41 -> 0x40
        assert!(!is_low_s(&n_minus_one).unwrap());
        let (norm_one, was_high_n1) = normalize_s_scalar(&n_minus_one).unwrap();
        assert!(was_high_n1);
        let mut expected_one = [0u8; 32];
        expected_one[31] = 1;
        assert_eq!(norm_one, expected_one);

        // 0 and >= n are rejected
        assert!(is_low_s(&[0u8; 32]).is_err());
        assert!(is_low_s(&SECP256K1_ORDER).is_err());
        assert!(is_low_s(&[0xffu8; 32]).is_err());
    }

    #[test]
    fn test_low_s_normalization_on_high_s_ecdsa_signatures_and_recovery_id() {
        let seed =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let key = derive_bip32_str(&seed, "m/44'/60'/0'/0/0").unwrap();
        let privkey = key.private_key();
        let pubkey = key.public_key();

        for i in 0u8..20u8 {
            let mut digest = [0u8; 32];
            digest[0] = i;
            digest[31] = i.wrapping_mul(17).wrapping_add(3);
            let digest_hash: [u8; 32] = Sha256::digest(digest).into();

            // Sign in software (produces low-S)
            let low_s_raw = sign_secp256k1_ecdsa_software_raw(privkey, &digest_hash).unwrap();
            let (r, s_low) = split_ecdsa_rs(&low_s_raw);
            assert!(is_low_s(&s_low).unwrap());

            // Artificially construct the valid malleable high-S counterpart: s_high = n - s_low
            let s_low_scalar = Scalar::from_repr(s_low.into()).unwrap();
            let s_high_scalar = -s_low_scalar;
            assert!(bool::from(s_high_scalar.is_high()));

            let mut high_s_raw = [0u8; 64];
            high_s_raw[..32].copy_from_slice(&r);
            high_s_raw[32..64].copy_from_slice(s_high_scalar.to_bytes().as_ref());

            // Verify normalize_ecdsa_low_s converts high_s_raw back to low_s_raw
            let (norm_bytes, was_normalized) = normalize_ecdsa_low_s(&high_s_raw).unwrap();
            assert!(was_normalized);
            assert_eq!(norm_bytes, low_s_raw);

            // Verify postprocess_ecdsa_signature on the high-S input normalizes S, finds the
            // exact recovery ID, and recovers the derived 33-byte compressed public key
            let processed_from_high =
                postprocess_ecdsa_signature(&high_s_raw, &digest_hash, pubkey, true).unwrap();
            let processed_from_low =
                postprocess_ecdsa_signature(&low_s_raw, &digest_hash, pubkey, false).unwrap();

            assert_eq!(processed_from_high.bytes, low_s_raw.to_vec());
            assert_eq!(processed_from_high.r, Some(r));
            assert_eq!(processed_from_high.s, Some(s_low));
            assert_eq!(
                processed_from_high.recovery_id,
                processed_from_low.recovery_id
            );
            assert_eq!(processed_from_high.der, processed_from_low.der);
            assert!(processed_from_high.signing_in_hsm);
            assert!(!processed_from_low.signing_in_hsm);

            let recid = processed_from_high.recovery_id.unwrap();
            assert!(recid == 0 || recid == 1);

            // Recover compressed and uncompressed pubkeys using the recovery_id
            let recovered_compressed =
                recover_secp256k1_pubkey_compressed(&digest_hash, &low_s_raw, recid).unwrap();
            assert_eq!(&recovered_compressed, pubkey);

            // Opposite parity must NOT match the derived public key
            let other_parity = 1 - recid;
            if let Ok(other_pk) =
                recover_secp256k1_pubkey_compressed(&digest_hash, &low_s_raw, other_parity)
            {
                assert_ne!(&other_pk, pubkey);
            }

            let recovered_uncompressed =
                recover_secp256k1_pubkey_uncompressed(&digest_hash, &low_s_raw, recid).unwrap();
            assert_eq!(recovered_uncompressed[0], 0x04);
            assert_eq!(&recovered_uncompressed[1..33], &pubkey[1..33]);
        }
    }

    #[test]
    fn test_recovery_id_covers_both_parities_and_rejects_wrong_pubkey() {
        let seed = [0x42u8; 64];
        let key = derive_bip32_str(&seed, "m/44'/195'/0'/0/0").unwrap();
        let other_key = derive_bip32_str(&seed, "m/44'/195'/0'/0/1").unwrap();

        let mut seen_recid_0 = false;
        let mut seen_recid_1 = false;

        for counter in 0u32..100u32 {
            let digest: [u8; 32] = Sha256::digest(counter.to_be_bytes()).into();
            let sig = sign_secp256k1_ecdsa_software(key.private_key(), &digest).unwrap();
            assert!(!sig.signing_in_hsm);
            match sig.recovery_id {
                Some(0) => seen_recid_0 = true,
                Some(1) => seen_recid_1 = true,
                other => panic!("unexpected recovery_id: {other:?}"),
            }
            if seen_recid_0 && seen_recid_1 {
                break;
            }
        }
        assert!(seen_recid_0, "expected to observe recovery_id == 0");
        assert!(seen_recid_1, "expected to observe recovery_id == 1");

        // Passing the wrong expected public key must fail closed
        let digest = [0x77u8; 32];
        let raw_sig = sign_secp256k1_ecdsa_software_raw(key.private_key(), &digest).unwrap();
        let err = postprocess_ecdsa_signature(&raw_sig, &digest, other_key.public_key(), false)
            .unwrap_err();
        assert!(matches!(err, BackendError::Crypto(_)));
    }

    #[test]
    fn test_der_encoding_and_bip66_conformance() {
        // Case 1: R and S both have MSB >= 0x80 (requiring 0x00 prefix pad -> 33 bytes each -> 72 bytes total DER)
        let r_high_msb = [0x80u8; 32];
        let mut s_low_with_msb = [0u8; 32];
        // Wait: if s is low-S, s <= 0x7fff..., so s[0] is at most 0x7f when 32 bytes long,
        // UNLESS s has leading zero bytes and the first non-zero byte has MSB >= 0x80!
        // For example: s = 0x0080_0000_... (31 significant bytes, first non-zero byte is 0x80 -> needs 0x00 pad -> 32 DER bytes).
        s_low_with_msb[1] = 0x85;
        s_low_with_msb[31] = 0x01;
        assert!(is_low_s(&s_low_with_msb).unwrap());

        let der = encode_ecdsa_rs_der(&r_high_msb, &s_low_with_msb).unwrap();
        assert_eq!(der[0], 0x30);
        // R is 33 bytes (0x00 || 32 bytes of 0x80), S is 32 bytes (0x00 || 31 bytes starting with 0x85)
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33);
        assert_eq!(der[4], 0x00);
        assert_eq!(der[5], 0x80);

        let decoded_rs = decode_ecdsa_der(&der).unwrap();
        let (dec_r, dec_s) = split_ecdsa_rs(&decoded_rs);
        assert_eq!(dec_r, r_high_msb);
        assert_eq!(dec_s, s_low_with_msb);

        // Case 2: R and S with multiple leading zeros (compact DER)
        let mut r_small = [0u8; 32];
        r_small[30] = 0x12;
        r_small[31] = 0x34;
        let mut s_small = [0u8; 32];
        s_small[31] = 0x7f;

        let der_small = encode_ecdsa_rs_der(&r_small, &s_small).unwrap();
        // R is 2 bytes (0x12, 0x34), S is 1 byte (0x7f) -> total = 2 + (2+2) + (2+1) = 9 bytes
        assert_eq!(
            der_small,
            vec![0x30, 0x07, 0x02, 0x02, 0x12, 0x34, 0x02, 0x01, 0x7f]
        );
        let decoded_small = decode_ecdsa_der(&der_small).unwrap();
        let (dec_r_small, dec_s_small) = split_ecdsa_rs(&decoded_small);
        assert_eq!(dec_r_small, r_small);
        assert_eq!(dec_s_small, s_small);

        // Case 3: Reject non-canonical BIP66 DER (unnecessary leading 0x00 when next byte < 0x80)
        let non_minimal_der = vec![0x30, 0x08, 0x02, 0x03, 0x00, 0x12, 0x34, 0x02, 0x01, 0x7f];
        assert!(decode_ecdsa_der(&non_minimal_der).is_err());
    }

    #[test]
    fn test_software_ed25519_signing_and_verification() {
        let seed =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();
        let slip10_key = derive_slip10_str(&seed, "m/44'/501'/0'/0'").unwrap();
        let message = b"Solana legacy transfer message payload";

        let sig = sign_ed25519_software(slip10_key.private_key(), message).unwrap();
        assert!(!sig.signing_in_hsm);
        assert_eq!(sig.bytes.len(), 64);
        assert!(sig.r.is_none());
        assert!(sig.s.is_none());
        assert!(sig.recovery_id.is_none());
        assert!(sig.der.is_none());
        assert_eq!(sig.public_key, slip10_key.public_key().to_vec());

        let sig_arr: [u8; 64] = sig.bytes.clone().try_into().unwrap();
        verify_ed25519_signature(slip10_key.public_key(), message, &sig_arr).unwrap();

        // Tampered message or signature must fail verification
        assert!(verify_ed25519_signature(slip10_key.public_key(), b"tampered", &sig_arr).is_err());
        let mut bad_sig = sig_arr;
        bad_sig[0] ^= 0x01;
        assert!(verify_ed25519_signature(slip10_key.public_key(), message, &bad_sig).is_err());
    }

    #[test]
    fn test_bip86_published_test_vector_key_tweaking() {
        // Official BIP-0086 Test Vector (Account 0, first receiving address m/86'/0'/0'/0/0):
        // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        // BIP39 Seed (no passphrase):
        // 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
        // 9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();

        // m/86'/0'/0'/0/0:
        // Internal compressed pubkey: 03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
        // Internal x-only pubkey:     cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
        // Tweaked x-only pubkey (Q_x): a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
        let key0 = derive_bip32_str(&seed, "m/86'/0'/0'/0/0").unwrap();
        assert_eq!(
            hex::encode(key0.public_key()),
            "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );

        let pub_tweaked0 = bip86_tweak_public_key(key0.public_key()).unwrap();
        assert_eq!(
            hex::encode(pub_tweaked0.internal_x_only_pubkey),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        assert_eq!(
            hex::encode(pub_tweaked0.tweaked_x_only_pubkey),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );

        let priv_tweaked0 = bip86_tweak_private_key(key0.private_key()).unwrap();
        assert_eq!(
            priv_tweaked0.internal_x_only_pubkey,
            pub_tweaked0.internal_x_only_pubkey
        );
        assert_eq!(
            priv_tweaked0.tweaked_x_only_pubkey,
            pub_tweaked0.tweaked_x_only_pubkey
        );
        assert_eq!(priv_tweaked0.parity, pub_tweaked0.parity);

        // m/86'/0'/0'/0/1 (second receiving address):
        // Internal compressed pubkey: 0283dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145
        // Tweaked x-only pubkey (Q_x): a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb
        let key1 = derive_bip32_str(&seed, "m/86'/0'/0'/0/1").unwrap();
        assert_eq!(
            hex::encode(key1.public_key()),
            "0283dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"
        );
        let pub_tweaked1 = bip86_tweak_public_key(key1.public_key()).unwrap();
        assert_eq!(
            hex::encode(pub_tweaked1.tweaked_x_only_pubkey),
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
        );
        let priv_tweaked1 = bip86_tweak_private_key(key1.private_key()).unwrap();
        assert_eq!(
            priv_tweaked1.tweaked_x_only_pubkey,
            pub_tweaked1.tweaked_x_only_pubkey
        );

        // m/86'/0'/0'/1/0 (first change address):
        // Internal compressed pubkey: 02399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef
        // Tweaked x-only pubkey (Q_x): 882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc
        let key_change0 = derive_bip32_str(&seed, "m/86'/0'/0'/1/0").unwrap();
        assert_eq!(
            hex::encode(key_change0.public_key()),
            "02399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"
        );
        let pub_tweaked_change0 = bip86_tweak_public_key(key_change0.public_key()).unwrap();
        assert_eq!(
            hex::encode(pub_tweaked_change0.tweaked_x_only_pubkey),
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
        );
    }

    #[test]
    fn test_bip340_official_schnorr_test_vectors() {
        // Official BIP-0340 Test Vectors (0, 1, 2, 3)
        struct Bip340Vector {
            seckey: &'static str,
            pubkey: &'static str,
            aux_rand: &'static str,
            msg: &'static str,
            expected_sig: &'static str,
        }

        let vectors = [
            Bip340Vector {
                seckey: "0000000000000000000000000000000000000000000000000000000000000003",
                pubkey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                aux_rand: "0000000000000000000000000000000000000000000000000000000000000000",
                msg: "0000000000000000000000000000000000000000000000000000000000000000",
                expected_sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
                               25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            },
            Bip340Vector {
                seckey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                aux_rand: "0000000000000000000000000000000000000000000000000000000000000001",
                msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                expected_sig: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341\
                               8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            },
            Bip340Vector {
                seckey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
                pubkey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                aux_rand: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
                msg: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                expected_sig: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B\
                               AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            },
            Bip340Vector {
                seckey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
                pubkey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
                aux_rand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                msg: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                expected_sig: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC\
                               97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            },
        ];

        for v in vectors {
            let seckey: [u8; 32] = hex::decode(v.seckey).unwrap().try_into().unwrap();
            let expected_pubkey: [u8; 32] = hex::decode(v.pubkey).unwrap().try_into().unwrap();
            let aux_rand: [u8; 32] = hex::decode(v.aux_rand).unwrap().try_into().unwrap();
            let msg: [u8; 32] = hex::decode(v.msg).unwrap().try_into().unwrap();
            let expected_sig: [u8; 64] = hex::decode(v.expected_sig).unwrap().try_into().unwrap();

            let (sig, pubkey) = sign_bip340_schnorr_raw_with_aux(&seckey, &msg, &aux_rand).unwrap();
            assert_eq!(pubkey, expected_pubkey);
            assert_eq!(sig, expected_sig);
            verify_bip340_schnorr(&pubkey, &msg, &sig).unwrap();
        }
    }

    #[test]
    fn test_taproot_digest32_bip86_schnorr_signing_and_verification() {
        let seed = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .unwrap();

        // Test signing on both odd-Y internal key (m/86'/0'/0'/0/0) and even-Y internal key (m/86'/0'/0'/0/1)
        for path in ["m/86'/0'/0'/0/0", "m/86'/0'/0'/0/1", "m/86'/0'/0'/1/0"] {
            let derived = derive_bip32_str(&seed, path).unwrap();
            let expected_tweaked_x_only = bip86_tweaked_x_only_pubkey(derived.public_key()).unwrap();

            let taproot_digest: [u8; 32] = Sha256::digest(path.as_bytes()).into();
            let sig = sign_taproot_schnorr_software(derived.private_key(), &taproot_digest).unwrap();

            // Must always flag signing_in_hsm: false
            assert!(!sig.signing_in_hsm);
            assert_eq!(sig.bytes.len(), 64);
            assert!(sig.r.is_none());
            assert!(sig.s.is_none());
            assert!(sig.recovery_id.is_none());
            assert!(sig.der.is_none());
            assert_eq!(sig.public_key, expected_tweaked_x_only.to_vec());

            let sig_64: [u8; 64] = sig.bytes.try_into().unwrap();
            verify_bip340_schnorr(&expected_tweaked_x_only, &taproot_digest, &sig_64).unwrap();

            // Verification against the untweaked internal x-only pubkey must fail
            let untweaked_x_only = extract_x_only_pubkey(derived.public_key()).unwrap();
            assert!(
                verify_bip340_schnorr(&untweaked_x_only, &taproot_digest, &sig_64).is_err(),
                "Taproot Schnorr signature must verify against tweaked key, not untweaked internal key"
            );
        }
    }

    #[test]
    fn test_error_handling_on_invalid_keys_and_signatures_and_debug_redaction() {
        // Zero and >= n private keys must be rejected across software ECDSA and BIP86 tweak
        let zero_key = [0u8; 32];
        let digest = [0x11u8; 32];
        assert!(sign_secp256k1_ecdsa_software(&zero_key, &digest).is_err());
        assert!(bip86_tweak_private_key(&zero_key).is_err());
        assert!(bip86_tweak_private_key(&SECP256K1_ORDER).is_err());
        assert!(sign_taproot_schnorr_software(&zero_key, &digest).is_err());

        // Invalid raw ECDSA signatures (r == 0, s == 0, r >= n, s >= n) must be rejected
        assert!(normalize_ecdsa_low_s(&[0u8; 64]).is_err());
        let mut r_overflow = [0x01u8; 64];
        r_overflow[..32].copy_from_slice(&SECP256K1_ORDER);
        assert!(normalize_ecdsa_low_s(&r_overflow).is_err());

        // Invalid compressed SEC1 pubkey prefix (0x00 or 0x05) must be rejected
        let mut bad_pubkey = [0x02u8; 33];
        bad_pubkey[0] = 0x05;
        assert!(decompress_secp256k1_pubkey(&bad_pubkey).is_err());
        assert!(bip86_tweak_public_key(&bad_pubkey).is_err());

        // X coordinate >= field prime p (0xffffffff...) is not a valid secp256k1 point
        let invalid_x_only = [0xffu8; 32];
        assert!(bip86_tweak_x_only_pubkey(&invalid_x_only).is_err());
        assert!(verify_bip340_schnorr(&invalid_x_only, &digest, &[0x22u8; 64]).is_err());

        // Debug output of Bip86TweakedKeypair must redact the tweaked private key
        let valid_priv = [0x07u8; 32];
        let tweaked_kp = bip86_tweak_private_key(&valid_priv).unwrap();
        let dbg = format!("{tweaked_kp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&hex::encode(*tweaked_kp.tweaked_private_key)));

        // tap_tweak_hash with Some(merkle_root) vs None must differ
        let root = [0xaa; 32];
        assert_ne!(
            tap_tweak_hash(&tweaked_kp.internal_x_only_pubkey, None),
            tap_tweak_hash(&tweaked_kp.internal_x_only_pubkey, Some(&root))
        );
    }
}
