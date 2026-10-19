//! XRP Ledger (XRPL) binary payment codec (Task 17, Section 5 of `Specs.md`).
//!
//! Implements decoding, summary extraction, and signing input preparation for XRPL transactions:
//! - Binary-encoded transactions matching XRPL canonical serialization format.
//! - Accept only `TransactionType == Payment` (`0x0000`) for XRP drops or issued currency amounts.
//! - Rejection of non-Payment transactions, multi-signed transactions (`Signers` array), or mismatched `SigningPubKey`.
//! - XRPL classic address derivation: `r...` via RIPEMD-160(SHA-256(compressed_secp256k1_pubkey)) with XRPL Base58 alphabet.
//! - Verification that derived address matches `Account` and derived public key matches `SigningPubKey`.
//! - Signing input computation: `SHA-512Half` (first 32 bytes of SHA-512) over `STX\0` (`0x53545800`) prefix + canonical signing fields (`SigningInput::Digest32`).
//! - Unified [`ParsedTx`] summary (`transfers`, `fee` in drops, `sequence`, `destination_tag`, flags in `details`).
//! - Returned signature formatting as canonical strict ASN.1 DER-encoded low-S ECDSA.

use std::collections::BTreeMap;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};

use crate::backend::generic::crypto::{
    decode_ecdsa_der, encode_ecdsa_der, is_low_s, normalize_ecdsa_low_s,
};
use crate::chains::{
    parse_caip2, ChainCodec, ChainError, DecodedTx, DerivedKeys, FeeSummary, ParsedTx,
    SequenceField, SigningInput, Transfer,
};

/// XRPL single-signing transaction hash prefix: `STX\0` (`0x53545800`).
pub const XRPL_HASH_PREFIX_TX_SIGN: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

/// XRPL TransactionType for Payment: `0x0000`.
pub const XRPL_TRANSACTION_TYPE_PAYMENT: u16 = 0;

/// XRPL standard Base58 dictionary (the Ripple alphabet).
pub const XRPL_BASE58_ALPHABET: &[u8; 58] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

// -----------------------------------------------------------------------------
// XRPL Field Types and Standard Field Codes
// -----------------------------------------------------------------------------

pub const TYPE_UINT16: u16 = 1;
pub const TYPE_UINT32: u16 = 2;
pub const TYPE_UINT64: u16 = 3;
pub const TYPE_HASH128: u16 = 4;
pub const TYPE_HASH256: u16 = 5;
pub const TYPE_AMOUNT: u16 = 6;
pub const TYPE_BLOB: u16 = 7;
pub const TYPE_ACCOUNT_ID: u16 = 8;
pub const TYPE_ST_OBJECT: u16 = 14;
pub const TYPE_ST_ARRAY: u16 = 15;
pub const TYPE_UINT8: u16 = 16;
pub const TYPE_HASH160: u16 = 17;
pub const TYPE_PATH_SET: u16 = 18;
pub const TYPE_VECTOR256: u16 = 19;

// Common field codes (nth)
pub const FIELD_TRANSACTION_TYPE: u16 = 2; // (UInt16, 2)
pub const FIELD_NETWORK_ID: u16 = 1;       // (UInt32, 1)
pub const FIELD_FLAGS: u16 = 2;            // (UInt32, 2)
pub const FIELD_SOURCE_TAG: u16 = 3;       // (UInt32, 3)
pub const FIELD_SEQUENCE: u16 = 4;         // (UInt32, 4)
pub const FIELD_PREV_TXN_LGR_SEQ: u16 = 5; // (UInt32, 5)
pub const FIELD_DESTINATION_TAG: u16 = 14; // (UInt32, 14)
pub const FIELD_LAST_LEDGER_SEQ: u16 = 27; // (UInt32, 27)
pub const FIELD_ACCOUNT_TXN_ID: u16 = 9;   // (Hash256, 9)
pub const FIELD_INVOICE_ID: u16 = 17;      // (Hash256, 17)
pub const FIELD_AMOUNT: u16 = 1;           // (Amount, 1)
pub const FIELD_FEE: u16 = 8;              // (Amount, 8)
pub const FIELD_SEND_MAX: u16 = 9;         // (Amount, 9)
pub const FIELD_DELIVER_MIN: u16 = 10;     // (Amount, 10)
pub const FIELD_SIGNING_PUB_KEY: u16 = 3;  // (Blob, 3)
pub const FIELD_TXN_SIGNATURE: u16 = 4;    // (Blob, 4)
pub const FIELD_ACCOUNT: u16 = 1;          // (AccountID, 1)
pub const FIELD_DESTINATION: u16 = 3;      // (AccountID, 3)
pub const FIELD_SIGNERS: u16 = 3;          // (STArray, 3)
pub const FIELD_MEMOS: u16 = 9;            // (STArray, 9)

/// XRPL Formatted Signature structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrplSignature {
    /// Canonical ASN.1 DER-encoded low-S ECDSA signature formatted as hex string.
    pub signature_hex: String,
    /// 32-byte big-endian `r` scalar as 0x-prefixed hex string.
    pub r: String,
    /// 32-byte big-endian low-S normalized `s` scalar as 0x-prefixed hex string.
    pub s: String,
    /// Signer classic address (`r...`).
    pub signer_address: String,
}

impl XrplSignature {
    /// Constructs an [`XrplSignature`] from raw 64-byte `(r, s)` signature and signer address.
    pub fn from_raw_ecdsa(
        sig_64: &[u8; 64],
        signer_address: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let (normalized, _) =
            normalize_ecdsa_low_s(sig_64).map_err(|e| ChainError::Crypto(e.to_string()))?;
        let der =
            encode_ecdsa_der(&normalized).map_err(|e| ChainError::Crypto(e.to_string()))?;
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&normalized[..32]);
        s_bytes.copy_from_slice(&normalized[32..64]);

        Ok(Self {
            signature_hex: hex::encode(der),
            r: format!("0x{}", hex::encode(r_bytes)),
            s: format!("0x{}", hex::encode(s_bytes)),
            signer_address: signer_address.into(),
        })
    }

    /// Constructs an [`XrplSignature`] from DER-encoded signature bytes.
    pub fn from_der(
        der_bytes: &[u8],
        signer_address: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let raw = decode_ecdsa_der(der_bytes).map_err(|e| ChainError::Crypto(e.to_string()))?;
        let low_s = is_low_s(raw[32..64].try_into().unwrap())
            .map_err(|e| ChainError::Crypto(e.to_string()))?;
        if !low_s {
            return Err(ChainError::Crypto(
                "XRPL ECDSA signature is not low-S normalized".to_string(),
            ));
        }
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&raw[..32]);
        s_bytes.copy_from_slice(&raw[32..64]);

        Ok(Self {
            signature_hex: hex::encode(der_bytes),
            r: format!("0x{}", hex::encode(r_bytes)),
            s: format!("0x{}", hex::encode(s_bytes)),
            signer_address: signer_address.into(),
        })
    }
}

/// Verifies a DER-encoded ECDSA signature against `digest_32` and `pubkey_bytes`.
pub fn verify_xrpl_signature(
    digest_32: &[u8; 32],
    der_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool, ChainError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| ChainError::Crypto(format!("invalid public key for verification: {e}")))?;
    let signature = K256Signature::from_der(der_bytes)
        .map_err(|e| ChainError::Crypto(format!("invalid DER signature for verification: {e}")))?;
    verifying_key
        .verify_prehash(digest_32, &signature)
        .map(|_| true)
        .map_err(|e| ChainError::Crypto(format!("signature verification failed: {e}")))
}

// -----------------------------------------------------------------------------
// Address & Base58 Handling
// -----------------------------------------------------------------------------

/// Converts a 20-byte XRPL AccountID into a classic Base58 address (`r...`).
pub fn xrpl_account_id_to_address(account_id: &[u8; 20]) -> String {
    let mut payload = [0u8; 25];
    payload[0] = 0x00; // Type prefix for classic account address
    payload[1..21].copy_from_slice(account_id);

    let h1 = Sha256::digest(&payload[..21]);
    let h2 = Sha256::digest(&h1);
    payload[21..25].copy_from_slice(&h2[..4]);

    let alphabet = bs58::Alphabet::new(XRPL_BASE58_ALPHABET).unwrap();
    bs58::encode(&payload).with_alphabet(&alphabet).into_string()
}

/// Decodes an XRPL classic address (`r...`) into its 20-byte AccountID.
pub fn xrpl_address_to_account_id(address: &str) -> Result<[u8; 20], ChainError> {
    let alphabet = bs58::Alphabet::new(XRPL_BASE58_ALPHABET).unwrap();
    let decoded = bs58::decode(address)
        .with_alphabet(&alphabet)
        .into_vec()
        .map_err(|e| {
            ChainError::MalformedTransaction(format!("invalid Base58 address '{address}': {e}"))
        })?;
    if decoded.len() != 25 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid XRPL address length {}, expected 25 bytes",
            decoded.len()
        )));
    }
    if decoded[0] != 0x00 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid XRPL address type prefix {:#04x}, expected 0x00",
            decoded[0]
        )));
    }
    let h1 = Sha256::digest(&decoded[..21]);
    let h2 = Sha256::digest(&h1);
    if &h2[..4] != &decoded[21..25] {
        return Err(ChainError::MalformedTransaction(format!(
            "checksum verification failed for XRPL address '{address}'"
        )));
    }
    let mut account_id = [0u8; 20];
    account_id.copy_from_slice(&decoded[1..21]);
    Ok(account_id)
}

/// Derives the XRPL classic account address (`r...`) from a 33-byte compressed secp256k1 public key.
pub fn derive_xrpl_address(pubkey_bytes: &[u8]) -> Result<String, ChainError> {
    if pubkey_bytes.len() != 33 {
        return Err(ChainError::InvalidKeys(format!(
            "expected 33-byte compressed secp256k1 public key, got {}",
            pubkey_bytes.len()
        )));
    }
    let sha = Sha256::digest(pubkey_bytes);
    let mut ripemd = Ripemd160::new();
    ripemd.update(&sha);
    let account_id_bytes = ripemd.finalize();

    let mut account_id = [0u8; 20];
    account_id.copy_from_slice(&account_id_bytes);
    Ok(xrpl_account_id_to_address(&account_id))
}

// -----------------------------------------------------------------------------
// Binary Field Representation & Parsing
// -----------------------------------------------------------------------------

/// Represents an individual serialized field extracted from an XRPL binary transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawField {
    pub type_code: u16,
    pub field_code: u16,
    pub header_bytes: Vec<u8>,
    pub data_bytes: Vec<u8>,
}

impl RawField {
    /// Constructs a [`RawField`], automatically generating its canonical `header_bytes`.
    pub fn new(type_code: u16, field_code: u16, data_bytes: Vec<u8>) -> Self {
        let header_bytes = encode_field_header(type_code, field_code);
        Self {
            type_code,
            field_code,
            header_bytes,
            data_bytes,
        }
    }

    /// Returns the combined serialized bytes `(header_bytes || data_bytes)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_bytes.len() + self.data_bytes.len());
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&self.data_bytes);
        out
    }
}

/// Encodes an XRPL field header (Field ID) given `type_code` and `field_code`.
pub fn encode_field_header(type_code: u16, field_code: u16) -> Vec<u8> {
    if type_code < 16 && field_code < 16 {
        vec![((type_code as u8) << 4) | (field_code as u8)]
    } else if type_code < 16 && field_code >= 16 {
        vec![(type_code as u8) << 4, field_code as u8]
    } else if type_code >= 16 && field_code < 16 {
        vec![field_code as u8, type_code as u8]
    } else {
        vec![0x00, type_code as u8, field_code as u8]
    }
}

/// Encodes a variable-length (VL) prefix according to XRPL binary specification.
pub fn encode_vl_prefix(len: usize) -> Vec<u8> {
    if len <= 192 {
        vec![len as u8]
    } else if len <= 12480 {
        let diff = len - 193;
        vec![193 + (diff / 256) as u8, (diff % 256) as u8]
    } else {
        let diff = len - 12481;
        vec![
            241 + (diff / 65536) as u8,
            ((diff / 256) % 256) as u8,
            (diff % 256) as u8,
        ]
    }
}

/// Decodes a variable-length (VL) prefix from `cursor`, returning `(length, prefix_byte_count)`.
pub fn decode_vl_prefix(cursor: &[u8]) -> Result<(usize, usize), ChainError> {
    if cursor.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "unexpected EOF reading VL length prefix".to_string(),
        ));
    }
    let b1 = cursor[0] as usize;
    if b1 <= 192 {
        Ok((b1, 1))
    } else if b1 <= 240 {
        if cursor.len() < 2 {
            return Err(ChainError::MalformedTransaction(
                "unexpected EOF reading 2-byte VL length prefix".to_string(),
            ));
        }
        let b2 = cursor[1] as usize;
        let len = 193 + (b1 - 193) * 256 + b2;
        Ok((len, 2))
    } else if b1 <= 254 {
        if cursor.len() < 3 {
            return Err(ChainError::MalformedTransaction(
                "unexpected EOF reading 3-byte VL length prefix".to_string(),
            ));
        }
        let b2 = cursor[1] as usize;
        let b3 = cursor[2] as usize;
        let len = 12481 + (b1 - 241) * 65536 + b2 * 256 + b3;
        Ok((len, 3))
    } else {
        Err(ChainError::MalformedTransaction(format!(
            "invalid VL prefix first byte {b1:#04x}"
        )))
    }
}

/// Decodes an XRPL `Amount` field: either native XRP drops (8 bytes) or issued currency (48 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedAmount {
    Drops(u64),
    Issued {
        value: String,
        currency: String,
        issuer: String,
    },
}

/// Formats normalized XFL mantissa and exponent into an exact decimal string.
pub fn format_xfl(mantissa: u64, exp: i64) -> String {
    if mantissa == 0 {
        return "0".to_string();
    }
    let s = mantissa.to_string();
    if exp >= 0 {
        format!("{}{}", s, "0".repeat(exp as usize))
    } else {
        let k = (-exp) as usize;
        if k < s.len() {
            let split = s.len() - k;
            let int_part = &s[..split];
            let frac_part = s[split..].trim_end_matches('0');
            if frac_part.is_empty() {
                int_part.to_string()
            } else {
                format!("{int_part}.{frac_part}")
            }
        } else {
            let zeros = "0".repeat(k - s.len());
            let frac_part = format!("{zeros}{s}");
            let trimmed = frac_part.trim_end_matches('0');
            if trimmed.is_empty() {
                "0".to_string()
            } else {
                format!("0.{trimmed}")
            }
        }
    }
}

/// Decodes an 8-byte or 48-byte `Amount` slice.
pub fn decode_amount(data: &[u8]) -> Result<DecodedAmount, ChainError> {
    if data.len() == 8 {
        // Native XRP amount
        let b0 = data[0];
        if (b0 & 0x80) != 0 {
            return Err(ChainError::MalformedTransaction(
                "8-byte amount has non-XRP bit set".to_string(),
            ));
        }
        if (b0 & 0x40) == 0 && data.iter().any(|&b| b != 0) {
            return Err(ChainError::UnsupportedTransaction(
                "negative XRP amount is unsupported".to_string(),
            ));
        }
        let raw = u64::from_be_bytes(data.try_into().unwrap());
        let drops = raw & 0x3FFF_FFFF_FFFF_FFFF;
        Ok(DecodedAmount::Drops(drops))
    } else if data.len() == 48 {
        // Issued currency amount
        let b0 = data[0];
        if (b0 & 0x80) == 0 {
            return Err(ChainError::MalformedTransaction(
                "48-byte amount does not have not-XRP bit set".to_string(),
            ));
        }
        let raw = u64::from_be_bytes(data[..8].try_into().unwrap());
        let sign = (raw >> 62) & 1;
        if sign == 0 {
            return Err(ChainError::UnsupportedTransaction(
                "negative issued currency amount is unsupported".to_string(),
            ));
        }
        let exp = (((raw >> 54) & 0xFF) as i64) - 97;
        let mantissa = raw & 0x003F_FFFF_FFFF_FFFF;
        let value = format_xfl(mantissa, exp);

        // Currency code (20 bytes)
        let curr_bytes = &data[8..28];
        let currency = if curr_bytes[..12].iter().all(|&b| b == 0)
            && curr_bytes[15..].iter().all(|&b| b == 0)
        {
            // Standard 3-character ASCII currency code
            let code_slice = &curr_bytes[12..15];
            std::str::from_utf8(code_slice)
                .map(|s| s.trim_matches('\0').to_string())
                .unwrap_or_else(|_| hex::encode(curr_bytes))
        } else {
            hex::encode(curr_bytes)
        };

        // Issuer AccountID (20 bytes)
        let issuer_bytes: &[u8; 20] = data[28..48].try_into().unwrap();
        let issuer = xrpl_account_id_to_address(issuer_bytes);

        Ok(DecodedAmount::Issued {
            value,
            currency,
            issuer,
        })
    } else {
        Err(ChainError::MalformedTransaction(format!(
            "invalid Amount byte length {}, expected 8 or 48",
            data.len()
        )))
    }
}

/// Parses raw binary XRPL transaction bytes into canonical sorted [`RawField`] list.
pub fn parse_xrpl_fields(mut buf: &[u8]) -> Result<Vec<RawField>, ChainError> {
    let mut fields = Vec::new();

    while !buf.is_empty() {
        let b0 = buf[0];
        let high = (b0 >> 4) as u16;
        let low = (b0 & 0x0F) as u16;

        let (type_code, field_code, header_len) = if high != 0 && low != 0 {
            (high, low, 1)
        } else if high != 0 && low == 0 {
            if buf.len() < 2 {
                return Err(ChainError::MalformedTransaction(
                    "unexpected EOF reading 2-byte field ID".to_string(),
                ));
            }
            (high, buf[1] as u16, 2)
        } else if high == 0 && low != 0 {
            if buf.len() < 2 {
                return Err(ChainError::MalformedTransaction(
                    "unexpected EOF reading 2-byte field ID".to_string(),
                ));
            }
            (buf[1] as u16, low, 2)
        } else {
            if buf.len() < 3 {
                return Err(ChainError::MalformedTransaction(
                    "unexpected EOF reading 3-byte field ID".to_string(),
                ));
            }
            (buf[1] as u16, buf[2] as u16, 3)
        };

        let header_bytes = buf[..header_len].to_vec();
        buf = &buf[header_len..];

        // Read payload based on type_code
        let data_len = match type_code {
            TYPE_UINT16 => 2,
            TYPE_UINT32 => 4,
            TYPE_UINT64 => 8,
            TYPE_HASH128 => 16,
            TYPE_HASH256 => 32,
            TYPE_AMOUNT => {
                if buf.is_empty() {
                    return Err(ChainError::MalformedTransaction(
                        "unexpected EOF reading Amount field".to_string(),
                    ));
                }
                if (buf[0] & 0x80) == 0 {
                    8
                } else {
                    48
                }
            }
            TYPE_BLOB | TYPE_ACCOUNT_ID | TYPE_VECTOR256 => {
                let (payload_len, prefix_len) = decode_vl_prefix(buf)?;
                let total_len = prefix_len + payload_len;
                if buf.len() < total_len {
                    return Err(ChainError::MalformedTransaction(format!(
                        "unexpected EOF reading VL field: need {total_len} bytes, got {}",
                        buf.len()
                    )));
                }
                total_len
            }
            TYPE_UINT8 => 1,
            TYPE_HASH160 => 20,
            TYPE_ST_OBJECT => {
                // STObject reading until ObjectEndMarker (0xE1)
                let mut offset = 0;
                while offset < buf.len() && buf[offset] != 0xE1 {
                    // Skip nested field
                    let sub_b0 = buf[offset];
                    let sub_high = (sub_b0 >> 4) as u16;
                    let sub_low = (sub_b0 & 0x0F) as u16;
                    let sub_hdr_len = if sub_high != 0 && sub_low != 0 {
                        1
                    } else if (sub_high != 0 && sub_low == 0) || (sub_high == 0 && sub_low != 0) {
                        2
                    } else {
                        3
                    };
                    offset += sub_hdr_len;
                }
                if offset < buf.len() && buf[offset] == 0xE1 {
                    offset += 1; // Include 0xE1 ObjectEndMarker
                }
                offset
            }
            TYPE_ST_ARRAY => {
                // STArray reading until ArrayEndMarker (0xF1)
                let mut offset = 0;
                while offset < buf.len() && buf[offset] != 0xF1 {
                    offset += 1;
                }
                if offset < buf.len() && buf[offset] == 0xF1 {
                    offset += 1; // Include 0xF1 ArrayEndMarker
                }
                offset
            }
            TYPE_PATH_SET => {
                // PathSet reading until 0x00 boundary
                let mut offset = 0;
                while offset < buf.len() && buf[offset] != 0x00 {
                    offset += 1;
                }
                if offset < buf.len() && buf[offset] == 0x00 {
                    offset += 1;
                }
                offset
            }
            other => {
                return Err(ChainError::UnsupportedTransaction(format!(
                    "unsupported XRPL serialized field type {other}"
                )));
            }
        };

        if buf.len() < data_len {
            return Err(ChainError::MalformedTransaction(format!(
                "unexpected EOF reading field (type {type_code}, field {field_code}): need {data_len} bytes, got {}",
                buf.len()
            )));
        }

        let data_bytes = buf[..data_len].to_vec();
        buf = &buf[data_len..];

        fields.push(RawField {
            type_code,
            field_code,
            header_bytes,
            data_bytes,
        });
    }

    Ok(fields)
}

// -----------------------------------------------------------------------------
// Transaction Codec Implementation
// -----------------------------------------------------------------------------

/// Validates that `chain` is a supported CAIP-2 XRPL network identifier.
pub fn validate_xrpl_chain(
    chain: &str,
    tx_network_id: Option<u32>,
) -> Result<(&str, &str), ChainError> {
    let (ns, ref_id) = parse_caip2(chain)?;
    if ns != "xrpl" {
        return Err(ChainError::UnsupportedChain(format!(
            "expected 'xrpl' namespace, got '{ns}'"
        )));
    }
    if ref_id.is_empty() || ref_id.len() > 64 {
        return Err(ChainError::UnsupportedTransaction(format!(
            "invalid XRPL chain reference '{ref_id}' in '{chain}'"
        )));
    }
    if let Some(net_id) = tx_network_id {
        let expected_net_id: Option<u32> = match ref_id {
            "0" | "mainnet" => Some(0),
            "1" | "testnet" => Some(1),
            "2" | "devnet" => Some(2),
            numeric => numeric.parse::<u32>().ok(),
        };
        if let Some(exp) = expected_net_id {
            if exp != net_id {
                return Err(ChainError::ChainMismatch {
                    expected: chain.to_string(),
                    actual: format!("xrpl:{net_id}"),
                });
            }
        }
    }
    Ok((ns, ref_id))
}

/// XRP Ledger Payment transaction codec implementing [`ChainCodec`].
#[derive(Debug, Clone, Copy, Default)]
pub struct XrplCodec;

impl XrplCodec {
    /// Constructs a new [`XrplCodec`].
    pub fn new() -> Self {
        Self
    }
}

impl ChainCodec for XrplCodec {
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        decode_xrpl_tx(chain, raw_tx_bytes, keys)
    }
}

/// Decodes an XRPL binary transaction, enforces single-key Payment policy, verifies sender bindings,
/// and produces [`DecodedTx`].
pub fn decode_xrpl_tx(
    chain: &str,
    raw_tx_bytes: &[u8],
    keys: &DerivedKeys,
) -> Result<DecodedTx, ChainError> {
    // 1. Resolve raw bytes (handling hex-encoded or binary bytes gracefully)
    let binary_bytes: Vec<u8> = if raw_tx_bytes.starts_with(b"0x") {
        let hex_str = std::str::from_utf8(&raw_tx_bytes[2..]).map_err(|e| {
            ChainError::MalformedTransaction(format!("invalid hex string UTF-8: {e}"))
        })?;
        hex::decode(hex_str)
            .map_err(|e| ChainError::MalformedTransaction(format!("invalid hex transaction: {e}")))?
    } else if raw_tx_bytes.len() >= 6
        && raw_tx_bytes[0] != 0x12
        && raw_tx_bytes.iter().all(|&b| b.is_ascii_hexdigit())
    {
        let hex_str = std::str::from_utf8(raw_tx_bytes).map_err(|e| {
            ChainError::MalformedTransaction(format!("invalid hex string UTF-8: {e}"))
        })?;
        hex::decode(hex_str)
            .map_err(|e| ChainError::MalformedTransaction(format!("invalid hex transaction: {e}")))?
    } else {
        raw_tx_bytes.to_vec()
    };

    if binary_bytes.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "empty transaction bytes".to_string(),
        ));
    }

    // 2. Validate derived public key and compute expected address
    let single_key = keys.single()?;
    if single_key.len() != 33 {
        return Err(ChainError::InvalidKeys(format!(
            "expected 33-byte compressed secp256k1 public key, got {}",
            single_key.len()
        )));
    }
    let expected_signer_address = derive_xrpl_address(single_key)?;

    // 3. Parse all binary fields
    let all_fields = parse_xrpl_fields(&binary_bytes)?;

    // Check for multi-signing (Signers array)
    if all_fields
        .iter()
        .any(|f| f.type_code == TYPE_ST_ARRAY && f.field_code == FIELD_SIGNERS)
    {
        return Err(ChainError::UnsupportedTransaction(
            "multi-signed transactions are unsupported".to_string(),
        ));
    }

    // Map fields by (type_code, field_code)
    let mut field_map: BTreeMap<(u16, u16), &RawField> = BTreeMap::new();
    for f in &all_fields {
        field_map.insert((f.type_code, f.field_code), f);
    }

    // 4. Validate TransactionType == Payment (0)
    let tt_field = field_map
        .get(&(TYPE_UINT16, FIELD_TRANSACTION_TYPE))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing TransactionType field".to_string())
        })?;
    if tt_field.data_bytes.len() != 2 {
        return Err(ChainError::MalformedTransaction(
            "invalid TransactionType field length".to_string(),
        ));
    }
    let tx_type = u16::from_be_bytes(tt_field.data_bytes.as_slice().try_into().unwrap());
    if tx_type != XRPL_TRANSACTION_TYPE_PAYMENT {
        return Err(ChainError::UnsupportedTransaction(format!(
            "unsupported transaction type {tx_type}: only Payment (0x0000) is supported"
        )));
    }

    // Check optional NetworkID
    let tx_network_id = field_map
        .get(&(TYPE_UINT32, FIELD_NETWORK_ID))
        .and_then(|f| {
            if f.data_bytes.len() == 4 {
                Some(u32::from_be_bytes(f.data_bytes.as_slice().try_into().unwrap()))
            } else {
                None
            }
        });
    validate_xrpl_chain(chain, tx_network_id)?;

    // 5. Validate SigningPubKey
    let pubkey_field = field_map
        .get(&(TYPE_BLOB, FIELD_SIGNING_PUB_KEY))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing SigningPubKey field".to_string())
        })?;
    let (pk_payload_len, pk_prefix_len) = decode_vl_prefix(&pubkey_field.data_bytes)?;
    if pk_payload_len == 0 {
        return Err(ChainError::UnsupportedTransaction(
            "empty SigningPubKey: multi-signed transactions are unsupported".to_string(),
        ));
    }
    let actual_pk_bytes = &pubkey_field.data_bytes[pk_prefix_len..pk_prefix_len + pk_payload_len];
    if actual_pk_bytes != single_key {
        return Err(ChainError::UnsupportedTransaction(format!(
            "mismatched SigningPubKey: transaction pubkey ({}) does not match derived signer pubkey ({})",
            hex::encode(actual_pk_bytes),
            hex::encode(single_key)
        )));
    }

    // 6. Validate Account matches derived address
    let account_field = field_map
        .get(&(TYPE_ACCOUNT_ID, FIELD_ACCOUNT))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing Account field".to_string())
        })?;
    let (acct_len, acct_prefix_len) = decode_vl_prefix(&account_field.data_bytes)?;
    if acct_len != 20 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid Account length {acct_len}, expected 20 bytes"
        )));
    }
    let account_id: &[u8; 20] = account_field.data_bytes[acct_prefix_len..acct_prefix_len + 20]
        .try_into()
        .unwrap();
    let from_address = xrpl_account_id_to_address(account_id);
    if from_address != expected_signer_address {
        return Err(ChainError::UnsupportedTransaction(format!(
            "mismatched Account: transaction specifies '{from_address}', but derived signer address is '{expected_signer_address}'"
        )));
    }

    // 7. Validate Destination
    let dest_field = field_map
        .get(&(TYPE_ACCOUNT_ID, FIELD_DESTINATION))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing Destination field".to_string())
        })?;
    let (dest_len, dest_prefix_len) = decode_vl_prefix(&dest_field.data_bytes)?;
    if dest_len != 20 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid Destination length {dest_len}, expected 20 bytes"
        )));
    }
    let dest_id: &[u8; 20] = dest_field.data_bytes[dest_prefix_len..dest_prefix_len + 20]
        .try_into()
        .unwrap();
    let to_address = xrpl_account_id_to_address(dest_id);

    // 8. Parse Amount
    let amount_field = field_map
        .get(&(TYPE_AMOUNT, FIELD_AMOUNT))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing Amount field".to_string())
        })?;
    let decoded_amount = decode_amount(&amount_field.data_bytes)?;

    // 9. Parse Fee
    let fee_field = field_map
        .get(&(TYPE_AMOUNT, FIELD_FEE))
        .ok_or_else(|| ChainError::UnsupportedTransaction("missing Fee field".to_string()))?;
    let decoded_fee = decode_amount(&fee_field.data_bytes)?;
    let fee_drops = match decoded_fee {
        DecodedAmount::Drops(d) => d,
        DecodedAmount::Issued { .. } => {
            return Err(ChainError::UnsupportedTransaction(
                "transaction fee must be denominated in native XRP drops".to_string(),
            ));
        }
    };

    // 10. Parse Sequence
    let seq_field = field_map
        .get(&(TYPE_UINT32, FIELD_SEQUENCE))
        .ok_or_else(|| {
            ChainError::UnsupportedTransaction("missing Sequence field".to_string())
        })?;
    if seq_field.data_bytes.len() != 4 {
        return Err(ChainError::MalformedTransaction(
            "invalid Sequence field length".to_string(),
        ));
    }
    let sequence = u32::from_be_bytes(seq_field.data_bytes.as_slice().try_into().unwrap()) as u64;

    // Optional fields
    let flags = field_map
        .get(&(TYPE_UINT32, FIELD_FLAGS))
        .and_then(|f| {
            if f.data_bytes.len() == 4 {
                Some(u32::from_be_bytes(f.data_bytes.as_slice().try_into().unwrap()))
            } else {
                None
            }
        })
        .unwrap_or(0);

    let destination_tag = field_map
        .get(&(TYPE_UINT32, FIELD_DESTINATION_TAG))
        .and_then(|f| {
            if f.data_bytes.len() == 4 {
                Some(u32::from_be_bytes(f.data_bytes.as_slice().try_into().unwrap()))
            } else {
                None
            }
        });

    let source_tag = field_map
        .get(&(TYPE_UINT32, FIELD_SOURCE_TAG))
        .and_then(|f| {
            if f.data_bytes.len() == 4 {
                Some(u32::from_be_bytes(f.data_bytes.as_slice().try_into().unwrap()))
            } else {
                None
            }
        });

    let last_ledger_sequence = field_map
        .get(&(TYPE_UINT32, FIELD_LAST_LEDGER_SEQ))
        .and_then(|f| {
            if f.data_bytes.len() == 4 {
                Some(u32::from_be_bytes(f.data_bytes.as_slice().try_into().unwrap()))
            } else {
                None
            }
        });

    // 11. Build Transfer & Details
    let (transfer, mut details_map) = match decoded_amount {
        DecodedAmount::Drops(drops) => {
            let det = serde_json::json!({
                "transaction_type": "Payment",
                "account": from_address,
                "destination": to_address,
                "amount_drops": drops,
                "fee_drops": fee_drops,
                "sequence": sequence,
                "flags": flags,
                "chain": chain,
            });
            let transfer = Transfer::new(&from_address, &to_address, drops.to_string(), "XRP");
            (transfer, det)
        }
        DecodedAmount::Issued {
            value,
            currency,
            issuer,
        } => {
            let det = serde_json::json!({
                "transaction_type": "Payment",
                "account": from_address,
                "destination": to_address,
                "amount": value,
                "currency": currency,
                "issuer": issuer,
                "fee_drops": fee_drops,
                "sequence": sequence,
                "flags": flags,
                "chain": chain,
            });
            let transfer = Transfer::new(&from_address, &to_address, &value, &currency);
            (transfer, det)
        }
    };

    if let Some(dtag) = destination_tag {
        details_map["destination_tag"] = serde_json::json!(dtag);
    }
    if let Some(stag) = source_tag {
        details_map["source_tag"] = serde_json::json!(stag);
    }
    if let Some(lseq) = last_ledger_sequence {
        details_map["last_ledger_sequence"] = serde_json::json!(lseq);
    }
    if let Some(nid) = tx_network_id {
        details_map["network_id"] = serde_json::json!(nid);
    }

    let parsed = ParsedTx::new(
        vec![transfer],
        FeeSummary::new(fee_drops.to_string(), "drops"),
        SequenceField::sequence(sequence),
        details_map,
    );

    // 12. Canonical signing input computation:
    // Gather all fields EXCEPT TxnSignature (type 7, field 4) and sort canonically by (type_code, field_code)
    let mut signing_fields: Vec<RawField> = all_fields
        .into_iter()
        .filter(|f| !(f.type_code == TYPE_BLOB && f.field_code == FIELD_TXN_SIGNATURE))
        .collect();
    signing_fields.sort_by_key(|f| (f.type_code, f.field_code));

    let mut canonical_signing_bytes = Vec::new();
    for f in &signing_fields {
        canonical_signing_bytes.extend_from_slice(&f.header_bytes);
        canonical_signing_bytes.extend_from_slice(&f.data_bytes);
    }

    // Compute SHA-512Half(0x53545800 || canonical_signing_bytes)
    let mut hasher = Sha512::new();
    hasher.update(&XRPL_HASH_PREFIX_TX_SIGN);
    hasher.update(&canonical_signing_bytes);
    let full_hash = hasher.finalize();

    let mut digest_32 = [0u8; 32];
    digest_32.copy_from_slice(&full_hash[..32]);

    Ok(DecodedTx::new(
        parsed,
        SigningInput::Digest32(digest_32),
        expected_signer_address,
    ))
}

// -----------------------------------------------------------------------------
// Transaction Construction Helpers for Vectors & Testing
// -----------------------------------------------------------------------------

/// Constructs canonical binary bytes for an XRPL Payment transaction.
#[derive(Debug, Clone)]
pub struct XrplPaymentBuilder {
    pub account: [u8; 20],
    pub destination: [u8; 20],
    pub amount: DecodedAmount,
    pub fee_drops: u64,
    pub sequence: u32,
    pub signing_pub_key: Vec<u8>,
    pub flags: Option<u32>,
    pub destination_tag: Option<u32>,
    pub source_tag: Option<u32>,
    pub last_ledger_sequence: Option<u32>,
    pub network_id: Option<u32>,
    pub txn_signature: Option<Vec<u8>>,
    pub custom_transaction_type: Option<u16>,
    pub include_signers: bool,
}

impl XrplPaymentBuilder {
    pub fn new(
        account: [u8; 20],
        destination: [u8; 20],
        amount: DecodedAmount,
        fee_drops: u64,
        sequence: u32,
        signing_pub_key: Vec<u8>,
    ) -> Self {
        Self {
            account,
            destination,
            amount,
            fee_drops,
            sequence,
            signing_pub_key,
            flags: Some(0x80000000), // tfFullyCanonicalSig
            destination_tag: None,
            source_tag: None,
            last_ledger_sequence: None,
            network_id: None,
            txn_signature: None,
            custom_transaction_type: None,
            include_signers: false,
        }
    }

    /// Serializes all configured fields in canonical XRPL binary order.
    pub fn build_fields(&self) -> Vec<RawField> {
        let mut fields = Vec::new();

        // TransactionType (UInt16, 2)
        let tt = self
            .custom_transaction_type
            .unwrap_or(XRPL_TRANSACTION_TYPE_PAYMENT);
        fields.push(RawField::new(
            TYPE_UINT16,
            FIELD_TRANSACTION_TYPE,
            tt.to_be_bytes().to_vec(),
        ));

        // NetworkID (UInt32, 1)
        if let Some(net_id) = self.network_id {
            fields.push(RawField::new(
                TYPE_UINT32,
                FIELD_NETWORK_ID,
                net_id.to_be_bytes().to_vec(),
            ));
        }

        // Flags (UInt32, 2)
        if let Some(flg) = self.flags {
            fields.push(RawField::new(
                TYPE_UINT32,
                FIELD_FLAGS,
                flg.to_be_bytes().to_vec(),
            ));
        }

        // SourceTag (UInt32, 3)
        if let Some(stag) = self.source_tag {
            fields.push(RawField::new(
                TYPE_UINT32,
                FIELD_SOURCE_TAG,
                stag.to_be_bytes().to_vec(),
            ));
        }

        // Sequence (UInt32, 4)
        fields.push(RawField::new(
            TYPE_UINT32,
            FIELD_SEQUENCE,
            self.sequence.to_be_bytes().to_vec(),
        ));

        // DestinationTag (UInt32, 14)
        if let Some(dtag) = self.destination_tag {
            fields.push(RawField::new(
                TYPE_UINT32,
                FIELD_DESTINATION_TAG,
                dtag.to_be_bytes().to_vec(),
            ));
        }

        // LastLedgerSequence (UInt32, 27)
        if let Some(lseq) = self.last_ledger_sequence {
            fields.push(RawField::new(
                TYPE_UINT32,
                FIELD_LAST_LEDGER_SEQ,
                lseq.to_be_bytes().to_vec(),
            ));
        }

        // Amount (Amount, 1)
        let amount_bytes = match &self.amount {
            DecodedAmount::Drops(drops) => {
                let val = 0x4000_0000_0000_0000u64 | (*drops & 0x3FFF_FFFF_FFFF_FFFF);
                val.to_be_bytes().to_vec()
            }
            DecodedAmount::Issued {
                value,
                currency,
                issuer,
            } => {
                let mut data = vec![0u8; 48];
                let (mantissa, exp) = parse_xfl_string(value);
                let val_u64 = 0x8000_0000_0000_0000u64
                    | 0x4000_0000_0000_0000u64
                    | (((exp + 97) as u64 & 0xFF) << 54)
                    | (mantissa & 0x003F_FFFF_FFFF_FFFF);
                data[..8].copy_from_slice(&val_u64.to_be_bytes());

                // Currency code in bytes 8..28
                let curr_bytes = currency.as_bytes();
                if curr_bytes.len() == 3 {
                    data[20..23].copy_from_slice(curr_bytes);
                } else {
                    let decoded_hex = hex::decode(currency).unwrap_or_default();
                    let copy_len = decoded_hex.len().min(20);
                    data[8..8 + copy_len].copy_from_slice(&decoded_hex[..copy_len]);
                }

                // Issuer AccountID in bytes 28..48
                let issuer_id = xrpl_address_to_account_id(issuer).unwrap_or([0u8; 20]);
                data[28..48].copy_from_slice(&issuer_id);
                data
            }
        };
        fields.push(RawField::new(TYPE_AMOUNT, FIELD_AMOUNT, amount_bytes));

        // Fee (Amount, 8)
        let fee_val = 0x4000_0000_0000_0000u64 | (self.fee_drops & 0x3FFF_FFFF_FFFF_FFFF);
        fields.push(RawField::new(
            TYPE_AMOUNT,
            FIELD_FEE,
            fee_val.to_be_bytes().to_vec(),
        ));

        // SigningPubKey (Blob, 3)
        let mut pk_data = encode_vl_prefix(self.signing_pub_key.len());
        pk_data.extend_from_slice(&self.signing_pub_key);
        fields.push(RawField::new(TYPE_BLOB, FIELD_SIGNING_PUB_KEY, pk_data));

        // TxnSignature (Blob, 4) if present
        if let Some(sig) = &self.txn_signature {
            let mut sig_data = encode_vl_prefix(sig.len());
            sig_data.extend_from_slice(sig);
            fields.push(RawField::new(TYPE_BLOB, FIELD_TXN_SIGNATURE, sig_data));
        }

        // Account (AccountID, 1)
        let mut acct_data = encode_vl_prefix(20);
        acct_data.extend_from_slice(&self.account);
        fields.push(RawField::new(TYPE_ACCOUNT_ID, FIELD_ACCOUNT, acct_data));

        // Destination (AccountID, 3)
        let mut dest_data = encode_vl_prefix(20);
        dest_data.extend_from_slice(&self.destination);
        fields.push(RawField::new(TYPE_ACCOUNT_ID, FIELD_DESTINATION, dest_data));

        // Signers (STArray, 3) if requested (for negative test)
        if self.include_signers {
            fields.push(RawField::new(
                TYPE_ST_ARRAY,
                FIELD_SIGNERS,
                vec![0xF1], // ArrayEndMarker
            ));
        }

        fields.sort_by_key(|f| (f.type_code, f.field_code));
        fields
    }

    /// Serializes the transaction to binary bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let fields = self.build_fields();
        let mut out = Vec::new();
        for f in &fields {
            out.extend_from_slice(&f.header_bytes);
            out.extend_from_slice(&f.data_bytes);
        }
        out
    }
}

/// Helper to parse decimal amount string to normalized XFL mantissa and exponent.
fn parse_xfl_string(s: &str) -> (u64, i64) {
    if s == "0" || s.is_empty() {
        return (0, 0);
    }
    let (digits, exp) = if let Some((int_p, frac_p)) = s.split_once('.') {
        let trimmed_frac = frac_p.trim_end_matches('0');
        let combined = format!("{}{}", int_p, trimmed_frac);
        let digits = combined.trim_start_matches('0').to_string();
        (digits, -(trimmed_frac.len() as i64))
    } else {
        let digits = s.trim_start_matches('0').to_string();
        (digits, 0i64)
    };

    let cur_len = digits.len();
    let (norm_digits, final_exp) = if cur_len < 16 {
        let padded = format!("{}{}", digits, "0".repeat(16 - cur_len));
        (padded, exp - (16 - cur_len) as i64)
    } else if cur_len > 16 {
        (digits[..16].to_string(), exp + (cur_len - 16) as i64)
    } else {
        (digits, exp)
    };

    let mantissa = norm_digits.parse::<u64>().unwrap_or(0);
    (mantissa, final_exp)
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_xrpl_address_derivation_from_genesis_key() {
        // XRPL genesis key
        let genesis_pk = hex::decode("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020").unwrap();
        let derived_addr = derive_xrpl_address(&genesis_pk).unwrap();
        assert_eq!(derived_addr, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh");

        // Roundtrip to account_id and back
        let acct_id = xrpl_address_to_account_id(&derived_addr).unwrap();
        let re_encoded = xrpl_account_id_to_address(&acct_id);
        assert_eq!(re_encoded, derived_addr);
        assert_eq!(hex::encode(acct_id), "b5f762798a53d543a014caf8b297cff8f2f937e8");
    }

    #[test]
    fn test_vl_prefix_encoding_and_decoding() {
        for len in [0, 1, 33, 192, 193, 200, 12480] {
            let enc = encode_vl_prefix(len);
            let (dec_len, prefix_len) = decode_vl_prefix(&enc).unwrap();
            assert_eq!(dec_len, len);
            assert_eq!(prefix_len, enc.len());
        }
    }

    #[test]
    fn test_field_header_encoding() {
        // Type < 16, Field < 16: 1 byte
        assert_eq!(encode_field_header(1, 2), vec![0x12]);
        assert_eq!(encode_field_header(2, 4), vec![0x24]);
        assert_eq!(encode_field_header(6, 1), vec![0x61]);
        assert_eq!(encode_field_header(7, 3), vec![0x73]);

        // Type < 16, Field >= 16: 2 bytes (high nibble type, second byte field)
        assert_eq!(encode_field_header(2, 27), vec![0x20, 0x1B]);

        // Type >= 16, Field < 16: 2 bytes (low nibble field, second byte type)
        assert_eq!(encode_field_header(18, 1), vec![0x01, 0x12]);
    }

    #[test]
    fn test_format_xfl_precision() {
        assert_eq!(format_xfl(1000000000000000, -15), "1");
        assert_eq!(format_xfl(1000000000000000, -14), "10");
        assert_eq!(format_xfl(1000000000000000, -16), "0.1");
        assert_eq!(format_xfl(5000000000000000, -18), "0.005");
        assert_eq!(format_xfl(1234560000000000, -13), "123.456");
    }

    #[test]
    fn test_native_xrp_payment_decoding_and_signature_recovery() {
        // Derive key from standard BIP32 seed
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key, pub_key) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/144'/0'/0/0".parse().unwrap())
                .unwrap();
        let signing_key = SigningKey::from_bytes((&*priv_key).into()).unwrap();
        let pubkey_bytes = pub_key.to_vec();
        let signer_address = derive_xrpl_address(&pubkey_bytes).unwrap();
        let account_id = xrpl_address_to_account_id(&signer_address).unwrap();

        let dest_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let dest_id = xrpl_address_to_account_id(dest_address).unwrap();

        let builder = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(25_000_000), // 25 XRP
            12,                              // 12 drops fee
            1,                               // Sequence 1
            pubkey_bytes.clone(),
        );

        let raw_tx_bytes = builder.to_bytes();
        let keys = DerivedKeys::from(&pubkey_bytes);
        let codec = XrplCodec::new();

        let decoded = codec.decode("xrpl:0", &raw_tx_bytes, &keys).unwrap();

        assert_eq!(decoded.signer_address, signer_address);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].from, signer_address);
        assert_eq!(decoded.parsed.transfers[0].to, dest_address);
        assert_eq!(decoded.parsed.transfers[0].amount, "25000000");
        assert_eq!(decoded.parsed.transfers[0].asset, "XRP");
        assert_eq!(decoded.parsed.fee.amount, "12");
        assert_eq!(decoded.parsed.fee.asset, "drops");
        assert_eq!(decoded.parsed.sequence.as_sequence(), Some(1));

        let digest_32 = match decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };

        // Sign digest with private key
        let (sig, _rec_id) = signing_key.sign_prehash_recoverable(&digest_32).unwrap();
        let mut sig_64 = [0u8; 64];
        sig_64.copy_from_slice(&sig.to_bytes());

        let xrpl_sig = XrplSignature::from_raw_ecdsa(&sig_64, &signer_address).unwrap();
        let der_bytes = hex::decode(&xrpl_sig.signature_hex).unwrap();

        // Verify DER signature
        assert!(verify_xrpl_signature(&digest_32, &der_bytes, &pubkey_bytes).unwrap());
    }

    #[test]
    fn test_issued_currency_payment_decoding() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (_priv_key, pub_key) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/144'/0'/0/0".parse().unwrap())
                .unwrap();
        let pubkey_bytes = pub_key.to_vec();
        let signer_address = derive_xrpl_address(&pubkey_bytes).unwrap();
        let account_id = xrpl_address_to_account_id(&signer_address).unwrap();

        let dest_address = "ra5nK24KXen9AHvsdFTKHSANinZseWnPcX";
        let dest_id = xrpl_address_to_account_id(dest_address).unwrap();

        let issuer_address = "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn";

        let mut builder = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Issued {
                value: "100".to_string(),
                currency: "USD".to_string(),
                issuer: issuer_address.to_string(),
            },
            15, // 15 drops fee
            5,  // Sequence 5
            pubkey_bytes.clone(),
        );
        builder.destination_tag = Some(10001);

        let raw_tx_bytes = builder.to_bytes();
        let keys = DerivedKeys::from(&pubkey_bytes);
        let codec = XrplCodec::new();

        let decoded = codec.decode("xrpl:mainnet", &raw_tx_bytes, &keys).unwrap();

        assert_eq!(decoded.parsed.transfers[0].amount, "100");
        assert_eq!(decoded.parsed.transfers[0].asset, "USD");
        assert_eq!(decoded.parsed.details["destination_tag"], 10001);
        assert_eq!(decoded.parsed.details["currency"], "USD");
        assert_eq!(decoded.parsed.details["issuer"], issuer_address);
    }

    #[test]
    fn test_xrpl_rejections_and_negative_cases() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (_priv_key, pub_key) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/144'/0'/0/0".parse().unwrap())
                .unwrap();
        let pubkey_bytes = pub_key.to_vec();
        let signer_address = derive_xrpl_address(&pubkey_bytes).unwrap();
        let account_id = xrpl_address_to_account_id(&signer_address).unwrap();
        let dest_id = xrpl_address_to_account_id("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe").unwrap();

        let keys = DerivedKeys::from(&pubkey_bytes);
        let codec = XrplCodec::new();

        // 1. Non-Payment transaction type (AccountSet = 3)
        let mut b1 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        b1.custom_transaction_type = Some(3); // AccountSet
        let err1 = codec.decode("xrpl:0", &b1.to_bytes(), &keys).unwrap_err();
        assert_eq!(err1.reason_code(), "unsupported_transaction");

        // 2. Multi-signed transaction (Signers array present)
        let mut b2 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        b2.include_signers = true;
        let err2 = codec.decode("xrpl:0", &b2.to_bytes(), &keys).unwrap_err();
        assert_eq!(err2.reason_code(), "unsupported_transaction");

        // 3. Mismatched SigningPubKey
        let wrong_pk = hex::decode("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020").unwrap();
        let b3 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            wrong_pk,
        );
        let err3 = codec.decode("xrpl:0", &b3.to_bytes(), &keys).unwrap_err();
        assert_eq!(err3.reason_code(), "unsupported_transaction");

        // 4. Mismatched Account
        let wrong_account_id = xrpl_address_to_account_id("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh").unwrap();
        let b4 = XrplPaymentBuilder::new(
            wrong_account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        let err4 = codec.decode("xrpl:0", &b4.to_bytes(), &keys).unwrap_err();
        assert_eq!(err4.reason_code(), "unsupported_transaction");

        // 5. NetworkID mismatch
        let mut b5 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        b5.network_id = Some(21337);
        let err5 = codec.decode("xrpl:0", &b5.to_bytes(), &keys).unwrap_err();
        assert_eq!(err5.reason_code(), "chain_mismatch");
    }

    #[test]
    fn test_generate_and_verify_xrpl_reference_vectors() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key, pub_key) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/144'/0'/0/0".parse().unwrap())
                .unwrap();
        let signing_key = SigningKey::from_bytes((&*priv_key).into()).unwrap();
        let pubkey_bytes = pub_key.to_vec();
        let signer_address = derive_xrpl_address(&pubkey_bytes).unwrap();
        let account_id = xrpl_address_to_account_id(&signer_address).unwrap();

        let dest_address = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe";
        let dest_id = xrpl_address_to_account_id(dest_address).unwrap();

        let codec = XrplCodec::new();
        let keys = DerivedKeys::from(&pubkey_bytes);

        // Vector 1: Native XRP Payment
        let b1 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(25_000_000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        let raw_tx_1 = b1.to_bytes();
        let decoded1 = codec.decode("xrpl:0", &raw_tx_1, &keys).unwrap();
        let digest1 = match decoded1.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (sig1, _) = signing_key.sign_prehash_recoverable(&digest1).unwrap();
        let mut sig1_64 = [0u8; 64];
        sig1_64.copy_from_slice(&sig1.to_bytes());
        let xrpl_sig1 = XrplSignature::from_raw_ecdsa(&sig1_64, &signer_address).unwrap();

        // Vector 2: Issued Currency Payment
        let mut b2 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Issued {
                value: "100".to_string(),
                currency: "USD".to_string(),
                issuer: "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn".to_string(),
            },
            15,
            2,
            pubkey_bytes.clone(),
        );
        b2.destination_tag = Some(10001);
        let raw_tx_2 = b2.to_bytes();
        let decoded2 = codec.decode("xrpl:0", &raw_tx_2, &keys).unwrap();
        let digest2 = match decoded2.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (sig2, _) = signing_key.sign_prehash_recoverable(&digest2).unwrap();
        let mut sig2_64 = [0u8; 64];
        sig2_64.copy_from_slice(&sig2.to_bytes());
        let xrpl_sig2 = XrplSignature::from_raw_ecdsa(&sig2_64, &signer_address).unwrap();

        // Vector 3: Payment with DestinationTag and SourceTag
        let mut b3 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(5_000_000),
            10,
            3,
            pubkey_bytes.clone(),
        );
        b3.destination_tag = Some(98765);
        b3.source_tag = Some(12345);
        let raw_tx_3 = b3.to_bytes();
        let decoded3 = codec.decode("xrpl:0", &raw_tx_3, &keys).unwrap();
        let digest3 = match decoded3.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (sig3, _) = signing_key.sign_prehash_recoverable(&digest3).unwrap();
        let mut sig3_64 = [0u8; 64];
        sig3_64.copy_from_slice(&sig3.to_bytes());
        let xrpl_sig3 = XrplSignature::from_raw_ecdsa(&sig3_64, &signer_address).unwrap();

        // Negative Vector 4: Unsupported Transaction Type (AccountSet = 3)
        let mut b4 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        b4.custom_transaction_type = Some(3);
        let raw_tx_4 = b4.to_bytes();

        // Negative Vector 5: Multi-signed (Signers array)
        let mut b5 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            pubkey_bytes.clone(),
        );
        b5.include_signers = true;
        let raw_tx_5 = b5.to_bytes();

        // Negative Vector 6: Mismatched SigningPubKey
        let wrong_pk = hex::decode("0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020").unwrap();
        let b6 = XrplPaymentBuilder::new(
            account_id,
            dest_id,
            DecodedAmount::Drops(1000),
            12,
            1,
            wrong_pk,
        );
        let raw_tx_6 = b6.to_bytes();

        // Construct JSON test vectors
        let vectors = serde_json::json!([
            {
                "id": "xrpl_mainnet_native_xrp_payment",
                "description": "Native XRP Payment of 25 XRP (25000000 drops) on XRPL Mainnet",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "signer_address": signer_address,
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_1)),
                "signing_input": format!("0x{}", hex::encode(digest1)),
                "parsed": decoded1.parsed,
                "result": xrpl_sig1
            },
            {
                "id": "xrpl_mainnet_issued_currency_payment",
                "description": "Issued currency Payment of 100 USD with destination tag",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "signer_address": signer_address,
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_2)),
                "signing_input": format!("0x{}", hex::encode(digest2)),
                "parsed": decoded2.parsed,
                "result": xrpl_sig2
            },
            {
                "id": "xrpl_payment_with_destination_and_source_tags",
                "description": "Native XRP Payment of 5 XRP with destination and source tags",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "signer_address": signer_address,
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_3)),
                "signing_input": format!("0x{}", hex::encode(digest3)),
                "parsed": decoded3.parsed,
                "result": xrpl_sig3
            },
            {
                "id": "xrpl_rejection_unsupported_transaction_type",
                "description": "Rejection of non-Payment XRPL transaction (AccountSet = 3)",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_4)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "xrpl_rejection_multi_signed_transaction",
                "description": "Rejection of multi-signed XRPL transaction containing Signers field",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_5)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "xrpl_rejection_mismatched_signing_pub_key",
                "description": "Rejection of transaction when SigningPubKey does not match derived signer key",
                "chain": "xrpl:0",
                "path": "m/44'/144'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(&pubkey_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_tx_6)),
                "expected_error": "unsupported_transaction"
            }
        ]);

        let vectors_pretty = serde_json::to_string_pretty(&vectors).unwrap();

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let search_paths = [
            manifest_dir.parent().unwrap().join("vectors").join("tx_xrpl.json"),
            manifest_dir.join("vectors").join("tx_xrpl.json"),
            std::path::PathBuf::from("vectors/tx_xrpl.json"),
        ];

        for path in &search_paths {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let _ = fs::write(path, vectors_pretty.as_bytes());
                    break;
                }
            }
        }
    }

    #[test]
    fn test_xrpl_reference_vectors_from_file() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let p1 = manifest_dir.parent().unwrap().join("vectors").join("tx_xrpl.json");
        let p2 = manifest_dir.join("vectors").join("tx_xrpl.json");
        let path = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            std::path::PathBuf::from("vectors/tx_xrpl.json")
        };

        if !path.exists() {
            // First run will create file via test_generate_and_verify_xrpl_reference_vectors
            return;
        }

        let content = fs::read_to_string(&path).expect("read tx_xrpl.json");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&content).expect("parse tx_xrpl.json");

        let codec = XrplCodec::new();

        for vec_val in vectors {
            let id = vec_val["id"].as_str().unwrap();
            let chain = vec_val["chain"].as_str().unwrap();
            let pk_hex = vec_val["public_key"].as_str().unwrap().trim_start_matches("0x");
            let pk_bytes = hex::decode(pk_hex).expect("decode pk hex");
            let keys = DerivedKeys::from(&pk_bytes);

            let raw_tx_hex = vec_val["raw_tx"].as_str().unwrap().trim_start_matches("0x");
            let raw_tx_bytes = hex::decode(raw_tx_hex).expect("decode raw tx hex");

            if let Some(expected_err) = vec_val.get("expected_error").and_then(|e| e.as_str()) {
                let err = codec.decode(chain, &raw_tx_bytes, &keys).unwrap_err();
                assert_eq!(
                    err.reason_code(),
                    expected_err,
                    "vector '{id}' expected error '{expected_err}'"
                );
            } else {
                let decoded = codec
                    .decode(chain, &raw_tx_bytes, &keys)
                    .unwrap_or_else(|e| panic!("vector '{id}' failed to decode: {e}"));

                let expected_parsed: ParsedTx =
                    serde_json::from_value(vec_val["parsed"].clone()).unwrap();
                assert_eq!(decoded.parsed, expected_parsed, "vector '{id}' parsed mismatch");

                let expected_signing_input_hex = vec_val["signing_input"].as_str().unwrap();
                let expected_signing_input =
                    hex::decode(expected_signing_input_hex.trim_start_matches("0x")).unwrap();
                match decoded.signing_input {
                    SigningInput::Digest32(d) => {
                        assert_eq!(d, expected_signing_input.as_slice(), "vector '{id}' digest mismatch");
                    }
                    _ => panic!("vector '{id}' expected Digest32 signing input"),
                }

                let expected_signer = vec_val["signer_address"].as_str().unwrap();
                assert_eq!(decoded.signer_address, expected_signer, "vector '{id}' signer mismatch");

                // Verify signature recovery from vector result
                let result_val = &vec_val["result"];
                let sig_hex = result_val["signature_hex"].as_str().unwrap().trim_start_matches("0x");
                let der_bytes = hex::decode(sig_hex).unwrap();

                let digest_32: &[u8; 32] = expected_signing_input.as_slice().try_into().unwrap();
                assert!(
                    verify_xrpl_signature(digest_32, &der_bytes, &pk_bytes).unwrap(),
                    "vector '{id}' signature verification failed"
                );
            }
        }
    }
}
