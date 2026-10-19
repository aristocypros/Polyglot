//! Tron TRX and TRC-20 transaction codec (Task 16, Section 5 of `Specs.md`).
//!
//! Implements decoding, summary extraction, and signing input preparation for Tron transactions:
//! - Protobuf-encoded `raw_data` containing exactly one contract of type:
//!   - `TransferContract` (native TRX transfer)
//!   - `TriggerSmartContract` calling TRC-20 `transfer(address,uint256)` (`0xa9059cbb` + 64-byte ABI data, `call_value == 0`).
//! - Top-level `Transaction` protobuf wrappers enclosing `raw_data`.
//! - Tron address derivation: `0x41` prefix + last 20 bytes of Keccak-256 of uncompressed public key, Base58Check encoded (`T...`).
//! - Verification of `owner_address` against the derived signer key.
//! - Signing input computation: `SHA-256(raw_data)` (`SigningInput::Digest32`).
//! - Unified [`ParsedTx`] summary (`transfers`, `fee_limit` as fee, `expiration`/`timestamp`/`ref_block_bytes` as sequence/details).
//! - 65-byte low-S signature formatting (`r || s || v`) and public key recovery verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::backend::generic::crypto::{
    decompress_secp256k1_pubkey, is_low_s, recover_secp256k1_pubkey_uncompressed,
};
use crate::chains::evm::u256_be_bytes_to_dec_string;
use crate::chains::{
    parse_caip2, ChainCodec, ChainError, DecodedTx, DerivedKeys, FeeSummary, ParsedTx,
    SequenceField, SigningInput, Transfer,
};

/// 1-byte Tron address prefix for mainnet / standard addresses: `0x41` ('A' in ASCII).
pub const TRON_ADDRESS_PREFIX: u8 = 0x41;

/// Byte length of a raw Tron address payload (`0x41` + 20-byte hash): `21` bytes.
pub const TRON_RAW_ADDRESS_LEN: usize = 21;

/// Byte length of a Base58Check checksum suffix: `4` bytes.
pub const TRON_CHECKSUM_LEN: usize = 4;

/// TRC-20 `transfer(address,uint256)` 4-byte method selector: `0xa9059cbb`.
pub const TRC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Protobuf contract type for native TRX transfer: `TransferContract` (1).
pub const CONTRACT_TYPE_TRANSFER: u32 = 1;

/// Protobuf contract type for smart contract invocation: `TriggerSmartContract` (31).
pub const CONTRACT_TYPE_TRIGGER_SMART: u32 = 31;

/// Canonical CAIP-2 Tron Mainnet reference: `0x2b6653dc`.
pub const TRON_MAINNET_CHAIN_REF: &str = "0x2b6653dc";

/// Formatted Tron 65-byte signature (`r (32B) || s (32B, low-S) || v (1B)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TronSignature {
    /// 65-byte signature encoded as `0x`-prefixed 130-character hex (`r || s || v`).
    pub signature_hex: String,
    /// 32-byte big-endian `r` scalar encoded as `0x`-prefixed 64-character hex.
    pub r: String,
    /// 32-byte big-endian low-S normalized `s` scalar encoded as `0x`-prefixed 64-character hex.
    pub s: String,
    /// Recovery byte `v` (standard 27 + recovery_id, matching TronWeb and java-tron).
    pub v: u8,
    /// Recovery ID (`0` or `1`).
    pub recovery_id: u8,
    /// Base58Check-encoded signer address matching the derived key (`T...`).
    pub signer_address: String,
}

impl TronSignature {
    /// Returns the raw 65-byte signature slice `[r (32B), s (32B), v (1B)]`.
    pub fn to_bytes(&self) -> Result<[u8; 65], ChainError> {
        let clean_hex = self.signature_hex.trim_start_matches("0x");
        let bytes = hex::decode(clean_hex).map_err(|e| {
            ChainError::Crypto(format!("failed to decode signature hex: {e}"))
        })?;
        if bytes.len() != 65 {
            return Err(ChainError::Crypto(format!(
                "expected 65-byte signature, found {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 65];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Tron transaction codec implementing [`ChainCodec`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TronCodec;

impl TronCodec {
    /// Constructs a new [`TronCodec`].
    pub fn new() -> Self {
        Self
    }
}

impl ChainCodec for TronCodec {
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        decode_tron_tx(chain, raw_tx_bytes, keys)
    }
}

/// Validates that `chain` is a supported CAIP-2 Tron network identifier.
pub fn validate_tron_chain(chain: &str) -> Result<(&str, &str), ChainError> {
    let (ns, ref_id) = parse_caip2(chain)?;
    if ns != "tron" {
        return Err(ChainError::UnsupportedChain(format!(
            "expected 'tron' namespace, got '{ns}'"
        )));
    }
    if ref_id.is_empty()
        || ref_id.len() > 64
        || ref_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        return Err(ChainError::UnsupportedTransaction(format!(
            "invalid Tron chain reference '{ref_id}' in '{chain}'"
        )));
    }
    Ok((ns, ref_id))
}

/// Computes the 4-byte double-SHA256 checksum over `payload`.
pub fn double_sha256_checksum(payload: &[u8]) -> [u8; 4] {
    let h1 = Sha256::digest(payload);
    let h2 = Sha256::digest(&h1);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&h2[..4]);
    checksum
}

/// Base58Check-encodes an arbitrary payload with double-SHA256 checksum.
pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = double_sha256_checksum(payload);
    let mut combined = Vec::with_capacity(payload.len() + TRON_CHECKSUM_LEN);
    combined.extend_from_slice(payload);
    combined.extend_from_slice(&checksum);
    bs58::encode(combined).into_string()
}

/// Decodes and verifies a Base58Check-encoded string.
pub fn base58check_decode(encoded: &str) -> Result<Vec<u8>, ChainError> {
    let raw = bs58::decode(encoded).into_vec().map_err(|e| {
        ChainError::MalformedTransaction(format!("invalid Base58 encoding '{encoded}': {e}"))
    })?;
    if raw.len() < TRON_CHECKSUM_LEN {
        return Err(ChainError::MalformedTransaction(format!(
            "Base58Check payload too short ({} bytes)",
            raw.len()
        )));
    }
    let (payload, checksum) = raw.split_at(raw.len() - TRON_CHECKSUM_LEN);
    let expected_checksum = double_sha256_checksum(payload);
    if checksum != expected_checksum {
        return Err(ChainError::MalformedTransaction(format!(
            "Base58Check checksum mismatch for '{encoded}'"
        )));
    }
    Ok(payload.to_vec())
}

/// Derives the 21-byte raw Tron address (`0x41` + last 20 bytes of Keccak256(pubkey[1..65]))
/// from a 33-byte compressed or 65-byte uncompressed `secp256k1` public key.
pub fn pubkey_to_tron_raw_address(pubkey: &[u8]) -> Result<[u8; 21], ChainError> {
    let uncompressed = if pubkey.len() == 33 {
        let pk_arr: &[u8; 33] = pubkey.try_into().map_err(|_| {
            ChainError::InvalidKeys("invalid compressed public key slice".to_string())
        })?;
        decompress_secp256k1_pubkey(pk_arr)
            .map_err(|e| ChainError::InvalidKeys(format!("invalid secp256k1 public key: {e}")))?
    } else if pubkey.len() == 65 {
        if pubkey[0] != 0x04 {
            return Err(ChainError::InvalidKeys(
                "uncompressed public key must start with 0x04".to_string(),
            ));
        }
        let mut arr = [0u8; 65];
        arr.copy_from_slice(pubkey);
        arr
    } else {
        return Err(ChainError::InvalidKeys(format!(
            "expected 33-byte compressed or 65-byte uncompressed secp256k1 public key, got {}",
            pubkey.len()
        )));
    };

    let hash = Keccak256::digest(&uncompressed[1..65]);
    let mut raw_addr = [0u8; 21];
    raw_addr[0] = TRON_ADDRESS_PREFIX;
    raw_addr[1..21].copy_from_slice(&hash[12..32]);
    Ok(raw_addr)
}

/// Derives the Base58Check Tron address (`T...`) from a compressed or uncompressed `secp256k1` public key.
pub fn pubkey_to_tron_address(pubkey: &[u8]) -> Result<String, ChainError> {
    let raw = pubkey_to_tron_raw_address(pubkey)?;
    Ok(base58check_encode(&raw))
}

/// Converts a Base58Check Tron address string into its 21-byte raw representation.
pub fn tron_address_to_raw(address_b58: &str) -> Result<[u8; 21], ChainError> {
    let bytes = base58check_decode(address_b58)?;
    if bytes.len() != TRON_RAW_ADDRESS_LEN {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid Tron raw address length: expected {TRON_RAW_ADDRESS_LEN}, got {}",
            bytes.len()
        )));
    }
    if bytes[0] != TRON_ADDRESS_PREFIX {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid Tron address prefix: expected 0x{:02x}, got 0x{:02x}",
            TRON_ADDRESS_PREFIX, bytes[0]
        )));
    }
    let mut raw = [0u8; 21];
    raw.copy_from_slice(&bytes);
    Ok(raw)
}

/// Converts a 21-byte raw Tron address into its Base58Check string representation.
pub fn tron_raw_to_address(raw: &[u8; 21]) -> String {
    base58check_encode(raw)
}

/// Formats a 64-byte `(r, s)` signature and recovery ID into a canonical 65-byte [`TronSignature`].
pub fn format_tron_signature(
    sig_64: &[u8; 64],
    recovery_id: u8,
    signer_address: &str,
) -> Result<TronSignature, ChainError> {
    if recovery_id > 1 {
        return Err(ChainError::Crypto(format!(
            "invalid ECDSA recovery_id {recovery_id}: expected 0 or 1"
        )));
    }
    let s_arr: &[u8; 32] = sig_64[32..64].try_into().unwrap();
    let low_s = is_low_s(s_arr).map_err(|e| ChainError::Crypto(e.to_string()))?;
    if !low_s {
        return Err(ChainError::Crypto(
            "cannot format high-S signature into Tron canonical signature".to_string(),
        ));
    }

    let mut sig_65 = [0u8; 65];
    sig_65[0..64].copy_from_slice(sig_64);
    let v = 27 + recovery_id;
    sig_65[64] = v;

    Ok(TronSignature {
        signature_hex: format!("0x{}", hex::encode(sig_65)),
        r: format!("0x{}", hex::encode(&sig_64[0..32])),
        s: format!("0x{}", hex::encode(&sig_64[32..64])),
        v,
        recovery_id,
        signer_address: signer_address.to_string(),
    })
}

/// Verifies that public key recovery from `digest32`, `sig_64`, and `recovery_id` (or `v = 27/28`)
/// yields a Tron address matching `expected_signer_address`.
pub fn verify_signature_recovery(
    digest32: &[u8; 32],
    sig_64: &[u8; 64],
    recovery_id_or_v: u8,
    expected_signer_address: &str,
) -> Result<bool, ChainError> {
    let recid = if recovery_id_or_v >= 27 {
        recovery_id_or_v - 27
    } else {
        recovery_id_or_v
    };
    if recid > 1 {
        return Err(ChainError::Crypto(format!(
            "invalid recovery_id {recovery_id_or_v}: expected 0, 1, 27, or 28"
        )));
    }

    let recovered_pubkey = recover_secp256k1_pubkey_uncompressed(digest32, sig_64, recid)
        .map_err(|e| ChainError::Crypto(format!("secp256k1 public key recovery failed: {e}")))?;
    let recovered_addr = pubkey_to_tron_address(&recovered_pubkey)?;

    if recovered_addr == expected_signer_address {
        Ok(true)
    } else {
        Err(ChainError::KeyMismatch(format!(
            "recovered Tron address '{recovered_addr}' does not match expected signer '{expected_signer_address}'"
        )))
    }
}

/// Verifies a 65-byte low-S Tron signature `r (32B) || s (32B) || v (1B)` over `digest32`.
pub fn verify_tron_signature_65(
    digest32: &[u8; 32],
    sig_65: &[u8; 65],
    expected_signer_address: &str,
) -> Result<bool, ChainError> {
    let mut sig_64 = [0u8; 64];
    sig_64.copy_from_slice(&sig_65[0..64]);
    let s_arr: &[u8; 32] = sig_65[32..64].try_into().unwrap();
    let low_s = is_low_s(s_arr).map_err(|e| ChainError::Crypto(e.to_string()))?;
    if !low_s {
        return Err(ChainError::Crypto(
            "Tron signature is not low-S normalized".to_string(),
        ));
    }
    let v = sig_65[64];
    verify_signature_recovery(digest32, &sig_64, v, expected_signer_address)
}

// -----------------------------------------------------------------------------
// Protobuf Wire Format Parser Primitives
// -----------------------------------------------------------------------------

/// Reads a protobuf varint from `buf`, returning `(value, remaining_slice)`.
fn read_varint(mut buf: &[u8]) -> Result<(u64, &[u8]), ChainError> {
    let mut val = 0u64;
    let mut shift = 0;
    while !buf.is_empty() {
        let b = buf[0];
        buf = &buf[1..];
        val |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok((val, buf));
        }
        shift += 7;
        if shift >= 64 {
            return Err(ChainError::MalformedTransaction(
                "protobuf varint overflow".to_string(),
            ));
        }
    }
    Err(ChainError::MalformedTransaction(
        "unexpected EOF reading varint".to_string(),
    ))
}

/// Reads a protobuf tag `(field_number, wire_type, remaining_slice)` or `None` if EOF.
fn read_tag(buf: &[u8]) -> Result<Option<(u32, u8, &[u8])>, ChainError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let (val, rest) = read_varint(buf)?;
    let wire_type = (val & 0x07) as u8;
    let field_num = (val >> 3) as u32;
    Ok(Some((field_num, wire_type, rest)))
}

/// Reads a length-delimited byte slice from `buf`, returning `(content, remaining_slice)`.
fn read_length_delimited(buf: &[u8]) -> Result<(&[u8], &[u8]), ChainError> {
    let (len, rest) = read_varint(buf)?;
    let len = len as usize;
    if rest.len() < len {
        return Err(ChainError::MalformedTransaction(format!(
            "unexpected EOF reading length-delimited field: need {len} bytes, available {}",
            rest.len()
        )));
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Skips an unknown or unneeded field according to its protobuf wire type.
fn skip_field(wire_type: u8, buf: &[u8]) -> Result<&[u8], ChainError> {
    match wire_type {
        0 => {
            let (_, rest) = read_varint(buf)?;
            Ok(rest)
        }
        1 => {
            if buf.len() < 8 {
                return Err(ChainError::MalformedTransaction(
                    "unexpected EOF skipping 64-bit field".to_string(),
                ));
            }
            Ok(&buf[8..])
        }
        2 => {
            let (_, rest) = read_length_delimited(buf)?;
            Ok(rest)
        }
        5 => {
            if buf.len() < 4 {
                return Err(ChainError::MalformedTransaction(
                    "unexpected EOF skipping 32-bit field".to_string(),
                ));
            }
            Ok(&buf[4..])
        }
        other => Err(ChainError::MalformedTransaction(format!(
            "unsupported protobuf wire type {other}"
        ))),
    }
}

// -----------------------------------------------------------------------------
// Tron Transaction Protobuf Structures
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedRawData<'a> {
    ref_block_bytes: Option<&'a [u8]>,
    ref_block_num: Option<i64>,
    ref_block_hash: Option<&'a [u8]>,
    expiration: Option<i64>,
    timestamp: Option<i64>,
    fee_limit: Option<i64>,
    contracts: Vec<ParsedContract<'a>>,
}

#[derive(Debug, Clone)]
struct ParsedContract<'a> {
    contract_type: u32,
    parameter_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
struct ParsedTransferContract {
    owner_address: [u8; 21],
    to_address: [u8; 21],
    amount: i64,
}

#[derive(Debug, Clone)]
struct ParsedTriggerSmartContract<'a> {
    owner_address: [u8; 21],
    contract_address: [u8; 21],
    call_value: i64,
    data: &'a [u8],
    call_token_value: i64,
}

/// Parses the inner fields of a `raw` protobuf message.
fn parse_raw_data_message(mut buf: &[u8]) -> Result<ParsedRawData<'_>, ChainError> {
    let mut ref_block_bytes = None;
    let mut ref_block_num = None;
    let mut ref_block_hash = None;
    let mut expiration = None;
    let mut timestamp = None;
    let mut fee_limit = None;
    let mut contracts = Vec::new();

    while let Some((field_num, wire_type, rest)) = read_tag(buf)? {
        match (field_num, wire_type) {
            (1, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                ref_block_bytes = Some(bytes);
                buf = next;
            }
            (3, 0) => {
                let (val, next) = read_varint(rest)?;
                ref_block_num = Some(val as i64);
                buf = next;
            }
            (4, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                ref_block_hash = Some(bytes);
                buf = next;
            }
            (8, 0) => {
                let (val, next) = read_varint(rest)?;
                expiration = Some(val as i64);
                buf = next;
            }
            (11, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                let contract = parse_contract_message(bytes)?;
                contracts.push(contract);
                buf = next;
            }
            (14, 0) => {
                let (val, next) = read_varint(rest)?;
                timestamp = Some(val as i64);
                buf = next;
            }
            (18, 0) => {
                let (val, next) = read_varint(rest)?;
                fee_limit = Some(val as i64);
                buf = next;
            }
            (_, wt) => {
                buf = skip_field(wt, rest)?;
            }
        }
    }

    Ok(ParsedRawData {
        ref_block_bytes,
        ref_block_num,
        ref_block_hash,
        expiration,
        timestamp,
        fee_limit,
        contracts,
    })
}

/// Parses a `Transaction.Contract` protobuf message.
fn parse_contract_message(mut buf: &[u8]) -> Result<ParsedContract<'_>, ChainError> {
    let mut contract_type = None;
    let mut parameter_bytes = None;

    while let Some((field_num, wire_type, rest)) = read_tag(buf)? {
        match (field_num, wire_type) {
            (1, 0) => {
                let (val, next) = read_varint(rest)?;
                contract_type = Some(val as u32);
                buf = next;
            }
            (2, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                parameter_bytes = Some(bytes);
                buf = next;
            }
            (_, wt) => {
                buf = skip_field(wt, rest)?;
            }
        }
    }

    let contract_type = contract_type.ok_or_else(|| {
        ChainError::MalformedTransaction("missing contract type in Transaction.Contract".to_string())
    })?;
    let parameter_bytes = parameter_bytes.ok_or_else(|| {
        ChainError::MalformedTransaction("missing parameter in Transaction.Contract".to_string())
    })?;

    Ok(ParsedContract {
        contract_type,
        parameter_bytes,
    })
}

/// Extracts the inner `value` bytes from a `google.protobuf.Any` parameter message.
fn parse_any_parameter(mut buf: &[u8]) -> Result<&[u8], ChainError> {
    let mut value = None;

    while let Some((field_num, wire_type, rest)) = read_tag(buf)? {
        match (field_num, wire_type) {
            (1, 2) => {
                // type_url (string) - skip or validate
                let (_, next) = read_length_delimited(rest)?;
                buf = next;
            }
            (2, 2) => {
                // value (bytes)
                let (bytes, next) = read_length_delimited(rest)?;
                value = Some(bytes);
                buf = next;
            }
            (_, wt) => {
                buf = skip_field(wt, rest)?;
            }
        }
    }

    value.ok_or_else(|| {
        ChainError::MalformedTransaction("missing value in google.protobuf.Any parameter".to_string())
    })
}

/// Parses a `TransferContract` message (native TRX transfer).
fn parse_transfer_contract(mut buf: &[u8]) -> Result<ParsedTransferContract, ChainError> {
    let mut owner_address = None;
    let mut to_address = None;
    let mut amount = None;

    while let Some((field_num, wire_type, rest)) = read_tag(buf)? {
        match (field_num, wire_type) {
            (1, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                if bytes.len() != TRON_RAW_ADDRESS_LEN || bytes[0] != TRON_ADDRESS_PREFIX {
                    return Err(ChainError::MalformedTransaction(format!(
                        "invalid owner_address length {} or prefix in TransferContract",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 21];
                arr.copy_from_slice(bytes);
                owner_address = Some(arr);
                buf = next;
            }
            (2, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                if bytes.len() != TRON_RAW_ADDRESS_LEN || bytes[0] != TRON_ADDRESS_PREFIX {
                    return Err(ChainError::MalformedTransaction(format!(
                        "invalid to_address length {} or prefix in TransferContract",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 21];
                arr.copy_from_slice(bytes);
                to_address = Some(arr);
                buf = next;
            }
            (3, 0) => {
                let (val, next) = read_varint(rest)?;
                amount = Some(val as i64);
                buf = next;
            }
            (_, wt) => {
                buf = skip_field(wt, rest)?;
            }
        }
    }

    let owner_address = owner_address.ok_or_else(|| {
        ChainError::MalformedTransaction("missing owner_address in TransferContract".to_string())
    })?;
    let to_address = to_address.ok_or_else(|| {
        ChainError::MalformedTransaction("missing to_address in TransferContract".to_string())
    })?;
    let amount = amount.ok_or_else(|| {
        ChainError::MalformedTransaction("missing amount in TransferContract".to_string())
    })?;

    if amount < 0 {
        return Err(ChainError::UnsupportedTransaction(
            "TransferContract amount cannot be negative".to_string(),
        ));
    }

    Ok(ParsedTransferContract {
        owner_address,
        to_address,
        amount,
    })
}

/// Parses a `TriggerSmartContract` message (smart contract call).
fn parse_trigger_smart_contract(mut buf: &[u8]) -> Result<ParsedTriggerSmartContract<'_>, ChainError> {
    let mut owner_address = None;
    let mut contract_address = None;
    let mut call_value = 0i64;
    let mut data = None;
    let mut call_token_value = 0i64;

    while let Some((field_num, wire_type, rest)) = read_tag(buf)? {
        match (field_num, wire_type) {
            (1, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                if bytes.len() != TRON_RAW_ADDRESS_LEN || bytes[0] != TRON_ADDRESS_PREFIX {
                    return Err(ChainError::MalformedTransaction(format!(
                        "invalid owner_address length {} or prefix in TriggerSmartContract",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 21];
                arr.copy_from_slice(bytes);
                owner_address = Some(arr);
                buf = next;
            }
            (2, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                if bytes.len() != TRON_RAW_ADDRESS_LEN || bytes[0] != TRON_ADDRESS_PREFIX {
                    return Err(ChainError::MalformedTransaction(format!(
                        "invalid contract_address length {} or prefix in TriggerSmartContract",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 21];
                arr.copy_from_slice(bytes);
                contract_address = Some(arr);
                buf = next;
            }
            (3, 0) => {
                let (val, next) = read_varint(rest)?;
                call_value = val as i64;
                buf = next;
            }
            (4, 2) => {
                let (bytes, next) = read_length_delimited(rest)?;
                data = Some(bytes);
                buf = next;
            }
            (5, 0) => {
                let (val, next) = read_varint(rest)?;
                call_token_value = val as i64;
                buf = next;
            }
            (_, wt) => {
                buf = skip_field(wt, rest)?;
            }
        }
    }

    let owner_address = owner_address.ok_or_else(|| {
        ChainError::MalformedTransaction("missing owner_address in TriggerSmartContract".to_string())
    })?;
    let contract_address = contract_address.ok_or_else(|| {
        ChainError::MalformedTransaction("missing contract_address in TriggerSmartContract".to_string())
    })?;
    let data = data.ok_or_else(|| {
        ChainError::MalformedTransaction("missing data in TriggerSmartContract".to_string())
    })?;

    Ok(ParsedTriggerSmartContract {
        owner_address,
        contract_address,
        call_value,
        data,
        call_token_value,
    })
}

/// Resolves whether `raw_tx_bytes` is a top-level `Transaction` message containing `raw_data = 1`
/// or the `raw_data` message directly. Returns `(parsed_raw_data, exact_raw_data_bytes)`.
fn extract_raw_data(raw_tx_bytes: &[u8]) -> Result<(ParsedRawData<'_>, &[u8]), ChainError> {
    if raw_tx_bytes.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "empty transaction payload".to_string(),
        ));
    }

    // Check if the payload is a top-level Transaction message whose field 1 (tag 0x0a)
    // is a length-delimited raw_data message containing field 11 (contract).
    let mut is_wrapped_transaction = false;
    let mut wrapped_raw_slice: Option<&[u8]> = None;

    let peek_buf = raw_tx_bytes;
    if let Ok(Some((1, 2, rest))) = read_tag(peek_buf) {
        if let Ok((inner_bytes, next_rest)) = read_length_delimited(rest) {
            // Check if inner_bytes parses as a valid raw_data containing at least one field 11
            if let Ok(inner_parsed) = parse_raw_data_message(inner_bytes) {
                if !inner_parsed.contracts.is_empty() {
                    // Also verify that the rest of raw_tx_bytes only contains valid Transaction fields (signature=2, ret=5)
                    let mut valid_transaction_envelope = true;
                    let mut rem = next_rest;
                    while let Ok(Some((fn_num, wt, r))) = read_tag(rem) {
                        if fn_num == 2 || fn_num == 5 {
                            if let Ok(after) = skip_field(wt, r) {
                                rem = after;
                            } else {
                                valid_transaction_envelope = false;
                                break;
                            }
                        } else {
                            valid_transaction_envelope = false;
                            break;
                        }
                    }
                    if valid_transaction_envelope {
                        is_wrapped_transaction = true;
                        wrapped_raw_slice = Some(inner_bytes);
                    }
                }
            }
        }
    }

    if is_wrapped_transaction {
        let raw_slice = wrapped_raw_slice.unwrap();
        let parsed = parse_raw_data_message(raw_slice)?;
        Ok((parsed, raw_slice))
    } else {
        let parsed = parse_raw_data_message(raw_tx_bytes)?;
        Ok((parsed, raw_tx_bytes))
    }
}

// -----------------------------------------------------------------------------
// Transaction Decoding & Validation
// -----------------------------------------------------------------------------

/// Decodes an unsigned Tron transaction for `chain` using the derived key in `keys`.
pub fn decode_tron_tx(
    chain: &str,
    raw_tx_bytes: &[u8],
    keys: &DerivedKeys,
) -> Result<DecodedTx, ChainError> {
    // 1. Validate CAIP-2 chain identifier
    validate_tron_chain(chain)?;

    // 2. Validate derived public key and derive expected Tron signer address
    let single_key = keys.single()?;
    if single_key.len() != 33 {
        return Err(ChainError::InvalidKeys(format!(
            "expected 33-byte compressed secp256k1 public key, got {}",
            single_key.len()
        )));
    }
    let expected_raw_address = pubkey_to_tron_raw_address(single_key)?;
    let signer_address = base58check_encode(&expected_raw_address);

    // 3. Parse Tron raw_data (either standalone or extracted from top-level Transaction)
    let (raw_data, raw_data_bytes_for_signing) = extract_raw_data(raw_tx_bytes)?;

    // 4. Enforce exactly one contract
    if raw_data.contracts.is_empty() {
        return Err(ChainError::UnsupportedTransaction(
            "transaction contains no contracts".to_string(),
        ));
    }
    if raw_data.contracts.len() > 1 {
        return Err(ChainError::UnsupportedTransaction(format!(
            "multi-contract transactions unsupported: expected 1, found {}",
            raw_data.contracts.len()
        )));
    }

    let contract = &raw_data.contracts[0];
    let contract_param_value = parse_any_parameter(contract.parameter_bytes)?;

    let (transfer, contract_type_name, contract_details) = match contract.contract_type {
        CONTRACT_TYPE_TRANSFER => {
            let parsed_transfer = parse_transfer_contract(contract_param_value)?;

            // Verify owner_address matches derived signer key
            if parsed_transfer.owner_address != expected_raw_address {
                let tx_owner = base58check_encode(&parsed_transfer.owner_address);
                return Err(ChainError::KeyMismatch(format!(
                    "owner_address '{tx_owner}' does not match derived signer '{signer_address}'"
                )));
            }

            let to_b58 = base58check_encode(&parsed_transfer.to_address);
            let transfer = Transfer::new(
                &signer_address,
                to_b58,
                parsed_transfer.amount.to_string(),
                "TRX",
            );

            let details = serde_json::json!({
                "contract_type": "TransferContract",
                "amount_sun": parsed_transfer.amount,
            });

            (transfer, "TransferContract", details)
        }
        CONTRACT_TYPE_TRIGGER_SMART => {
            let parsed_trigger = parse_trigger_smart_contract(contract_param_value)?;

            // Verify owner_address matches derived signer key
            if parsed_trigger.owner_address != expected_raw_address {
                let tx_owner = base58check_encode(&parsed_trigger.owner_address);
                return Err(ChainError::KeyMismatch(format!(
                    "owner_address '{tx_owner}' does not match derived signer '{signer_address}'"
                )));
            }

            // Enforce call_value == 0 for TRC-20 transfers
            if parsed_trigger.call_value != 0 {
                return Err(ChainError::UnsupportedTransaction(format!(
                    "TRC-20 transfer must have call_value == 0, found {}",
                    parsed_trigger.call_value
                )));
            }
            if parsed_trigger.call_token_value != 0 {
                return Err(ChainError::UnsupportedTransaction(format!(
                    "TRC-20 transfer must have call_token_value == 0, found {}",
                    parsed_trigger.call_token_value
                )));
            }

            // Validate TRC-20 transfer(address,uint256) data: 4 bytes selector + 64 bytes ABI parameters = 68 bytes
            let data = parsed_trigger.data;
            if data.len() < 4 || data[..4] != TRC20_TRANSFER_SELECTOR {
                let sel_hex = if data.len() >= 4 {
                    format!("0x{}", hex::encode(&data[..4]))
                } else {
                    format!("0x{}", hex::encode(data))
                };
                return Err(ChainError::UnsupportedTransaction(format!(
                    "unsupported smart contract method selector '{sel_hex}', expected TRC-20 transfer 0xa9059cbb"
                )));
            }
            if data.len() != 68 {
                return Err(ChainError::UnsupportedTransaction(format!(
                    "invalid TRC-20 transfer calldata length: expected 68 bytes, got {}",
                    data.len()
                )));
            }

            // Extract recipient address from first 32 bytes (data[4..36])
            let recipient_slot = &data[4..36];
            let mut recipient_raw = [0u8; 21];
            if recipient_slot[..12] == [0u8; 12] {
                // Standard EVM 12-zero prefix + 20-byte address
                recipient_raw[0] = TRON_ADDRESS_PREFIX;
                recipient_raw[1..21].copy_from_slice(&recipient_slot[12..32]);
            } else if recipient_slot[..11] == [0u8; 11] && recipient_slot[11] == TRON_ADDRESS_PREFIX {
                // 11-zero prefix + 0x41 + 20-byte address (21 bytes total)
                recipient_raw.copy_from_slice(&recipient_slot[11..32]);
            } else {
                return Err(ChainError::MalformedTransaction(
                    "invalid TRC-20 recipient address ABI padding".to_string(),
                ));
            }
            let recipient_b58 = base58check_encode(&recipient_raw);

            // Extract token amount from second 32 bytes (data[36..68])
            let amount_bytes = &data[36..68];
            let amount_str = u256_be_bytes_to_dec_string(amount_bytes);

            let token_contract_b58 = base58check_encode(&parsed_trigger.contract_address);
            let transfer = Transfer::new(
                &signer_address,
                recipient_b58,
                amount_str,
                &token_contract_b58,
            );

            let details = serde_json::json!({
                "contract_type": "TriggerSmartContract",
                "contract_address": token_contract_b58,
                "selector": "0xa9059cbb",
                "method": "transfer(address,uint256)",
                "call_value": 0,
            });

            (transfer, "TriggerSmartContract", details)
        }
        unsupported => {
            return Err(ChainError::UnsupportedTransaction(format!(
                "unsupported Tron contract type: {unsupported}"
            )));
        }
    };

    // 5. Populate fee summary from fee_limit
    let fee_limit = raw_data.fee_limit.unwrap_or(0);
    let fee = FeeSummary::new(fee_limit.to_string(), "sun");

    // 6. Populate sequence identifier from timestamp or expiration
    let seq_val = if let Some(ts) = raw_data.timestamp {
        if ts > 0 {
            ts as u64
        } else if let Some(exp) = raw_data.expiration {
            exp as u64
        } else {
            0
        }
    } else if let Some(exp) = raw_data.expiration {
        exp as u64
    } else {
        0
    };
    let sequence = SequenceField::sequence(seq_val);

    // 7. Assemble transaction details metadata
    let ref_block_bytes_hex = raw_data
        .ref_block_bytes
        .map(|b| format!("0x{}", hex::encode(b)))
        .unwrap_or_else(|| "0x".to_string());
    let ref_block_hash_hex = raw_data
        .ref_block_hash
        .map(|b| format!("0x{}", hex::encode(b)));

    let mut details_map = serde_json::Map::new();
    details_map.insert("chain".to_string(), serde_json::json!(chain));
    details_map.insert(
        "contract_type".to_string(),
        serde_json::json!(contract_type_name),
    );
    details_map.insert(
        "ref_block_bytes".to_string(),
        serde_json::json!(ref_block_bytes_hex),
    );
    if let Some(rbh) = ref_block_hash_hex {
        details_map.insert("ref_block_hash".to_string(), serde_json::json!(rbh));
    }
    if let Some(rbn) = raw_data.ref_block_num {
        details_map.insert("ref_block_num".to_string(), serde_json::json!(rbn));
    }
    if let Some(exp) = raw_data.expiration {
        details_map.insert("expiration".to_string(), serde_json::json!(exp));
    }
    if let Some(ts) = raw_data.timestamp {
        details_map.insert("timestamp".to_string(), serde_json::json!(ts));
    }
    details_map.insert("fee_limit".to_string(), serde_json::json!(fee_limit));

    // Merge specific contract details
    if let serde_json::Value::Object(sub_map) = contract_details {
        for (k, v) in sub_map {
            details_map.insert(k, v);
        }
    }

    let parsed = ParsedTx::new(
        vec![transfer],
        fee,
        sequence,
        serde_json::Value::Object(details_map),
    );

    // 8. Compute signing input as SHA-256 of raw_data bytes
    let sha256_digest = Sha256::digest(raw_data_bytes_for_signing);
    let mut digest_32 = [0u8; 32];
    digest_32.copy_from_slice(&sha256_digest);
    let signing_input = SigningInput::digest32(digest_32);

    Ok(DecodedTx::new(parsed, signing_input, signer_address))
}

// -----------------------------------------------------------------------------
// Protobuf Serialization Helpers for Testing & Builders
// -----------------------------------------------------------------------------

/// Appends a protobuf varint to `buf`.
pub fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

/// Appends a protobuf tag `(field_number << 3) | wire_type` to `buf`.
pub fn encode_tag(field_number: u32, wire_type: u8, buf: &mut Vec<u8>) {
    encode_varint(((field_number as u64) << 3) | ((wire_type & 0x07) as u64), buf);
}

/// Appends a length-delimited byte slice field to `buf`.
pub fn encode_bytes_field(field_number: u32, bytes: &[u8], buf: &mut Vec<u8>) {
    encode_tag(field_number, 2, buf);
    encode_varint(bytes.len() as u64, buf);
    buf.extend_from_slice(bytes);
}

/// Appends a varint field to `buf`.
pub fn encode_varint_field(field_number: u32, val: u64, buf: &mut Vec<u8>) {
    encode_tag(field_number, 0, buf);
    encode_varint(val, buf);
}

/// Serializes a `TransferContract` protobuf message.
pub fn build_transfer_contract(
    owner_address: &[u8; 21],
    to_address: &[u8; 21],
    amount: i64,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes_field(1, owner_address, &mut buf);
    encode_bytes_field(2, to_address, &mut buf);
    encode_varint_field(3, amount as u64, &mut buf);
    buf
}

/// Serializes a `TriggerSmartContract` protobuf message.
pub fn build_trigger_smart_contract(
    owner_address: &[u8; 21],
    contract_address: &[u8; 21],
    call_value: i64,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes_field(1, owner_address, &mut buf);
    encode_bytes_field(2, contract_address, &mut buf);
    if call_value != 0 {
        encode_varint_field(3, call_value as u64, &mut buf);
    }
    encode_bytes_field(4, data, &mut buf);
    buf
}

/// Serializes a `google.protobuf.Any` wrapper message.
pub fn build_any_parameter(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes_field(1, type_url.as_bytes(), &mut buf);
    encode_bytes_field(2, value, &mut buf);
    buf
}

/// Serializes a `Transaction.Contract` message.
pub fn build_contract_message(contract_type: u32, parameter_any: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_varint_field(1, contract_type as u64, &mut buf);
    encode_bytes_field(2, parameter_any, &mut buf);
    buf
}

/// Serializes a Tron `raw` data protobuf message.
pub fn build_raw_data(
    ref_block_bytes: &[u8],
    ref_block_num: Option<i64>,
    ref_block_hash: Option<&[u8]>,
    expiration: i64,
    contract_bytes: &[u8],
    timestamp: i64,
    fee_limit: Option<i64>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    if !ref_block_bytes.is_empty() {
        encode_bytes_field(1, ref_block_bytes, &mut buf);
    }
    if let Some(rbn) = ref_block_num {
        encode_varint_field(3, rbn as u64, &mut buf);
    }
    if let Some(rbh) = ref_block_hash {
        if !rbh.is_empty() {
            encode_bytes_field(4, rbh, &mut buf);
        }
    }
    if expiration > 0 {
        encode_varint_field(8, expiration as u64, &mut buf);
    }
    encode_bytes_field(11, contract_bytes, &mut buf);
    if timestamp > 0 {
        encode_varint_field(14, timestamp as u64, &mut buf);
    }
    if let Some(fl) = fee_limit {
        if fl > 0 {
            encode_varint_field(18, fl as u64, &mut buf);
        }
    }
    buf
}

/// Serializes a top-level `Transaction` protobuf message wrapping `raw_data` and signatures.
pub fn build_transaction_message(raw_data: &[u8], signatures: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes_field(1, raw_data, &mut buf);
    for sig in signatures {
        encode_bytes_field(2, sig, &mut buf);
    }
    buf
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::backend::generic::crypto::compute_ecdsa_recovery_id;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_tron_address_generation_and_base58check() {
        // Test Genesis/Burn Address: 0x41 followed by 20 zeroes -> T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb
        let mut zero_raw = [0u8; 21];
        zero_raw[0] = TRON_ADDRESS_PREFIX;
        let zero_b58 = base58check_encode(&zero_raw);
        assert_eq!(zero_b58, "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");
        let decoded_zero = tron_address_to_raw(&zero_b58).unwrap();
        assert_eq!(decoded_zero, zero_raw);

        // Test USDT Contract Address: 41a614f803b6fd780986a42c78ec9c7f77e6ded13c -> TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
        let usdt_raw_bytes = hex::decode("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").unwrap();
        let usdt_raw: &[u8; 21] = usdt_raw_bytes.as_slice().try_into().unwrap();
        let usdt_b58 = base58check_encode(usdt_raw);
        assert_eq!(usdt_b58, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        let decoded_usdt = tron_address_to_raw(&usdt_b58).unwrap();
        assert_eq!(&decoded_usdt, usdt_raw);

        // Test address derivation from secp256k1 private key = 1
        // Private key 1 public key compressed:
        let sk = SigningKey::from_bytes((&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1u8,
        ])
            .into())
        .unwrap();
        let vk = sk.verifying_key();
        let pk_compressed = vk.to_encoded_point(true);
        let pk_uncompressed = vk.to_encoded_point(false);

        let addr1 = pubkey_to_tron_address(pk_compressed.as_bytes()).unwrap();
        let addr2 = pubkey_to_tron_address(pk_uncompressed.as_bytes()).unwrap();
        assert_eq!(addr1, addr2);
        assert!(addr1.starts_with('T'));
        assert_eq!(addr1.len(), 34);

        // Verify the raw hex address starts with 417e5f4552091a69125d5dfcb7b8c2659029395bdf
        let raw1 = pubkey_to_tron_raw_address(pk_compressed.as_bytes()).unwrap();
        assert_eq!(
            hex::encode(raw1),
            "417e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn test_tron_chain_validation() {
        assert!(validate_tron_chain("tron:0x2b6653dc").is_ok());
        assert!(validate_tron_chain("tron:mainnet").is_ok());
        assert!(validate_tron_chain("tron:shasta").is_ok());
        assert!(validate_tron_chain("tron:nile").is_ok());

        // Rejects non-tron namespaces
        assert!(matches!(
            validate_tron_chain("eip155:1").unwrap_err(),
            ChainError::UnsupportedChain(_)
        ));
        assert!(matches!(
            validate_tron_chain("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").unwrap_err(),
            ChainError::UnsupportedChain(_)
        ));
        assert!(matches!(
            validate_tron_chain("invalid_no_colon").unwrap_err(),
            ChainError::UnsupportedTransaction(_)
        ));
    }

    #[test]
    fn test_native_trx_transfer_decoding_and_signature_recovery() {
        // Derive key from standard master seed on Tron BIP44 path m/44'/195'/0'/0/0
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key_bytes, pub_key_bytes) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/195'/0'/0/0".parse().unwrap())
                .unwrap();

        let signer_addr = pubkey_to_tron_address(&pub_key_bytes).unwrap();
        let signer_raw = pubkey_to_tron_raw_address(&pub_key_bytes).unwrap();

        // Recipient address: T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb
        let mut recipient_raw = [0u8; 21];
        recipient_raw[0] = TRON_ADDRESS_PREFIX;
        let recipient_b58 = tron_raw_to_address(&recipient_raw);

        // Build TransferContract: 50 TRX (50,000,000 sun)
        let amount = 50_000_000i64;
        let transfer_proto = build_transfer_contract(&signer_raw, &recipient_raw, amount);
        let any_proto = build_any_parameter(
            "type.googleapis.com/protocol.TransferContract",
            &transfer_proto,
        );
        let contract_proto = build_contract_message(CONTRACT_TYPE_TRANSFER, &any_proto);

        let ref_block_bytes = [0x12, 0x34];
        let ref_block_hash = [0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let timestamp = 1700000000000i64;
        let expiration = 1700000060000i64;

        let raw_data = build_raw_data(
            &ref_block_bytes,
            None,
            Some(&ref_block_hash),
            expiration,
            &contract_proto,
            timestamp,
            None,
        );

        // Decode with TronCodec
        let codec = TronCodec::new();
        let keys = DerivedKeys::from(&pub_key_bytes);
        let decoded = codec
            .decode("tron:0x2b6653dc", &raw_data, &keys)
            .expect("decode native trx transfer");

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        let tx = &decoded.parsed.transfers[0];
        assert_eq!(tx.from, signer_addr);
        assert_eq!(tx.to, recipient_b58);
        assert_eq!(tx.amount, "50000000");
        assert_eq!(tx.asset, "TRX");
        assert_eq!(decoded.parsed.fee.amount, "0");
        assert_eq!(decoded.parsed.fee.asset, "sun");
        assert_eq!(decoded.parsed.sequence.as_sequence(), Some(timestamp as u64));

        // Sign with private key
        let signing_key = SigningKey::from_bytes((&*priv_key_bytes).into()).unwrap();
        let digest_bytes = match decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (raw_sig, _) = signing_key.sign_prehash(&digest_bytes).unwrap();
        let mut sig_64 = [0u8; 64];
        sig_64.copy_from_slice(&raw_sig.to_bytes());

        // Determine recovery ID
        let recid = compute_ecdsa_recovery_id(&digest_bytes, &sig_64, &pub_key_bytes).unwrap();
        let formatted = format_tron_signature(&sig_64, recid, &signer_addr).unwrap();
        assert_eq!(formatted.v, 27 + recid);

        // Verify recovery matches signer address
        let sig_65 = formatted.to_bytes().unwrap();
        assert!(verify_tron_signature_65(&digest_bytes, &sig_65, &signer_addr).unwrap());
    }

    #[test]
    fn test_trc20_usdt_transfer_decoding_and_signature_recovery() {
        // Derive key from standard master seed on Tron BIP44 path m/44'/195'/0'/0/0
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key_bytes, pub_key_bytes) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/195'/0'/0/0".parse().unwrap())
                .unwrap();

        let signer_addr = pubkey_to_tron_address(&pub_key_bytes).unwrap();
        let signer_raw = pubkey_to_tron_raw_address(&pub_key_bytes).unwrap();

        // USDT Contract: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t (41a614f803b6fd780986a42c78ec9c7f77e6ded13c)
        let usdt_contract_raw =
            tron_address_to_raw("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();

        // Recipient: T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb
        let mut recipient_raw = [0u8; 21];
        recipient_raw[0] = TRON_ADDRESS_PREFIX;
        let recipient_b58 = tron_raw_to_address(&recipient_raw);

        // Prepare TRC-20 transfer(address,uint256) data:
        // 4 bytes selector: 0xa9059cbb
        // 32 bytes recipient: 12 zeroes + 20-byte address (recipient_raw[1..21])
        // 32 bytes amount: 100 USDT (100_000_000 atomic units for 6 decimals)
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&TRC20_TRANSFER_SELECTOR);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&recipient_raw[1..21]);
        let mut amount_bytes = [0u8; 32];
        let amount_u64 = 100_000_000u64;
        amount_bytes[24..32].copy_from_slice(&amount_u64.to_be_bytes());
        calldata.extend_from_slice(&amount_bytes);
        assert_eq!(calldata.len(), 68);

        // Build TriggerSmartContract
        let trigger_proto =
            build_trigger_smart_contract(&signer_raw, &usdt_contract_raw, 0, &calldata);
        let any_proto = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger_proto,
        );
        let contract_proto = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any_proto);

        let ref_block_bytes = [0x55, 0x66];
        let timestamp = 1700000010000i64;
        let expiration = 1700000070000i64;
        let fee_limit = 10_000_000i64; // 10 TRX energy limit in sun

        let raw_data = build_raw_data(
            &ref_block_bytes,
            None,
            None,
            expiration,
            &contract_proto,
            timestamp,
            Some(fee_limit),
        );

        // Wrap inside a top-level Transaction message to test wrapped transaction parsing
        let wrapped_tx = build_transaction_message(&raw_data, &[]);

        // Decode with TronCodec
        let codec = TronCodec::new();
        let keys = DerivedKeys::from(&pub_key_bytes);
        let decoded = codec
            .decode("tron:0x2b6653dc", &wrapped_tx, &keys)
            .expect("decode trc-20 transfer");

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        let tx = &decoded.parsed.transfers[0];
        assert_eq!(tx.from, signer_addr);
        assert_eq!(tx.to, recipient_b58);
        assert_eq!(tx.amount, "100000000");
        assert_eq!(tx.asset, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assert_eq!(decoded.parsed.fee.amount, "10000000");
        assert_eq!(decoded.parsed.fee.asset, "sun");

        // Verify signing input matches SHA-256 of raw_data bytes
        let expected_digest = Sha256::digest(&raw_data);
        match decoded.signing_input {
            SigningInput::Digest32(d) => assert_eq!(&d[..], &expected_digest[..]),
            _ => panic!("expected Digest32"),
        }

        // Sign and verify low-S signature recovery
        let signing_key = SigningKey::from_bytes((&*priv_key_bytes).into()).unwrap();
        let digest_bytes: [u8; 32] = expected_digest.into();
        let (raw_sig, _) = signing_key.sign_prehash(&digest_bytes).unwrap();
        let mut sig_64 = [0u8; 64];
        sig_64.copy_from_slice(&raw_sig.to_bytes());
        let recid = compute_ecdsa_recovery_id(&digest_bytes, &sig_64, &pub_key_bytes).unwrap();
        let formatted = format_tron_signature(&sig_64, recid, &signer_addr).unwrap();
        let sig_65 = formatted.to_bytes().unwrap();
        assert!(verify_tron_signature_65(&digest_bytes, &sig_65, &signer_addr).unwrap());
    }

    #[test]
    fn test_tron_rejections_and_negative_cases() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (_, pub_key_bytes) =
            crate::derive::derive_bip32_pair(&seed, &"m/44'/195'/0'/0/0".parse().unwrap())
                .unwrap();
        let signer_raw = pubkey_to_tron_raw_address(&pub_key_bytes).unwrap();
        let keys = DerivedKeys::from(&pub_key_bytes);
        let codec = TronCodec::new();

        // 1. Rejection of unsupported contract type (e.g. VoteWitnessContract = 4)
        let any_proto = build_any_parameter("type.googleapis.com/protocol.VoteWitnessContract", &[]);
        let contract_proto = build_contract_message(4, &any_proto);
        let raw_data = build_raw_data(&[0x12, 0x34], None, None, 1000, &contract_proto, 1000, None);
        let err = codec.decode("tron:0x2b6653dc", &raw_data, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
        assert!(err.to_string().contains("unsupported Tron contract type"));

        // 2. Rejection of unsupported smart contract method selector (e.g. approve = 0x095ea7b3)
        let mut bad_calldata = vec![0x09, 0x5e, 0xa7, 0xb3];
        bad_calldata.extend_from_slice(&[0u8; 64]);
        let trigger_proto = build_trigger_smart_contract(&signer_raw, &signer_raw, 0, &bad_calldata);
        let any_proto = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger_proto,
        );
        let contract_proto = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any_proto);
        let raw_data = build_raw_data(&[0x12, 0x34], None, None, 1000, &contract_proto, 1000, None);
        let err = codec.decode("tron:0x2b6653dc", &raw_data, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
        assert!(err.to_string().contains("unsupported smart contract method"));

        // 3. Rejection of TriggerSmartContract with call_value > 0
        let mut valid_calldata = TRC20_TRANSFER_SELECTOR.to_vec();
        valid_calldata.extend_from_slice(&[0u8; 64]);
        let trigger_proto = build_trigger_smart_contract(&signer_raw, &signer_raw, 500, &valid_calldata);
        let any_proto = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger_proto,
        );
        let contract_proto = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any_proto);
        let raw_data = build_raw_data(&[0x12, 0x34], None, None, 1000, &contract_proto, 1000, None);
        let err = codec.decode("tron:0x2b6653dc", &raw_data, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
        assert!(err.to_string().contains("call_value == 0"));

        // 4. Rejection of key mismatch (owner_address != derived signer)
        let mut other_owner = signer_raw;
        other_owner[20] ^= 0xff;
        let transfer_proto = build_transfer_contract(&other_owner, &signer_raw, 1000);
        let any_proto = build_any_parameter(
            "type.googleapis.com/protocol.TransferContract",
            &transfer_proto,
        );
        let contract_proto = build_contract_message(CONTRACT_TYPE_TRANSFER, &any_proto);
        let raw_data = build_raw_data(&[0x12, 0x34], None, None, 1000, &contract_proto, 1000, None);
        let err = codec.decode("tron:0x2b6653dc", &raw_data, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "key_mismatch");

        // 5. Rejection of multiple contracts in one transaction
        let mut multi_buf = Vec::new();
        encode_bytes_field(11, &contract_proto, &mut multi_buf);
        encode_bytes_field(11, &contract_proto, &mut multi_buf);
        let err = codec.decode("tron:0x2b6653dc", &multi_buf, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
        assert!(err.to_string().contains("multi-contract"));

        // 6. Rejection of chain mismatch
        let err = codec.decode("solana:mainnet", &raw_data, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
    }

    #[test]
    fn test_generate_and_verify_tron_reference_vectors() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let path_str = "m/44'/195'/0'/0/0";
        let (priv_key_bytes, pub_key_bytes) =
            crate::derive::derive_bip32_pair(&seed, &path_str.parse().unwrap()).unwrap();
        let signing_key = SigningKey::from_bytes((&*priv_key_bytes).into()).unwrap();
        let signer_addr = pubkey_to_tron_address(&pub_key_bytes).unwrap();
        let signer_raw = pubkey_to_tron_raw_address(&pub_key_bytes).unwrap();

        // Vector 1: Native TRX transfer of 50 TRX (50,000,000 sun) to burn/genesis address
        let mut recipient1_raw = [0u8; 21];
        recipient1_raw[0] = TRON_ADDRESS_PREFIX;
        let recipient1_b58 = tron_raw_to_address(&recipient1_raw);

        let transfer1_proto = build_transfer_contract(&signer_raw, &recipient1_raw, 50_000_000);
        let any1 = build_any_parameter(
            "type.googleapis.com/protocol.TransferContract",
            &transfer1_proto,
        );
        let contract1 = build_contract_message(CONTRACT_TYPE_TRANSFER, &any1);
        let raw_data1 = build_raw_data(
            &[0x1a, 0x2b],
            None,
            Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            1700000060000,
            &contract1,
            1700000000000,
            None,
        );

        let digest1: [u8; 32] = Sha256::digest(&raw_data1).into();
        let (sig1_raw, _) = signing_key.sign_prehash(&digest1).unwrap();
        let mut sig1_64 = [0u8; 64];
        sig1_64.copy_from_slice(&sig1_raw.to_bytes());
        let recid1 = compute_ecdsa_recovery_id(&digest1, &sig1_64, &pub_key_bytes).unwrap();
        let formatted1 = format_tron_signature(&sig1_64, recid1, &signer_addr).unwrap();

        // Vector 2: TRC-20 USDT transfer of 100 USDT (100,000,000 units)
        let usdt_contract_raw =
            tron_address_to_raw("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").unwrap();
        let mut calldata2 = Vec::with_capacity(68);
        calldata2.extend_from_slice(&TRC20_TRANSFER_SELECTOR);
        calldata2.extend_from_slice(&[0u8; 12]);
        calldata2.extend_from_slice(&recipient1_raw[1..21]);
        let mut amount_bytes2 = [0u8; 32];
        amount_bytes2[24..32].copy_from_slice(&100_000_000u64.to_be_bytes());
        calldata2.extend_from_slice(&amount_bytes2);

        let trigger2_proto =
            build_trigger_smart_contract(&signer_raw, &usdt_contract_raw, 0, &calldata2);
        let any2 = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger2_proto,
        );
        let contract2 = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any2);
        let raw_data2 = build_raw_data(
            &[0x3c, 0x4d],
            None,
            Some(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]),
            1700000070000,
            &contract2,
            1700000010000,
            Some(10_000_000),
        );
        let wrapped_tx2 = build_transaction_message(&raw_data2, &[]);

        let digest2: [u8; 32] = Sha256::digest(&raw_data2).into();
        let (sig2_raw, _) = signing_key.sign_prehash(&digest2).unwrap();
        let mut sig2_64 = [0u8; 64];
        sig2_64.copy_from_slice(&sig2_raw.to_bytes());
        let recid2 = compute_ecdsa_recovery_id(&digest2, &sig2_64, &pub_key_bytes).unwrap();
        let formatted2 = format_tron_signature(&sig2_64, recid2, &signer_addr).unwrap();

        // Vector 3: Negative rejection: unknown contract type (ExchangeCreateContract = 41)
        let any3 = build_any_parameter(
            "type.googleapis.com/protocol.ExchangeCreateContract",
            &[0u8; 10],
        );
        let contract3 = build_contract_message(41, &any3);
        let raw_data3 = build_raw_data(&[0x11, 0x22], None, None, 1000, &contract3, 1000, None);

        // Vector 4: Negative rejection: unknown smart contract selector (approve = 0x095ea7b3)
        let mut calldata4 = vec![0x09, 0x5e, 0xa7, 0xb3];
        calldata4.extend_from_slice(&[0u8; 64]);
        let trigger4_proto =
            build_trigger_smart_contract(&signer_raw, &usdt_contract_raw, 0, &calldata4);
        let any4 = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger4_proto,
        );
        let contract4 = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any4);
        let raw_data4 = build_raw_data(&[0x33, 0x44], None, None, 1000, &contract4, 1000, None);

        // Vector 5: Negative rejection: key mismatch
        let mut other_signer = signer_raw;
        other_signer[20] ^= 0x01;
        let transfer5_proto =
            build_transfer_contract(&other_signer, &recipient1_raw, 10_000_000);
        let any5 = build_any_parameter(
            "type.googleapis.com/protocol.TransferContract",
            &transfer5_proto,
        );
        let contract5 = build_contract_message(CONTRACT_TYPE_TRANSFER, &any5);
        let raw_data5 = build_raw_data(&[0x55, 0x66], None, None, 1000, &contract5, 1000, None);

        // Vector 6: Negative rejection: non-zero call_value on TRC-20 TriggerSmartContract
        let trigger6_proto =
            build_trigger_smart_contract(&signer_raw, &usdt_contract_raw, 1_000_000, &calldata2);
        let any6 = build_any_parameter(
            "type.googleapis.com/protocol.TriggerSmartContract",
            &trigger6_proto,
        );
        let contract6 = build_contract_message(CONTRACT_TYPE_TRIGGER_SMART, &any6);
        let raw_data6 = build_raw_data(&[0x77, 0x88], None, None, 1000, &contract6, 1000, None);

        let vectors = serde_json::json!([
            {
                "id": "tron_mainnet_native_trx_transfer",
                "description": "Native TRX transfer of 50 TRX on Tron Mainnet (TransferContract)",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&raw_data1)),
                "signing_input": format!("0x{}", hex::encode(digest1)),
                "parsed": {
                    "transfers": [
                        {
                            "from": signer_addr,
                            "to": recipient1_b58,
                            "amount": "50000000",
                            "asset": "TRX"
                        }
                    ],
                    "fee": {
                        "amount": "0",
                        "asset": "sun"
                    },
                    "sequence": {
                        "sequence": 1700000000000u64
                    },
                    "details": {
                        "chain": "tron:0x2b6653dc",
                        "contract_type": "TransferContract",
                        "amount_sun": 50000000,
                        "ref_block_bytes": "0x1a2b",
                        "ref_block_hash": "0x1122334455667788",
                        "expiration": 1700000060000u64,
                        "timestamp": 1700000000000u64,
                        "fee_limit": 0
                    }
                },
                "result": {
                    "signature_hex": formatted1.signature_hex,
                    "r": formatted1.r,
                    "s": formatted1.s,
                    "v": formatted1.v,
                    "recovery_id": formatted1.recovery_id,
                    "signer_address": formatted1.signer_address
                }
            },
            {
                "id": "tron_mainnet_trc20_usdt_transfer",
                "description": "TRC-20 transfer of 100 USDT on Tron Mainnet (TriggerSmartContract in top-level Transaction wrapper)",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&wrapped_tx2)),
                "signing_input": format!("0x{}", hex::encode(digest2)),
                "parsed": {
                    "transfers": [
                        {
                            "from": signer_addr,
                            "to": recipient1_b58,
                            "amount": "100000000",
                            "asset": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
                        }
                    ],
                    "fee": {
                        "amount": "10000000",
                        "asset": "sun"
                    },
                    "sequence": {
                        "sequence": 1700000010000u64
                    },
                    "details": {
                        "chain": "tron:0x2b6653dc",
                        "contract_type": "TriggerSmartContract",
                        "contract_address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                        "selector": "0xa9059cbb",
                        "method": "transfer(address,uint256)",
                        "call_value": 0,
                        "ref_block_bytes": "0x3c4d",
                        "ref_block_hash": "0xaabbccddeeff0011",
                        "expiration": 1700000070000u64,
                        "timestamp": 1700000010000u64,
                        "fee_limit": 10000000
                    }
                },
                "result": {
                    "signature_hex": formatted2.signature_hex,
                    "r": formatted2.r,
                    "s": formatted2.s,
                    "v": formatted2.v,
                    "recovery_id": formatted2.recovery_id,
                    "signer_address": formatted2.signer_address
                }
            },
            {
                "id": "tron_rejection_unsupported_contract_type",
                "description": "Rejection of unsupported Tron contract type (ExchangeCreateContract = 41)",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_data3)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "tron_rejection_unsupported_smart_contract_method",
                "description": "Rejection of unsupported smart contract method selector (approve 0x095ea7b3)",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_data4)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "tron_rejection_key_mismatch",
                "description": "Rejection when owner_address does not match the derived signer key",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_data5)),
                "expected_error": "key_mismatch"
            },
            {
                "id": "tron_rejection_nonzero_call_value",
                "description": "Rejection of TRC-20 TriggerSmartContract with call_value > 0",
                "chain": "tron:0x2b6653dc",
                "path": path_str,
                "public_key": format!("0x{}", hex::encode(pub_key_bytes)),
                "raw_tx": format!("0x{}", hex::encode(&raw_data6)),
                "expected_error": "unsupported_transaction"
            }
        ]);

        let vectors_pretty = serde_json::to_string_pretty(&vectors).unwrap();

        // Write vectors/tx_tron.json if in repo root or relative path
        let candidates = [
            Path::new("vectors/tx_tron.json"),
            Path::new("../vectors/tx_tron.json"),
            Path::new("../../vectors/tx_tron.json"),
        ];
        for path in &candidates {
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let _ = fs::write(path, vectors_pretty.as_bytes());
                    break;
                }
            }
        }
    }

    #[test]
    fn test_tron_reference_vectors_from_file() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let p1 = manifest_dir.parent().unwrap().join("vectors").join("tx_tron.json");
        let p2 = manifest_dir.join("vectors").join("tx_tron.json");
        let path = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            std::path::PathBuf::from("vectors/tx_tron.json")
        };

        if !path.exists() {
            // First run will create file via test_generate_and_verify_tron_reference_vectors
            return;
        }

        let content = fs::read_to_string(&path).expect("read tx_tron.json");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&content).expect("parse tx_tron.json");

        let codec = TronCodec::new();

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
                let sig_bytes = hex::decode(sig_hex).unwrap();
                let sig_65: &[u8; 65] = sig_bytes.as_slice().try_into().unwrap();

                let digest_32: &[u8; 32] = expected_signing_input.as_slice().try_into().unwrap();
                assert!(
                    verify_tron_signature_65(digest_32, sig_65, expected_signer).unwrap(),
                    "vector '{id}' signature recovery failed"
                );
            }
        }
    }
}
