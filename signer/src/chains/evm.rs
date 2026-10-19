//! Ethereum and EVM-compatible networks transaction codec (Task 14, Section 5 of `Specs.md`).
//!
//! Implements decoding and summary extraction for:
//! - EIP-1559 (Type 2) transactions: `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list])`
//! - Legacy EIP-155 unsigned transactions: `rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])`
//!
//! Supports native ETH/EVM value transfers and ERC-20 `transfer(address,uint256)` calls.
//! Enforces internal chain ID validation against CAIP-2 `eip155:<chain_id>`, EIP-55 checksummed
//! address formatting, Keccak-256 signing digest calculation, and secp256k1 signature recovery verification.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::backend::generic::crypto::{
    decompress_secp256k1_pubkey, recover_secp256k1_pubkey_compressed,
};
use crate::chains::{
    parse_caip2, ChainCodec, ChainError, DecodedTx, DerivedKeys, FeeSummary, ParsedTx,
    SequenceField, SigningInput, Transfer,
};

/// ERC-20 `transfer(address,uint256)` 4-byte method selector: `0xa9059cbb`.
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// EIP-1559 transaction type identifier prefix byte: `0x02`.
pub const EIP1559_TX_TYPE: u8 = 0x02;

/// Formatted EVM signature carrying `r`, `s`, `v`, and `y_parity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmSignature {
    /// 32-byte big-endian `r` scalar encoded as `0x`-prefixed 64-character hex.
    pub r: String,
    /// 32-byte big-endian low-S normalized `s` scalar encoded as `0x`-prefixed 64-character hex.
    pub s: String,
    /// Recovery identifier:
    /// - EIP-1559: `y_parity` (0 or 1)
    /// - Legacy EIP-155: `y_parity + chain_id * 2 + 35`
    pub v: u64,
    /// ECDSA recovery ID / y-parity (`0` or `1`).
    pub y_parity: u8,
    /// EIP-55 checksummed signer address.
    pub signer_address: String,
}

/// EVM transaction codec implementing [`ChainCodec`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmCodec;

impl EvmCodec {
    /// Constructs a new [`EvmCodec`].
    pub fn new() -> Self {
        Self
    }
}

impl ChainCodec for EvmCodec {
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        decode_evm_tx(chain, raw_tx_bytes, keys)
    }
}

/// Decodes an EVM transaction for `chain` using the derived public key in `keys`.
pub fn decode_evm_tx(
    chain: &str,
    raw_tx_bytes: &[u8],
    keys: &DerivedKeys,
) -> Result<DecodedTx, ChainError> {
    // 1. Verify CAIP-2 namespace and extract numeric expected chain ID
    let (ns, ref_id) = parse_caip2(chain)?;
    if ns != "eip155" {
        return Err(ChainError::UnsupportedChain(format!(
            "expected 'eip155' namespace, got '{ns}'"
        )));
    }
    let expected_chain_id: u64 = ref_id.parse().map_err(|_| {
        ChainError::UnsupportedTransaction(format!(
            "invalid numeric chain ID '{ref_id}' in '{chain}'"
        ))
    })?;
    if expected_chain_id == 0 {
        return Err(ChainError::UnsupportedTransaction(
            "chain ID must be greater than zero".to_string(),
        ));
    }

    // 2. Validate derived public key and derive EIP-55 checksummed signer address
    let single_key = keys.single()?;
    if single_key.len() != 33 {
        return Err(ChainError::InvalidKeys(format!(
            "expected 33-byte compressed secp256k1 public key, got {}",
            single_key.len()
        )));
    }
    let pk_array: &[u8; 33] = single_key
        .try_into()
        .map_err(|_| ChainError::InvalidKeys("invalid key slice length".to_string()))?;
    let signer_address = pubkey_to_address(pk_array)?;

    // 3. Inspect raw transaction bytes
    if raw_tx_bytes.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "empty transaction payload".to_string(),
        ));
    }

    if raw_tx_bytes[0] == EIP1559_TX_TYPE {
        decode_eip1559_tx(chain, expected_chain_id, raw_tx_bytes, signer_address)
    } else if raw_tx_bytes[0] >= 0xc0 {
        decode_legacy_eip155_tx(chain, expected_chain_id, raw_tx_bytes, signer_address)
    } else {
        Err(ChainError::UnsupportedTransaction(format!(
            "unsupported transaction type 0x{:02x}",
            raw_tx_bytes[0]
        )))
    }
}

/// Decodes an unsigned EIP-1559 (Type 2) transaction.
fn decode_eip1559_tx(
    chain: &str,
    expected_chain_id: u64,
    raw_tx_bytes: &[u8],
    signer_address: String,
) -> Result<DecodedTx, ChainError> {
    let rlp_payload = &raw_tx_bytes[1..];
    let (item, rest) = RlpItem::parse(rlp_payload)?;
    if !rest.is_empty() {
        return Err(ChainError::MalformedTransaction(format!(
            "unexpected trailing bytes after EIP-1559 RLP payload ({} bytes remaining)",
            rest.len()
        )));
    }

    let items = item.as_list()?;
    if items.len() != 9 {
        return Err(ChainError::MalformedTransaction(format!(
            "expected 9 elements in unsigned EIP-1559 payload, got {}",
            items.len()
        )));
    }

    // 0: chain_id
    let chain_id_bytes = items[0].as_string()?;
    let tx_chain_id = parse_be_u64(chain_id_bytes)?;
    if tx_chain_id != expected_chain_id {
        return Err(ChainError::ChainMismatch {
            expected: chain.to_string(),
            actual: format!("eip155:{tx_chain_id}"),
        });
    }

    // 1: nonce
    let nonce_bytes = items[1].as_string()?;
    let nonce = parse_be_u64(nonce_bytes)?;

    // 2: max_priority_fee_per_gas
    let max_priority_fee_bytes = items[2].as_string()?;
    validate_u256_canonical_int(max_priority_fee_bytes)?;
    let max_priority_fee_str = u256_be_bytes_to_dec_string(max_priority_fee_bytes);

    // 3: max_fee_per_gas
    let max_fee_bytes = items[3].as_string()?;
    validate_u256_canonical_int(max_fee_bytes)?;
    let max_fee_str = u256_be_bytes_to_dec_string(max_fee_bytes);

    // Ensure max_priority_fee_per_gas <= max_fee_per_gas
    if compare_be_u256(max_priority_fee_bytes, max_fee_bytes).is_gt() {
        return Err(ChainError::MalformedTransaction(
            "max_priority_fee_per_gas exceeds max_fee_per_gas".to_string(),
        ));
    }

    // 4: gas_limit
    let gas_limit_bytes = items[4].as_string()?;
    let gas_limit = parse_be_u64(gas_limit_bytes)?;
    if gas_limit == 0 {
        return Err(ChainError::MalformedTransaction(
            "gas_limit must be greater than zero".to_string(),
        ));
    }

    // 5: to
    let to_bytes = items[5].as_string()?;
    if to_bytes.is_empty() {
        return Err(ChainError::UnsupportedTransaction(
            "contract creation (to == empty) is not supported".to_string(),
        ));
    }
    if to_bytes.len() != 20 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid recipient address length: expected 20 bytes, got {}",
            to_bytes.len()
        )));
    }
    let to_addr: [u8; 20] = to_bytes
        .try_into()
        .map_err(|_| ChainError::MalformedTransaction("address slice mismatch".to_string()))?;
    let to_checksum = eip55_checksum(&to_addr);

    // 6: value
    let value_bytes = items[6].as_string()?;
    validate_u256_canonical_int(value_bytes)?;
    let value_str = u256_be_bytes_to_dec_string(value_bytes);

    // 7: data
    let data_bytes = items[7].as_string()?;

    // 8: access_list
    let access_list_item = &items[8];
    let access_list_val = parse_access_list(access_list_item)?;

    // Parse transfers (native vs ERC-20)
    let transfers = parse_transfers(
        &signer_address,
        &to_checksum,
        value_bytes,
        &value_str,
        data_bytes,
    )?;

    // Fee: gas_limit * max_fee_per_gas
    let fee_amount = mul_u64_by_u256_be_to_dec_string(gas_limit, max_fee_bytes);
    let fee = FeeSummary::new(fee_amount, "wei");

    let sequence = SequenceField::nonce(nonce);

    let details = serde_json::json!({
        "chain_id": tx_chain_id,
        "gas_limit": gas_limit,
        "max_fee_per_gas": max_fee_str,
        "max_priority_fee_per_gas": max_priority_fee_str,
        "type": 2,
        "access_list": access_list_val,
    });

    let signing_digest = keccak256(raw_tx_bytes);
    let parsed = ParsedTx::new(transfers, fee, sequence, details);

    Ok(DecodedTx::new(
        parsed,
        SigningInput::digest32(signing_digest),
        signer_address,
    ))
}

/// Decodes an unsigned legacy EIP-155 transaction.
fn decode_legacy_eip155_tx(
    chain: &str,
    expected_chain_id: u64,
    raw_tx_bytes: &[u8],
    signer_address: String,
) -> Result<DecodedTx, ChainError> {
    let (item, rest) = RlpItem::parse(raw_tx_bytes)?;
    if !rest.is_empty() {
        return Err(ChainError::MalformedTransaction(format!(
            "unexpected trailing bytes after legacy transaction RLP ({} bytes remaining)",
            rest.len()
        )));
    }

    let items = item.as_list()?;
    if items.len() == 6 {
        return Err(ChainError::UnsupportedTransaction(
            "legacy pre-EIP-155 transaction without internal chain ID is not supported".to_string(),
        ));
    }
    if items.len() != 9 {
        return Err(ChainError::MalformedTransaction(format!(
            "expected 9 elements in unsigned legacy EIP-155 transaction, got {}",
            items.len()
        )));
    }

    // 0: nonce
    let nonce_bytes = items[0].as_string()?;
    let nonce = parse_be_u64(nonce_bytes)?;

    // 1: gas_price
    let gas_price_bytes = items[1].as_string()?;
    validate_u256_canonical_int(gas_price_bytes)?;
    let gas_price_str = u256_be_bytes_to_dec_string(gas_price_bytes);

    // 2: gas_limit
    let gas_limit_bytes = items[2].as_string()?;
    let gas_limit = parse_be_u64(gas_limit_bytes)?;
    if gas_limit == 0 {
        return Err(ChainError::MalformedTransaction(
            "gas_limit must be greater than zero".to_string(),
        ));
    }

    // 3: to
    let to_bytes = items[3].as_string()?;
    if to_bytes.is_empty() {
        return Err(ChainError::UnsupportedTransaction(
            "contract creation (to == empty) is not supported".to_string(),
        ));
    }
    if to_bytes.len() != 20 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid recipient address length: expected 20 bytes, got {}",
            to_bytes.len()
        )));
    }
    let to_addr: [u8; 20] = to_bytes
        .try_into()
        .map_err(|_| ChainError::MalformedTransaction("address slice mismatch".to_string()))?;
    let to_checksum = eip55_checksum(&to_addr);

    // 4: value
    let value_bytes = items[4].as_string()?;
    validate_u256_canonical_int(value_bytes)?;
    let value_str = u256_be_bytes_to_dec_string(value_bytes);

    // 5: data
    let data_bytes = items[5].as_string()?;

    // 6: chain_id
    let chain_id_bytes = items[6].as_string()?;
    let tx_chain_id = parse_be_u64(chain_id_bytes)?;
    if tx_chain_id != expected_chain_id {
        return Err(ChainError::ChainMismatch {
            expected: chain.to_string(),
            actual: format!("eip155:{tx_chain_id}"),
        });
    }

    // 7 & 8: dummy r and s values for unsigned EIP-155 payload
    let r_dummy = items[7].as_string()?;
    let s_dummy = items[8].as_string()?;
    let r_is_zero = r_dummy.is_empty() || (r_dummy.len() == 1 && r_dummy[0] == 0);
    let s_is_zero = s_dummy.is_empty() || (s_dummy.len() == 1 && s_dummy[0] == 0);
    if !r_is_zero || !s_is_zero {
        return Err(ChainError::MalformedTransaction(
            "unsigned legacy EIP-155 transaction must have empty r and s values".to_string(),
        ));
    }

    // Parse transfers (native vs ERC-20)
    let transfers = parse_transfers(
        &signer_address,
        &to_checksum,
        value_bytes,
        &value_str,
        data_bytes,
    )?;

    // Fee: gas_limit * gas_price
    let fee_amount = mul_u64_by_u256_be_to_dec_string(gas_limit, gas_price_bytes);
    let fee = FeeSummary::new(fee_amount, "wei");

    let sequence = SequenceField::nonce(nonce);

    let details = serde_json::json!({
        "chain_id": tx_chain_id,
        "gas_limit": gas_limit,
        "gas_price": gas_price_str,
        "type": 0,
    });

    let signing_digest = keccak256(raw_tx_bytes);
    let parsed = ParsedTx::new(transfers, fee, sequence, details);

    Ok(DecodedTx::new(
        parsed,
        SigningInput::digest32(signing_digest),
        signer_address,
    ))
}

/// Parses transfers for EVM transactions.
///
/// Accepts:
/// - Native ETH/EVM transfer when `data_bytes.is_empty()`.
/// - ERC-20 `transfer(address,uint256)` when `data_bytes` is 68 bytes with `0xa9059cbb` selector.
///
/// Rejects all other contract calldata with `ChainError::UnsupportedTransaction`.
fn parse_transfers(
    signer_address: &str,
    to_checksum: &str,
    value_bytes: &[u8],
    value_str: &str,
    data_bytes: &[u8],
) -> Result<Vec<Transfer>, ChainError> {
    if data_bytes.is_empty() {
        // Native ETH/EVM transfer
        Ok(vec![Transfer::new(
            signer_address,
            to_checksum,
            value_str,
            "ETH",
        )])
    } else {
        // Must match ERC-20 transfer(address,uint256) selector and length
        if data_bytes.len() != 68 || &data_bytes[..4] != ERC20_TRANSFER_SELECTOR {
            let selector_hex = if data_bytes.len() >= 4 {
                format!("0x{}", hex::encode(&data_bytes[..4]))
            } else {
                format!("0x{}", hex::encode(data_bytes))
            };
            return Err(ChainError::UnsupportedTransaction(format!(
                "unsupported contract calldata (selector {selector_hex}, len {})",
                data_bytes.len()
            )));
        }

        // Native value must be zero for standard non-payable ERC-20 transfer
        let is_value_zero =
            value_bytes.is_empty() || (value_bytes.len() == 1 && value_bytes[0] == 0);
        if !is_value_zero {
            return Err(ChainError::UnsupportedTransaction(
                "non-payable ERC-20 transfer has non-zero native value".to_string(),
            ));
        }

        // Check ABI padding for recipient address (first 12 bytes must be 0)
        if data_bytes[4..16] != [0u8; 12] {
            return Err(ChainError::MalformedTransaction(
                "invalid ERC-20 transfer recipient address: non-zero ABI padding".to_string(),
            ));
        }

        let mut erc20_to_bytes = [0u8; 20];
        erc20_to_bytes.copy_from_slice(&data_bytes[16..36]);
        let erc20_to_checksum = eip55_checksum(&erc20_to_bytes);

        let erc20_amount_bytes = &data_bytes[36..68];
        let erc20_amount_str = u256_be_bytes_to_dec_string(erc20_amount_bytes);

        // ERC-20 transfer summary:
        // - from: signer_address
        // - to: erc20 recipient
        // - amount: token amount
        // - asset: token contract address
        Ok(vec![Transfer::new(
            signer_address,
            erc20_to_checksum,
            erc20_amount_str,
            to_checksum,
        )])
    }
}

/// Parses an EIP-2930 / EIP-1559 access list RLP item.
fn parse_access_list(item: &RlpItem) -> Result<serde_json::Value, ChainError> {
    let list = item.as_list()?;
    let mut json_list = Vec::with_capacity(list.len());
    for entry in list {
        let entry_items = entry.as_list()?;
        if entry_items.len() != 2 {
            return Err(ChainError::MalformedTransaction(format!(
                "invalid access list entry: expected 2 elements, got {}",
                entry_items.len()
            )));
        }
        let addr_bytes = entry_items[0].as_string()?;
        if addr_bytes.len() != 20 {
            return Err(ChainError::MalformedTransaction(format!(
                "invalid address in access list: expected 20 bytes, got {}",
                addr_bytes.len()
            )));
        }
        let addr: [u8; 20] = addr_bytes
            .try_into()
            .map_err(|_| ChainError::MalformedTransaction("address slice mismatch".to_string()))?;
        let addr_checksum = eip55_checksum(&addr);

        let storage_keys_items = entry_items[1].as_list()?;
        let mut storage_keys = Vec::with_capacity(storage_keys_items.len());
        for key_item in storage_keys_items {
            let key_bytes = key_item.as_string()?;
            if key_bytes.len() != 32 {
                return Err(ChainError::MalformedTransaction(format!(
                    "invalid storage key in access list: expected 32 bytes, got {}",
                    key_bytes.len()
                )));
            }
            storage_keys.push(format!("0x{}", hex::encode(key_bytes)));
        }

        json_list.push(serde_json::json!({
            "address": addr_checksum,
            "storage_keys": storage_keys
        }));
    }
    Ok(serde_json::Value::Array(json_list))
}

/// Computes the Keccak-256 hash of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes the EIP-55 checksummed hex string (`0x...`) for a 20-byte Ethereum address.
pub fn eip55_checksum(address_bytes: &[u8; 20]) -> String {
    let hex_addr = hex::encode(address_bytes);
    let hash = keccak256(hex_addr.as_bytes());
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, ch) in hex_addr.chars().enumerate() {
        if ch.is_ascii_digit() {
            checksummed.push(ch);
        } else {
            let hash_byte = hash[i / 2];
            let nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };
            if nibble >= 8 {
                checksummed.push(ch.to_ascii_uppercase());
            } else {
                checksummed.push(ch.to_ascii_lowercase());
            }
        }
    }
    checksummed
}

/// Derives the EIP-55 checksummed Ethereum address from a 33-byte compressed `secp256k1` public key.
pub fn pubkey_to_address(compressed_pubkey: &[u8; 33]) -> Result<String, ChainError> {
    let uncompressed = decompress_secp256k1_pubkey(compressed_pubkey)
        .map_err(|e| ChainError::InvalidKeys(format!("invalid secp256k1 public key: {e}")))?;
    let hash = keccak256(&uncompressed[1..65]);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    Ok(eip55_checksum(&addr_bytes))
}

/// Verifies that public key recovery from `digest32`, `sig_64`, and `recovery_id`
/// yields an address matching `expected_signer_address`.
pub fn verify_signature_recovery(
    digest32: &[u8; 32],
    sig_64: &[u8; 64],
    recovery_id: u8,
    expected_signer_address: &str,
) -> Result<bool, ChainError> {
    let recovered_pubkey = recover_secp256k1_pubkey_compressed(digest32, sig_64, recovery_id)
        .map_err(|e| ChainError::Crypto(format!("secp256k1 public key recovery failed: {e}")))?;
    let recovered_addr = pubkey_to_address(&recovered_pubkey)?;

    if recovered_addr.eq_ignore_ascii_case(expected_signer_address) {
        Ok(true)
    } else {
        Err(ChainError::KeyMismatch(format!(
            "recovered address '{recovered_addr}' does not match expected signer '{expected_signer_address}'"
        )))
    }
}

/// Formats a 64-byte `(r, s)` signature and recovery ID into an [`EvmSignature`].
pub fn format_evm_signature(
    sig_64: &[u8; 64],
    recovery_id: u8,
    chain_id: u64,
    is_eip1559: bool,
    signer_address: &str,
) -> EvmSignature {
    let r_hex = format!("0x{}", hex::encode(&sig_64[..32]));
    let s_hex = format!("0x{}", hex::encode(&sig_64[32..]));
    let v = if is_eip1559 {
        recovery_id as u64
    } else {
        (recovery_id as u64) + chain_id * 2 + 35
    };
    EvmSignature {
        r: r_hex,
        s: s_hex,
        v,
        y_parity: recovery_id,
        signer_address: signer_address.to_string(),
    }
}

/// Validates that big-endian integer bytes follow canonical RLP rules:
/// no leading zeros (unless zero itself), and maximum 32 bytes for U256.
fn validate_u256_canonical_int(bytes: &[u8]) -> Result<(), ChainError> {
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(ChainError::MalformedTransaction(
            "non-canonical RLP: integer has leading zero".to_string(),
        ));
    }
    if bytes.len() > 32 {
        return Err(ChainError::MalformedTransaction(format!(
            "integer overflow: value exceeds 32 bytes (got {})",
            bytes.len()
        )));
    }
    Ok(())
}

/// Compares two big-endian integers (ignoring leading zeros).
fn compare_be_u256(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let mut a_trimmed = a;
    while !a_trimmed.is_empty() && a_trimmed[0] == 0 {
        a_trimmed = &a_trimmed[1..];
    }
    let mut b_trimmed = b;
    while !b_trimmed.is_empty() && b_trimmed[0] == 0 {
        b_trimmed = &b_trimmed[1..];
    }
    match a_trimmed.len().cmp(&b_trimmed.len()) {
        std::cmp::Ordering::Equal => a_trimmed.cmp(b_trimmed),
        other => other,
    }
}

/// Converts big-endian bytes into a decimal string using arbitrary-precision schoolbook divmod.
pub fn u256_be_bytes_to_dec_string(bytes: &[u8]) -> String {
    let mut trimmed = bytes;
    while !trimmed.is_empty() && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    if trimmed.is_empty() {
        return "0".to_string();
    }

    let mut num = trimmed.to_vec();
    let mut digits = Vec::new();
    while !num.is_empty() {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(num.len());
        for &b in &num {
            let cur = (rem << 8) | (b as u32);
            let q = cur / 10;
            rem = cur % 10;
            if !next.is_empty() || q > 0 {
                next.push(q as u8);
            }
        }
        digits.push((b'0' + rem as u8) as char);
        num = next;
    }
    digits.into_iter().rev().collect()
}

/// Multiplies a `u64` multiplier with big-endian integer bytes and returns the decimal string product.
pub fn mul_u64_by_u256_be_to_dec_string(multiplier: u64, bytes: &[u8]) -> String {
    if multiplier == 0 {
        return "0".to_string();
    }
    let mut trimmed = bytes;
    while !trimmed.is_empty() && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    if trimmed.is_empty() {
        return "0".to_string();
    }

    let mut carry = 0u128;
    let mut product_rev = Vec::with_capacity(trimmed.len() + 8);
    for &b in trimmed.iter().rev() {
        let prod = (b as u128) * (multiplier as u128) + carry;
        product_rev.push((prod & 0xff) as u8);
        carry = prod >> 8;
    }
    while carry > 0 {
        product_rev.push((carry & 0xff) as u8);
        carry >>= 8;
    }
    product_rev.reverse();
    u256_be_bytes_to_dec_string(&product_rev)
}

/// Parses big-endian bytes into a `u64`.
pub fn parse_be_u64(bytes: &[u8]) -> Result<u64, ChainError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(ChainError::MalformedTransaction(
            "non-canonical RLP: integer has leading zero".to_string(),
        ));
    }
    if bytes.len() > 8 {
        return Err(ChainError::MalformedTransaction(format!(
            "integer overflow: expected at most 8 bytes for u64, got {}",
            bytes.len()
        )));
    }
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | (b as u64);
    }
    Ok(val)
}

/// Parses big-endian bytes into `usize`.
fn parse_be_usize(bytes: &[u8]) -> Result<usize, ChainError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > std::mem::size_of::<usize>() {
        return Err(ChainError::MalformedTransaction(
            "RLP length field exceeds usize".to_string(),
        ));
    }
    let mut val = 0usize;
    for &b in bytes {
        val = (val << 8) | (b as usize);
    }
    Ok(val)
}

// ============================================================================
// Recursive Length Prefix (RLP) Parser & Serializer
// ============================================================================

/// Parsed Recursive Length Prefix (RLP) item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem<'a> {
    /// Arbitrary byte string (integers, addresses, calldata, hashes).
    String(&'a [u8]),
    /// List of RLP items.
    List(Vec<RlpItem<'a>>),
}

impl<'a> RlpItem<'a> {
    /// Parses an RLP item from `input`, returning the parsed item and remaining unparsed slice.
    pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), ChainError> {
        if input.is_empty() {
            return Err(ChainError::MalformedTransaction(
                "empty RLP input".to_string(),
            ));
        }
        let prefix = input[0];

        if prefix <= 0x7f {
            // Single byte in [0x00, 0x7f] is its own RLP encoding
            Ok((RlpItem::String(&input[..1]), &input[1..]))
        } else if prefix <= 0xb7 {
            // Short string of length 0..=55
            let len = (prefix - 0x80) as usize;
            if input.len() < 1 + len {
                return Err(ChainError::MalformedTransaction(format!(
                    "unexpected end of RLP string: expected {len} bytes, got {}",
                    input.len() - 1
                )));
            }
            let data = &input[1..1 + len];
            // Non-canonical check: single byte < 0x80 encoded as short string
            if len == 1 && data[0] <= 0x7f {
                return Err(ChainError::MalformedTransaction(
                    "non-canonical RLP: single byte <= 0x7f must be encoded directly".to_string(),
                ));
            }
            Ok((RlpItem::String(data), &input[1 + len..]))
        } else if prefix <= 0xbf {
            // Long string of length > 55
            let len_of_len = (prefix - 0xb7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(ChainError::MalformedTransaction(
                    "unexpected end of RLP length-of-length".to_string(),
                ));
            }
            let len_bytes = &input[1..1 + len_of_len];
            if len_bytes[0] == 0 {
                return Err(ChainError::MalformedTransaction(
                    "non-canonical RLP: leading zero in string length".to_string(),
                ));
            }
            let str_len = parse_be_usize(len_bytes)?;
            if str_len <= 55 {
                return Err(ChainError::MalformedTransaction(
                    "non-canonical RLP: string length <= 55 encoded as long string".to_string(),
                ));
            }
            let total_len = 1 + len_of_len + str_len;
            if input.len() < total_len {
                return Err(ChainError::MalformedTransaction(format!(
                    "unexpected end of RLP string: expected {str_len} bytes, got {}",
                    input.len() - (1 + len_of_len)
                )));
            }
            let data = &input[1 + len_of_len..total_len];
            Ok((RlpItem::String(data), &input[total_len..]))
        } else if prefix <= 0xf7 {
            // Short list with payload length 0..=55
            let len = (prefix - 0xc0) as usize;
            if input.len() < 1 + len {
                return Err(ChainError::MalformedTransaction(format!(
                    "unexpected end of RLP list: expected {len} bytes, got {}",
                    input.len() - 1
                )));
            }
            let mut list_payload = &input[1..1 + len];
            let mut items = Vec::new();
            while !list_payload.is_empty() {
                let (sub_item, rest) = Self::parse(list_payload)?;
                items.push(sub_item);
                list_payload = rest;
            }
            Ok((RlpItem::List(items), &input[1 + len..]))
        } else {
            // Long list with payload length > 55
            let len_of_len = (prefix - 0xf7) as usize;
            if input.len() < 1 + len_of_len {
                return Err(ChainError::MalformedTransaction(
                    "unexpected end of RLP list length-of-length".to_string(),
                ));
            }
            let len_bytes = &input[1..1 + len_of_len];
            if len_bytes[0] == 0 {
                return Err(ChainError::MalformedTransaction(
                    "non-canonical RLP: leading zero in list length".to_string(),
                ));
            }
            let list_len = parse_be_usize(len_bytes)?;
            if list_len <= 55 {
                return Err(ChainError::MalformedTransaction(
                    "non-canonical RLP: list length <= 55 encoded as long list".to_string(),
                ));
            }
            let total_len = 1 + len_of_len + list_len;
            if input.len() < total_len {
                return Err(ChainError::MalformedTransaction(format!(
                    "unexpected end of RLP list: expected {list_len} bytes, got {}",
                    input.len() - (1 + len_of_len)
                )));
            }
            let mut list_payload = &input[1 + len_of_len..total_len];
            let mut items = Vec::new();
            while !list_payload.is_empty() {
                let (sub_item, rest) = Self::parse(list_payload)?;
                items.push(sub_item);
                list_payload = rest;
            }
            Ok((RlpItem::List(items), &input[total_len..]))
        }
    }

    /// Returns the borrowed string bytes if this is [`RlpItem::String`].
    pub fn as_string(&self) -> Result<&'a [u8], ChainError> {
        match self {
            Self::String(s) => Ok(s),
            Self::List(_) => Err(ChainError::MalformedTransaction(
                "expected RLP string, found list".to_string(),
            )),
        }
    }

    /// Returns the slice of sub-items if this is [`RlpItem::List`].
    pub fn as_list(&self) -> Result<&[RlpItem<'a>], ChainError> {
        match self {
            Self::List(l) => Ok(l),
            Self::String(_) => Err(ChainError::MalformedTransaction(
                "expected RLP list, found string".to_string(),
            )),
        }
    }
}

/// Encodes an arbitrary byte slice as an RLP string.
pub fn encode_rlp_string(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        vec![bytes[0]]
    } else if bytes.len() <= 55 {
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
        out
    } else {
        let len_bytes = usize_to_be_bytes(bytes.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(bytes);
        out
    }
}

/// Encodes pre-encoded RLP payloads as an RLP list.
pub fn encode_rlp_list(payloads: &[&[u8]]) -> Vec<u8> {
    let total_payload_len: usize = payloads.iter().map(|p| p.len()).sum();
    if total_payload_len <= 55 {
        let mut out = Vec::with_capacity(1 + total_payload_len);
        out.push(0xc0 + total_payload_len as u8);
        for p in payloads {
            out.extend_from_slice(p);
        }
        out
    } else {
        let len_bytes = usize_to_be_bytes(total_payload_len);
        let mut out = Vec::with_capacity(1 + len_bytes.len() + total_payload_len);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        for p in payloads {
            out.extend_from_slice(p);
        }
        out
    }
}

/// Encodes a `u64` integer into canonical RLP.
pub fn encode_rlp_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        encode_rlp_string(&[])
    } else {
        let be = n.to_be_bytes();
        let mut start = 0;
        while start < be.len() && be[start] == 0 {
            start += 1;
        }
        encode_rlp_string(&be[start..])
    }
}

/// Converts a `usize` into minimal big-endian bytes with no leading zeros.
fn usize_to_be_bytes(val: usize) -> Vec<u8> {
    let be = val.to_be_bytes();
    let mut start = 0;
    while start < be.len() && be[start] == 0 {
        start += 1;
    }
    if start == be.len() {
        vec![0]
    } else {
        be[start..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// Signs a 32-byte digest using a private key and returns `(sig_64, recovery_id, compressed_pubkey)`.
    fn sign_digest(privkey_bytes: &[u8; 32], digest: &[u8; 32]) -> ([u8; 64], u8, [u8; 33]) {
        let signing_key = SigningKey::from_bytes(privkey_bytes.into()).expect("valid signing key");
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(digest)
            .expect("sign prehash recoverable");
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: [u8; 33] = verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed pubkey");

        let mut sig_64 = [0u8; 64];
        sig_64.copy_from_slice(sig.to_bytes().as_ref());
        (sig_64, recid.to_byte(), pubkey_bytes)
    }

    #[test]
    fn test_eip55_checksum_official_vectors() {
        let cases = [
            (
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];

        for (raw_hex, expected_checksummed) in cases {
            let bytes = hex::decode(raw_hex).expect("valid hex");
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&bytes);
            let result = eip55_checksum(&addr);
            assert_eq!(result, expected_checksummed);
        }
    }

    #[test]
    fn test_eip1559_native_transfer_roundtrip() {
        let privkey: [u8; 32] =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap()
                .try_into()
                .unwrap();
        let signing_key = SigningKey::from_bytes((&privkey).into()).unwrap();
        let pubkey: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let signer_addr = pubkey_to_address(&pubkey).unwrap();

        let to_addr = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let chain_id = 1u64;
        let nonce = 5u64;
        let max_priority_fee = 1_000_000_000u64; // 1 Gwei
        let max_fee = 20_000_000_000u64; // 20 Gwei
        let gas_limit = 21000u64;
        let value = hex::decode("0de0b6b3a7640000").unwrap(); // 1 ETH (10^18 wei)
        let data = Vec::new();

        // Encode unsigned EIP-1559 payload: 0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])
        let enc_chain_id = encode_rlp_u64(chain_id);
        let enc_nonce = encode_rlp_u64(nonce);
        let enc_priority = encode_rlp_u64(max_priority_fee);
        let enc_fee = encode_rlp_u64(max_fee);
        let enc_gas = encode_rlp_u64(gas_limit);
        let enc_to = encode_rlp_string(&to_addr);
        let enc_value = encode_rlp_string(&value);
        let enc_data = encode_rlp_string(&data);
        let enc_access_list = encode_rlp_list(&[]);

        let rlp_list = encode_rlp_list(&[
            &enc_chain_id,
            &enc_nonce,
            &enc_priority,
            &enc_fee,
            &enc_gas,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_access_list,
        ]);

        let mut raw_tx = vec![EIP1559_TX_TYPE];
        raw_tx.extend_from_slice(&rlp_list);

        let keys = DerivedKeys::from(&pubkey);
        let decoded = decode_evm_tx("eip155:1", &raw_tx, &keys).expect("decode eip1559");

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].from, signer_addr);
        assert_eq!(
            decoded.parsed.transfers[0].to,
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            decoded.parsed.transfers[0].amount,
            "1000000000000000000"
        );
        assert_eq!(decoded.parsed.transfers[0].asset, "ETH");
        assert_eq!(decoded.parsed.fee.amount, "420000000000000"); // 21000 * 20 Gwei
        assert_eq!(decoded.parsed.fee.asset, "wei");
        assert_eq!(decoded.parsed.sequence.as_nonce(), Some(5));

        // Sign digest and verify recovery
        let digest = match decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (sig_64, recid, _) = sign_digest(&privkey, &digest);
        let recovery_ok =
            verify_signature_recovery(&digest, &sig_64, recid, &signer_addr).unwrap();
        assert!(recovery_ok);

        let formatted_sig =
            format_evm_signature(&sig_64, recid, chain_id, true, &signer_addr);
        assert_eq!(formatted_sig.v, recid as u64);
        assert_eq!(formatted_sig.y_parity, recid);
    }

    #[test]
    fn test_eip1559_erc20_transfer_polygon() {
        let privkey: [u8; 32] =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap()
                .try_into()
                .unwrap();
        let signing_key = SigningKey::from_bytes((&privkey).into()).unwrap();
        let pubkey: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let signer_addr = pubkey_to_address(&pubkey).unwrap();

        let token_contract =
            hex::decode("2791Bca1f2de4661ED88A30C99A7a9449Aa84174").unwrap(); // USDC on Polygon
        let recipient = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let chain_id = 137u64; // Polygon
        let nonce = 12u64;
        let max_priority_fee = 30_000_000_000u64; // 30 Gwei
        let max_fee = 50_000_000_000u64; // 50 Gwei
        let gas_limit = 65000u64;
        let value = Vec::new(); // 0 ETH

        // Construct ERC-20 transfer calldata: 0xa9059cbb + 32-byte recipient + 32-byte amount (500 USDC = 500 * 10^6 = 500000000)
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(&recipient);
        let amount_u256_be = {
            let mut arr = [0u8; 32];
            arr[28..32].copy_from_slice(&500_000_000u32.to_be_bytes());
            arr
        };
        calldata.extend_from_slice(&amount_u256_be);

        let enc_chain_id = encode_rlp_u64(chain_id);
        let enc_nonce = encode_rlp_u64(nonce);
        let enc_priority = encode_rlp_u64(max_priority_fee);
        let enc_fee = encode_rlp_u64(max_fee);
        let enc_gas = encode_rlp_u64(gas_limit);
        let enc_to = encode_rlp_string(&token_contract);
        let enc_value = encode_rlp_string(&value);
        let enc_data = encode_rlp_string(&calldata);
        let enc_access_list = encode_rlp_list(&[]);

        let rlp_list = encode_rlp_list(&[
            &enc_chain_id,
            &enc_nonce,
            &enc_priority,
            &enc_fee,
            &enc_gas,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_access_list,
        ]);

        let mut raw_tx = vec![EIP1559_TX_TYPE];
        raw_tx.extend_from_slice(&rlp_list);

        let keys = DerivedKeys::from(&pubkey);
        let decoded =
            decode_evm_tx("eip155:137", &raw_tx, &keys).expect("decode eip1559 erc20");

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].from, signer_addr);
        assert_eq!(
            decoded.parsed.transfers[0].to,
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(decoded.parsed.transfers[0].amount, "500000000");
        assert_eq!(
            decoded.parsed.transfers[0].asset,
            "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
        );
        assert_eq!(decoded.parsed.fee.amount, "3250000000000000"); // 65000 * 50 Gwei
        assert_eq!(decoded.parsed.sequence.as_nonce(), Some(12));
    }

    #[test]
    fn test_legacy_eip155_native_transfer() {
        let privkey: [u8; 32] =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap()
                .try_into()
                .unwrap();
        let signing_key = SigningKey::from_bytes((&privkey).into()).unwrap();
        let pubkey: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let signer_addr = pubkey_to_address(&pubkey).unwrap();

        let to_addr = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let chain_id = 1u64;
        let nonce = 3u64;
        let gas_price = 15_000_000_000u64; // 15 Gwei
        let gas_limit = 21000u64;
        let value = hex::decode("06f05b59d3b20000").unwrap(); // 0.5 ETH (5 * 10^17 wei)
        let data = Vec::new();

        // Encode legacy EIP-155 unsigned payload:
        // rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])
        let enc_nonce = encode_rlp_u64(nonce);
        let enc_gas_price = encode_rlp_u64(gas_price);
        let enc_gas_limit = encode_rlp_u64(gas_limit);
        let enc_to = encode_rlp_string(&to_addr);
        let enc_value = encode_rlp_string(&value);
        let enc_data = encode_rlp_string(&data);
        let enc_chain_id = encode_rlp_u64(chain_id);
        let enc_r = encode_rlp_string(&[]);
        let enc_s = encode_rlp_string(&[]);

        let raw_tx = encode_rlp_list(&[
            &enc_nonce,
            &enc_gas_price,
            &enc_gas_limit,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_chain_id,
            &enc_r,
            &enc_s,
        ]);

        let keys = DerivedKeys::from(&pubkey);
        let decoded =
            decode_evm_tx("eip155:1", &raw_tx, &keys).expect("decode legacy eip155");

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(
            decoded.parsed.transfers[0].amount,
            "500000000000000000"
        );
        assert_eq!(decoded.parsed.fee.amount, "315000000000000"); // 21000 * 15 Gwei
        assert_eq!(decoded.parsed.sequence.as_nonce(), Some(3));

        // Sign and verify EIP-155 signature formatting (v = chain_id * 2 + 35 + recid)
        let digest = match decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (sig_64, recid, _) = sign_digest(&privkey, &digest);
        let formatted = format_evm_signature(&sig_64, recid, chain_id, false, &signer_addr);
        let expected_v = chain_id * 2 + 35 + (recid as u64);
        assert_eq!(formatted.v, expected_v);
    }

    #[test]
    fn test_chain_mismatch_rejection() {
        let pubkey = [0x02u8; 33];
        let keys = DerivedKeys::from(&pubkey);

        let enc_chain_id = encode_rlp_u64(1); // Encoded for chain ID 1
        let enc_nonce = encode_rlp_u64(0);
        let enc_priority = encode_rlp_u64(1);
        let enc_fee = encode_rlp_u64(1);
        let enc_gas = encode_rlp_u64(21000);
        let enc_to = encode_rlp_string(&[0x11u8; 20]);
        let enc_value = encode_rlp_string(&[]);
        let enc_data = encode_rlp_string(&[]);
        let enc_access = encode_rlp_list(&[]);

        let rlp_list = encode_rlp_list(&[
            &enc_chain_id,
            &enc_nonce,
            &enc_priority,
            &enc_fee,
            &enc_gas,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_access,
        ]);
        let mut raw_tx = vec![EIP1559_TX_TYPE];
        raw_tx.extend_from_slice(&rlp_list);

        // Submit for eip155:137 (Polygon) -> must reject with ChainMismatch
        let err = decode_evm_tx("eip155:137", &raw_tx, &keys).unwrap_err();
        match err {
            ChainError::ChainMismatch { expected, actual } => {
                assert_eq!(expected, "eip155:137");
                assert_eq!(actual, "eip155:1");
            }
            other => panic!("expected ChainMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_contract_creation_rejected() {
        let pubkey = [0x02u8; 33];
        let keys = DerivedKeys::from(&pubkey);

        let enc_chain_id = encode_rlp_u64(1);
        let enc_nonce = encode_rlp_u64(0);
        let enc_priority = encode_rlp_u64(1);
        let enc_fee = encode_rlp_u64(1);
        let enc_gas = encode_rlp_u64(21000);
        let enc_to = encode_rlp_string(&[]); // Empty to -> contract creation
        let enc_value = encode_rlp_string(&[]);
        let enc_data = encode_rlp_string(&[]);
        let enc_access = encode_rlp_list(&[]);

        let rlp_list = encode_rlp_list(&[
            &enc_chain_id,
            &enc_nonce,
            &enc_priority,
            &enc_fee,
            &enc_gas,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_access,
        ]);
        let mut raw_tx = vec![EIP1559_TX_TYPE];
        raw_tx.extend_from_slice(&rlp_list);

        let err = decode_evm_tx("eip155:1", &raw_tx, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
    }

    #[test]
    fn test_unknown_contract_calldata_rejected() {
        let pubkey = [0x02u8; 33];
        let keys = DerivedKeys::from(&pubkey);

        let enc_chain_id = encode_rlp_u64(1);
        let enc_nonce = encode_rlp_u64(0);
        let enc_priority = encode_rlp_u64(1);
        let enc_fee = encode_rlp_u64(1);
        let enc_gas = encode_rlp_u64(50000);
        let enc_to = encode_rlp_string(&[0x11u8; 20]);
        let enc_value = encode_rlp_string(&[]);
        let enc_data = encode_rlp_string(&[0x12, 0x34, 0x56, 0x78]); // Arbitrary selector
        let enc_access = encode_rlp_list(&[]);

        let rlp_list = encode_rlp_list(&[
            &enc_chain_id,
            &enc_nonce,
            &enc_priority,
            &enc_fee,
            &enc_gas,
            &enc_to,
            &enc_value,
            &enc_data,
            &enc_access,
        ]);
        let mut raw_tx = vec![EIP1559_TX_TYPE];
        raw_tx.extend_from_slice(&rlp_list);

        let err = decode_evm_tx("eip155:1", &raw_tx, &keys).unwrap_err();
        assert_eq!(err.reason_code(), "unsupported_transaction");
    }

    #[test]
    fn test_generate_and_verify_evm_reference_vectors() {
        use std::fs;
        use std::path::Path;

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let path = crate::derive::DerivationPath::parse_str("m/44'/60'/0'/0/0").unwrap();
        let derived = crate::derive::derive_bip32(&seed, &path).unwrap();
        let privkey: [u8; 32] = *derived.private_key;
        let pubkey: [u8; 33] = derived.public_key;
        let signer_addr = pubkey_to_address(&pubkey).unwrap();
        let recipient = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();

        // --- Vector 1: EIP-1559 Native Transfer (Ethereum Mainnet) ---
        let v1_chain = "eip155:1";
        let v1_chain_id = 1u64;
        let v1_nonce = 5u64;
        let v1_priority_fee = 1_000_000_000u64;
        let v1_max_fee = 20_000_000_000u64;
        let v1_gas_limit = 21000u64;
        let v1_value = hex::decode("0de0b6b3a7640000").unwrap(); // 1 ETH
        let v1_data = Vec::new();

        let v1_raw = {
            let enc_chain_id = encode_rlp_u64(v1_chain_id);
            let enc_nonce = encode_rlp_u64(v1_nonce);
            let enc_priority = encode_rlp_u64(v1_priority_fee);
            let enc_fee = encode_rlp_u64(v1_max_fee);
            let enc_gas = encode_rlp_u64(v1_gas_limit);
            let enc_to = encode_rlp_string(&recipient);
            let enc_value = encode_rlp_string(&v1_value);
            let enc_data = encode_rlp_string(&v1_data);
            let enc_access = encode_rlp_list(&[]);
            let list = encode_rlp_list(&[
                &enc_chain_id,
                &enc_nonce,
                &enc_priority,
                &enc_fee,
                &enc_gas,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_access,
            ]);
            let mut raw = vec![EIP1559_TX_TYPE];
            raw.extend_from_slice(&list);
            raw
        };

        let v1_decoded =
            decode_evm_tx(v1_chain, &v1_raw, &DerivedKeys::from(&pubkey)).unwrap();
        let v1_digest = match v1_decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (v1_sig64, v1_recid, _) = sign_digest(&privkey, &v1_digest);
        let v1_sig = format_evm_signature(&v1_sig64, v1_recid, v1_chain_id, true, &signer_addr);

        // --- Vector 2: EIP-1559 ERC-20 Transfer (Polygon) ---
        let v2_chain = "eip155:137";
        let v2_chain_id = 137u64;
        let v2_token_contract =
            hex::decode("2791Bca1f2de4661ED88A30C99A7a9449Aa84174").unwrap();
        let v2_nonce = 12u64;
        let v2_priority_fee = 30_000_000_000u64;
        let v2_max_fee = 50_000_000_000u64;
        let v2_gas_limit = 65000u64;
        let v2_value = Vec::new(); // 0 ETH

        let mut v2_calldata = Vec::with_capacity(68);
        v2_calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
        v2_calldata.extend_from_slice(&[0u8; 12]);
        v2_calldata.extend_from_slice(&recipient);
        let mut v2_amount_bytes = [0u8; 32];
        v2_amount_bytes[28..32].copy_from_slice(&500_000_000u32.to_be_bytes()); // 500 USDC
        v2_calldata.extend_from_slice(&v2_amount_bytes);

        let v2_raw = {
            let enc_chain_id = encode_rlp_u64(v2_chain_id);
            let enc_nonce = encode_rlp_u64(v2_nonce);
            let enc_priority = encode_rlp_u64(v2_priority_fee);
            let enc_fee = encode_rlp_u64(v2_max_fee);
            let enc_gas = encode_rlp_u64(v2_gas_limit);
            let enc_to = encode_rlp_string(&v2_token_contract);
            let enc_value = encode_rlp_string(&v2_value);
            let enc_data = encode_rlp_string(&v2_calldata);
            let enc_access = encode_rlp_list(&[]);
            let list = encode_rlp_list(&[
                &enc_chain_id,
                &enc_nonce,
                &enc_priority,
                &enc_fee,
                &enc_gas,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_access,
            ]);
            let mut raw = vec![EIP1559_TX_TYPE];
            raw.extend_from_slice(&list);
            raw
        };

        let v2_decoded =
            decode_evm_tx(v2_chain, &v2_raw, &DerivedKeys::from(&pubkey)).unwrap();
        let v2_digest = match v2_decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (v2_sig64, v2_recid, _) = sign_digest(&privkey, &v2_digest);
        let v2_sig = format_evm_signature(&v2_sig64, v2_recid, v2_chain_id, true, &signer_addr);

        // --- Vector 3: Legacy EIP-155 Native Transfer (Ethereum Mainnet) ---
        let v3_chain = "eip155:1";
        let v3_chain_id = 1u64;
        let v3_nonce = 3u64;
        let v3_gas_price = 15_000_000_000u64;
        let v3_gas_limit = 21000u64;
        let v3_value = hex::decode("06f05b59d3b20000").unwrap(); // 0.5 ETH
        let v3_data = Vec::new();

        let v3_raw = {
            let enc_nonce = encode_rlp_u64(v3_nonce);
            let enc_gas_price = encode_rlp_u64(v3_gas_price);
            let enc_gas_limit = encode_rlp_u64(v3_gas_limit);
            let enc_to = encode_rlp_string(&recipient);
            let enc_value = encode_rlp_string(&v3_value);
            let enc_data = encode_rlp_string(&v3_data);
            let enc_chain_id = encode_rlp_u64(v3_chain_id);
            let enc_r = encode_rlp_string(&[]);
            let enc_s = encode_rlp_string(&[]);
            encode_rlp_list(&[
                &enc_nonce,
                &enc_gas_price,
                &enc_gas_limit,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_chain_id,
                &enc_r,
                &enc_s,
            ])
        };

        let v3_decoded =
            decode_evm_tx(v3_chain, &v3_raw, &DerivedKeys::from(&pubkey)).unwrap();
        let v3_digest = match v3_decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (v3_sig64, v3_recid, _) = sign_digest(&privkey, &v3_digest);
        let v3_sig = format_evm_signature(&v3_sig64, v3_recid, v3_chain_id, false, &signer_addr);

        // --- Vector 4: Legacy EIP-155 ERC-20 Transfer (BNB Smart Chain) ---
        let v4_chain = "eip155:56";
        let v4_chain_id = 56u64;
        let v4_token_contract =
            hex::decode("55d398326f99059fF775485246999027B3197955").unwrap(); // USDT on BSC
        let v4_nonce = 7u64;
        let v4_gas_price = 5_000_000_000u64;
        let v4_gas_limit = 60000u64;
        let v4_value = Vec::new(); // 0 BNB

        let mut v4_calldata = Vec::with_capacity(68);
        v4_calldata.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
        v4_calldata.extend_from_slice(&[0u8; 12]);
        let recipient_v4 = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        v4_calldata.extend_from_slice(&recipient_v4);
        // 100 USDT (18 decimals): 100 * 10^18 = 0x056bc75e2d63100000
        let v4_amount_bytes = {
            let mut arr = [0u8; 32];
            let val = hex::decode("056bc75e2d63100000").unwrap();
            arr[32 - val.len()..].copy_from_slice(&val);
            arr
        };
        v4_calldata.extend_from_slice(&v4_amount_bytes);

        let v4_raw = {
            let enc_nonce = encode_rlp_u64(v4_nonce);
            let enc_gas_price = encode_rlp_u64(v4_gas_price);
            let enc_gas_limit = encode_rlp_u64(v4_gas_limit);
            let enc_to = encode_rlp_string(&v4_token_contract);
            let enc_value = encode_rlp_string(&v4_value);
            let enc_data = encode_rlp_string(&v4_calldata);
            let enc_chain_id = encode_rlp_u64(v4_chain_id);
            let enc_r = encode_rlp_string(&[]);
            let enc_s = encode_rlp_string(&[]);
            encode_rlp_list(&[
                &enc_nonce,
                &enc_gas_price,
                &enc_gas_limit,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_chain_id,
                &enc_r,
                &enc_s,
            ])
        };

        let v4_decoded =
            decode_evm_tx(v4_chain, &v4_raw, &DerivedKeys::from(&pubkey)).unwrap();
        let v4_digest = match v4_decoded.signing_input {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let (v4_sig64, v4_recid, _) = sign_digest(&privkey, &v4_digest);
        let v4_sig = format_evm_signature(&v4_sig64, v4_recid, v4_chain_id, false, &signer_addr);

        // --- Negative vectors ---
        // Vector 5: Chain Mismatch (encoded for 1, requested eip155:137)
        let v5_raw = v1_raw.clone();

        // Vector 6: Unknown Calldata
        let v6_raw = {
            let enc_chain_id = encode_rlp_u64(1);
            let enc_nonce = encode_rlp_u64(0);
            let enc_priority = encode_rlp_u64(1_000_000_000);
            let enc_fee = encode_rlp_u64(20_000_000_000);
            let enc_gas = encode_rlp_u64(100000);
            let enc_to = encode_rlp_string(&recipient);
            let enc_value = encode_rlp_string(&[]);
            let enc_data = encode_rlp_string(&hex::decode("38ed1739000000000000000000000000").unwrap()); // Unknown selector
            let enc_access = encode_rlp_list(&[]);
            let list = encode_rlp_list(&[
                &enc_chain_id,
                &enc_nonce,
                &enc_priority,
                &enc_fee,
                &enc_gas,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_access,
            ]);
            let mut raw = vec![EIP1559_TX_TYPE];
            raw.extend_from_slice(&list);
            raw
        };

        // Vector 7: Contract Creation (to empty)
        let v7_raw = {
            let enc_chain_id = encode_rlp_u64(1);
            let enc_nonce = encode_rlp_u64(0);
            let enc_priority = encode_rlp_u64(1_000_000_000);
            let enc_fee = encode_rlp_u64(20_000_000_000);
            let enc_gas = encode_rlp_u64(100000);
            let enc_to = encode_rlp_string(&[]); // Empty
            let enc_value = encode_rlp_string(&[]);
            let enc_data = encode_rlp_string(&[]);
            let enc_access = encode_rlp_list(&[]);
            let list = encode_rlp_list(&[
                &enc_chain_id,
                &enc_nonce,
                &enc_priority,
                &enc_fee,
                &enc_gas,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_access,
            ]);
            let mut raw = vec![EIP1559_TX_TYPE];
            raw.extend_from_slice(&list);
            raw
        };

        // Vector 8: ERC-20 with non-zero native value
        let v8_raw = {
            let enc_chain_id = encode_rlp_u64(137);
            let enc_nonce = encode_rlp_u64(0);
            let enc_priority = encode_rlp_u64(1_000_000_000);
            let enc_fee = encode_rlp_u64(20_000_000_000);
            let enc_gas = encode_rlp_u64(65000);
            let enc_to = encode_rlp_string(&v2_token_contract);
            let enc_value = encode_rlp_string(&hex::decode("0de0b6b3a7640000").unwrap()); // Non-zero value!
            let enc_data = encode_rlp_string(&v2_calldata);
            let enc_access = encode_rlp_list(&[]);
            let list = encode_rlp_list(&[
                &enc_chain_id,
                &enc_nonce,
                &enc_priority,
                &enc_fee,
                &enc_gas,
                &enc_to,
                &enc_value,
                &enc_data,
                &enc_access,
            ]);
            let mut raw = vec![EIP1559_TX_TYPE];
            raw.extend_from_slice(&list);
            raw
        };

        // Vector 9: Malformed RLP
        let v9_raw = vec![EIP1559_TX_TYPE, 0xf8, 0x10, 0x01, 0x02];

        // Assemble JSON
        let vectors_json = serde_json::json!([
            {
                "id": "eip1559_native_transfer",
                "description": "EIP-1559 Type 2 native ETH transfer on Ethereum Mainnet",
                "chain": v1_chain,
                "path": "m/44'/60'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v1_raw)),
                "signing_input": format!("0x{}", hex::encode(v1_digest)),
                "parsed": v1_decoded.parsed,
                "result": v1_sig
            },
            {
                "id": "eip1559_erc20_transfer",
                "description": "EIP-1559 Type 2 ERC-20 transfer of 500 USDC on Polygon",
                "chain": v2_chain,
                "path": "m/44'/60'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v2_raw)),
                "signing_input": format!("0x{}", hex::encode(v2_digest)),
                "parsed": v2_decoded.parsed,
                "result": v2_sig
            },
            {
                "id": "legacy_eip155_native_transfer",
                "description": "Legacy EIP-155 native ETH transfer of 0.5 ETH on Ethereum Mainnet",
                "chain": v3_chain,
                "path": "m/44'/60'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v3_raw)),
                "signing_input": format!("0x{}", hex::encode(v3_digest)),
                "parsed": v3_decoded.parsed,
                "result": v3_sig
            },
            {
                "id": "legacy_eip155_erc20_transfer",
                "description": "Legacy EIP-155 ERC-20 transfer of 100 USDT on BNB Smart Chain",
                "chain": v4_chain,
                "path": "m/44'/60'/0'/0/0",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v4_raw)),
                "signing_input": format!("0x{}", hex::encode(v4_digest)),
                "parsed": v4_decoded.parsed,
                "result": v4_sig
            },
            {
                "id": "negative_chain_mismatch",
                "description": "Transaction encoded for chain ID 1 submitted for eip155:137",
                "chain": "eip155:137",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "raw_tx": format!("0x{}", hex::encode(&v5_raw)),
                "expected_error": "chain_mismatch"
            },
            {
                "id": "negative_unknown_calldata",
                "description": "Transaction with arbitrary unknown contract method selector",
                "chain": "eip155:1",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "raw_tx": format!("0x{}", hex::encode(&v6_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_contract_creation",
                "description": "Contract creation transaction with empty 'to' address",
                "chain": "eip155:1",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "raw_tx": format!("0x{}", hex::encode(&v7_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_erc20_nonzero_native_value",
                "description": "ERC-20 transfer with non-zero native ETH value",
                "chain": "eip155:137",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "raw_tx": format!("0x{}", hex::encode(&v8_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_malformed_rlp",
                "description": "Truncated / invalid RLP transaction payload",
                "chain": "eip155:1",
                "public_key": format!("0x{}", hex::encode(pubkey)),
                "raw_tx": format!("0x{}", hex::encode(&v9_raw)),
                "expected_error": "unsupported_transaction"
            }
        ]);

        let vectors_pretty =
            serde_json::to_string_pretty(&vectors_json).expect("pretty json");

        // Locate vectors/tx_evm.json path relative to repository
        let candidate_paths = [
            Path::new("vectors/tx_evm.json"),
            Path::new("../vectors/tx_evm.json"),
            Path::new("../../vectors/tx_evm.json"),
        ];
        let mut target_path = None;
        for p in candidate_paths {
            if let Some(parent) = p.parent() {
                if parent.exists() && parent.is_dir() {
                    target_path = Some(p);
                    break;
                }
            }
        }
        if let Some(path) = target_path {
            fs::write(path, vectors_pretty.as_bytes()).expect("write vectors/tx_evm.json");
            println!("Successfully wrote {}", path.display());
        }

        // Now verify every vector loaded back from the JSON!
        let parsed_vectors: serde_json::Value =
            serde_json::from_str(&vectors_pretty).expect("must parse vector json");
        let list = parsed_vectors.as_array().expect("array of vectors");
        assert_eq!(list.len(), 9);

        for v in list {
            let id = v["id"].as_str().unwrap();
            let chain = v["chain"].as_str().unwrap();
            let raw_tx_hex = v["raw_tx"].as_str().unwrap().trim_start_matches("0x");
            let raw_tx_bytes = hex::decode(raw_tx_hex).unwrap();
            let pk_hex = v["public_key"].as_str().unwrap().trim_start_matches("0x");
            let pk_bytes = hex::decode(pk_hex).unwrap();
            let keys = DerivedKeys::from(pk_bytes.as_slice());

            if let Some(expected_err) = v.get("expected_error").and_then(|e| e.as_str()) {
                let err = decode_evm_tx(chain, &raw_tx_bytes, &keys).unwrap_err();
                assert_eq!(
                    err.reason_code(),
                    expected_err,
                    "vector {id} error reason mismatch"
                );
            } else {
                let decoded = decode_evm_tx(chain, &raw_tx_bytes, &keys).unwrap();
                let expected_signing_input =
                    v["signing_input"].as_str().unwrap().trim_start_matches("0x");
                let actual_digest = match decoded.signing_input {
                    SigningInput::Digest32(d) => hex::encode(d),
                    _ => panic!("expected Digest32"),
                };
                assert_eq!(
                    actual_digest, expected_signing_input,
                    "vector {id} signing input mismatch"
                );

                let expected_parsed: ParsedTx =
                    serde_json::from_value(v["parsed"].clone()).unwrap();
                assert_eq!(decoded.parsed, expected_parsed, "vector {id} parsed mismatch");

                let expected_signer = v["signer_address"].as_str().unwrap();
                assert_eq!(
                    decoded.signer_address, expected_signer,
                    "vector {id} signer address mismatch"
                );

                let result = &v["result"];
                let r_hex = result["r"].as_str().unwrap().trim_start_matches("0x");
                let s_hex = result["s"].as_str().unwrap().trim_start_matches("0x");
                let y_parity = result["y_parity"].as_u64().unwrap() as u8;

                let mut sig_64 = [0u8; 64];
                sig_64[..32].copy_from_slice(&hex::decode(r_hex).unwrap());
                sig_64[32..].copy_from_slice(&hex::decode(s_hex).unwrap());

                let digest_32: [u8; 32] = hex::decode(actual_digest).unwrap().try_into().unwrap();
                let rec_ok =
                    verify_signature_recovery(&digest_32, &sig_64, y_parity, expected_signer)
                        .unwrap();
                assert!(rec_ok, "vector {id} recovery verification failed");
            }
        }
    }

    fn get_vectors_path() -> std::path::PathBuf {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let p1 = manifest_dir.parent().unwrap().join("vectors").join("tx_evm.json");
        if p1.exists() {
            return p1;
        }
        let p2 = manifest_dir.join("vectors").join("tx_evm.json");
        if p2.exists() {
            return p2;
        }
        std::path::PathBuf::from("vectors/tx_evm.json")
    }

    #[test]
    fn test_evm_reference_vectors_from_file() {
        let path = get_vectors_path();
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read vectors from {}: {e}", path.display()));
        let list: Vec<serde_json::Value> =
            serde_json::from_str(&content).expect("valid vector json");
        assert!(list.len() >= 9, "expected at least 9 vectors");

        for v in &list {
            let id = v["id"].as_str().unwrap();
            let chain = v["chain"].as_str().unwrap();
            let raw_tx_hex = v["raw_tx"].as_str().unwrap().trim_start_matches("0x");
            let raw_tx_bytes = hex::decode(raw_tx_hex).unwrap();
            let pk_hex = v["public_key"].as_str().unwrap().trim_start_matches("0x");
            let pk_bytes = hex::decode(pk_hex).unwrap();
            let keys = DerivedKeys::from(pk_bytes.as_slice());

            if let Some(expected_err) = v.get("expected_error").and_then(|e| e.as_str()) {
                let err = decode_evm_tx(chain, &raw_tx_bytes, &keys).unwrap_err();
                assert_eq!(
                    err.reason_code(),
                    expected_err,
                    "vector {id} error reason mismatch"
                );
            } else {
                let decoded = decode_evm_tx(chain, &raw_tx_bytes, &keys).unwrap();
                let expected_signing_input =
                    v["signing_input"].as_str().unwrap().trim_start_matches("0x");
                let actual_digest = match decoded.signing_input {
                    SigningInput::Digest32(d) => hex::encode(d),
                    _ => panic!("expected Digest32"),
                };
                assert_eq!(
                    actual_digest, expected_signing_input,
                    "vector {id} signing input mismatch"
                );

                let expected_parsed: ParsedTx =
                    serde_json::from_value(v["parsed"].clone()).unwrap();
                assert_eq!(decoded.parsed, expected_parsed, "vector {id} parsed mismatch");

                let expected_signer = v["signer_address"].as_str().unwrap();
                assert_eq!(
                    decoded.signer_address, expected_signer,
                    "vector {id} signer address mismatch"
                );

                let result = &v["result"];
                let r_hex = result["r"].as_str().unwrap().trim_start_matches("0x");
                let s_hex = result["s"].as_str().unwrap().trim_start_matches("0x");
                let y_parity = result["y_parity"].as_u64().unwrap() as u8;

                let mut sig_64 = [0u8; 64];
                sig_64[..32].copy_from_slice(&hex::decode(r_hex).unwrap());
                sig_64[32..].copy_from_slice(&hex::decode(s_hex).unwrap());

                let digest_32: [u8; 32] = hex::decode(actual_digest).unwrap().try_into().unwrap();
                let rec_ok =
                    verify_signature_recovery(&digest_32, &sig_64, y_parity, expected_signer)
                        .unwrap();
                assert!(rec_ok, "vector {id} recovery verification failed");
            }
        }
    }
}
