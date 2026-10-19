//! Solana transaction and legacy message codec (Task 15, Section 5 of `Specs.md`).
//!
//! Implements decoding, summary extraction, and signing input preparation for:
//! - Legacy serialized Solana messages made exclusively of System Program
//!   (`11111111111111111111111111111111`) `Transfer` (instruction index `2`, `u64` lamports) instructions.
//! - Unsigned wire transactions containing a legacy message (prefixed with signature count / dummy signatures).
//!
//! Enforces:
//! - Rejection of versioned (v0) messages with `unsupported_transaction`.
//! - Rejection of non-System programs or non-Transfer System instructions with `unsupported_transaction`.
//! - Derived 32-byte Ed25519 public key verification against fee payer and transfer source signer accounts.
//! - Unified [`ParsedTx`] summary (`transfers` in lamports/SOL, `recent_blockhash` as sequence, `fee` in lamports, Base58 `signer_address`).
//! - Returns raw serialized message bytes as [`SigningInput::Message`] and formats 64-byte Ed25519 signatures.

use serde::{Deserialize, Serialize};

use crate::backend::generic::crypto::verify_ed25519_signature;
use crate::chains::{
    parse_caip2, ChainCodec, ChainError, DecodedTx, DerivedKeys, FeeSummary, ParsedTx,
    SequenceField, SigningInput, Transfer,
};

/// 32-byte System Program identifier: all zeroes (`[0u8; 32]`).
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// System Program Base58 address: 32 ones.
pub const SYSTEM_PROGRAM_ADDRESS: &str = "11111111111111111111111111111111";

/// System Program `Transfer` instruction index (`2` as little-endian `u32`).
pub const SYSTEM_TRANSFER_INDEX: u32 = 2;

/// Standard Solana lamports per SOL: `1_000_000_000` (10^9).
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Standard Solana fee per signature in lamports: `5_000`.
pub const DEFAULT_LAMPORTS_PER_SIGNATURE: u64 = 5_000;

/// Byte length of an Ed25519 public key (`32` bytes).
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Byte length of an Ed25519 signature (`64` bytes).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Solana message header specifying account signature and mutability permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Number of required signatures for the transaction.
    pub num_required_signatures: u8,
    /// Number of readonly accounts that require signatures.
    pub num_readonly_signed_accounts: u8,
    /// Number of readonly accounts that do not require signatures.
    pub num_readonly_unsigned_accounts: u8,
}

/// A compiled instruction within a serialized Solana message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledInstruction {
    /// Index into `account_keys` pointing to the program to execute.
    pub program_id_index: u8,
    /// Indices into `account_keys` passed to the instruction.
    pub accounts: Vec<u8>,
    /// Raw instruction data bytes.
    pub data: Vec<u8>,
}

/// Deserialized Solana legacy message structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaMessage {
    /// Account permissions header.
    pub header: MessageHeader,
    /// Account public keys ordered by signers (writable, readonly) then non-signers (writable, readonly).
    pub account_keys: Vec<[u8; 32]>,
    /// Recent blockhash for transaction expiration and deduplication.
    pub recent_blockhash: [u8; 32],
    /// Compiled instructions to execute atomically.
    pub instructions: Vec<CompiledInstruction>,
}

/// Formatted Solana signature output carrying Base58, hex, and signer address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaSignature {
    /// 64-byte Ed25519 signature encoded in Base58 (standard Solana RPC format).
    pub signature: String,
    /// 64-byte Ed25519 signature encoded as `0x`-prefixed 128-character hex.
    pub signature_hex: String,
    /// Base58-encoded signer address matching the derived key.
    pub signer_address: String,
}

/// Formats a 64-byte Ed25519 signature into a [`SolanaSignature`].
pub fn format_solana_signature(sig_64: &[u8; ED25519_SIGNATURE_LEN], signer_address: &str) -> SolanaSignature {
    SolanaSignature {
        signature: bs58::encode(sig_64).into_string(),
        signature_hex: format!("0x{}", hex::encode(sig_64)),
        signer_address: signer_address.to_string(),
    }
}

/// Verifies a 64-byte Ed25519 signature over `message` using the 32-byte Ed25519 public key.
pub fn verify_solana_sig(
    pubkey: &[u8; ED25519_PUBKEY_LEN],
    message: &[u8],
    sig_64: &[u8; ED25519_SIGNATURE_LEN],
) -> Result<(), ChainError> {
    verify_ed25519_signature(pubkey, message, sig_64)
        .map_err(|e| ChainError::Crypto(format!("solana signature verification failed: {e}")))
}

/// Decodes a Solana compact-u16 / short-vec encoded integer from `bytes`.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn decode_compact_u16(bytes: &[u8]) -> Result<(u16, usize), ChainError> {
    let mut val: u64 = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 3 {
            return Err(ChainError::MalformedTransaction(
                "compact-u16 exceeds 3 bytes".to_string(),
            ));
        }
        val |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            if val > u16::MAX as u64 {
                return Err(ChainError::MalformedTransaction(
                    "compact-u16 value exceeds u16::MAX".to_string(),
                ));
            }
            return Ok((val as u16, i + 1));
        }
    }
    Err(ChainError::MalformedTransaction(
        "unexpected EOF decoding compact-u16".to_string(),
    ))
}

/// Encodes a `u16` value into Solana compact-u16 / short-vec format.
pub fn encode_compact_u16(mut val: u16, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
            buf.push(byte);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Serializes a [`SolanaMessage`] into canonical legacy message bytes.
pub fn serialize_solana_message(msg: &SolanaMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(msg.header.num_required_signatures);
    buf.push(msg.header.num_readonly_signed_accounts);
    buf.push(msg.header.num_readonly_unsigned_accounts);

    encode_compact_u16(msg.account_keys.len() as u16, &mut buf);
    for key in &msg.account_keys {
        buf.extend_from_slice(key);
    }

    buf.extend_from_slice(&msg.recent_blockhash);

    encode_compact_u16(msg.instructions.len() as u16, &mut buf);
    for inst in &msg.instructions {
        buf.push(inst.program_id_index);
        encode_compact_u16(inst.accounts.len() as u16, &mut buf);
        buf.extend_from_slice(&inst.accounts);
        encode_compact_u16(inst.data.len() as u16, &mut buf);
        buf.extend_from_slice(&inst.data);
    }

    buf
}

/// Assembles a signed Solana wire transaction from message bytes and 64-byte signatures.
pub fn assemble_signed_transaction(message_bytes: &[u8], signatures: &[[u8; ED25519_SIGNATURE_LEN]]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_compact_u16(signatures.len() as u16, &mut buf);
    for sig in signatures {
        buf.extend_from_slice(sig);
    }
    buf.extend_from_slice(message_bytes);
    buf
}

/// Assembles an unsigned Solana wire transaction with dummy zeroed signatures.
pub fn assemble_unsigned_wire_transaction(message_bytes: &[u8], num_signatures: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_compact_u16(num_signatures as u16, &mut buf);
    for _ in 0..num_signatures {
        buf.extend_from_slice(&[0u8; ED25519_SIGNATURE_LEN]);
    }
    buf.extend_from_slice(message_bytes);
    buf
}

/// Parses raw legacy serialized Solana message bytes into a [`SolanaMessage`].
pub fn parse_solana_message(bytes: &[u8]) -> Result<SolanaMessage, ChainError> {
    if bytes.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "empty message payload".to_string(),
        ));
    }

    // Version check: v0 versioned messages have the high bit set on the first byte.
    if bytes[0] & 0x80 != 0 {
        return Err(ChainError::UnsupportedTransaction(
            "versioned messages (v0) are unsupported".to_string(),
        ));
    }

    if bytes.len() < 3 {
        return Err(ChainError::MalformedTransaction(
            "message too short for header (minimum 3 bytes)".to_string(),
        ));
    }

    let num_required_signatures = bytes[0];
    if num_required_signatures == 0 {
        return Err(ChainError::UnsupportedTransaction(
            "message header specifies 0 required signatures".to_string(),
        ));
    }

    let num_readonly_signed_accounts = bytes[1];
    let num_readonly_unsigned_accounts = bytes[2];
    let mut offset = 3;

    if num_readonly_signed_accounts >= num_required_signatures {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid header: readonly signed accounts ({num_readonly_signed_accounts}) >= required signatures ({num_required_signatures})"
        )));
    }

    // 2. Account Keys
    let (num_accounts, len_len) = decode_compact_u16(&bytes[offset..])?;
    offset += len_len;

    if (num_accounts as usize) < (num_required_signatures as usize) {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid account keys count ({num_accounts}) < required signatures ({num_required_signatures})"
        )));
    }

    let total_account_bytes = (num_accounts as usize)
        .checked_mul(32)
        .ok_or_else(|| ChainError::MalformedTransaction("account keys length overflow".to_string()))?;

    if bytes.len() < offset + total_account_bytes {
        return Err(ChainError::MalformedTransaction(format!(
            "truncated account keys: expected {total_account_bytes} bytes, available {}",
            bytes.len().saturating_sub(offset)
        )));
    }

    let mut account_keys = Vec::with_capacity(num_accounts as usize);
    for _ in 0..num_accounts {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[offset..offset + 32]);
        account_keys.push(key);
        offset += 32;
    }

    // 3. Recent Blockhash (32 bytes)
    if bytes.len() < offset + 32 {
        return Err(ChainError::MalformedTransaction(
            "truncated message: missing 32-byte recent blockhash".to_string(),
        ));
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    // 4. Instructions
    let (num_instructions, inst_len_len) = decode_compact_u16(&bytes[offset..])?;
    offset += inst_len_len;

    if num_instructions == 0 {
        return Err(ChainError::UnsupportedTransaction(
            "transaction contains no instructions".to_string(),
        ));
    }

    let mut instructions = Vec::with_capacity(num_instructions as usize);
    for i in 0..num_instructions {
        if bytes.len() <= offset {
            return Err(ChainError::MalformedTransaction(format!(
                "unexpected EOF before instruction {i}"
            )));
        }
        let program_id_index = bytes[offset];
        offset += 1;
        if (program_id_index as usize) >= account_keys.len() {
            return Err(ChainError::MalformedTransaction(format!(
                "instruction {i} program_id_index {program_id_index} out of bounds"
            )));
        }

        // Instruction accounts
        let (num_inst_accounts, acc_len_len) = decode_compact_u16(&bytes[offset..])?;
        offset += acc_len_len;
        if bytes.len() < offset + (num_inst_accounts as usize) {
            return Err(ChainError::MalformedTransaction(format!(
                "truncated accounts for instruction {i}"
            )));
        }
        let inst_accounts = bytes[offset..offset + (num_inst_accounts as usize)].to_vec();
        offset += num_inst_accounts as usize;

        for &acc_idx in &inst_accounts {
            if (acc_idx as usize) >= account_keys.len() {
                return Err(ChainError::MalformedTransaction(format!(
                    "instruction {i} account index {acc_idx} out of bounds"
                )));
            }
        }

        // Instruction data
        let (data_len, data_len_len) = decode_compact_u16(&bytes[offset..])?;
        offset += data_len_len;
        if bytes.len() < offset + (data_len as usize) {
            return Err(ChainError::MalformedTransaction(format!(
                "truncated data for instruction {i}"
            )));
        }
        let inst_data = bytes[offset..offset + (data_len as usize)].to_vec();
        offset += data_len as usize;

        instructions.push(CompiledInstruction {
            program_id_index,
            accounts: inst_accounts,
            data: inst_data,
        });
    }

    // 5. Ensure no trailing bytes
    if offset != bytes.len() {
        return Err(ChainError::MalformedTransaction(format!(
            "unconsumed trailing bytes in message: {} extra bytes",
            bytes.len() - offset
        )));
    }

    Ok(SolanaMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        account_keys,
        recent_blockhash,
        instructions,
    })
}

/// Extracts the underlying serialized message bytes and parsed [`SolanaMessage`]
/// from either:
/// 1. An unsigned wire transaction with dummy signatures matching `num_required_signatures`.
/// 2. A wire transaction with an empty signature array (`0x00`).
/// 3. A raw serialized legacy message directly.
pub fn extract_solana_message(raw_tx_bytes: &[u8]) -> Result<(&[u8], SolanaMessage), ChainError> {
    if raw_tx_bytes.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "empty transaction payload".to_string(),
        ));
    }

    // Immediate versioned v0 check on the first byte
    if raw_tx_bytes[0] & 0x80 != 0 {
        return Err(ChainError::UnsupportedTransaction(
            "versioned messages (v0) are unsupported".to_string(),
        ));
    }

    // Attempt wire transaction decoding
    if let Ok((sig_count, prefix_len)) = decode_compact_u16(raw_tx_bytes) {
        if sig_count == 0 {
            let msg_bytes = &raw_tx_bytes[prefix_len..];
            if !msg_bytes.is_empty() && (msg_bytes[0] & 0x80 != 0) {
                return Err(ChainError::UnsupportedTransaction(
                    "versioned messages (v0) are unsupported".to_string(),
                ));
            }
            if let Ok(msg) = parse_solana_message(msg_bytes) {
                return Ok((msg_bytes, msg));
            }
        } else {
            let sigs_bytes_len = (sig_count as usize) * ED25519_SIGNATURE_LEN;
            if raw_tx_bytes.len() >= prefix_len + sigs_bytes_len {
                let msg_bytes = &raw_tx_bytes[prefix_len + sigs_bytes_len..];
                if !msg_bytes.is_empty() && (msg_bytes[0] & 0x80 != 0) {
                    return Err(ChainError::UnsupportedTransaction(
                        "versioned messages (v0) are unsupported".to_string(),
                    ));
                }
                if let Ok(msg) = parse_solana_message(msg_bytes) {
                    if msg.header.num_required_signatures == sig_count as u8 {
                        return Ok((msg_bytes, msg));
                    }
                }
            }
        }
    }

    // Attempt direct message parsing
    let msg = parse_solana_message(raw_tx_bytes)?;
    Ok((raw_tx_bytes, msg))
}

/// Validates a CAIP-2 Solana chain identifier (e.g. `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`,
/// `solana:mainnet`, `solana:devnet`, `solana:testnet`).
pub fn validate_solana_chain(chain: &str) -> Result<(&str, &str), ChainError> {
    let (ns, ref_id) = parse_caip2(chain)?;
    if ns != "solana" {
        return Err(ChainError::UnsupportedChain(format!(
            "expected 'solana' namespace, got '{ns}'"
        )));
    }
    if ref_id.is_empty()
        || ref_id.len() > 64
        || ref_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-')
    {
        return Err(ChainError::UnsupportedTransaction(format!(
            "invalid Solana chain reference '{ref_id}' in '{chain}'"
        )));
    }
    Ok((ns, ref_id))
}

/// Solana transaction codec implementing [`ChainCodec`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SolanaCodec;

impl SolanaCodec {
    /// Constructs a new [`SolanaCodec`].
    pub fn new() -> Self {
        Self
    }
}

impl ChainCodec for SolanaCodec {
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        decode_solana_tx(chain, raw_tx_bytes, keys)
    }
}

/// Decodes a Solana transaction for `chain` using derived key material.
pub fn decode_solana_tx(
    chain: &str,
    raw_tx_bytes: &[u8],
    keys: &DerivedKeys,
) -> Result<DecodedTx, ChainError> {
    // 1. Validate CAIP-2 chain identifier
    validate_solana_chain(chain)?;

    // 2. Extract single 32-byte Ed25519 derived public key
    let single_key = keys.single()?;
    if single_key.len() != ED25519_PUBKEY_LEN {
        return Err(ChainError::InvalidKeys(format!(
            "expected 32-byte Ed25519 public key, got {}",
            single_key.len()
        )));
    }
    let derived_pk: [u8; ED25519_PUBKEY_LEN] = single_key
        .try_into()
        .map_err(|_| ChainError::InvalidKeys("failed to convert key to 32 bytes".to_string()))?;
    let signer_address = bs58::encode(&derived_pk).into_string();

    // 3. Extract and parse message
    let (message_bytes, msg) = extract_solana_message(raw_tx_bytes)?;

    // 4. Verify fee payer matches derived key
    if msg.account_keys.is_empty() {
        return Err(ChainError::MalformedTransaction(
            "transaction message has no account keys".to_string(),
        ));
    }
    if msg.account_keys[0] != derived_pk {
        let fee_payer_b58 = bs58::encode(&msg.account_keys[0]).into_string();
        return Err(ChainError::KeyMismatch(format!(
            "derived public key '{signer_address}' does not match transaction fee payer '{fee_payer_b58}'"
        )));
    }

    // 5. Verify instructions: must be exclusively System Program Transfer instructions
    if msg.instructions.is_empty() {
        return Err(ChainError::UnsupportedTransaction(
            "transaction contains no instructions".to_string(),
        ));
    }

    let mut transfers = Vec::with_capacity(msg.instructions.len());

    for (idx, inst) in msg.instructions.iter().enumerate() {
        let program_id = msg.account_keys[inst.program_id_index as usize];
        if program_id != SYSTEM_PROGRAM_ID {
            let prog_b58 = bs58::encode(&program_id).into_string();
            return Err(ChainError::UnsupportedTransaction(format!(
                "instruction {idx} targets unsupported program '{prog_b58}', only System Program ({SYSTEM_PROGRAM_ADDRESS}) is supported"
            )));
        }

        if inst.data.len() != 12 {
            return Err(ChainError::UnsupportedTransaction(format!(
                "instruction {idx} data length must be 12 bytes for System Transfer, got {}",
                inst.data.len()
            )));
        }

        let instruction_type = u32::from_le_bytes(inst.data[0..4].try_into().unwrap());
        if instruction_type != SYSTEM_TRANSFER_INDEX {
            return Err(ChainError::UnsupportedTransaction(format!(
                "instruction {idx} is System instruction index {instruction_type}, only Transfer ({SYSTEM_TRANSFER_INDEX}) is supported"
            )));
        }

        if inst.accounts.len() != 2 {
            return Err(ChainError::UnsupportedTransaction(format!(
                "instruction {idx} accounts count must be 2 for System Transfer, got {}",
                inst.accounts.len()
            )));
        }

        let from_idx = inst.accounts[0] as usize;
        let to_idx = inst.accounts[1] as usize;

        if from_idx >= (msg.header.num_required_signatures as usize) {
            return Err(ChainError::UnsupportedTransaction(format!(
                "instruction {idx} source account at index {from_idx} is not marked as signer"
            )));
        }

        let from_pubkey = msg.account_keys[from_idx];
        let to_pubkey = msg.account_keys[to_idx];

        if from_pubkey != derived_pk {
            let from_b58 = bs58::encode(&from_pubkey).into_string();
            return Err(ChainError::KeyMismatch(format!(
                "instruction {idx} source account '{from_b58}' does not match derived signer key '{signer_address}'"
            )));
        }

        let lamports = u64::from_le_bytes(inst.data[4..12].try_into().unwrap());
        let from_b58 = bs58::encode(&from_pubkey).into_string();
        let to_b58 = bs58::encode(&to_pubkey).into_string();

        transfers.push(Transfer::new(
            from_b58,
            to_b58,
            lamports.to_string(),
            "SOL",
        ));
    }

    // 6. Build FeeSummary (5,000 lamports per required signature)
    let fee_lamports = (msg.header.num_required_signatures as u64) * DEFAULT_LAMPORTS_PER_SIGNATURE;
    let fee = FeeSummary::new(fee_lamports.to_string(), "lamports");

    // 7. Sequence identifier: Recent blockhash in Base58
    let recent_blockhash_b58 = bs58::encode(&msg.recent_blockhash).into_string();
    let sequence = SequenceField::recent_blockhash(&recent_blockhash_b58);

    // 8. Build details metadata
    let details = serde_json::json!({
        "chain": chain,
        "fee_payer": signer_address,
        "recent_blockhash": recent_blockhash_b58,
        "instructions_count": msg.instructions.len(),
        "num_signatures": msg.header.num_required_signatures,
        "num_readonly_signed_accounts": msg.header.num_readonly_signed_accounts,
        "num_readonly_unsigned_accounts": msg.header.num_readonly_unsigned_accounts
    });

    let parsed = ParsedTx::new(transfers, fee, sequence, details);
    let signing_input = SigningInput::Message(message_bytes.to_vec());

    Ok(DecodedTx::new(parsed, signing_input, signer_address))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::backend::generic::crypto::sign_ed25519_software_raw;
    use crate::derive::slip10::derive_slip10_str;

    /// Generates a test Ed25519 keypair using the standard SLIP-10 vector seed and path `m/44'/501'/0'/0'`.
    pub fn test_solana_keypair() -> ([u8; 32], [u8; 32], String) {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let key = derive_slip10_str(&seed, "m/44'/501'/0'/0'").expect("SLIP-10 derivation failed");
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(key.private_key().as_ref());
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(key.public_key());
        let address = bs58::encode(&pub_bytes).into_string();
        (priv_bytes, pub_bytes, address)
    }

    /// Builds a canonical Solana System Transfer message.
    pub fn build_system_transfer_message(
        payer_and_source: &[u8; 32],
        recipients_and_lamports: &[([u8; 32], u64)],
        recent_blockhash: &[u8; 32],
    ) -> SolanaMessage {
        let mut account_keys = Vec::new();
        account_keys.push(*payer_and_source);

        for (recip, _) in recipients_and_lamports {
            if !account_keys.contains(recip) {
                account_keys.push(*recip);
            }
        }
        account_keys.push(SYSTEM_PROGRAM_ID);
        let system_prog_idx = (account_keys.len() - 1) as u8;

        let mut instructions = Vec::new();
        for (recip, lamports) in recipients_and_lamports {
            let to_idx = account_keys.iter().position(|k| k == recip).unwrap() as u8;
            let mut data = Vec::with_capacity(12);
            data.extend_from_slice(&SYSTEM_TRANSFER_INDEX.to_le_bytes());
            data.extend_from_slice(&lamports.to_le_bytes());

            instructions.push(CompiledInstruction {
                program_id_index: system_prog_idx,
                accounts: vec![0, to_idx],
                data,
            });
        }

        SolanaMessage {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            },
            account_keys,
            recent_blockhash: *recent_blockhash,
            instructions,
        }
    }

    #[test]
    fn test_compact_u16_roundtrip() {
        let test_cases: &[u16] = &[0, 1, 42, 127, 128, 255, 300, 16383, 16384, 65535];
        for &val in test_cases {
            let mut buf = Vec::new();
            encode_compact_u16(val, &mut buf);
            let (decoded, consumed) = decode_compact_u16(&buf).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_solana_single_system_transfer_message() {
        let (priv_key, pub_key, signer_addr) = test_solana_keypair();
        let recip = [0x55u8; 32];
        let blockhash = [0x77u8; 32];

        let msg = build_system_transfer_message(&pub_key, &[([0x55u8; 32], 1_000_000_000)], &blockhash);
        let msg_bytes = serialize_solana_message(&msg);

        let keys = DerivedKeys::from(pub_key.as_slice());
        let decoded = decode_solana_tx("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", &msg_bytes, &keys).unwrap();

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.fee.amount, "5000");
        assert_eq!(decoded.parsed.fee.asset, "lamports");
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].from, signer_addr);
        assert_eq!(decoded.parsed.transfers[0].to, bs58::encode(&recip).into_string());
        assert_eq!(decoded.parsed.transfers[0].amount, "1000000000");
        assert_eq!(decoded.parsed.transfers[0].asset, "SOL");
        assert_eq!(
            decoded.parsed.sequence.as_recent_blockhash().unwrap(),
            bs58::encode(&blockhash).into_string()
        );

        // Verify signing input and signature
        match &decoded.signing_input {
            SigningInput::Message(m) => {
                assert_eq!(m, &msg_bytes);
                let sig_64 = sign_ed25519_software_raw(&priv_key, m);
                let formatted = format_solana_signature(&sig_64, &signer_addr);
                assert_eq!(formatted.signer_address, signer_addr);
                verify_solana_sig(&pub_key, m, &sig_64).unwrap();
            }
            _ => panic!("expected SigningInput::Message"),
        }
    }

    #[test]
    fn test_solana_unsigned_wire_transaction_with_dummy_signature() {
        let (priv_key, pub_key, signer_addr) = test_solana_keypair();
        let blockhash = [0x88u8; 32];
        let recip = [0x33u8; 32];

        let msg = build_system_transfer_message(&pub_key, &[(recip, 2_500_000_000)], &blockhash);
        let msg_bytes = serialize_solana_message(&msg);
        let wire_tx = assemble_unsigned_wire_transaction(&msg_bytes, 1);

        let keys = DerivedKeys::from(pub_key.as_slice());
        let decoded = decode_solana_tx("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", &wire_tx, &keys).unwrap();

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers[0].amount, "2500000000");

        // Verify signing input is the extracted message, not the wire transaction wrapper
        match &decoded.signing_input {
            SigningInput::Message(m) => {
                assert_eq!(m, &msg_bytes);
                let sig_64 = sign_ed25519_software_raw(&priv_key, m);
                verify_solana_sig(&pub_key, m, &sig_64).unwrap();
            }
            _ => panic!("expected SigningInput::Message"),
        }
    }

    #[test]
    fn test_solana_wire_transaction_with_zero_signatures_prefix() {
        let (priv_key, pub_key, signer_addr) = test_solana_keypair();
        let blockhash = [0x99u8; 32];
        let recip = [0x44u8; 32];

        let msg = build_system_transfer_message(&pub_key, &[(recip, 50_000_000)], &blockhash);
        let msg_bytes = serialize_solana_message(&msg);
        let wire_tx = assemble_unsigned_wire_transaction(&msg_bytes, 0);

        let keys = DerivedKeys::from(pub_key.as_slice());
        let decoded = decode_solana_tx("solana:devnet", &wire_tx, &keys).unwrap();

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers[0].amount, "50000000");
        match &decoded.signing_input {
            SigningInput::Message(m) => {
                assert_eq!(m, &msg_bytes);
                let sig_64 = sign_ed25519_software_raw(&priv_key, m);
                verify_solana_sig(&pub_key, m, &sig_64).unwrap();
            }
            _ => panic!("expected SigningInput::Message"),
        }
    }

    #[test]
    fn test_solana_multi_transfer_message() {
        let (_priv_key, pub_key, signer_addr) = test_solana_keypair();
        let blockhash = [0xaau8; 32];
        let recip1 = [0x11u8; 32];
        let recip2 = [0x22u8; 32];

        let msg = build_system_transfer_message(
            &pub_key,
            &[(recip1, 100_000_000), (recip2, 200_000_000)],
            &blockhash,
        );
        let msg_bytes = serialize_solana_message(&msg);

        let keys = DerivedKeys::from(pub_key.as_slice());
        let decoded = decode_solana_tx("solana:mainnet", &msg_bytes, &keys).unwrap();

        assert_eq!(decoded.signer_address, signer_addr);
        assert_eq!(decoded.parsed.transfers.len(), 2);
        assert_eq!(decoded.parsed.transfers[0].amount, "100000000");
        assert_eq!(decoded.parsed.transfers[0].to, bs58::encode(&recip1).into_string());
        assert_eq!(decoded.parsed.transfers[1].amount, "200000000");
        assert_eq!(decoded.parsed.transfers[1].to, bs58::encode(&recip2).into_string());
    }

    #[test]
    fn test_solana_rejections_and_negative_cases() {
        let (_priv_key, pub_key, _signer_addr) = test_solana_keypair();
        let keys = DerivedKeys::from(pub_key.as_slice());
        let blockhash = [0x12u8; 32];

        // 1. Versioned v0 message rejection
        let mut v0_bytes = vec![0x80, 0x01, 0x00, 0x01];
        v0_bytes.extend_from_slice(&[0u8; 100]);
        let err_v0 = decode_solana_tx("solana:mainnet", &v0_bytes, &keys).unwrap_err();
        assert_eq!(err_v0.reason_code(), "unsupported_transaction");

        // 2. Non-System Program rejection (e.g. Token Program)
        let token_program = [0x06u8; 32];
        let mut bad_prog_msg = build_system_transfer_message(&pub_key, &[([0x55u8; 32], 1_000)], &blockhash);
        let last_idx = bad_prog_msg.account_keys.len() - 1;
        bad_prog_msg.account_keys[last_idx] = token_program;
        let bad_prog_bytes = serialize_solana_message(&bad_prog_msg);
        let err_prog = decode_solana_tx("solana:mainnet", &bad_prog_bytes, &keys).unwrap_err();
        assert_eq!(err_prog.reason_code(), "unsupported_transaction");

        // 3. Non-Transfer System instruction rejection (e.g. CreateAccount index 0)
        let mut bad_inst_msg = build_system_transfer_message(&pub_key, &[([0x55u8; 32], 1_000)], &blockhash);
        bad_inst_msg.instructions[0].data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let bad_inst_bytes = serialize_solana_message(&bad_inst_msg);
        let err_inst = decode_solana_tx("solana:mainnet", &bad_inst_bytes, &keys).unwrap_err();
        assert_eq!(err_inst.reason_code(), "unsupported_transaction");

        // 4. Key mismatch: fee payer is not the derived key
        let other_key = [0xeeu8; 32];
        let valid_msg = build_system_transfer_message(&other_key, &[([0x55u8; 32], 1_000)], &blockhash);
        let valid_bytes = serialize_solana_message(&valid_msg);
        let err_key = decode_solana_tx("solana:mainnet", &valid_bytes, &keys).unwrap_err();
        assert_eq!(err_key.reason_code(), "key_mismatch");

        // 5. Malformed / truncated message
        let err_trunc = decode_solana_tx("solana:mainnet", &[0x01, 0x00], &keys).unwrap_err();
        assert_eq!(err_trunc.reason_code(), "unsupported_transaction");

        // 6. Chain namespace rejection
        let msg = build_system_transfer_message(&pub_key, &[([0x55u8; 32], 1_000)], &blockhash);
        let msg_bytes = serialize_solana_message(&msg);
        let err_chain = decode_solana_tx("eip155:1", &msg_bytes, &keys).unwrap_err();
        assert_eq!(err_chain.reason_code(), "unsupported_transaction");
    }

    #[test]
    fn test_generate_and_verify_solana_reference_vectors() {
        let (priv_key, pub_key, signer_addr) = test_solana_keypair();
        let pub_hex = format!("0x{}", hex::encode(pub_key));

        // Vector 1: Mainnet System Transfer (raw message)
        let v1_recip = [0x55u8; 32];
        let v1_blockhash = [0x77u8; 32];
        let v1_msg = build_system_transfer_message(&pub_key, &[(v1_recip, 1_000_000_000)], &v1_blockhash);
        let v1_msg_bytes = serialize_solana_message(&v1_msg);
        let v1_sig = sign_ed25519_software_raw(&priv_key, &v1_msg_bytes);
        let v1_keys = DerivedKeys::from(pub_key.as_slice());
        let v1_decoded = decode_solana_tx("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", &v1_msg_bytes, &v1_keys).unwrap();

        // Vector 2: Devnet Unsigned Wire Transaction (1 dummy sig)
        let v2_recip = [0x33u8; 32];
        let v2_blockhash = [0x88u8; 32];
        let v2_msg = build_system_transfer_message(&pub_key, &[(v2_recip, 2_500_000_000)], &v2_blockhash);
        let v2_msg_bytes = serialize_solana_message(&v2_msg);
        let v2_wire_tx = assemble_unsigned_wire_transaction(&v2_msg_bytes, 1);
        let v2_sig = sign_ed25519_software_raw(&priv_key, &v2_msg_bytes);
        let v2_keys = DerivedKeys::from(pub_key.as_slice());
        let v2_decoded = decode_solana_tx("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", &v2_wire_tx, &v2_keys).unwrap();

        // Vector 3: Devnet Zero-signature Wire Transaction (0 sig prefix)
        let v3_recip = [0x44u8; 32];
        let v3_blockhash = [0x99u8; 32];
        let v3_msg = build_system_transfer_message(&pub_key, &[(v3_recip, 50_000_000)], &v3_blockhash);
        let v3_msg_bytes = serialize_solana_message(&v3_msg);
        let v3_wire_tx = assemble_unsigned_wire_transaction(&v3_msg_bytes, 0);
        let v3_sig = sign_ed25519_software_raw(&priv_key, &v3_msg_bytes);
        let v3_keys = DerivedKeys::from(pub_key.as_slice());
        let v3_decoded = decode_solana_tx("solana:devnet", &v3_wire_tx, &v3_keys).unwrap();

        // Vector 4: Mainnet Multi-Transfer Message
        let v4_recip1 = [0x11u8; 32];
        let v4_recip2 = [0x22u8; 32];
        let v4_blockhash = [0xaau8; 32];
        let v4_msg = build_system_transfer_message(
            &pub_key,
            &[(v4_recip1, 100_000_000), (v4_recip2, 200_000_000)],
            &v4_blockhash,
        );
        let v4_msg_bytes = serialize_solana_message(&v4_msg);
        let v4_sig = sign_ed25519_software_raw(&priv_key, &v4_msg_bytes);
        let v4_keys = DerivedKeys::from(pub_key.as_slice());
        let v4_decoded = decode_solana_tx("solana:mainnet", &v4_msg_bytes, &v4_keys).unwrap();

        // Vector 5: Negative Versioned v0 Message
        let mut v5_raw = vec![0x80u8, 0x01, 0x00, 0x01];
        v5_raw.extend_from_slice(&[0u8; 60]);

        // Vector 6: Negative Non-System Program
        let v6_bad_prog = [0x06u8; 32];
        let mut v6_msg = build_system_transfer_message(&pub_key, &[(v1_recip, 1_000_000)], &v1_blockhash);
        let last_idx = v6_msg.account_keys.len() - 1;
        v6_msg.account_keys[last_idx] = v6_bad_prog;
        let v6_raw = serialize_solana_message(&v6_msg);

        // Vector 7: Negative Non-Transfer System Instruction (CreateAccount index 0)
        let mut v7_msg = build_system_transfer_message(&pub_key, &[(v1_recip, 1_000_000)], &v1_blockhash);
        v7_msg.instructions[0].data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let v7_raw = serialize_solana_message(&v7_msg);

        // Vector 8: Negative Key Mismatch
        let other_key = [0xeeu8; 32];
        let v8_msg = build_system_transfer_message(&other_key, &[(v1_recip, 1_000_000)], &v1_blockhash);
        let v8_raw = serialize_solana_message(&v8_msg);

        // Vector 9: Negative Truncated Message
        let v9_raw = vec![0x01u8, 0x00];

        // Vector 10: Negative Chain Namespace
        let v10_raw = v1_msg_bytes.clone();

        let vectors_json = serde_json::json!([
            {
                "id": "solana_mainnet_native_transfer_message",
                "description": "Legacy System Program native transfer of 1 SOL on Solana Mainnet Beta",
                "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "path": "m/44'/501'/0'/0'",
                "public_key": pub_hex,
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v1_msg_bytes)),
                "signing_input": format!("0x{}", hex::encode(&v1_msg_bytes)),
                "parsed": v1_decoded.parsed,
                "result": {
                    "signature": bs58::encode(&v1_sig).into_string(),
                    "signature_hex": format!("0x{}", hex::encode(&v1_sig)),
                    "signer_address": signer_addr
                }
            },
            {
                "id": "solana_devnet_native_transfer_unsigned_tx",
                "description": "Unsigned wire transaction (with 1 dummy 64-byte zero signature) of 2.5 SOL on Solana Devnet",
                "chain": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                "path": "m/44'/501'/0'/0'",
                "public_key": pub_hex,
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v2_wire_tx)),
                "signing_input": format!("0x{}", hex::encode(&v2_msg_bytes)),
                "parsed": v2_decoded.parsed,
                "result": {
                    "signature": bs58::encode(&v2_sig).into_string(),
                    "signature_hex": format!("0x{}", hex::encode(&v2_sig)),
                    "signer_address": signer_addr
                }
            },
            {
                "id": "solana_devnet_zero_signatures_wire_tx",
                "description": "Wire transaction with empty signature prefix (0 signatures) of 0.05 SOL on Solana Devnet",
                "chain": "solana:devnet",
                "path": "m/44'/501'/0'/0'",
                "public_key": pub_hex,
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v3_wire_tx)),
                "signing_input": format!("0x{}", hex::encode(&v3_msg_bytes)),
                "parsed": v3_decoded.parsed,
                "result": {
                    "signature": bs58::encode(&v3_sig).into_string(),
                    "signature_hex": format!("0x{}", hex::encode(&v3_sig)),
                    "signer_address": signer_addr
                }
            },
            {
                "id": "solana_mainnet_multi_transfer_message",
                "description": "Legacy System Program multi-recipient transfer of 0.1 SOL and 0.2 SOL on Solana Mainnet",
                "chain": "solana:mainnet",
                "path": "m/44'/501'/0'/0'",
                "public_key": pub_hex,
                "signer_address": signer_addr,
                "raw_tx": format!("0x{}", hex::encode(&v4_msg_bytes)),
                "signing_input": format!("0x{}", hex::encode(&v4_msg_bytes)),
                "parsed": v4_decoded.parsed,
                "result": {
                    "signature": bs58::encode(&v4_sig).into_string(),
                    "signature_hex": format!("0x{}", hex::encode(&v4_sig)),
                    "signer_address": signer_addr
                }
            },
            {
                "id": "negative_versioned_v0_message",
                "description": "Versioned v0 transaction message rejected by codec",
                "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v5_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_non_system_program",
                "description": "Transaction invoking unsupported Token Program rejected by codec",
                "chain": "solana:mainnet",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v6_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_non_transfer_system_instruction",
                "description": "Transaction invoking System Program CreateAccount instruction rejected by codec",
                "chain": "solana:mainnet",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v7_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_key_mismatch",
                "description": "Transaction fee payer does not match derived signer public key",
                "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v8_raw)),
                "expected_error": "key_mismatch"
            },
            {
                "id": "negative_truncated_message",
                "description": "Truncated / malformed message payload rejected by codec",
                "chain": "solana:devnet",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v9_raw)),
                "expected_error": "unsupported_transaction"
            },
            {
                "id": "negative_unsupported_chain_namespace",
                "description": "EVM chain identifier submitted to Solana codec",
                "chain": "eip155:1",
                "public_key": pub_hex,
                "raw_tx": format!("0x{}", hex::encode(&v10_raw)),
                "expected_error": "unsupported_transaction"
            }
        ]);

        let vectors_pretty = serde_json::to_string_pretty(&vectors_json).expect("pretty json");

        let candidate_paths = [
            std::path::Path::new("vectors/tx_solana.json"),
            std::path::Path::new("../vectors/tx_solana.json"),
            std::path::Path::new("../../vectors/tx_solana.json"),
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
            std::fs::write(path, vectors_pretty.as_bytes()).expect("write vectors/tx_solana.json");
        }
    }

    fn get_vectors_path() -> std::path::PathBuf {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let p1 = manifest_dir.parent().unwrap().join("vectors").join("tx_solana.json");
        if p1.exists() {
            return p1;
        }
        let p2 = manifest_dir.join("vectors").join("tx_solana.json");
        if p2.exists() {
            return p2;
        }
        std::path::PathBuf::from("vectors/tx_solana.json")
    }

    #[test]
    fn test_solana_reference_vectors_from_file() {
        let path = get_vectors_path();
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read vectors from {}: {e}", path.display()));
        let list: Vec<serde_json::Value> =
            serde_json::from_str(&content).expect("valid vector json");
        assert!(list.len() >= 8, "expected at least 8 vectors");

        for v in &list {
            let id = v["id"].as_str().unwrap();
            let chain = v["chain"].as_str().unwrap();
            let raw_tx_hex = v["raw_tx"].as_str().unwrap().trim_start_matches("0x");
            let raw_tx_bytes = hex::decode(raw_tx_hex).unwrap();
            let pk_hex = v["public_key"].as_str().unwrap().trim_start_matches("0x");
            let pk_bytes = hex::decode(pk_hex).unwrap();
            let keys = DerivedKeys::from(pk_bytes.as_slice());

            if let Some(expected_err) = v.get("expected_error").and_then(|e| e.as_str()) {
                let err = decode_solana_tx(chain, &raw_tx_bytes, &keys).unwrap_err();
                assert_eq!(
                    err.reason_code(),
                    expected_err,
                    "vector {id} error reason mismatch"
                );
            } else {
                let decoded = decode_solana_tx(chain, &raw_tx_bytes, &keys).unwrap();

                let expected_signing_input =
                    v["signing_input"].as_str().unwrap().trim_start_matches("0x");
                let actual_msg_hex = match &decoded.signing_input {
                    SigningInput::Message(m) => hex::encode(m),
                    _ => panic!("expected SigningInput::Message"),
                };
                assert_eq!(
                    actual_msg_hex, expected_signing_input,
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
                let sig_b58 = result["signature"].as_str().unwrap();
                let sig_bytes = bs58::decode(sig_b58).into_vec().expect("valid b58 sig");
                assert_eq!(sig_bytes.len(), 64);
                let mut sig_64 = [0u8; 64];
                sig_64.copy_from_slice(&sig_bytes);

                let pubkey_32: [u8; 32] = pk_bytes.try_into().unwrap();
                match &decoded.signing_input {
                    SigningInput::Message(m) => {
                        verify_solana_sig(&pubkey_32, m, &sig_64).expect("signature must verify");
                    }
                    _ => panic!("expected SigningInput::Message"),
                }
            }
        }
    }
}
