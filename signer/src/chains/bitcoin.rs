//! Bitcoin PSBT parser, prevout verification, sighash calculation, and transaction codec
//! (`signer/src/chains/bitcoin.rs`).
//!
//! Implements Task 18 of Milestone 3 (Section 5 of `Specs.md`):
//! - **PSBT Parser & Serializer (BIP174)**:
//!   - Strict deserialization of Partially Signed Bitcoin Transactions from binary, hex, or base64.
//!   - Global unsigned transaction parsing and validation (no witnesses, empty `scriptSig`).
//!   - Map parsing for global, input, and output key-value stores.
//! - **Prevout Verification (Section 5)**:
//!   - For every non-Taproot input, requires full `PSBT_IN_NON_WITNESS_UTXO` previous transaction.
//!   - Hashes previous transaction with double-SHA256 (stripping witness data if SegWit serialized)
//!     and verifies exact byte match against the input's prevout `txid`.
//!   - Extracts previous output amount and `scriptPubKey`. Rejects missing or mismatched prevout.
//! - **Input Classification & Key Matching**:
//!   - **P2PKH** (`m/44'/...`): `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`.
//!     Verifies pubkey hash against key derived at `input_paths[i]`. Computes Legacy sighash.
//!   - **P2WPKH** (`m/84'/...`): `OP_0 <20-byte witness_program>`.
//!     Verifies witness program against key derived at `input_paths[i]`. Computes BIP143 sighash.
//!   - **P2SH-P2WPKH** (`m/49'/...`): `OP_HASH160 <20-byte script_hash> OP_EQUAL`.
//!     Requires `PSBT_IN_REDEEM_SCRIPT` matching `0x0014{HASH160(derived_pubkey)}`.
//!     Verifies P2SH `scriptPubKey` matches `HASH160(redeem_script)`. Computes BIP143 sighash.
//!   - **P2TR** (`m/86'/...`): Recognized and classified for Task 19.
//!   - Any other script type (multisig, non-SegWit P2SH, P2WSH, custom scripts) is rejected
//!     with `unsupported_transaction`.
//! - **Sighash Algorithms**:
//!   - Bitcoin Core legacy sighash (BIP174 / `SignatureHash`) with support for `SIGHASH_ALL`,
//!     `SIGHASH_NONE`, `SIGHASH_SINGLE`, and `SIGHASH_ANYONECANPAY`.
//!   - BIP143 SegWit v0 digest algorithm (`hashPrevouts`, `hashSequence`, `hashOutputs`, `scriptCode`).
//! - **Signature Formatting**:
//!   - Formats per-input ECDSA signatures as canonical strict low-S ASN.1 `DER || sighash_byte`.
//! - **Unified Summary ([`ParsedTx`])**:
//!   - Populates transfers for recipient and change outputs, fee in satoshis, sequence, and details.

use std::fmt;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::backend::generic::crypto::{
    bip340_tagged_hash, bip86_tweaked_x_only_pubkey, encode_ecdsa_der,
};
use crate::chains::{
    parse_caip2, ChainCodec, ChainError, DecodedTx, DerivedKeys, FeeSummary, ParsedTx,
    SequenceField, SigningInput, Transfer,
};

/// PSBT BIP174 magic bytes: `psbt\xff` (`0x70, 0x73, 0x62, 0x74, 0xff`).
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

// -----------------------------------------------------------------------------
// BIP174 PSBT Key Types
// -----------------------------------------------------------------------------

/// Global key type: Unsigned Transaction.
pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Global key type: Extended Public Key (xpub).
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// Global key type: Version Number.
pub const PSBT_GLOBAL_VERSION: u8 = 0xFB;

/// Input key type: Non-witness UTXO (full serialized previous transaction).
pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Input key type: Witness UTXO (`CTxOut`: 8-byte value + scriptPubKey).
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
/// Input key type: Partial Signature.
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Input key type: Sighash Type (4 bytes little-endian uint32).
pub const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Input key type: Redeem Script (for P2SH).
pub const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Input key type: Witness Script (for P2WSH).
pub const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Input key type: BIP32 Derivation Path.
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Input key type: Final ScriptSig.
pub const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Input key type: Final ScriptWitness.
pub const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// Input key type: BIP371 Taproot Script Signature.
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Input key type: BIP371 Taproot Leaf Script.
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
/// Input key type: BIP371 Taproot BIP32 Derivation Path.
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
/// Input key type: BIP371 Taproot Internal Key.
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Input key type: BIP371 Taproot Merkle Root.
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;

/// Output key type: Redeem Script.
pub const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Output key type: Witness Script.
pub const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Output key type: BIP32 Derivation Path.
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;

// -----------------------------------------------------------------------------
// Bitcoin Sighash Flags
// -----------------------------------------------------------------------------

/// BIP341 Taproot default sighash type (commits to all inputs and all outputs).
pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;
pub const SIGHASH_OUTPUT_MASK: u32 = 0x1f;

// -----------------------------------------------------------------------------
// Bitcoin CAIP-2 Network Genesis Identifiers
// -----------------------------------------------------------------------------

/// Bitcoin Mainnet CAIP-2 chain reference / genesis hash:
/// `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.
pub const BITCOIN_MAINNET_GENESIS_HEX: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Bitcoin Testnet3 CAIP-2 chain reference / genesis hash:
/// `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943`.
pub const BITCOIN_TESTNET3_GENESIS_HEX: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";

// ============================================================================
// Cryptographic Hash Helpers
// ============================================================================

/// Computes RIPEMD160(SHA256(data)) (Bitcoin `HASH160`).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(&sha);
    let out = ripemd.finalize();
    let mut res = [0u8; 20];
    res.copy_from_slice(&out);
    res
}

/// Computes SHA256(SHA256(data)) (Bitcoin double-SHA256).
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

// ============================================================================
// Base58Check & Bech32 / Bech32m Address Encoding
// ============================================================================

/// Encodes `payload` using Bitcoin standard Base58Check (payload + first 4 bytes of double-SHA256).
pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = double_sha256(payload);
    let mut combined = Vec::with_capacity(payload.len() + 4);
    combined.extend_from_slice(payload);
    combined.extend_from_slice(&checksum[..4]);
    bs58::encode(combined).into_string()
}

/// Decodes a Bitcoin Base58Check string, validating the 4-byte checksum.
pub fn base58check_decode(encoded: &str) -> Result<Vec<u8>, ChainError> {
    let raw = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| ChainError::MalformedTransaction(format!("invalid Base58 address: {e}")))?;
    if raw.len() < 4 {
        return Err(ChainError::MalformedTransaction(
            "Base58Check payload too short for checksum".to_string(),
        ));
    }
    let payload = &raw[..raw.len() - 4];
    let expected_checksum = &raw[raw.len() - 4..];
    let computed_checksum = &double_sha256(payload)[..4];
    if computed_checksum != expected_checksum {
        return Err(ChainError::MalformedTransaction(
            "Base58Check checksum mismatch".to_string(),
        ));
    }
    Ok(payload.to_vec())
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc830a3;
const BECH32_CONST: u32 = 1;

fn bech32_polymod(values: &[u8]) -> u32 {
    let gen: [u32; 5] = [
        0x3b41c105, 0x08f00708, 0x11e0e540, 0x1b404408, 0x2590a140,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5 {
            if ((b >> i) & 1) != 0 {
                chk ^= gen[i];
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 31);
    }
    out
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, ChainError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;
    let max_acc: u32 = (1 << (from_bits + to_bits - 1)) - 1;
    for &value in data {
        if (value as u32) >> from_bits != 0 {
            return Err(ChainError::MalformedTransaction("invalid bit value in conversion".to_string()));
        }
        acc = ((acc << from_bits) | (value as u32)) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(ChainError::MalformedTransaction("invalid padding in bit conversion".to_string()));
    }
    Ok(ret)
}

/// Encodes a SegWit address using Bech32 (version 0) or Bech32m (version 1+).
pub fn encode_segwit_address(hrp: &str, witness_version: u8, witness_program: &[u8]) -> Result<String, ChainError> {
    if witness_version > 16 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid witness version {witness_version}"
        )));
    }
    let mut data = vec![witness_version];
    let converted = convert_bits(witness_program, 8, 5, true)?;
    data.extend_from_slice(&converted);

    let const_val = if witness_version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };

    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(&data);
    values.extend_from_slice(&[0u8; 6]);

    let polymod = bech32_polymod(&values) ^ const_val;
    let mut chk = [0u8; 6];
    for i in 0..6 {
        chk[i] = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &d in &data {
        out.push(BECH32_CHARSET[d as usize] as char);
    }
    for &c in &chk {
        out.push(BECH32_CHARSET[c as usize] as char);
    }
    Ok(out)
}

// ============================================================================
// Bitcoin Network & Input Classification Types
// ============================================================================

/// Bitcoin network identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Bitcoin Mainnet (`bip122:000000000019d668...` or `bitcoin:mainnet`).
    Mainnet,
    /// Bitcoin Testnet3 (`bip122:000000000933ea01...` or `bitcoin:testnet`).
    Testnet,
    /// Bitcoin Regtest (`bitcoin:regtest`).
    Regtest,
}

impl BitcoinNetwork {
    /// Resolves [`BitcoinNetwork`] from a CAIP-2 chain identifier.
    pub fn from_chain_id(chain: &str) -> Result<Self, ChainError> {
        let (namespace, reference) = parse_caip2(chain)?;
        match namespace {
            "bip122" => {
                if reference == BITCOIN_MAINNET_GENESIS_HEX {
                    Ok(Self::Mainnet)
                } else if reference == BITCOIN_TESTNET3_GENESIS_HEX {
                    Ok(Self::Testnet)
                } else {
                    // Default to testnet/regtest for custom bip122 hashes
                    Ok(Self::Testnet)
                }
            }
            "bitcoin" => match reference {
                "mainnet" => Ok(Self::Mainnet),
                "testnet" | "testnet3" | "testnet4" => Ok(Self::Testnet),
                "regtest" => Ok(Self::Regtest),
                other => Err(ChainError::UnsupportedChain(format!(
                    "unsupported bitcoin network '{other}'"
                ))),
            },
            other => Err(ChainError::UnsupportedChain(other.to_string())),
        }
    }

    /// Returns the Human Readable Part (HRP) for Bech32 SegWit addresses.
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet => "tb",
            Self::Regtest => "bcrt",
        }
    }

    /// Returns the Base58Check version byte for P2PKH addresses.
    pub fn p2pkh_version_byte(&self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet | Self::Regtest => 0x6f,
        }
    }

    /// Returns the Base58Check version byte for P2SH addresses.
    pub fn p2sh_version_byte(&self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            Self::Testnet | Self::Regtest => 0xc4,
        }
    }
}

/// Bitcoin single-key input classification from its previous output script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinInputType {
    /// Pay to Public Key Hash (BIP44 derivation `m/44'/...`, Legacy sighash).
    P2pkh,
    /// Pay to Witness Public Key Hash (BIP84 derivation `m/84'/...`, BIP143 sighash).
    P2wpkh,
    /// Nested Pay to Witness Public Key Hash in P2SH (BIP49 derivation `m/49'/...`, BIP143 sighash).
    P2shP2wpkh,
    /// Pay to Taproot key-path (BIP86 derivation `m/86'/...`, BIP341 sighash).
    P2tr,
}

impl BitcoinInputType {
    /// Returns the expected standard BIP43/44 derivation purpose.
    pub fn expected_purpose(&self) -> u32 {
        match self {
            Self::P2pkh => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
            Self::P2tr => 86,
        }
    }

    /// Returns true if this input type requires `PSBT_IN_NON_WITNESS_UTXO`.
    pub fn requires_non_witness_utxo(&self) -> bool {
        matches!(self, Self::P2pkh | Self::P2wpkh | Self::P2shP2wpkh)
    }

    /// Returns true if this is a SegWit v0 input using BIP143 sighash.
    pub fn is_segwit_v0(&self) -> bool {
        matches!(self, Self::P2wpkh | Self::P2shP2wpkh)
    }
}

impl fmt::Display for BitcoinInputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P2pkh => write!(f, "P2PKH"),
            Self::P2wpkh => write!(f, "P2WPKH"),
            Self::P2shP2wpkh => write!(f, "P2SH-P2WPKH"),
            Self::P2tr => write!(f, "P2TR"),
        }
    }
}

// ============================================================================
// Bitcoin Transaction Models (OutPoint, TxIn, TxOut, BitcoinTx)
// ============================================================================

/// Transaction outpoint (`txid` in wire order + output index `vout`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutPoint {
    /// 32-byte transaction ID in internal wire byte order (reverse of RPC hex).
    #[serde(with = "hex_bytes32")]
    pub txid: [u8; 32],
    /// 0-indexed output position within the previous transaction.
    pub vout: u32,
}

impl OutPoint {
    /// Constructs a new [`OutPoint`].
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Returns the RPC display hex string for this `txid` (byte-reversed).
    pub fn txid_rpc_hex(&self) -> String {
        let mut rev = self.txid;
        rev.reverse();
        hex::encode(rev)
    }
}

/// Transaction input (`TxIn`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIn {
    /// Previous outpoint spent by this input.
    pub prevout: OutPoint,
    /// Unlocking script bytes (`scriptSig`).
    #[serde(with = "hex_bytes")]
    pub script_sig: Vec<u8>,
    /// Input sequence number (e.g. `0xFFFFFFFF` or RBF).
    pub sequence: u32,
    /// SegWit witness stack items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<Vec<u8>>,
}

/// Transaction output (`TxOut`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOut {
    /// Output amount in satoshis.
    pub value: u64,
    /// Locking script bytes (`scriptPubKey`).
    #[serde(with = "hex_bytes")]
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    /// Constructs a new [`TxOut`].
    pub fn new(value: u64, script_pubkey: impl Into<Vec<u8>>) -> Self {
        Self {
            value,
            script_pubkey: script_pubkey.into(),
        }
    }
}

/// Bitcoin transaction representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinTx {
    /// Transaction version (typically 1 or 2).
    pub version: i32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// Transaction locktime.
    pub locktime: u32,
}

impl BitcoinTx {
    /// Computes the transaction ID (`txid`) as the double-SHA256 of the legacy serialization.
    pub fn txid(&self) -> [u8; 32] {
        let legacy_bytes = self.serialize_legacy();
        double_sha256(&legacy_bytes)
    }

    /// Returns the RPC display hex string for the transaction ID (byte-reversed).
    pub fn txid_rpc_hex(&self) -> String {
        let mut id = self.txid();
        id.reverse();
        hex::encode(id)
    }

    /// Serializes this transaction using legacy wire format (without SegWit marker/flag/witnesses).
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        write_compact_size(self.inputs.len() as u64, &mut buf);
        for input in &self.inputs {
            buf.extend_from_slice(&input.prevout.txid);
            buf.extend_from_slice(&input.prevout.vout.to_le_bytes());
            write_compact_size(input.script_sig.len() as u64, &mut buf);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact_size(self.outputs.len() as u64, &mut buf);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_compact_size(output.script_pubkey.len() as u64, &mut buf);
            buf.extend_from_slice(&output.script_pubkey);
        }
        buf.extend_from_slice(&self.locktime.to_le_bytes());
        buf
    }
}

// ============================================================================
// BIP174 PSBT Structures
// ============================================================================

/// PSBT per-input map data (BIP174).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtInput {
    /// Full previous transaction for non-witness inputs.
    pub non_witness_utxo: Option<BitcoinTx>,
    /// Raw serialized bytes of `non_witness_utxo`.
    #[serde(skip)]
    pub raw_non_witness_utxo: Option<Vec<u8>>,
    /// Previous output for witness inputs.
    pub witness_utxo: Option<TxOut>,
    /// Optional specified sighash type.
    pub sighash_type: Option<u32>,
    /// Redeem script (for P2SH).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_bytes")]
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script (for P2WSH).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_bytes")]
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 key derivation paths: `(pubkey_bytes, master_fingerprint, path_indices)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bip32_derivation: Vec<(Vec<u8>, u32, Vec<u32>)>,
    /// BIP371 Taproot internal key (32-byte x-only pubkey).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tap_internal_key: Option<[u8; 32]>,
    /// BIP371 Taproot BIP32 key derivation paths: `(x_only_pubkey, leaf_hashes, master_fingerprint, path_indices)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tap_bip32_derivation: Vec<([u8; 32], Vec<[u8; 32]>, u32, Vec<u32>)>,
    /// Flag indicating whether Taproot script-path spending fields are present.
    #[serde(default)]
    pub has_tap_script_spend: bool,
}

/// PSBT per-output map data (BIP174).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtOutput {
    /// Redeem script for P2SH output.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_bytes")]
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script for P2WSH output.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex_bytes")]
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 key derivation paths: `(pubkey_bytes, master_fingerprint, path_indices)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bip32_derivation: Vec<(Vec<u8>, u32, Vec<u32>)>,
}

/// Fully parsed Partially Signed Bitcoin Transaction (BIP174).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Psbt {
    /// Global unsigned transaction.
    pub unsigned_tx: BitcoinTx,
    /// Per-input key-value maps (length equals `unsigned_tx.inputs.len()`).
    pub inputs: Vec<PsbtInput>,
    /// Per-output key-value maps (length equals `unsigned_tx.outputs.len()`).
    pub outputs: Vec<PsbtOutput>,
}

// ============================================================================
// CompactSize (VarInt) Parsing & Serialization
// ============================================================================

/// Reads a Bitcoin CompactSize (VarInt) from `data` at `offset`.
/// Returns `(value, new_offset)`.
pub fn read_compact_size(data: &[u8], mut offset: usize) -> Result<(u64, usize), ChainError> {
    if offset >= data.len() {
        return Err(ChainError::MalformedTransaction(
            "unexpected end of data reading compact size".to_string(),
        ));
    }
    let first = data[offset];
    offset += 1;
    match first {
        0x00..=0xfc => Ok((first as u64, offset)),
        0xfd => {
            if offset + 2 > data.len() {
                return Err(ChainError::MalformedTransaction("truncated 2-byte compact size".to_string()));
            }
            let v = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if v < 0xfd {
                return Err(ChainError::MalformedTransaction("non-canonical compact size encoding".to_string()));
            }
            Ok((v as u64, offset + 2))
        }
        0xfe => {
            if offset + 4 > data.len() {
                return Err(ChainError::MalformedTransaction("truncated 4-byte compact size".to_string()));
            }
            let v = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if v <= 0xffff {
                return Err(ChainError::MalformedTransaction("non-canonical compact size encoding".to_string()));
            }
            Ok((v as u64, offset + 4))
        }
        0xff => {
            if offset + 8 > data.len() {
                return Err(ChainError::MalformedTransaction("truncated 8-byte compact size".to_string()));
            }
            let v = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            if v <= 0xffffffff {
                return Err(ChainError::MalformedTransaction("non-canonical compact size encoding".to_string()));
            }
            Ok((v, offset + 8))
        }
    }
}

/// Appends a Bitcoin CompactSize (VarInt) to `buf`.
pub fn write_compact_size(val: u64, buf: &mut Vec<u8>) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ============================================================================
// Raw Transaction Parsing
// ============================================================================

/// Parses a raw Bitcoin transaction from wire bytes (legacy or SegWit extended format).
pub fn parse_bitcoin_tx(data: &[u8]) -> Result<BitcoinTx, ChainError> {
    let mut offset = 0;
    if data.len() < 10 {
        return Err(ChainError::MalformedTransaction(
            "transaction data too short".to_string(),
        ));
    }
    let version = i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    offset += 4;

    // Detect SegWit extended serialization: marker 0x00 followed by flag != 0x00 (typically 0x01)
    let is_segwit = offset + 2 <= data.len() && data[offset] == 0x00 && data[offset + 1] != 0x00;
    if is_segwit {
        offset += 2; // skip marker and flag
    }

    // Input count
    let (in_count, new_offset) = read_compact_size(data, offset)?;
    offset = new_offset;
    let mut inputs = Vec::with_capacity(in_count as usize);

    for _ in 0..in_count {
        if offset + 36 > data.len() {
            return Err(ChainError::MalformedTransaction("truncated transaction input".to_string()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let vout = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let (script_len, new_offset) = read_compact_size(data, offset)?;
        offset = new_offset;
        let script_len_usize = script_len as usize;
        if offset + script_len_usize > data.len() {
            return Err(ChainError::MalformedTransaction("truncated scriptSig in input".to_string()));
        }
        let script_sig = data[offset..offset + script_len_usize].to_vec();
        offset += script_len_usize;

        if offset + 4 > data.len() {
            return Err(ChainError::MalformedTransaction("truncated sequence in input".to_string()));
        }
        let sequence = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        inputs.push(TxIn {
            prevout: OutPoint::new(txid, vout),
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    // Output count
    let (out_count, new_offset) = read_compact_size(data, offset)?;
    offset = new_offset;
    let mut outputs = Vec::with_capacity(out_count as usize);

    for _ in 0..out_count {
        if offset + 8 > data.len() {
            return Err(ChainError::MalformedTransaction("truncated transaction output".to_string()));
        }
        let value = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        let (script_len, new_offset) = read_compact_size(data, offset)?;
        offset = new_offset;
        let script_len_usize = script_len as usize;
        if offset + script_len_usize > data.len() {
            return Err(ChainError::MalformedTransaction("truncated scriptPubKey in output".to_string()));
        }
        let script_pubkey = data[offset..offset + script_len_usize].to_vec();
        offset += script_len_usize;

        outputs.push(TxOut::new(value, script_pubkey));
    }

    // SegWit witness stack if extended format
    if is_segwit {
        for input in &mut inputs {
            let (stack_count, new_offset) = read_compact_size(data, offset)?;
            offset = new_offset;
            for _ in 0..stack_count {
                let (item_len, new_offset) = read_compact_size(data, offset)?;
                offset = new_offset;
                let item_len_usize = item_len as usize;
                if offset + item_len_usize > data.len() {
                    return Err(ChainError::MalformedTransaction("truncated witness item".to_string()));
                }
                let item = data[offset..offset + item_len_usize].to_vec();
                offset += item_len_usize;
                input.witness.push(item);
            }
        }
    }

    if offset + 4 > data.len() {
        return Err(ChainError::MalformedTransaction("truncated locktime in transaction".to_string()));
    }
    let locktime = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);

    Ok(BitcoinTx {
        version,
        inputs,
        outputs,
        locktime,
    })
}

// ============================================================================
// BIP174 PSBT Parser
// ============================================================================

/// Parses key-value pairs forming a BIP174 PSBT map until terminating byte `0x00`.
/// Returns `(pairs, new_offset)`.
fn read_psbt_map(data: &[u8], mut offset: usize) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, usize), ChainError> {
    let mut pairs = Vec::new();
    loop {
        if offset >= data.len() {
            return Err(ChainError::MalformedTransaction(
                "unexpected EOF reading PSBT map (missing 0x00 separator)".to_string(),
            ));
        }
        let (key_len, new_offset) = read_compact_size(data, offset)?;
        offset = new_offset;
        if key_len == 0 {
            // 0x00 separator byte marks end of this map
            break;
        }
        let key_len_usize = key_len as usize;
        if offset + key_len_usize > data.len() {
            return Err(ChainError::MalformedTransaction("truncated PSBT key".to_string()));
        }
        let key = data[offset..offset + key_len_usize].to_vec();
        offset += key_len_usize;

        let (val_len, new_offset) = read_compact_size(data, offset)?;
        offset = new_offset;
        let val_len_usize = val_len as usize;
        if offset + val_len_usize > data.len() {
            return Err(ChainError::MalformedTransaction("truncated PSBT value".to_string()));
        }
        let val = data[offset..offset + val_len_usize].to_vec();
        offset += val_len_usize;

        pairs.push((key, val));
    }
    Ok((pairs, offset))
}

/// Parses a Partially Signed Bitcoin Transaction (BIP174) from raw binary, hex, or base64.
pub fn parse_psbt(raw_bytes: &[u8]) -> Result<Psbt, ChainError> {
    let binary_bytes = decode_psbt_payload_bytes(raw_bytes)?;

    if binary_bytes.len() < 5 || &binary_bytes[..5] != PSBT_MAGIC {
        return Err(ChainError::MalformedTransaction(
            "invalid PSBT magic bytes (expected 'psbt\\xff')".to_string(),
        ));
    }

    let mut offset = 5;

    // 1. Parse Global Map
    let (global_pairs, new_offset) = read_psbt_map(&binary_bytes, offset)?;
    offset = new_offset;

    let mut unsigned_tx: Option<BitcoinTx> = None;

    for (key, val) in global_pairs {
        if key.is_empty() {
            continue;
        }
        let key_type = key[0];
        if key_type == PSBT_GLOBAL_UNSIGNED_TX && key.len() == 1 {
            let tx = parse_bitcoin_tx(&val)?;
            // BIP174 requires unsigned transaction to have empty scriptSigs and no witnesses
            for input in &tx.inputs {
                if !input.script_sig.is_empty() {
                    return Err(ChainError::MalformedTransaction(
                        "global unsigned transaction must have empty scriptSig".to_string(),
                    ));
                }
                if !input.witness.is_empty() {
                    return Err(ChainError::MalformedTransaction(
                        "global unsigned transaction must not contain witness stack".to_string(),
                    ));
                }
            }
            unsigned_tx = Some(tx);
        }
    }

    let unsigned_tx = unsigned_tx.ok_or_else(|| {
        ChainError::MalformedTransaction("missing PSBT_GLOBAL_UNSIGNED_TX in PSBT".to_string())
    })?;

    let in_count = unsigned_tx.inputs.len();
    let out_count = unsigned_tx.outputs.len();

    // 2. Parse Input Maps
    let mut inputs = Vec::with_capacity(in_count);
    for _ in 0..in_count {
        let (pairs, new_offset) = read_psbt_map(&binary_bytes, offset)?;
        offset = new_offset;
        let mut psbt_in = PsbtInput::default();

        for (key, val) in pairs {
            if key.is_empty() {
                continue;
            }
            let key_type = key[0];
            match key_type {
                PSBT_IN_NON_WITNESS_UTXO if key.len() == 1 => {
                    let prev_tx = parse_bitcoin_tx(&val)?;
                    psbt_in.non_witness_utxo = Some(prev_tx);
                    psbt_in.raw_non_witness_utxo = Some(val);
                }
                PSBT_IN_WITNESS_UTXO if key.len() == 1 => {
                    if val.len() < 8 {
                        return Err(ChainError::MalformedTransaction("truncated witness UTXO".to_string()));
                    }
                    let value = u64::from_le_bytes([
                        val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    ]);
                    let (script_len, script_offset) = read_compact_size(&val, 8)?;
                    let script_pubkey = val[script_offset..script_offset + script_len as usize].to_vec();
                    psbt_in.witness_utxo = Some(TxOut::new(value, script_pubkey));
                }
                PSBT_IN_SIGHASH_TYPE if key.len() == 1 => {
                    if val.len() != 4 {
                        return Err(ChainError::MalformedTransaction("invalid sighash type length in PSBT".to_string()));
                    }
                    psbt_in.sighash_type = Some(u32::from_le_bytes([val[0], val[1], val[2], val[3]]));
                }
                PSBT_IN_REDEEM_SCRIPT if key.len() == 1 => {
                    psbt_in.redeem_script = Some(val);
                }
                PSBT_IN_WITNESS_SCRIPT if key.len() == 1 => {
                    psbt_in.witness_script = Some(val);
                }
                PSBT_IN_BIP32_DERIVATION => {
                    let pubkey = key[1..].to_vec();
                    if val.len() >= 4 && (val.len() - 4) % 4 == 0 {
                        let fingerprint = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                        let mut path = Vec::new();
                        for chunk in val[4..].chunks_exact(4) {
                            path.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                        }
                        psbt_in.bip32_derivation.push((pubkey, fingerprint, path));
                    }
                }
                PSBT_IN_TAP_INTERNAL_KEY if key.len() == 1 && val.len() == 32 => {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&val);
                    psbt_in.tap_internal_key = Some(k);
                }
                PSBT_IN_TAP_BIP32_DERIVATION if key.len() == 33 => {
                    let mut x_only = [0u8; 32];
                    x_only.copy_from_slice(&key[1..33]);
                    if let Ok((leaf_count, mut v_offset)) = read_compact_size(&val, 0) {
                        let mut leaf_hashes = Vec::new();
                        let mut ok = true;
                        for _ in 0..leaf_count {
                            if v_offset + 32 > val.len() {
                                ok = false;
                                break;
                            }
                            let mut lh = [0u8; 32];
                            lh.copy_from_slice(&val[v_offset..v_offset + 32]);
                            leaf_hashes.push(lh);
                            v_offset += 32;
                        }
                        if ok && v_offset + 4 <= val.len() {
                            let fp = u32::from_le_bytes([
                                val[v_offset],
                                val[v_offset + 1],
                                val[v_offset + 2],
                                val[v_offset + 3],
                            ]);
                            v_offset += 4;
                            let rem = &val[v_offset..];
                            if rem.len() % 4 == 0 {
                                let mut path = Vec::new();
                                for chunk in rem.chunks_exact(4) {
                                    path.push(u32::from_le_bytes([
                                        chunk[0], chunk[1], chunk[2], chunk[3],
                                    ]));
                                }
                                if leaf_count > 0 {
                                    psbt_in.has_tap_script_spend = true;
                                }
                                psbt_in.tap_bip32_derivation.push((
                                    x_only,
                                    leaf_hashes,
                                    fp,
                                    path,
                                ));
                            }
                        }
                    }
                }
                PSBT_IN_TAP_SCRIPT_SIG | PSBT_IN_TAP_LEAF_SCRIPT | PSBT_IN_TAP_MERKLE_ROOT => {
                    psbt_in.has_tap_script_spend = true;
                }
                _ => {
                    // Ignore unknown proprietary or unsupported key-values
                }
            }
        }
        inputs.push(psbt_in);
    }

    // 3. Parse Output Maps
    let mut outputs = Vec::with_capacity(out_count);
    for _ in 0..out_count {
        let (pairs, new_offset) = read_psbt_map(&binary_bytes, offset)?;
        offset = new_offset;
        let mut psbt_out = PsbtOutput::default();

        for (key, val) in pairs {
            if key.is_empty() {
                continue;
            }
            let key_type = key[0];
            match key_type {
                PSBT_OUT_REDEEM_SCRIPT if key.len() == 1 => {
                    psbt_out.redeem_script = Some(val);
                }
                PSBT_OUT_WITNESS_SCRIPT if key.len() == 1 => {
                    psbt_out.witness_script = Some(val);
                }
                PSBT_OUT_BIP32_DERIVATION => {
                    let pubkey = key[1..].to_vec();
                    if val.len() >= 4 && (val.len() - 4) % 4 == 0 {
                        let fingerprint = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                        let mut path = Vec::new();
                        for chunk in val[4..].chunks_exact(4) {
                            path.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                        }
                        psbt_out.bip32_derivation.push((pubkey, fingerprint, path));
                    }
                }
                _ => {}
            }
        }
        outputs.push(psbt_out);
    }

    Ok(Psbt {
        unsigned_tx,
        inputs,
        outputs,
    })
}

/// Helper that resolves raw bytes into binary PSBT bytes (handling binary, hex, or base64).
fn decode_psbt_payload_bytes(raw: &[u8]) -> Result<Vec<u8>, ChainError> {
    if raw.starts_with(&PSBT_MAGIC) {
        return Ok(raw.to_vec());
    }

    // Hex string check (with or without 0x)
    let clean_str = std::str::from_utf8(raw).map_err(|e| {
        ChainError::MalformedTransaction(format!("invalid UTF-8 in PSBT payload: {e}"))
    })?;
    let trimmed = clean_str.trim();

    if let Some(stripped) = trimmed.strip_prefix("0x") {
        return hex::decode(stripped)
            .map_err(|e| ChainError::MalformedTransaction(format!("invalid hex PSBT: {e}")));
    }

    if trimmed.len() >= 10 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(trimmed)
            .map_err(|e| ChainError::MalformedTransaction(format!("invalid hex PSBT: {e}")));
    }

    // Standard Base64 decode (starts with 'cHNidP8' for 'psbt\xff')
    if let Ok(b64_bytes) = decode_base64(trimmed) {
        if b64_bytes.starts_with(&PSBT_MAGIC) {
            return Ok(b64_bytes);
        }
    }

    Err(ChainError::MalformedTransaction(
        "payload is not a valid binary, hex, or base64 PSBT".to_string(),
    ))
}

/// Minimal RFC 4648 Base64 decoder.
fn decode_base64(input: &str) -> Result<Vec<u8>, ChainError> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 4 != 0 && !clean.ends_with('=') {
        // May be unpadded
    }
    let mut out = Vec::with_capacity((clean.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for byte in clean.bytes() {
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => {
                return Err(ChainError::MalformedTransaction(
                    "invalid base64 character in PSBT".to_string(),
                ))
            }
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ============================================================================
// BIP174 PSBT Serializer
// ============================================================================

/// Serializes a [`Psbt`] into canonical binary BIP174 format.
pub fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PSBT_MAGIC);

    // 1. Global Map
    let tx_bytes = psbt.unsigned_tx.serialize_legacy();
    // PSBT_GLOBAL_UNSIGNED_TX: key = [0x00], val = tx_bytes
    write_compact_size(1, &mut buf);
    buf.push(PSBT_GLOBAL_UNSIGNED_TX);
    write_compact_size(tx_bytes.len() as u64, &mut buf);
    buf.extend_from_slice(&tx_bytes);
    buf.push(0x00); // end global map

    // 2. Input Maps
    for input in &psbt.inputs {
        if let Some(ref raw_prev_tx) = input.raw_non_witness_utxo {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_NON_WITNESS_UTXO);
            write_compact_size(raw_prev_tx.len() as u64, &mut buf);
            buf.extend_from_slice(raw_prev_tx);
        } else if let Some(ref prev_tx) = input.non_witness_utxo {
            let prev_bytes = prev_tx.serialize_legacy();
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_NON_WITNESS_UTXO);
            write_compact_size(prev_bytes.len() as u64, &mut buf);
            buf.extend_from_slice(&prev_bytes);
        }

        if let Some(ref witness_utxo) = input.witness_utxo {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_WITNESS_UTXO);
            let mut utxo_val = Vec::new();
            utxo_val.extend_from_slice(&witness_utxo.value.to_le_bytes());
            write_compact_size(witness_utxo.script_pubkey.len() as u64, &mut utxo_val);
            utxo_val.extend_from_slice(&witness_utxo.script_pubkey);
            write_compact_size(utxo_val.len() as u64, &mut buf);
            buf.extend_from_slice(&utxo_val);
        }

        if let Some(sighash_type) = input.sighash_type {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_SIGHASH_TYPE);
            write_compact_size(4, &mut buf);
            buf.extend_from_slice(&sighash_type.to_le_bytes());
        }

        if let Some(ref redeem_script) = input.redeem_script {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_REDEEM_SCRIPT);
            write_compact_size(redeem_script.len() as u64, &mut buf);
            buf.extend_from_slice(redeem_script);
        }

        if let Some(ref witness_script) = input.witness_script {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_WITNESS_SCRIPT);
            write_compact_size(witness_script.len() as u64, &mut buf);
            buf.extend_from_slice(witness_script);
        }

        for (pubkey, fingerprint, path) in &input.bip32_derivation {
            let mut key = vec![PSBT_IN_BIP32_DERIVATION];
            key.extend_from_slice(pubkey);
            write_compact_size(key.len() as u64, &mut buf);
            buf.extend_from_slice(&key);

            let mut val = Vec::new();
            val.extend_from_slice(&fingerprint.to_le_bytes());
            for idx in path {
                val.extend_from_slice(&idx.to_le_bytes());
            }
            write_compact_size(val.len() as u64, &mut buf);
            buf.extend_from_slice(&val);
        }

        if let Some(ref internal_key) = input.tap_internal_key {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_TAP_INTERNAL_KEY);
            write_compact_size(32, &mut buf);
            buf.extend_from_slice(internal_key);
        }

        for (x_only, leaf_hashes, fingerprint, path) in &input.tap_bip32_derivation {
            let mut key = vec![PSBT_IN_TAP_BIP32_DERIVATION];
            key.extend_from_slice(x_only);
            write_compact_size(key.len() as u64, &mut buf);
            buf.extend_from_slice(&key);

            let mut val = Vec::new();
            write_compact_size(leaf_hashes.len() as u64, &mut val);
            for lh in leaf_hashes {
                val.extend_from_slice(lh);
            }
            val.extend_from_slice(&fingerprint.to_le_bytes());
            for idx in path {
                val.extend_from_slice(&idx.to_le_bytes());
            }
            write_compact_size(val.len() as u64, &mut buf);
            buf.extend_from_slice(&val);
        }

        if input.has_tap_script_spend {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_IN_TAP_MERKLE_ROOT);
            write_compact_size(32, &mut buf);
            buf.extend_from_slice(&[0u8; 32]);
        }

        buf.push(0x00); // end input map
    }

    // 3. Output Maps
    for output in &psbt.outputs {
        if let Some(ref redeem_script) = output.redeem_script {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_OUT_REDEEM_SCRIPT);
            write_compact_size(redeem_script.len() as u64, &mut buf);
            buf.extend_from_slice(redeem_script);
        }

        if let Some(ref witness_script) = output.witness_script {
            write_compact_size(1, &mut buf);
            buf.push(PSBT_OUT_WITNESS_SCRIPT);
            write_compact_size(witness_script.len() as u64, &mut buf);
            buf.extend_from_slice(witness_script);
        }

        for (pubkey, fingerprint, path) in &output.bip32_derivation {
            let mut key = vec![PSBT_OUT_BIP32_DERIVATION];
            key.extend_from_slice(pubkey);
            write_compact_size(key.len() as u64, &mut buf);
            buf.extend_from_slice(&key);

            let mut val = Vec::new();
            val.extend_from_slice(&fingerprint.to_le_bytes());
            for idx in path {
                val.extend_from_slice(&idx.to_le_bytes());
            }
            write_compact_size(val.len() as u64, &mut buf);
            buf.extend_from_slice(&val);
        }

        buf.push(0x00); // end output map
    }

    buf
}

// ============================================================================
// Input Classification & Prevout Verification
// ============================================================================

/// Classifies a Bitcoin input from its previous output script (`scriptPubKey`)
/// and optional redeem script (for P2SH).
pub fn classify_input(
    script_pubkey: &[u8],
    redeem_script: Option<&[u8]>,
) -> Result<BitcoinInputType, ChainError> {
    // 1. P2PKH: OP_DUP OP_HASH160 0x14 <20-byte pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    // Hex: 76 a9 14 <20 bytes> 88 ac (len = 25)
    if script_pubkey.len() == 25
        && script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac
    {
        return Ok(BitcoinInputType::P2pkh);
    }

    // 2. P2WPKH: OP_0 0x14 <20-byte witness_program>
    // Hex: 00 14 <20 bytes> (len = 22)
    if script_pubkey.len() == 22 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14 {
        return Ok(BitcoinInputType::P2wpkh);
    }

    // 3. P2SH: OP_HASH160 0x14 <20-byte script_hash> OP_EQUAL
    // Hex: a9 14 <20 bytes> 87 (len = 23)
    if script_pubkey.len() == 23
        && script_pubkey[0] == 0xa9
        && script_pubkey[1] == 0x14
        && script_pubkey[22] == 0x87
    {
        // Must contain redeem_script matching P2WPKH: 0x0014{pubkey_hash}
        let redeem = redeem_script.ok_or_else(|| {
            ChainError::MalformedTransaction("missing PSBT_IN_REDEEM_SCRIPT for P2SH input".to_string())
        })?;
        if redeem.len() == 22 && redeem[0] == 0x00 && redeem[1] == 0x14 {
            // Check that scriptPubKey matches HASH160(redeem_script)
            let computed_script_hash = hash160(redeem);
            if computed_script_hash != script_pubkey[2..22] {
                return Err(ChainError::KeyMismatch(
                    "P2SH scriptPubKey does not match HASH160 of redeemScript".to_string(),
                ));
            }
            return Ok(BitcoinInputType::P2shP2wpkh);
        } else {
            return Err(ChainError::UnsupportedTransaction(
                "unsupported P2SH redeemScript (only P2SH-P2WPKH supported)".to_string(),
            ));
        }
    }

    // 4. P2TR: OP_1 0x20 <32-byte tweaked_pubkey>
    // Hex: 51 20 <32 bytes> (len = 34)
    if script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20 {
        return Ok(BitcoinInputType::P2tr);
    }

    // All other script types (multisig, custom P2SH, P2WSH, script-path Taproot)
    Err(ChainError::UnsupportedTransaction(format!(
        "unsupported scriptPubKey: 0x{}",
        hex::encode(script_pubkey)
    )))
}

/// Resolved previous output details verified for an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrevout {
    /// Satoshis of the previous output.
    pub value: u64,
    /// ScriptPubKey bytes of the previous output.
    pub script_pubkey: Vec<u8>,
    /// Classified input type.
    pub input_type: BitcoinInputType,
    /// Pubkey hash or witness program (20 bytes for P2PKH, P2WPKH, P2SH-P2WPKH).
    pub pubkey_hash: [u8; 20],
}

/// Verifies `PSBT_IN_NON_WITNESS_UTXO` for a PSBT input against `input.prevout`,
/// verifies the derived key at `input_paths[i]`, and classifies the script.
pub fn verify_input_prevout(
    input_idx: usize,
    tx_in: &TxIn,
    psbt_in: &PsbtInput,
    derived_pubkey: &[u8],
    input_path: Option<&str>,
) -> Result<VerifiedPrevout, ChainError> {
    // 1. Validate derived public key: must be 33-byte compressed secp256k1 public key
    if derived_pubkey.len() != 33 || (derived_pubkey[0] != 0x02 && derived_pubkey[0] != 0x03) {
        return Err(ChainError::InvalidKeys(format!(
            "input {input_idx}: expected 33-byte compressed secp256k1 public key, got {} bytes",
            derived_pubkey.len()
        )));
    }
    let derived_pubkey_hash = hash160(derived_pubkey);

    // 2. Extract previous output amount and scriptPubKey
    // Per Section 5 of Specs.md: "For every input except Taproot, the PSBT must carry the full
    // previous transaction, which the signer hashes and matches to the input, so the amounts and the fee can be trusted"
    let (prevout_value, prevout_script_pubkey) = match &psbt_in.non_witness_utxo {
        Some(prev_tx) => {
            // Compute the double-SHA256 hash of the previous transaction's legacy serialization
            let prev_txid = prev_tx.txid();
            if prev_txid != tx_in.prevout.txid {
                return Err(ChainError::MalformedTransaction(format!(
                    "input {input_idx}: previous transaction txid mismatch (expected {:x?}, computed {:x?})",
                    tx_in.prevout.txid, prev_txid
                )));
            }

            let vout_idx = tx_in.prevout.vout as usize;
            let output = prev_tx.outputs.get(vout_idx).ok_or_else(|| {
                ChainError::MalformedTransaction(format!(
                    "input {input_idx}: prevout index {} out of bounds (previous tx has {} outputs)",
                    vout_idx,
                    prev_tx.outputs.len()
                ))
            })?;

            // If witness_utxo is also present, verify consistency
            if let Some(ref w_utxo) = psbt_in.witness_utxo {
                if w_utxo.value != output.value || w_utxo.script_pubkey != output.script_pubkey {
                    return Err(ChainError::MalformedTransaction(format!(
                        "input {input_idx}: witness_utxo mismatch with non_witness_utxo"
                    )));
                }
            }

            (output.value, output.script_pubkey.clone())
        }
        None => {
            // For Taproot inputs, witness_utxo is permitted if non_witness_utxo is absent
            if let Some(ref w_utxo) = psbt_in.witness_utxo {
                let is_taproot = w_utxo.script_pubkey.len() == 34
                    && w_utxo.script_pubkey[0] == 0x51
                    && w_utxo.script_pubkey[1] == 0x20;
                if is_taproot {
                    (w_utxo.value, w_utxo.script_pubkey.clone())
                } else {
                    return Err(ChainError::MalformedTransaction(format!(
                        "input {input_idx}: missing required PSBT_IN_NON_WITNESS_UTXO for non-Taproot input"
                    )));
                }
            } else {
                return Err(ChainError::MalformedTransaction(format!(
                    "input {input_idx}: missing required PSBT_IN_NON_WITNESS_UTXO for non-Taproot input"
                )));
            }
        }
    };

    // 3. Classify input from scriptPubKey and redeemScript
    let input_type = classify_input(
        &prevout_script_pubkey,
        psbt_in.redeem_script.as_deref(),
    )?;

    // 4. Validate scriptPubKey matches the derived key
    match input_type {
        BitcoinInputType::P2pkh => {
            let script_pubkey_hash = &prevout_script_pubkey[3..23];
            if script_pubkey_hash != derived_pubkey_hash {
                return Err(ChainError::KeyMismatch(format!(
                    "input {input_idx}: P2PKH pubkey hash does not match derived key"
                )));
            }
        }
        BitcoinInputType::P2wpkh => {
            let witness_program = &prevout_script_pubkey[2..22];
            if witness_program != derived_pubkey_hash {
                return Err(ChainError::KeyMismatch(format!(
                    "input {input_idx}: P2WPKH witness program does not match derived key"
                )));
            }
        }
        BitcoinInputType::P2shP2wpkh => {
            let redeem = psbt_in.redeem_script.as_ref().unwrap();
            let redeem_pubkey_hash = &redeem[2..22];
            if redeem_pubkey_hash != derived_pubkey_hash {
                return Err(ChainError::KeyMismatch(format!(
                    "input {input_idx}: P2SH-P2WPKH redeemScript does not match derived key"
                )));
            }
        }
        BitcoinInputType::P2tr => {
            // Reject any script-path spending artifacts
            if psbt_in.has_tap_script_spend
                || psbt_in.witness_script.is_some()
                || psbt_in.redeem_script.is_some()
            {
                return Err(ChainError::UnsupportedTransaction(
                    "Taproot script-path spends are not supported (only P2TR key-path supported)".to_string(),
                ));
            }

            // Derive key at input_paths[i], apply BIP86 tweak (TapTweak with empty merkle root),
            // and verify tweaked x-only pubkey matches prevout scriptPubKey
            let mut compressed_arr = [0u8; 33];
            compressed_arr.copy_from_slice(derived_pubkey);
            let tweaked_x_only = bip86_tweaked_x_only_pubkey(&compressed_arr)
                .map_err(|e| ChainError::Crypto(e.to_string()))?;

            let script_tweaked_x_only = &prevout_script_pubkey[2..34];
            if script_tweaked_x_only != tweaked_x_only {
                return Err(ChainError::KeyMismatch(format!(
                    "input {input_idx}: P2TR tweaked pubkey does not match derived key with BIP86 tweak"
                )));
            }

            // If PSBT carries tap_internal_key, verify it matches untweaked internal x-only pubkey
            if let Some(ref internal_key) = psbt_in.tap_internal_key {
                if internal_key != &derived_pubkey[1..33] {
                    return Err(ChainError::KeyMismatch(format!(
                        "input {input_idx}: PSBT tap_internal_key does not match derived internal x-only pubkey"
                    )));
                }
            }
        }
    }

    // 5. Validate derivation path purpose if provided
    if let Some(path_str) = input_path {
        validate_path_purpose(input_idx, path_str, input_type)?;
    }

    // Also check BIP32 derivation in PSBT if present
    for (pk, _fp, path_indices) in &psbt_in.bip32_derivation {
        if pk.as_slice() == derived_pubkey {
            if let Some(&first_idx) = path_indices.first() {
                let purpose = first_idx & 0x7fffffff;
                if purpose != input_type.expected_purpose() {
                    return Err(ChainError::KeyMismatch(format!(
                        "input {input_idx}: PSBT BIP32 derivation purpose {purpose}' does not match script type {input_type} (expected {}')",
                        input_type.expected_purpose()
                    )));
                }
            }
        }
    }

    // Check BIP371 Taproot BIP32 derivation in PSBT if present
    for (xpk, _leaf_hashes, _fp, path_indices) in &psbt_in.tap_bip32_derivation {
        if xpk == &derived_pubkey[1..33] {
            if let Some(&first_idx) = path_indices.first() {
                let purpose = first_idx & 0x7fffffff;
                if purpose != input_type.expected_purpose() {
                    return Err(ChainError::KeyMismatch(format!(
                        "input {input_idx}: PSBT Taproot BIP32 derivation purpose {purpose}' does not match script type {input_type} (expected {}')",
                        input_type.expected_purpose()
                    )));
                }
            }
        }
    }

    Ok(VerifiedPrevout {
        value: prevout_value,
        script_pubkey: prevout_script_pubkey,
        input_type,
        pubkey_hash: derived_pubkey_hash,
    })
}

/// Validates that a derivation path string matches the expected BIP43 purpose for `input_type`.
fn validate_path_purpose(
    input_idx: usize,
    path_str: &str,
    input_type: BitcoinInputType,
) -> Result<(), ChainError> {
    let clean = path_str.trim().trim_start_matches("m/");
    let first_elem = clean.split('/').next().unwrap_or("");
    let purpose_str = first_elem.trim_end_matches(['\'', 'h', 'H']);
    if let Ok(purpose_num) = purpose_str.parse::<u32>() {
        let expected = input_type.expected_purpose();
        if purpose_num != expected {
            return Err(ChainError::KeyMismatch(format!(
                "input {input_idx}: derivation path '{path_str}' purpose {purpose_num}' does not match script type {input_type} (expected {expected}')"
            )));
        }
    }
    Ok(())
}

// ============================================================================
// Sighash Calculation Algorithms
// ============================================================================

/// Computes the Bitcoin Core legacy transaction digest (`SignatureHash`) for input `input_idx`.
///
/// Implements consensus-critical rules:
/// - Strips all input `scriptSig`s except `tx.inputs[input_idx].script_sig`, which is replaced with `script_code`.
/// - If `(sighash_type & SIGHASH_OUTPUT_MASK) == SIGHASH_NONE`: clears outputs and zeroes other sequences.
/// - If `(sighash_type & SIGHASH_OUTPUT_MASK) == SIGHASH_SINGLE`: resizes outputs to `input_idx + 1`, zeroes other sequences,
///   and sets outputs before `input_idx` to null (`value = -1`, empty scriptPubKey). If `input_idx >= outputs.len()`, returns `0x0100...00`.
/// - If `(sighash_type & SIGHASH_ANYONECANPAY) != 0`: clears all other inputs.
/// - Appends 4-byte LE uint32 `sighash_type` and computes `double_sha256`.
pub fn compute_legacy_sighash(
    tx: &BitcoinTx,
    input_idx: usize,
    script_code: &[u8],
    sighash_type: u32,
) -> Result<[u8; 32], ChainError> {
    let mut one = [0u8; 32];
    one[0] = 0x01;

    if input_idx >= tx.inputs.len() {
        return Ok(one);
    }

    let base_type = sighash_type & SIGHASH_OUTPUT_MASK;
    let anyone_can_pay = (sighash_type & SIGHASH_ANYONECANPAY) != 0;

    if base_type == SIGHASH_SINGLE && input_idx >= tx.outputs.len() {
        return Ok(one);
    }

    // Bitcoin Core legacy SignatureHash performs FindAndDelete(OP_CODESEPARATOR) (0xab)
    let script_clean: Vec<u8> = script_code.iter().copied().filter(|&b| b != 0xab).collect();

    // Build txCopy inputs
    let mut modified_inputs = Vec::new();
    if anyone_can_pay {
        let mut in_copy = tx.inputs[input_idx].clone();
        in_copy.script_sig = script_clean;
        modified_inputs.push(in_copy);
    } else {
        for (i, input) in tx.inputs.iter().enumerate() {
            let mut in_copy = input.clone();
            if i == input_idx {
                in_copy.script_sig = script_clean.clone();
            } else {
                in_copy.script_sig = Vec::new();
                if base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE {
                    in_copy.sequence = 0;
                }
            }
            modified_inputs.push(in_copy);
        }
    }

    // Build txCopy outputs
    let mut modified_outputs = Vec::new();
    if base_type == SIGHASH_NONE {
        modified_outputs.clear();
    } else if base_type == SIGHASH_SINGLE {
        for i in 0..=input_idx {
            if i < input_idx {
                // CTxOut::SetNull(): nValue = -1 (0xFFFFFFFFFFFFFFFF), empty scriptPubKey
                modified_outputs.push(TxOut::new(u64::MAX, Vec::new()));
            } else {
                modified_outputs.push(tx.outputs[i].clone());
            }
        }
    } else {
        modified_outputs = tx.outputs.clone();
    }

    // Serialize modified transaction
    let mut buf = Vec::new();
    buf.extend_from_slice(&tx.version.to_le_bytes());
    write_compact_size(modified_inputs.len() as u64, &mut buf);
    for input in &modified_inputs {
        buf.extend_from_slice(&input.prevout.txid);
        buf.extend_from_slice(&input.prevout.vout.to_le_bytes());
        write_compact_size(input.script_sig.len() as u64, &mut buf);
        buf.extend_from_slice(&input.script_sig);
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_compact_size(modified_outputs.len() as u64, &mut buf);
    for output in &modified_outputs {
        buf.extend_from_slice(&output.value.to_le_bytes());
        write_compact_size(output.script_pubkey.len() as u64, &mut buf);
        buf.extend_from_slice(&output.script_pubkey);
    }
    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    // Append 4-byte LE uint32 sighash_type
    buf.extend_from_slice(&sighash_type.to_le_bytes());

    Ok(double_sha256(&buf))
}

/// Computes the BIP143 SegWit v0 transaction digest for input `input_idx`.
///
/// Preimage components:
/// 1. `nVersion` (4 bytes LE)
/// 2. `hashPrevouts` (32 bytes dSHA256 of all input outpoints, or 32 zero bytes if `ANYONECANPAY`)
/// 3. `hashSequence` (32 bytes dSHA256 of all input sequences, or 32 zero bytes if modified by flags)
/// 4. `outpoint` (32-byte txid + 4-byte vout)
/// 5. `scriptCode` (`0x1976a914{pubkey_hash}88ac` for P2WPKH)
/// 6. `value` (8 bytes LE satoshis)
/// 7. `nSequence` (4 bytes LE)
/// 8. `hashOutputs` (32 bytes dSHA256 of outputs, or 32 zero bytes)
/// 9. `nLockTime` (4 bytes LE)
/// 10. `sighash_type` (4 bytes LE)
pub fn compute_bip143_sighash(
    tx: &BitcoinTx,
    input_idx: usize,
    pubkey_hash: &[u8; 20],
    amount: u64,
    sighash_type: u32,
) -> Result<[u8; 32], ChainError> {
    if input_idx >= tx.inputs.len() {
        return Err(ChainError::MalformedTransaction(format!(
            "input index {input_idx} exceeds transaction inputs ({})",
            tx.inputs.len()
        )));
    }

    let base_type = sighash_type & SIGHASH_OUTPUT_MASK;
    let anyone_can_pay = (sighash_type & SIGHASH_ANYONECANPAY) != 0;

    // 1. hashPrevouts
    let hash_prevouts = if !anyone_can_pay {
        let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
        for input in &tx.inputs {
            prevouts_buf.extend_from_slice(&input.prevout.txid);
            prevouts_buf.extend_from_slice(&input.prevout.vout.to_le_bytes());
        }
        double_sha256(&prevouts_buf)
    } else {
        [0u8; 32]
    };

    // 2. hashSequence
    let hash_sequence = if !anyone_can_pay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        let mut seq_buf = Vec::with_capacity(tx.inputs.len() * 4);
        for input in &tx.inputs {
            seq_buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        double_sha256(&seq_buf)
    } else {
        [0u8; 32]
    };

    // 3. hashOutputs
    let hash_outputs = if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        let mut outputs_buf = Vec::new();
        for output in &tx.outputs {
            outputs_buf.extend_from_slice(&output.value.to_le_bytes());
            write_compact_size(output.script_pubkey.len() as u64, &mut outputs_buf);
            outputs_buf.extend_from_slice(&output.script_pubkey);
        }
        double_sha256(&outputs_buf)
    } else if base_type == SIGHASH_SINGLE && input_idx < tx.outputs.len() {
        let mut output_buf = Vec::new();
        let output = &tx.outputs[input_idx];
        output_buf.extend_from_slice(&output.value.to_le_bytes());
        write_compact_size(output.script_pubkey.len() as u64, &mut output_buf);
        output_buf.extend_from_slice(&output.script_pubkey);
        double_sha256(&output_buf)
    } else {
        [0u8; 32]
    };

    // 4. scriptCode for P2WPKH: 0x19 76 a9 14 <20-byte pubkey_hash> 88 ac
    let mut script_code = Vec::with_capacity(26);
    script_code.push(0x19);
    script_code.push(0x76);
    script_code.push(0xa9);
    script_code.push(0x14);
    script_code.extend_from_slice(pubkey_hash);
    script_code.push(0x88);
    script_code.push(0xac);

    // 5. Build BIP143 preimage
    let target_in = &tx.inputs[input_idx];
    let mut preimage = Vec::with_capacity(156);
    // 1. nVersion
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    // 2. hashPrevouts
    preimage.extend_from_slice(&hash_prevouts);
    // 3. hashSequence
    preimage.extend_from_slice(&hash_sequence);
    // 4. outpoint
    preimage.extend_from_slice(&target_in.prevout.txid);
    preimage.extend_from_slice(&target_in.prevout.vout.to_le_bytes());
    // 5. scriptCode
    preimage.extend_from_slice(&script_code);
    // 6. value
    preimage.extend_from_slice(&amount.to_le_bytes());
    // 7. nSequence
    preimage.extend_from_slice(&target_in.sequence.to_le_bytes());
    // 8. hashOutputs
    preimage.extend_from_slice(&hash_outputs);
    // 9. nLocktime
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    // 10. sighash_type
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    Ok(double_sha256(&preimage))
}

/// Computes the BIP341 Taproot transaction digest for input `input_idx` (`TapSighash`).
///
/// Implements BIP341 consensus rules:
/// - Preimage:
///   1. `epoch` (1 byte, `0x00`)
///   2. `hash_type` (1 byte)
///   3. `nVersion` (4 bytes LE)
///   4. `nLockTime` (4 bytes LE)
///   5. If not `ANYONECANPAY`:
///      - `sha_prevouts`: SHA256 of all input outpoints (each 32-byte txid + 4-byte LE vout)
///      - `sha_amounts`: SHA256 of all previous output amounts (each 8 bytes LE)
///      - `sha_scriptpubkeys`: SHA256 of all previous output scriptPubKeys (each compact_size(len) + scriptPubKey)
///      - `sha_sequences`: SHA256 of all input sequences (each 4 bytes LE)
///   6. If not `NONE` and not `SINGLE`:
///      - `sha_outputs`: SHA256 of all transaction outputs (each 8 bytes LE value + compact_size(len) + scriptPubKey)
///   7. `spend_type`: `(ext_flag * 2) + annex_present` (`0x00` for key-path without annex)
///   8. Input-specific data:
///      - If `ANYONECANPAY`: `outpoint || amount || compact_size(len) || scriptPubKey || sequence`
///      - Else: `input_index` (4 bytes LE)
///   9. If `SINGLE`: `sha_single_output` (SHA256 of output at `input_idx`)
///   10. Evaluated with tagged hash: `TaggedHash("TapSighash", preimage)`.
pub fn compute_bip341_sighash(
    tx: &BitcoinTx,
    input_idx: usize,
    prevouts: &[(u64, Vec<u8>)],
    sighash_type: u8,
) -> Result<[u8; 32], ChainError> {
    if input_idx >= tx.inputs.len() {
        return Err(ChainError::MalformedTransaction(format!(
            "input index {input_idx} exceeds transaction inputs ({})",
            tx.inputs.len()
        )));
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(ChainError::MalformedTransaction(format!(
            "expected {} prevouts for transaction inputs, got {}",
            tx.inputs.len(),
            prevouts.len()
        )));
    }

    // Validate sighash_type
    if (sighash_type & 0x7c) != 0 {
        return Err(ChainError::MalformedTransaction(format!(
            "invalid BIP341 sighash type 0x{sighash_type:02x}: undefined bits set"
        )));
    }
    let anyone_can_pay = (sighash_type & 0x80) != 0;
    let base_type = sighash_type & 0x03;
    if anyone_can_pay && base_type == 0 {
        return Err(ChainError::MalformedTransaction(
            "invalid BIP341 sighash type: SIGHASH_ANYONECANPAY cannot be combined with SIGHASH_DEFAULT"
                .to_string(),
        ));
    }
    if base_type == 0x03 && input_idx >= tx.outputs.len() {
        return Err(ChainError::MalformedTransaction(format!(
            "SIGHASH_SINGLE input index {input_idx} exceeds output count ({})",
            tx.outputs.len()
        )));
    }

    let mut msg = Vec::with_capacity(200);

    // 1. Epoch (0x00)
    msg.push(0x00);

    // 2. hash_type
    msg.push(sighash_type);

    // 3. nVersion
    msg.extend_from_slice(&(tx.version as u32).to_le_bytes());

    // 4. nLockTime
    msg.extend_from_slice(&tx.locktime.to_le_bytes());

    // 5. If not ANYONECANPAY:
    if !anyone_can_pay {
        // sha_prevouts: SHA256 of all input outpoints
        let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
        for input in &tx.inputs {
            prevouts_buf.extend_from_slice(&input.prevout.txid);
            prevouts_buf.extend_from_slice(&input.prevout.vout.to_le_bytes());
        }
        let sha_prevouts = Sha256::digest(&prevouts_buf);
        msg.extend_from_slice(&sha_prevouts);

        // sha_amounts: SHA256 of all input amounts (8 bytes LE each)
        let mut amounts_buf = Vec::with_capacity(prevouts.len() * 8);
        for (amount, _) in prevouts {
            amounts_buf.extend_from_slice(&amount.to_le_bytes());
        }
        let sha_amounts = Sha256::digest(&amounts_buf);
        msg.extend_from_slice(&sha_amounts);

        // sha_scriptpubkeys: SHA256 of all input scriptPubKeys (compactSize length + scriptPubKey)
        let mut spks_buf = Vec::new();
        for (_, spk) in prevouts {
            write_compact_size(spk.len() as u64, &mut spks_buf);
            spks_buf.extend_from_slice(spk);
        }
        let sha_scriptpubkeys = Sha256::digest(&spks_buf);
        msg.extend_from_slice(&sha_scriptpubkeys);

        // sha_sequences: SHA256 of all input sequences (4 bytes LE each)
        let mut seqs_buf = Vec::with_capacity(tx.inputs.len() * 4);
        for input in &tx.inputs {
            seqs_buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        let sha_sequences = Sha256::digest(&seqs_buf);
        msg.extend_from_slice(&sha_sequences);
    }

    // 6. sha_outputs (if not NONE and not SINGLE):
    if base_type != 0x02 && base_type != 0x03 {
        let mut outputs_buf = Vec::new();
        for output in &tx.outputs {
            outputs_buf.extend_from_slice(&output.value.to_le_bytes());
            write_compact_size(output.script_pubkey.len() as u64, &mut outputs_buf);
            outputs_buf.extend_from_slice(&output.script_pubkey);
        }
        let sha_outputs = Sha256::digest(&outputs_buf);
        msg.extend_from_slice(&sha_outputs);
    }

    // 7. spend_type: (ext_flag * 2) + annex_present
    // For key-path spend without annex: 0x00
    let spend_type = 0x00u8;
    msg.push(spend_type);

    // 8. Data about this input:
    if anyone_can_pay {
        let input = &tx.inputs[input_idx];
        let (amount, spk) = &prevouts[input_idx];
        msg.extend_from_slice(&input.prevout.txid);
        msg.extend_from_slice(&input.prevout.vout.to_le_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        write_compact_size(spk.len() as u64, &mut msg);
        msg.extend_from_slice(spk);
        msg.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(input_idx as u32).to_le_bytes());
    }

    // 9. If SINGLE:
    if base_type == 0x03 {
        let mut single_buf = Vec::new();
        let out = &tx.outputs[input_idx];
        single_buf.extend_from_slice(&out.value.to_le_bytes());
        write_compact_size(out.script_pubkey.len() as u64, &mut single_buf);
        single_buf.extend_from_slice(&out.script_pubkey);
        let sha_single = Sha256::digest(&single_buf);
        msg.extend_from_slice(&sha_single);
    }

    // 10. Tagged hash: TaggedHash("TapSighash", msg)
    Ok(bip340_tagged_hash("TapSighash", &msg))
}

// ============================================================================
// Address Formatting & Signature Formatting
// ============================================================================

/// Formats an address for an output locking script according to the target network.
pub fn format_bitcoin_address(script_pubkey: &[u8], network: BitcoinNetwork) -> String {
    // P2PKH: OP_DUP OP_HASH160 0x14 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    if script_pubkey.len() == 25
        && script_pubkey[0] == 0x76
        && script_pubkey[1] == 0xa9
        && script_pubkey[2] == 0x14
        && script_pubkey[23] == 0x88
        && script_pubkey[24] == 0xac
    {
        let mut payload = vec![network.p2pkh_version_byte()];
        payload.extend_from_slice(&script_pubkey[3..23]);
        return base58check_encode(&payload);
    }

    // P2SH: OP_HASH160 0x14 <script_hash> OP_EQUAL
    if script_pubkey.len() == 23
        && script_pubkey[0] == 0xa9
        && script_pubkey[1] == 0x14
        && script_pubkey[22] == 0x87
    {
        let mut payload = vec![network.p2sh_version_byte()];
        payload.extend_from_slice(&script_pubkey[2..22]);
        return base58check_encode(&payload);
    }

    // P2WPKH: OP_0 0x14 <20-byte witness_program>
    if script_pubkey.len() == 22 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14 {
        if let Ok(addr) = encode_segwit_address(network.bech32_hrp(), 0, &script_pubkey[2..22]) {
            return addr;
        }
    }

    // P2WSH: OP_0 0x20 <32-byte witness_program>
    if script_pubkey.len() == 34 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x20 {
        if let Ok(addr) = encode_segwit_address(network.bech32_hrp(), 0, &script_pubkey[2..34]) {
            return addr;
        }
    }

    // P2TR: OP_1 0x20 <32-byte tweaked_pubkey>
    if script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20 {
        if let Ok(addr) = encode_segwit_address(network.bech32_hrp(), 1, &script_pubkey[2..34]) {
            return addr;
        }
    }

    // OP_RETURN or non-standard script
    if !script_pubkey.is_empty() && script_pubkey[0] == 0x6a {
        return "OP_RETURN".to_string();
    }

    format!("script:0x{}", hex::encode(script_pubkey))
}

/// Formats a raw 64-byte `(r, s)` secp256k1 ECDSA signature into canonical strict low-S
/// ASN.1 DER with an appended sighash byte (`DER(low-S) || sighash_byte`).
pub fn format_bitcoin_ecdsa_signature(
    sig_64: &[u8; 64],
    sighash_type: u8,
) -> Result<Vec<u8>, ChainError> {
    let mut der = encode_ecdsa_der(sig_64).map_err(|e| ChainError::Crypto(e.to_string()))?;
    der.push(sighash_type);
    Ok(der)
}

/// Formats an existing DER signature slice by appending the sighash byte (`DER || sighash_byte`).
pub fn format_bitcoin_der_signature(der_sig: &[u8], sighash_type: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(der_sig.len() + 1);
    out.extend_from_slice(der_sig);
    out.push(sighash_type);
    out
}

/// Formats a 64-byte BIP340 Schnorr signature for Bitcoin Taproot.
///
/// If `sighash_type == SIGHASH_DEFAULT` (0x00), returns the 64-byte signature directly.
/// If `sighash_type != SIGHASH_DEFAULT` (e.g. `0x01` SIGHASH_ALL), appends the 1-byte sighash type (65 bytes total).
pub fn format_bitcoin_schnorr_signature(
    schnorr_sig_64: &[u8],
    sighash_type: u8,
) -> Result<Vec<u8>, ChainError> {
    if schnorr_sig_64.len() != 64 {
        return Err(ChainError::Crypto(format!(
            "expected 64-byte Schnorr signature, got {} bytes",
            schnorr_sig_64.len()
        )));
    }
    if sighash_type == SIGHASH_DEFAULT {
        Ok(schnorr_sig_64.to_vec())
    } else {
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(schnorr_sig_64);
        out.push(sighash_type);
        Ok(out)
    }
}

// ============================================================================
// Main Decoding Logic & ChainCodec Implementation
// ============================================================================

/// Decodes and validates a Bitcoin PSBT transaction, verifying non-Taproot single-key prevouts
/// against derived keys, computing per-input sighashes, and constructing [`DecodedTx`].
pub fn decode_bitcoin_psbt(
    chain: &str,
    raw_tx_bytes: &[u8],
    keys: &DerivedKeys,
    input_paths: Option<&[impl AsRef<str>]>,
) -> Result<DecodedTx, ChainError> {
    // 1. Resolve network from CAIP-2 chain identifier
    let network = BitcoinNetwork::from_chain_id(chain)?;

    // 2. Parse PSBT payload
    let psbt = parse_psbt(raw_tx_bytes)?;
    let in_count = psbt.unsigned_tx.inputs.len();

    // 3. Validate keys count
    if keys.len() != in_count {
        return Err(ChainError::InvalidKeys(format!(
            "expected {in_count} derived keys for {in_count} PSBT inputs, got {}",
            keys.len()
        )));
    }

    // 4. Validate input paths count if provided
    if let Some(paths) = input_paths {
        if paths.len() != in_count {
            return Err(ChainError::InvalidKeys(format!(
                "expected {in_count} derivation paths for {in_count} PSBT inputs, got {}",
                paths.len()
            )));
        }
    }

    // 5. Verify prevouts for all inputs (Pass 1)
    let mut verified_prevouts = Vec::with_capacity(in_count);
    let mut total_input_sats: u64 = 0;

    for (i, tx_in) in psbt.unsigned_tx.inputs.iter().enumerate() {
        let psbt_in = &psbt.inputs[i];
        let derived_pubkey = keys.get_key(i)?;
        let path_str = input_paths.map(|p| p[i].as_ref());

        let verified = verify_input_prevout(i, tx_in, psbt_in, derived_pubkey, path_str)?;
        total_input_sats = total_input_sats.checked_add(verified.value).ok_or_else(|| {
            ChainError::MalformedTransaction("total input satoshis overflowed u64".to_string())
        })?;
        verified_prevouts.push(verified);
    }

    // Collect all previous output amounts and scriptPubKeys for BIP341 sighash computation
    let all_prevouts: Vec<(u64, Vec<u8>)> = verified_prevouts
        .iter()
        .map(|v| (v.value, v.script_pubkey.clone()))
        .collect();

    // 6. Compute per-input sighashes (Pass 2)
    let mut signing_inputs = Vec::with_capacity(in_count);
    for (i, verified) in verified_prevouts.iter().enumerate() {
        let psbt_in = &psbt.inputs[i];

        let signing_input = match verified.input_type {
            BitcoinInputType::P2pkh => {
                let sighash_type = psbt_in.sighash_type.unwrap_or(SIGHASH_ALL);
                let sighash = compute_legacy_sighash(
                    &psbt.unsigned_tx,
                    i,
                    &verified.script_pubkey,
                    sighash_type,
                )?;
                SigningInput::Digest32(sighash)
            }
            BitcoinInputType::P2wpkh | BitcoinInputType::P2shP2wpkh => {
                let sighash_type = psbt_in.sighash_type.unwrap_or(SIGHASH_ALL);
                let sighash = compute_bip143_sighash(
                    &psbt.unsigned_tx,
                    i,
                    &verified.pubkey_hash,
                    verified.value,
                    sighash_type,
                )?;
                SigningInput::Digest32(sighash)
            }
            BitcoinInputType::P2tr => {
                let sighash_type = psbt_in
                    .sighash_type
                    .map(|v| v as u8)
                    .unwrap_or(SIGHASH_DEFAULT);
                let sighash = compute_bip341_sighash(
                    &psbt.unsigned_tx,
                    i,
                    &all_prevouts,
                    sighash_type,
                )?;
                SigningInput::TaprootDigest32(sighash)
            }
        };

        signing_inputs.push(signing_input);
    }

    // 6. Compute fee and validate non-negative
    let mut total_output_sats: u64 = 0;
    for out in &psbt.unsigned_tx.outputs {
        total_output_sats = total_output_sats.checked_add(out.value).ok_or_else(|| {
            ChainError::MalformedTransaction("total output satoshis overflowed u64".to_string())
        })?;
    }

    if total_output_sats > total_input_sats {
        return Err(ChainError::MalformedTransaction(format!(
            "transaction fee is negative: total outputs ({total_output_sats} sats) exceed inputs ({total_input_sats} sats)"
        )));
    }
    let fee_sats = total_input_sats - total_output_sats;

    // 7. Format signer address from primary input (input 0)
    let signer_address = format_bitcoin_address(&verified_prevouts[0].script_pubkey, network);

    // 8. Build transfers summary for each non-zero output
    let mut transfers = Vec::with_capacity(psbt.unsigned_tx.outputs.len());
    for out in &psbt.unsigned_tx.outputs {
        if out.value > 0 {
            let to_addr = format_bitcoin_address(&out.script_pubkey, network);
            transfers.push(Transfer::new(
                &signer_address,
                to_addr,
                out.value.to_string(),
                "BTC",
            ));
        }
    }

    // 9. Details JSON
    let input_details: Vec<serde_json::Value> = psbt
        .unsigned_tx
        .inputs
        .iter()
        .zip(verified_prevouts.iter())
        .enumerate()
        .map(|(idx, (tx_in, v))| {
            serde_json::json!({
                "index": idx,
                "txid": tx_in.prevout.txid_rpc_hex(),
                "vout": tx_in.prevout.vout,
                "amount_sats": v.value,
                "script_type": v.input_type.to_string(),
                "sequence": tx_in.sequence,
            })
        })
        .collect();

    let output_details: Vec<serde_json::Value> = psbt
        .unsigned_tx
        .outputs
        .iter()
        .enumerate()
        .map(|(idx, out)| {
            serde_json::json!({
                "index": idx,
                "value_sats": out.value,
                "address": format_bitcoin_address(&out.script_pubkey, network),
                "script_pubkey": hex::encode(&out.script_pubkey),
            })
        })
        .collect();

    let details = serde_json::json!({
        "chain": chain,
        "version": psbt.unsigned_tx.version,
        "locktime": psbt.unsigned_tx.locktime,
        "fee_satoshis": fee_sats,
        "total_inputs_satoshis": total_input_sats,
        "total_outputs_satoshis": total_output_sats,
        "inputs": input_details,
        "outputs": output_details,
    });

    let sequence = SequenceField::sequence(psbt.unsigned_tx.inputs[0].sequence as u64);
    let fee = FeeSummary::new(fee_sats.to_string(), "satoshis");
    let parsed = ParsedTx::new(transfers, fee, sequence, details);

    let primary_signing_input = signing_inputs.remove(0);
    let decoded = DecodedTx::new(parsed, primary_signing_input, signer_address)
        .with_additional_inputs(signing_inputs);

    Ok(decoded)
}

/// Bitcoin transaction codec implementing [`ChainCodec`].
#[derive(Debug, Default, Clone)]
pub struct BitcoinCodec;

impl BitcoinCodec {
    /// Constructs a new [`BitcoinCodec`].
    pub fn new() -> Self {
        Self
    }

    /// Decodes a PSBT with explicit derivation path validation.
    pub fn decode_with_paths(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
        input_paths: Option<&[impl AsRef<str>]>,
    ) -> Result<DecodedTx, ChainError> {
        decode_bitcoin_psbt(chain, raw_tx_bytes, keys, input_paths)
    }
}

impl ChainCodec for BitcoinCodec {
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        let no_paths: Option<&[&str]> = None;
        decode_bitcoin_psbt(chain, raw_tx_bytes, keys, no_paths)
    }
}

// ============================================================================
// Serde Hex Helpers
// ============================================================================

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

mod opt_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_bip143_published_native_p2wpkh_vector() {
        // BIP143 Native P2WPKH test vector
        let unsigned_tx_hex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        let raw_tx = hex::decode(unsigned_tx_hex).expect("valid unsigned tx hex");
        let tx = parse_bitcoin_tx(&raw_tx).expect("parse unsigned tx");

        // Input 1 is P2WPKH with amount 6 BTC (600_000_000 satoshis)
        let pubkey_bytes = hex::decode("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357").unwrap();
        let pubkey_hash = hash160(&pubkey_bytes);
        assert_eq!(
            hex::encode(pubkey_hash),
            "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
        );

        let amount = 600_000_000u64; // 6 BTC
        let sighash_type = 1u32; // SIGHASH_ALL

        let sighash = compute_bip143_sighash(&tx, 1, &pubkey_hash, amount, sighash_type)
            .expect("bip143 sighash must compute");

        let expected_sighash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
        assert_eq!(hex::encode(sighash), expected_sighash);
    }

    #[test]
    fn test_bip143_published_p2sh_p2wpkh_vector() {
        // BIP143 P2SH-P2WPKH test vector
        let unsigned_tx_hex = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";
        let raw_tx = hex::decode(unsigned_tx_hex).expect("valid unsigned tx hex");
        let tx = parse_bitcoin_tx(&raw_tx).expect("parse unsigned tx");

        let pubkey_bytes = hex::decode("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873").unwrap();
        let pubkey_hash = hash160(&pubkey_bytes);
        assert_eq!(
            hex::encode(pubkey_hash),
            "79091972186c449eb1ded22b78e40d009bdf0089"
        );

        let amount = 1_000_000_000u64; // 10 BTC
        let sighash_type = 1u32; // SIGHASH_ALL

        let sighash = compute_bip143_sighash(&tx, 0, &pubkey_hash, amount, sighash_type)
            .expect("bip143 sighash must compute");

        let expected_sighash = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
        assert_eq!(hex::encode(sighash), expected_sighash);
    }

    #[test]
    fn test_bitcoin_core_legacy_sighash_vectors() {
        // Test vectors from Bitcoin Core src/test/data/sighash.json
        struct Vector {
            raw_tx: &'static str,
            script: &'static str,
            input_idx: usize,
            sighash_type: i64,
            expected_sighash_hex: &'static str,
        }

        let vectors = [
            Vector {
                raw_tx: "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229",
                script: "",
                input_idx: 2,
                sighash_type: 1864164639,
                expected_sighash_hex: "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e",
            },
            Vector {
                raw_tx: "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5",
                script: "65",
                input_idx: 0,
                sighash_type: -1391424484,
                expected_sighash_hex: "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175",
            },
            Vector {
                raw_tx: "6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8",
                script: "acab655151",
                input_idx: 0,
                sighash_type: 479279909,
                expected_sighash_hex: "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c",
            },
            Vector {
                raw_tx: "73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000",
                script: "5163ac63635151ac",
                input_idx: 1,
                sighash_type: 1190874345,
                expected_sighash_hex: "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc",
            },
            Vector {
                raw_tx: "50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000",
                script: "6aac",
                input_idx: 0,
                sighash_type: 946795545,
                expected_sighash_hex: "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d",
            },
        ];

        for (idx, vec) in vectors.iter().enumerate() {
            let tx_bytes = hex::decode(vec.raw_tx).expect("valid tx hex");
            let tx = parse_bitcoin_tx(&tx_bytes).expect("parsed tx");
            let script_code = hex::decode(vec.script).expect("valid script hex");
            let sht = (vec.sighash_type as i32) as u32;

            let digest = compute_legacy_sighash(&tx, vec.input_idx, &script_code, sht)
                .expect("compute legacy sighash");

            // Bitcoin Core's sighash.json prints the 32-byte hash in reversed display hex
            let mut rev = digest;
            rev.reverse();
            let actual_hex = hex::encode(rev);

            assert_eq!(
                actual_hex, vec.expected_sighash_hex,
                "Vector {idx} legacy sighash mismatch"
            );
        }
    }

    #[test]
    fn test_psbt_full_cycle_p2pkh_p2wpkh_p2sh() {
        // Construct a full 3-input PSBT testing all three supported non-Taproot single-key types:
        // Input 0: P2PKH (m/44'/0'/0'/0/0)
        // Input 1: P2WPKH (m/84'/0'/0'/0/0)
        // Input 2: P2SH-P2WPKH (m/49'/0'/0'/0/0)

        // Generate known private keys and compressed public keys
        let sk0_bytes = hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        let sk1_bytes = hex::decode("101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f").unwrap();
        let sk2_bytes = hex::decode("202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f").unwrap();

        let pk0 = crate::derive::bip32::public_key_from_private(sk0_bytes[..32].try_into().unwrap()).unwrap();
        let pk1 = crate::derive::bip32::public_key_from_private(sk1_bytes[..32].try_into().unwrap()).unwrap();
        let pk2 = crate::derive::bip32::public_key_from_private(sk2_bytes[..32].try_into().unwrap()).unwrap();

        let pkh0 = hash160(&pk0);
        let pkh1 = hash160(&pk1);
        let pkh2 = hash160(&pk2);

        // Scripts:
        // 0. P2PKH: OP_DUP OP_HASH160 0x14 {pkh0} OP_EQUALVERIFY OP_CHECKSIG
        let mut script0 = vec![0x76, 0xa9, 0x14];
        script0.extend_from_slice(&pkh0);
        script0.extend_from_slice(&[0x88, 0xac]);

        // 1. P2WPKH: OP_0 0x14 {pkh1}
        let mut script1 = vec![0x00, 0x14];
        script1.extend_from_slice(&pkh1);

        // 2. P2SH-P2WPKH: redeemScript = 0x00 0x14 {pkh2}, scriptPubKey = OP_HASH160 0x14 {HASH160(redeem)} OP_EQUAL
        let mut redeem2 = vec![0x00, 0x14];
        redeem2.extend_from_slice(&pkh2);
        let redeem_hash2 = hash160(&redeem2);
        let mut script2 = vec![0xa9, 0x14];
        script2.extend_from_slice(&redeem_hash2);
        script2.push(0x87);

        // Create 3 mock previous transactions whose outputs are spent
        let prev_tx0 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([1u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(50_000, script0.clone())],
            locktime: 0,
        };
        let prev_txid0 = prev_tx0.txid();

        let prev_tx1 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([2u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(80_000, script1.clone())],
            locktime: 0,
        };
        let prev_txid1 = prev_tx1.txid();

        let prev_tx2 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([3u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(120_000, script2.clone())],
            locktime: 0,
        };
        let prev_txid2 = prev_tx2.txid();

        // Target spending transaction:
        // Spends 50_000 + 80_000 + 120_000 = 250_000 sats.
        // Sends 230_000 sats to a recipient, 20_000 sats fee.
        let recipient_script = vec![0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x12, 0x34, 0x56, 0x78];
        let spending_tx = BitcoinTx {
            version: 2,
            inputs: vec![
                TxIn {
                    prevout: OutPoint::new(prev_txid0, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid1, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid2, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut::new(230_000, recipient_script)],
            locktime: 0,
        };

        // Construct PSBT
        let psbt = Psbt {
            unsigned_tx: spending_tx,
            inputs: vec![
                PsbtInput {
                    non_witness_utxo: Some(prev_tx0),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(pk0.to_vec(), 0x12345678, vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0])],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx1),
                    raw_non_witness_utxo: None,
                    witness_utxo: Some(TxOut::new(80_000, script1)),
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(pk1.to_vec(), 0x12345678, vec![84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0])],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx2),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: Some(redeem2),
                    witness_script: None,
                    bip32_derivation: vec![(pk2.to_vec(), 0x12345678, vec![49 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0])],
                    tap_internal_key: None,
                    ..Default::default()
                },
            ],
            outputs: vec![PsbtOutput::default()],
        };

        let psbt_bytes = serialize_psbt(&psbt);

        // Derive keys and paths
        let keys_vec = vec![pk0.to_vec(), pk1.to_vec(), pk2.to_vec()];
        let derived_keys = DerivedKeys::from(&keys_vec);
        let input_paths = [
            "m/44'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
        ];

        let codec = BitcoinCodec::new();
        let decoded = codec
            .decode_with_paths(
                "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                &psbt_bytes,
                &derived_keys,
                Some(&input_paths),
            )
            .expect("must decode PSBT successfully");

        // Verify summary
        assert_eq!(decoded.parsed.fee.amount, "20000");
        assert_eq!(decoded.parsed.fee.asset, "satoshis");
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].amount, "230000");
        assert_eq!(decoded.parsed.transfers[0].asset, "BTC");

        // Verify all 3 signing inputs are populated
        let all_inputs = decoded.all_signing_inputs();
        assert_eq!(all_inputs.len(), 3);
        for sig_in in all_inputs {
            match sig_in {
                SigningInput::Digest32(d) => assert_ne!(*d, [0u8; 32]),
                _ => panic!("expected 32-byte ECDSA digest"),
            }
        }

        // Verify signature formatting helper
        let dummy_sig = [0x55u8; 64];
        let formatted_der = format_bitcoin_ecdsa_signature(&dummy_sig, 0x01)
            .expect("must format DER signature");
        assert_eq!(*formatted_der.last().unwrap(), 0x01);
        assert_eq!(formatted_der[0], 0x30);
    }

    #[test]
    fn test_missing_or_mismatched_prevout_is_rejected() {
        let sk0_bytes = [1u8; 32];
        let pk0 = crate::derive::bip32::public_key_from_private(&sk0_bytes).unwrap();
        let pkh0 = hash160(&pk0);
        let mut script0 = vec![0x76, 0xa9, 0x14];
        script0.extend_from_slice(&pkh0);
        script0.extend_from_slice(&[0x88, 0xac]);

        let prev_tx0 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([1u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(50_000, script0.clone())],
            locktime: 0,
        };
        let actual_prev_txid = prev_tx0.txid();

        // Case 1: Mismatched txid in spending tx input
        let mut wrong_txid = actual_prev_txid;
        wrong_txid[0] ^= 0xff; // tamper

        let spending_tx = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(wrong_txid, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, script0.clone())],
            locktime: 0,
        };

        let psbt_mismatched = Psbt {
            unsigned_tx: spending_tx,
            inputs: vec![PsbtInput {
                non_witness_utxo: Some(prev_tx0.clone()),
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: Some(SIGHASH_ALL),
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        let bytes_mismatched = serialize_psbt(&psbt_mismatched);
        let key_slice = [pk0.as_slice()];
        let derived_keys = DerivedKeys::Slices(&key_slice);

        let codec = BitcoinCodec::new();
        let err = codec
            .decode(
                "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                &bytes_mismatched,
                &derived_keys,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("previous transaction txid mismatch"),
            "Error: {err}"
        );

        // Case 2: Missing non_witness_utxo
        let spending_tx_ok = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(actual_prev_txid, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, script0)],
            locktime: 0,
        };
        let psbt_missing = Psbt {
            unsigned_tx: spending_tx_ok,
            inputs: vec![PsbtInput {
                non_witness_utxo: None,
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: Some(SIGHASH_ALL),
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };
        let bytes_missing = serialize_psbt(&psbt_missing);
        let err_missing = codec
            .decode(
                "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                &bytes_missing,
                &derived_keys,
            )
            .unwrap_err();
        assert!(
            err_missing.to_string().contains("missing required PSBT_IN_NON_WITNESS_UTXO"),
            "Error: {err_missing}"
        );
    }

    #[test]
    fn test_unsupported_scripts_and_key_mismatch_are_rejected() {
        let sk0_bytes = [2u8; 32];
        let pk0 = crate::derive::bip32::public_key_from_private(&sk0_bytes).unwrap();

        // 1. Key mismatch
        let other_pk = crate::derive::bip32::public_key_from_private(&[3u8; 32]).unwrap();
        let other_pkh = hash160(&other_pk);
        let mut script_other = vec![0x76, 0xa9, 0x14];
        script_other.extend_from_slice(&other_pkh);
        script_other.extend_from_slice(&[0x88, 0xac]);

        let prev_tx = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([0u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(50_000, script_other)],
            locktime: 0,
        };
        let prev_txid = prev_tx.txid();

        let spending_tx = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(prev_txid, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00])],
            locktime: 0,
        };

        let psbt = Psbt {
            unsigned_tx: spending_tx,
            inputs: vec![PsbtInput {
                non_witness_utxo: Some(prev_tx),
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: None,
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        let psbt_bytes = serialize_psbt(&psbt);
        let keys = DerivedKeys::from(pk0.as_slice());
        let codec = BitcoinCodec::new();

        let err_key = codec
            .decode("bitcoin:mainnet", &psbt_bytes, &keys)
            .unwrap_err();
        assert!(matches!(err_key, ChainError::KeyMismatch(_)));

        // 2. Unsupported script (e.g. bare multisig OP_2 ... OP_2 OP_CHECKMULTISIG)
        let multisig_script = vec![0x52, 0x21, 0x02, 0x00, 0x52, 0xae];
        let prev_tx_multi = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([0u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(50_000, multisig_script)],
            locktime: 0,
        };
        let prev_txid_multi = prev_tx_multi.txid();
        let spending_multi = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(prev_txid_multi, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00])],
            locktime: 0,
        };
        let psbt_multi = Psbt {
            unsigned_tx: spending_multi,
            inputs: vec![PsbtInput {
                non_witness_utxo: Some(prev_tx_multi),
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: None,
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };
        let bytes_multi = serialize_psbt(&psbt_multi);
        let err_multi = codec
            .decode("bitcoin:mainnet", &bytes_multi, &keys)
            .unwrap_err();
        assert!(matches!(err_multi, ChainError::UnsupportedTransaction(_)));
    }

    #[test]
    fn test_derivation_path_purpose_enforcement() {
        let sk_bytes = [4u8; 32];
        let pk = crate::derive::bip32::public_key_from_private(&sk_bytes).unwrap();
        let pkh = hash160(&pk);
        // P2WPKH script
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&pkh);

        let prev_tx = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([0u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(50_000, script)],
            locktime: 0,
        };
        let prev_txid = prev_tx.txid();

        let spending = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(prev_txid, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, vec![0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00])],
            locktime: 0,
        };

        let psbt = Psbt {
            unsigned_tx: spending,
            inputs: vec![PsbtInput {
                non_witness_utxo: Some(prev_tx),
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: None,
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        let bytes = serialize_psbt(&psbt);
        let keys = DerivedKeys::from(pk.as_slice());
        let codec = BitcoinCodec::new();

        // Path purpose mismatch: P2WPKH requires 84', we give 44'
        let wrong_paths = ["m/44'/0'/0'/0/0"];
        let err = codec
            .decode_with_paths("bitcoin:mainnet", &bytes, &keys, Some(&wrong_paths))
            .unwrap_err();
        assert!(matches!(err, ChainError::KeyMismatch(_)));

        // Correct path purpose 84'
        let right_paths = ["m/84'/0'/0'/0/0"];
        let ok = codec.decode_with_paths("bitcoin:mainnet", &bytes, &keys, Some(&right_paths));
        assert!(ok.is_ok());
    }

    #[test]
    fn test_negative_fee_is_rejected() {
        let sk_bytes = [5u8; 32];
        let pk = crate::derive::bip32::public_key_from_private(&sk_bytes).unwrap();
        let pkh = hash160(&pk);
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&pkh);
        script.extend_from_slice(&[0x88, 0xac]);

        let prev_tx = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([0u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            // Input has 50_000 sats
            outputs: vec![TxOut::new(50_000, script.clone())],
            locktime: 0,
        };
        let prev_txid = prev_tx.txid();

        // Spending tx tries to output 60_000 sats (exceeding inputs!)
        let spending = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new(prev_txid, 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(60_000, script)],
            locktime: 0,
        };

        let psbt = Psbt {
            unsigned_tx: spending,
            inputs: vec![PsbtInput {
                non_witness_utxo: Some(prev_tx),
                raw_non_witness_utxo: None,
                witness_utxo: None,
                sighash_type: None,
                redeem_script: None,
                witness_script: None,
                bip32_derivation: Vec::new(),
                tap_internal_key: None,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        let bytes = serialize_psbt(&psbt);
        let keys = DerivedKeys::from(pk.as_slice());
        let codec = BitcoinCodec::new();

        let err = codec.decode("bitcoin:mainnet", &bytes, &keys).unwrap_err();
        assert!(matches!(err, ChainError::MalformedTransaction(_)));
        assert!(err.to_string().contains("transaction fee is negative"));
    }

    #[test]
    fn test_bip341_published_wallet_test_vectors() {
        // BIP341 wallet-test-vectors.json reference transaction with 9 inputs and 2 outputs
        let raw_tx_hex = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d";
        let raw_tx = hex::decode(raw_tx_hex).expect("valid tx hex");
        let tx = parse_bitcoin_tx(&raw_tx).expect("valid parsed tx");

        let utxos_raw: [(u64, &str); 9] = [
            (420_000_000, "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
            (462_000_000, "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"),
            (294_000_000, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
            (504_000_000, "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"),
            (630_000_000, "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"),
            (378_000_000, "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc"),
            (672_000_000, "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"),
            (546_000_000, "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"),
            (588_000_000, "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"),
        ];

        let prevouts: Vec<(u64, Vec<u8>)> = utxos_raw
            .iter()
            .map(|(val, hex_spk)| (*val, hex::decode(hex_spk).unwrap()))
            .collect();

        struct TestCase {
            txin_idx: usize,
            hash_type: u8,
            expected_sighash: &'static str,
        }

        let cases = [
            TestCase {
                txin_idx: 4,
                hash_type: 0, // SIGHASH_DEFAULT
                expected_sighash: "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
            },
            TestCase {
                txin_idx: 3,
                hash_type: 1, // SIGHASH_ALL
                expected_sighash: "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
            },
            TestCase {
                txin_idx: 6,
                hash_type: 2, // SIGHASH_NONE
                expected_sighash: "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
            },
            TestCase {
                txin_idx: 0,
                hash_type: 3, // SIGHASH_SINGLE
                expected_sighash: "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
            },
            TestCase {
                txin_idx: 8,
                hash_type: 129, // SIGHASH_ALL | SIGHASH_ANYONECANPAY
                expected_sighash: "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
            },
            TestCase {
                txin_idx: 7,
                hash_type: 130, // SIGHASH_NONE | SIGHASH_ANYONECANPAY
                expected_sighash: "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
            },
            TestCase {
                txin_idx: 1,
                hash_type: 131, // SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
                expected_sighash: "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
            },
        ];

        for (idx, tc) in cases.iter().enumerate() {
            let sighash = compute_bip341_sighash(&tx, tc.txin_idx, &prevouts, tc.hash_type)
                .expect("compute bip341 sighash");
            assert_eq!(
                hex::encode(sighash),
                tc.expected_sighash,
                "BIP341 case {idx} (hash_type {}) sighash mismatch",
                tc.hash_type
            );
        }
    }

    #[test]
    fn test_psbt_full_cycle_composite_4input() {
        // Construct a full composite 4-input PSBT mixing all four supported input types:
        // Input 0: P2PKH (m/44'/0'/0'/0/0)
        // Input 1: P2SH-P2WPKH (m/49'/0'/0'/0/0)
        // Input 2: P2WPKH (m/84'/0'/0'/0/0)
        // Input 3: P2TR (m/86'/0'/0'/0/0)

        let sk0_bytes = hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        let sk1_bytes = hex::decode("101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f").unwrap();
        let sk2_bytes = hex::decode("202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f").unwrap();
        let sk3_bytes = hex::decode("303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f").unwrap();

        let pk0 = crate::derive::bip32::public_key_from_private(sk0_bytes[..32].try_into().unwrap()).unwrap();
        let pk1 = crate::derive::bip32::public_key_from_private(sk1_bytes[..32].try_into().unwrap()).unwrap();
        let pk2 = crate::derive::bip32::public_key_from_private(sk2_bytes[..32].try_into().unwrap()).unwrap();
        let pk3 = crate::derive::bip32::public_key_from_private(sk3_bytes[..32].try_into().unwrap()).unwrap();

        let pkh0 = hash160(&pk0);
        let pkh1 = hash160(&pk1);
        let pkh2 = hash160(&pk2);

        // 0. P2PKH script: OP_DUP OP_HASH160 0x14 {pkh0} OP_EQUALVERIFY OP_CHECKSIG
        let mut script0 = vec![0x76, 0xa9, 0x14];
        script0.extend_from_slice(&pkh0);
        script0.extend_from_slice(&[0x88, 0xac]);

        // 1. P2SH-P2WPKH: redeemScript = 0x00 0x14 {pkh1}, scriptPubKey = OP_HASH160 0x14 {HASH160(redeem)} OP_EQUAL
        let mut redeem1 = vec![0x00, 0x14];
        redeem1.extend_from_slice(&pkh1);
        let redeem_hash1 = hash160(&redeem1);
        let mut script1 = vec![0xa9, 0x14];
        script1.extend_from_slice(&redeem_hash1);
        script1.push(0x87);

        // 2. P2WPKH: OP_0 0x14 {pkh2}
        let mut script2 = vec![0x00, 0x14];
        script2.extend_from_slice(&pkh2);

        // 3. P2TR: OP_1 0x20 {bip86_tweaked_x_only_pubkey(pk3)}
        let tweaked_pubkey3 = bip86_tweaked_x_only_pubkey(&pk3).unwrap();
        let mut script3 = vec![0x51, 0x20];
        script3.extend_from_slice(&tweaked_pubkey3);

        // Previous transactions for inputs 0, 1, 2
        let prev_tx0 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([1u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(100_000, script0.clone())],
            locktime: 0,
        };
        let prev_txid0 = prev_tx0.txid();

        let prev_tx1 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([2u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(150_000, script1.clone())],
            locktime: 0,
        };
        let prev_txid1 = prev_tx1.txid();

        let prev_tx2 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([3u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(200_000, script2.clone())],
            locktime: 0,
        };
        let prev_txid2 = prev_tx2.txid();

        let prev_txid3 = [0x44u8; 32];

        // Spending transaction:
        // Total inputs: 100_000 + 150_000 + 200_000 + 300_000 = 750_000 satoshis.
        // Recipient receives 700_000 satoshis, fee is 50_000 satoshis.
        let recipient_script = vec![
            0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        let spending_tx = BitcoinTx {
            version: 2,
            inputs: vec![
                TxIn {
                    prevout: OutPoint::new(prev_txid0, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid1, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid2, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid3, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut::new(700_000, recipient_script)],
            locktime: 0,
        };

        let internal_x_only3: [u8; 32] = pk3[1..33].try_into().unwrap();

        let psbt = Psbt {
            unsigned_tx: spending_tx,
            inputs: vec![
                PsbtInput {
                    non_witness_utxo: Some(prev_tx0),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk0.to_vec(),
                        0x12345678,
                        vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx1),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: Some(redeem1),
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk1.to_vec(),
                        0x12345678,
                        vec![49 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx2),
                    raw_non_witness_utxo: None,
                    witness_utxo: Some(TxOut::new(200_000, script2)),
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk2.to_vec(),
                        0x12345678,
                        vec![84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: None,
                    raw_non_witness_utxo: None,
                    witness_utxo: Some(TxOut::new(300_000, script3)),
                    sighash_type: Some(SIGHASH_DEFAULT as u32),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk3.to_vec(),
                        0x12345678,
                        vec![86 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: Some(internal_x_only3),
                    ..Default::default()
                },
            ],
            outputs: vec![PsbtOutput::default()],
        };

        let psbt_bytes = serialize_psbt(&psbt);

        let keys_vec = vec![pk0.to_vec(), pk1.to_vec(), pk2.to_vec(), pk3.to_vec()];
        let derived_keys = DerivedKeys::from(&keys_vec);
        let input_paths = [
            "m/44'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/86'/0'/0'/0/0",
        ];

        let codec = BitcoinCodec::new();
        let decoded = codec
            .decode_with_paths(
                "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                &psbt_bytes,
                &derived_keys,
                Some(&input_paths),
            )
            .expect("must decode composite 4-input PSBT successfully");

        // Verify fee and transfers
        assert_eq!(decoded.parsed.fee.amount, "50000");
        assert_eq!(decoded.parsed.fee.asset, "satoshis");
        assert_eq!(decoded.parsed.transfers.len(), 1);
        assert_eq!(decoded.parsed.transfers[0].amount, "700000");
        assert_eq!(decoded.parsed.transfers[0].asset, "BTC");

        // Verify 4 signing inputs
        let all_inputs = decoded.all_signing_inputs();
        assert_eq!(all_inputs.len(), 4);
        assert!(matches!(all_inputs[0], SigningInput::Digest32(_)));
        assert!(matches!(all_inputs[1], SigningInput::Digest32(_)));
        assert!(matches!(all_inputs[2], SigningInput::Digest32(_)));
        assert!(matches!(all_inputs[3], SigningInput::TaprootDigest32(_)));

        // Test software signing of Taproot input (Input 3)
        if let SigningInput::TaprootDigest32(d3) = all_inputs[3] {
            let sk3_arr: [u8; 32] = sk3_bytes[..32].try_into().unwrap();
            let sig3 = crate::backend::generic::crypto::sign_taproot_schnorr_software(&sk3_arr, d3)
                .expect("software taproot schnorr signing must succeed");
            assert!(!sig3.signing_in_hsm, "Taproot Schnorr must have signing_in_hsm: false");
            assert_eq!(sig3.bytes.len(), 64);

            let schnorr_formatted = format_bitcoin_schnorr_signature(&sig3.bytes, SIGHASH_DEFAULT)
                .expect("format default schnorr");
            assert_eq!(schnorr_formatted.len(), 64);

            let schnorr_all = format_bitcoin_schnorr_signature(&sig3.bytes, 0x01)
                .expect("format non-default schnorr");
            assert_eq!(schnorr_all.len(), 65);
            assert_eq!(schnorr_all[64], 0x01);
        } else {
            panic!("expected TaprootDigest32 for input 3");
        }
    }

    #[test]
    fn test_taproot_rejections_and_negative_cases() {
        let sk_bytes = [6u8; 32];
        let pk = crate::derive::bip32::public_key_from_private(&sk_bytes).unwrap();
        let tweaked_pubkey = bip86_tweaked_x_only_pubkey(&pk).unwrap();
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&tweaked_pubkey);

        let spending = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([7u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(40_000, script.clone())],
            locktime: 0,
        };

        let keys = DerivedKeys::from(pk.as_slice());
        let codec = BitcoinCodec::new();

        // 1. Script-path spending rejection via witness_script on P2TR
        let psbt_script_path = Psbt {
            unsigned_tx: spending.clone(),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut::new(50_000, script.clone())),
                witness_script: Some(vec![0x51]), // indicates script-path spend
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };
        let bytes_sp = serialize_psbt(&psbt_script_path);
        let err_sp = codec.decode("bitcoin:mainnet", &bytes_sp, &keys).unwrap_err();
        assert!(matches!(err_sp, ChainError::UnsupportedTransaction(_)));
        assert!(err_sp.to_string().contains("Taproot script-path spends are not supported"));

        // 2. Script-path spending rejection via has_tap_script_spend
        let psbt_has_sp = Psbt {
            unsigned_tx: spending.clone(),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut::new(50_000, script.clone())),
                has_tap_script_spend: true,
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };
        let bytes_hsp = serialize_psbt(&psbt_has_sp);
        let err_hsp = codec.decode("bitcoin:mainnet", &bytes_hsp, &keys).unwrap_err();
        assert!(matches!(err_hsp, ChainError::UnsupportedTransaction(_)));

        // 3. Key mismatch: tweaked pubkey doesn't match scriptPubKey
        let other_pk = crate::derive::bip32::public_key_from_private(&[8u8; 32]).unwrap();
        let keys_other = DerivedKeys::from(other_pk.as_slice());
        let psbt_ok = Psbt {
            unsigned_tx: spending.clone(),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut::new(50_000, script.clone())),
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };
        let bytes_ok = serialize_psbt(&psbt_ok);
        let err_km = codec.decode("bitcoin:mainnet", &bytes_ok, &keys_other).unwrap_err();
        assert!(matches!(err_km, ChainError::KeyMismatch(_)));

        // 4. Derivation path purpose enforcement for Taproot: requires 86'
        let wrong_paths = ["m/44'/0'/0'/0/0"];
        let err_dp = codec
            .decode_with_paths("bitcoin:mainnet", &bytes_ok, &keys, Some(&wrong_paths))
            .unwrap_err();
        assert!(matches!(err_dp, ChainError::KeyMismatch(_)));
        assert!(err_dp.to_string().contains("expected 86'"));

        // 5. Invalid sighash type: SIGHASH_ANYONECANPAY combined with SIGHASH_DEFAULT
        let prevouts = vec![(50_000u64, script)];
        let err_sh = compute_bip341_sighash(&spending, 0, &prevouts, 0x80).unwrap_err();
        assert!(matches!(err_sh, ChainError::MalformedTransaction(_)));
        assert!(err_sh.to_string().contains("SIGHASH_ANYONECANPAY cannot be combined with SIGHASH_DEFAULT"));

        // 6. Invalid sighash type: undefined bits set
        let err_sh2 = compute_bip341_sighash(&spending, 0, &prevouts, 0x04).unwrap_err();
        assert!(matches!(err_sh2, ChainError::MalformedTransaction(_)));
        assert!(err_sh2.to_string().contains("undefined bits set"));
    }

    #[test]
    fn test_generate_and_verify_bitcoin_reference_vectors() {
        use std::fs;
        use std::path::Path;

        // Generate the composite 4-input PSBT
        let sk0_bytes = hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
        let sk1_bytes = hex::decode("101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f").unwrap();
        let sk2_bytes = hex::decode("202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f").unwrap();
        let sk3_bytes = hex::decode("303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f").unwrap();

        let pk0 = crate::derive::bip32::public_key_from_private(sk0_bytes[..32].try_into().unwrap()).unwrap();
        let pk1 = crate::derive::bip32::public_key_from_private(sk1_bytes[..32].try_into().unwrap()).unwrap();
        let pk2 = crate::derive::bip32::public_key_from_private(sk2_bytes[..32].try_into().unwrap()).unwrap();
        let pk3 = crate::derive::bip32::public_key_from_private(sk3_bytes[..32].try_into().unwrap()).unwrap();

        let pkh0 = hash160(&pk0);
        let pkh1 = hash160(&pk1);
        let pkh2 = hash160(&pk2);

        let mut script0 = vec![0x76, 0xa9, 0x14];
        script0.extend_from_slice(&pkh0);
        script0.extend_from_slice(&[0x88, 0xac]);

        let mut redeem1 = vec![0x00, 0x14];
        redeem1.extend_from_slice(&pkh1);
        let redeem_hash1 = hash160(&redeem1);
        let mut script1 = vec![0xa9, 0x14];
        script1.extend_from_slice(&redeem_hash1);
        script1.push(0x87);

        let mut script2 = vec![0x00, 0x14];
        script2.extend_from_slice(&pkh2);

        let tweaked_pubkey3 = bip86_tweaked_x_only_pubkey(&pk3).unwrap();
        let mut script3 = vec![0x51, 0x20];
        script3.extend_from_slice(&tweaked_pubkey3);

        let prev_tx0 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([1u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(100_000, script0.clone())],
            locktime: 0,
        };
        let prev_txid0 = prev_tx0.txid();

        let prev_tx1 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([2u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(150_000, script1.clone())],
            locktime: 0,
        };
        let prev_txid1 = prev_tx1.txid();

        let prev_tx2 = BitcoinTx {
            version: 2,
            inputs: vec![TxIn {
                prevout: OutPoint::new([3u8; 32], 0),
                script_sig: Vec::new(),
                sequence: 0xFFFFFFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut::new(200_000, script2.clone())],
            locktime: 0,
        };
        let prev_txid2 = prev_tx2.txid();
        let prev_txid3 = [0x44u8; 32];

        let recipient_script = vec![
            0x00, 0x14, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        let spending_tx = BitcoinTx {
            version: 2,
            inputs: vec![
                TxIn {
                    prevout: OutPoint::new(prev_txid0, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid1, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid2, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
                TxIn {
                    prevout: OutPoint::new(prev_txid3, 0),
                    script_sig: Vec::new(),
                    sequence: 0xFFFFFFFD,
                    witness: Vec::new(),
                },
            ],
            outputs: vec![TxOut::new(700_000, recipient_script)],
            locktime: 0,
        };

        let internal_x_only3: [u8; 32] = pk3[1..33].try_into().unwrap();

        let psbt = Psbt {
            unsigned_tx: spending_tx,
            inputs: vec![
                PsbtInput {
                    non_witness_utxo: Some(prev_tx0),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk0.to_vec(),
                        0x12345678,
                        vec![44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx1),
                    raw_non_witness_utxo: None,
                    witness_utxo: None,
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: Some(redeem1),
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk1.to_vec(),
                        0x12345678,
                        vec![49 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: Some(prev_tx2),
                    raw_non_witness_utxo: None,
                    witness_utxo: Some(TxOut::new(200_000, script2)),
                    sighash_type: Some(SIGHASH_ALL),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk2.to_vec(),
                        0x12345678,
                        vec![84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: None,
                    ..Default::default()
                },
                PsbtInput {
                    non_witness_utxo: None,
                    raw_non_witness_utxo: None,
                    witness_utxo: Some(TxOut::new(300_000, script3)),
                    sighash_type: Some(SIGHASH_DEFAULT as u32),
                    redeem_script: None,
                    witness_script: None,
                    bip32_derivation: vec![(
                        pk3.to_vec(),
                        0x12345678,
                        vec![86 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
                    )],
                    tap_internal_key: Some(internal_x_only3),
                    ..Default::default()
                },
            ],
            outputs: vec![PsbtOutput::default()],
        };

        let psbt_bytes = serialize_psbt(&psbt);
        let psbt_hex = hex::encode(&psbt_bytes);

        let keys_vec = vec![pk0.to_vec(), pk1.to_vec(), pk2.to_vec(), pk3.to_vec()];
        let derived_keys = DerivedKeys::from(&keys_vec);
        let input_paths = [
            "m/44'/0'/0'/0/0",
            "m/49'/0'/0'/0/0",
            "m/84'/0'/0'/0/0",
            "m/86'/0'/0'/0/0",
        ];

        let codec = BitcoinCodec::new();
        let decoded = codec
            .decode_with_paths(
                "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                &psbt_bytes,
                &derived_keys,
                Some(&input_paths),
            )
            .expect("must decode composite 4-input PSBT");

        let all_inputs = decoded.all_signing_inputs();

        // Sign all 4 inputs with their respective keys
        let d0 = match all_inputs[0] {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let d1 = match all_inputs[1] {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let d2 = match all_inputs[2] {
            SigningInput::Digest32(d) => d,
            _ => panic!("expected Digest32"),
        };
        let d3 = match all_inputs[3] {
            SigningInput::TaprootDigest32(d) => d,
            _ => panic!("expected TaprootDigest32"),
        };

        let sign_ecdsa = |sk_bytes: &[u8], digest: &[u8; 32]| -> Vec<u8> {
            let key = k256::ecdsa::SigningKey::from_bytes(sk_bytes.into()).unwrap();
            let (sig, _) = key.sign_prehash_recoverable(digest).unwrap();
            let mut raw_sig = [0u8; 64];
            raw_sig.copy_from_slice(&sig.to_bytes());
            format_bitcoin_ecdsa_signature(&raw_sig, 0x01).unwrap()
        };

        let sig0 = sign_ecdsa(&sk0_bytes, &d0);
        let sig1 = sign_ecdsa(&sk1_bytes, &d1);
        let sig2 = sign_ecdsa(&sk2_bytes, &d2);

        let sk3_arr: [u8; 32] = sk3_bytes[..32].try_into().unwrap();
        let schnorr_sig = crate::backend::generic::crypto::sign_taproot_schnorr_software(&sk3_arr, &d3).unwrap();
        let sig3 = format_bitcoin_schnorr_signature(&schnorr_sig.bytes, SIGHASH_DEFAULT).unwrap();

        // Locate vectors/tx_bitcoin.json
        let candidate_paths = [
            Path::new("vectors/tx_bitcoin.json"),
            Path::new("../vectors/tx_bitcoin.json"),
            Path::new("../../vectors/tx_bitcoin.json"),
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
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(mut list) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                    // Update or insert the composite PSBT vector
                    let psbt_vector = serde_json::json!({
                        "id": "bitcoin_psbt_composite_4input",
                        "description": "Composite 4-input PSBT spending P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR (Taproot BIP86 key-path) inputs",
                        "type": "psbt",
                        "chain": "bip122:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
                        "raw_psbt": format!("0x{psbt_hex}"),
                        "input_paths": input_paths,
                        "public_keys": [
                            format!("0x{}", hex::encode(pk0)),
                            format!("0x{}", hex::encode(pk1)),
                            format!("0x{}", hex::encode(pk2)),
                            format!("0x{}", hex::encode(pk3)),
                        ],
                        "parsed": decoded.parsed,
                        "signer_address": decoded.signer_address,
                        "signing_inputs": [
                            format!("0x{}", hex::encode(d0)),
                            format!("0x{}", hex::encode(d1)),
                            format!("0x{}", hex::encode(d2)),
                            format!("0x{}", hex::encode(d3)),
                        ],
                        "signatures": [
                            format!("0x{}", hex::encode(&sig0)),
                            format!("0x{}", hex::encode(&sig1)),
                            format!("0x{}", hex::encode(&sig2)),
                            format!("0x{}", hex::encode(&sig3)),
                        ],
                        "signing_in_hsm": false
                    });

                    let mut found = false;
                    for item in list.iter_mut() {
                        if item["id"] == "bitcoin_psbt_composite_4input" {
                            *item = psbt_vector.clone();
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        list.push(psbt_vector);
                    }

                    let pretty = serde_json::to_string_pretty(&list).unwrap();
                    fs::write(path, pretty.as_bytes()).expect("write tx_bitcoin.json");
                }
            }
        }
    }

    #[test]
    fn test_bitcoin_reference_vectors_from_file() {
        use std::fs;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let p1 = manifest_dir.parent().unwrap().join("vectors").join("tx_bitcoin.json");
        let p2 = manifest_dir.join("vectors").join("tx_bitcoin.json");
        let path = if p1.exists() {
            p1
        } else if p2.exists() {
            p2
        } else {
            PathBuf::from("vectors/tx_bitcoin.json")
        };

        if !path.exists() {
            return;
        }

        let content = fs::read_to_string(&path).expect("read tx_bitcoin.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(&content).expect("parse tx_bitcoin.json");
        assert!(!vectors.is_empty(), "tx_bitcoin.json must not be empty");

        let codec = BitcoinCodec::new();

        for vec_val in vectors {
            let id = vec_val["id"].as_str().unwrap();
            let vec_type = vec_val.get("type").and_then(|t| t.as_str()).unwrap_or("psbt");

            match vec_type {
                "legacy_sighash" => {
                    let raw_tx_hex = vec_val["raw_tx"].as_str().unwrap();
                    let tx_bytes = hex::decode(raw_tx_hex).expect("decode tx");
                    let tx = parse_bitcoin_tx(&tx_bytes).expect("parse tx");
                    let script_hex = vec_val["script"].as_str().unwrap();
                    let script_code = hex::decode(script_hex).expect("decode script");
                    let input_idx = vec_val["input_index"].as_u64().unwrap() as usize;
                    let sht = (vec_val["sighash_type"].as_i64().unwrap() as i32) as u32;

                    let digest = compute_legacy_sighash(&tx, input_idx, &script_code, sht)
                        .expect("compute legacy sighash");
                    let mut rev = digest;
                    rev.reverse();
                    let expected_hex = vec_val["expected_sighash"].as_str().unwrap();
                    assert_eq!(hex::encode(rev), expected_hex, "vector '{id}' mismatch");
                }
                "bip143" => {
                    let raw_tx_hex = vec_val["raw_tx"].as_str().unwrap();
                    let tx_bytes = hex::decode(raw_tx_hex).expect("decode tx");
                    let tx = parse_bitcoin_tx(&tx_bytes).expect("parse tx");
                    let input_idx = vec_val["input_index"].as_u64().unwrap() as usize;
                    let pk_hash_hex = vec_val["pubkey_hash"].as_str().unwrap();
                    let pk_hash_bytes = hex::decode(pk_hash_hex).expect("decode pubkey hash");
                    let mut pk_hash = [0u8; 20];
                    pk_hash.copy_from_slice(&pk_hash_bytes);
                    let amount = vec_val["amount_sats"].as_u64().unwrap();
                    let sht = vec_val["sighash_type"].as_u64().unwrap() as u32;

                    let sighash = compute_bip143_sighash(&tx, input_idx, &pk_hash, amount, sht)
                        .expect("compute bip143 sighash");
                    let expected_hex = vec_val["expected_sighash"].as_str().unwrap();
                    assert_eq!(hex::encode(sighash), expected_hex, "vector '{id}' mismatch");
                }
                "bip341" => {
                    let raw_tx_hex = vec_val["raw_unsigned_tx"].as_str().unwrap();
                    let tx_bytes = hex::decode(raw_tx_hex).expect("decode tx");
                    let tx = parse_bitcoin_tx(&tx_bytes).expect("parse tx");
                    let input_idx = vec_val["input_index"].as_u64().unwrap() as usize;
                    let hash_type = vec_val["hash_type"].as_u64().unwrap() as u8;

                    let utxos_arr = vec_val["utxos_spent"].as_array().unwrap();
                    let prevouts: Vec<(u64, Vec<u8>)> = utxos_arr
                        .iter()
                        .map(|u| {
                            let val = u["amount_sats"].as_u64().unwrap();
                            let spk = hex::decode(u["script_pubkey"].as_str().unwrap()).unwrap();
                            (val, spk)
                        })
                        .collect();

                    let sighash = compute_bip341_sighash(&tx, input_idx, &prevouts, hash_type)
                        .expect("compute bip341 sighash");
                    let expected_hex = vec_val["expected_sighash"].as_str().unwrap();
                    assert_eq!(hex::encode(sighash), expected_hex, "vector '{id}' mismatch");
                }
                "psbt" => {
                    let chain = vec_val["chain"].as_str().unwrap();
                    let raw_psbt_hex = vec_val["raw_psbt"].as_str().unwrap().trim_start_matches("0x");
                    let raw_psbt_bytes = hex::decode(raw_psbt_hex).expect("decode psbt hex");

                    let pk_hex_arr = vec_val["public_keys"].as_array().unwrap();
                    let pk_bytes_vec: Vec<Vec<u8>> = pk_hex_arr
                        .iter()
                        .map(|pk| hex::decode(pk.as_str().unwrap().trim_start_matches("0x")).unwrap())
                        .collect();
                    let derived_keys = DerivedKeys::from(&pk_bytes_vec);

                    let paths_arr = vec_val["input_paths"].as_array().unwrap();
                    let paths_vec: Vec<&str> = paths_arr.iter().map(|p| p.as_str().unwrap()).collect();

                    let decoded = codec
                        .decode_with_paths(chain, &raw_psbt_bytes, &derived_keys, Some(&paths_vec))
                        .expect("decode psbt");

                    // Validate summary
                    assert_eq!(
                        decoded.parsed.fee.amount,
                        vec_val["parsed"]["fee"]["amount"].as_str().unwrap()
                    );
                    assert_eq!(decoded.signer_address, vec_val["signer_address"].as_str().unwrap());

                    // Validate signing inputs
                    let all_inputs = decoded.all_signing_inputs();
                    let expected_inputs = vec_val["signing_inputs"].as_array().unwrap();
                    assert_eq!(all_inputs.len(), expected_inputs.len());
                    for (actual, exp_val) in all_inputs.iter().zip(expected_inputs.iter()) {
                        let exp_hex = exp_val.as_str().unwrap().trim_start_matches("0x");
                        let actual_hex = match actual {
                            SigningInput::Digest32(d) => hex::encode(d),
                            SigningInput::TaprootDigest32(d) => hex::encode(d),
                            SigningInput::Message(m) => hex::encode(m),
                        };
                        assert_eq!(actual_hex, exp_hex);
                    }
                }
                _ => {}
            }
        }
    }
}
