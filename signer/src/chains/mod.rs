//! Unified transaction summary representation and chain codec interfaces.
//!
//! This module defines the common transaction summary model (`parsed`), chain codec
//! abstractions, and codec dispatching as specified in Section 5 of `Specs.md`:
//!
//! - [`ParsedTx`]: Unified summary shape on every chain (`transfers`, `fee`, `sequence`, `details`).
//! - [`Transfer`]: Individual asset transfer summary (`from`, `to`, `amount`, `asset`).
//! - [`FeeSummary`]: Transaction fee summary (`amount`, `asset`).
//! - [`SequenceField`]: Chain-specific sequence identifier ([`SequenceField::Nonce`],
//!   [`SequenceField::Sequence`], or [`SequenceField::RecentBlockhash`]).
//! - [`SigningInput`]: Owned signing payload (32-byte digest, message bytes, or Taproot sighash).
//! - [`DerivedKeys`]: Derived public key material passed to codecs (single key or multiple keys).
//! - [`DecodedTx`]: Output of codec decoding containing [`ParsedTx`], [`SigningInput`], and `signer_address`.
//! - [`ChainCodec`]: Trait implemented by chain-specific transaction decoders (Tasks 14–19).
//! - [`CodecDispatcher`]: Registry and router dispatching transactions to the appropriate codec based on CAIP-2 chain ID.

pub mod bitcoin;
pub mod evm;
pub mod solana;
pub mod tron;
pub mod xrpl;

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Represents an individual asset transfer decoded from a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    /// Sender address formatted for the target chain.
    pub from: String,
    /// Recipient address formatted for the target chain.
    pub to: String,
    /// Base-10 or hex transfer amount (in smallest atomic units, e.g. wei, satoshis, drops, lamports).
    pub amount: String,
    /// Asset symbol or identifier (e.g. "ETH", "BTC", "SOL", "TRX", "XRP", contract address).
    pub asset: String,
}

impl Transfer {
    /// Constructs a new [`Transfer`].
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        amount: impl Into<String>,
        asset: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            amount: amount.into(),
            asset: asset.into(),
        }
    }
}

/// Represents the transaction fee summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSummary {
    /// Base-10 or hex fee amount.
    pub amount: String,
    /// Fee asset or denomination unit (e.g. "wei", "satoshis", "drops", "lamports", "sun").
    #[serde(alias = "unit")]
    pub asset: String,
}

impl FeeSummary {
    /// Constructs a new [`FeeSummary`].
    pub fn new(amount: impl Into<String>, asset: impl Into<String>) -> Self {
        Self {
            amount: amount.into(),
            asset: asset.into(),
        }
    }

    /// Returns the fee denomination unit / asset.
    pub fn unit(&self) -> &str {
        &self.asset
    }
}

/// Chain sequence identifier.
///
/// Section 5 of `Specs.md` specifies a sequence field containing either `nonce` (EVM),
/// `sequence` (XRPL / Tron), or `recent_blockhash` (Solana).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceField {
    /// Nonce counter (e.g., EVM accounts).
    Nonce(u64),
    /// Sequence counter (e.g., XRPL account sequence).
    Sequence(u64),
    /// Recent blockhash (e.g., Solana Base58 recent blockhash).
    RecentBlockhash(String),
}

impl SequenceField {
    /// Constructs a [`SequenceField::Nonce`].
    pub fn nonce(nonce: u64) -> Self {
        Self::Nonce(nonce)
    }

    /// Constructs a [`SequenceField::Sequence`].
    pub fn sequence(seq: u64) -> Self {
        Self::Sequence(seq)
    }

    /// Constructs a [`SequenceField::RecentBlockhash`].
    pub fn recent_blockhash(hash: impl Into<String>) -> Self {
        Self::RecentBlockhash(hash.into())
    }

    /// Returns the nonce value if this is [`SequenceField::Nonce`].
    pub fn as_nonce(&self) -> Option<u64> {
        match self {
            Self::Nonce(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the sequence value if this is [`SequenceField::Sequence`].
    pub fn as_sequence(&self) -> Option<u64> {
        match self {
            Self::Sequence(s) => Some(*s),
            _ => None,
        }
    }

    /// Returns the recent blockhash if this is [`SequenceField::RecentBlockhash`].
    pub fn as_recent_blockhash(&self) -> Option<&str> {
        match self {
            Self::RecentBlockhash(h) => Some(h.as_str()),
            _ => None,
        }
    }
}

/// Unified transaction summary (`parsed`) matching Section 5 of `Specs.md`.
///
/// Every supported chain decodes transactions into this common shape so that policy
/// engines and auditors can inspect any transaction regardless of underlying blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTx {
    /// Decoded value transfers (`from`, `to`, `amount`, `asset`).
    pub transfers: Vec<Transfer>,
    /// Transaction fee summary (`amount`, `asset` / unit).
    pub fee: FeeSummary,
    /// Sequence identifier (`nonce`, `sequence`, or `recent_blockhash`).
    pub sequence: SequenceField,
    /// Chain-specific metadata (e.g., gas limit, chain ID, access lists, contract call data).
    pub details: serde_json::Value,
}

impl ParsedTx {
    /// Constructs a new [`ParsedTx`].
    pub fn new(
        transfers: Vec<Transfer>,
        fee: FeeSummary,
        sequence: SequenceField,
        details: serde_json::Value,
    ) -> Self {
        Self {
            transfers,
            fee,
            sequence,
            details,
        }
    }
}

/// Owned input payload to be signed.
///
/// Converts cleanly to and from [`crate::backend::SigningInput`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningInput {
    /// 32-byte pre-hashed digest for ECDSA (`secp256k1`).
    Digest32([u8; 32]),
    /// Raw message bytes for Ed25519 (`ed25519`).
    Message(Vec<u8>),
    /// 32-byte BIP341 Taproot sighash digest for BIP340 Schnorr signing with
    /// BIP86 key-path tweak (`secp256k1`, executed in software).
    TaprootDigest32([u8; 32]),
}

impl SigningInput {
    /// Constructs a [`SigningInput::Digest32`].
    pub fn digest32(digest: [u8; 32]) -> Self {
        Self::Digest32(digest)
    }

    /// Constructs a [`SigningInput::Message`].
    pub fn message(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Message(bytes.into())
    }

    /// Constructs a [`SigningInput::TaprootDigest32`].
    pub fn taproot_digest32(digest: [u8; 32]) -> Self {
        Self::TaprootDigest32(digest)
    }

    /// Borrows this owned payload as a [`crate::backend::SigningInput`].
    pub fn to_backend_input(&self) -> crate::backend::SigningInput<'_> {
        match self {
            Self::Digest32(d) => crate::backend::SigningInput::Digest32(d),
            Self::Message(m) => crate::backend::SigningInput::Message(m.as_slice()),
            Self::TaprootDigest32(d) => crate::backend::SigningInput::TaprootDigest32(d),
        }
    }
}

impl<'a> From<&'a SigningInput> for crate::backend::SigningInput<'a> {
    fn from(input: &'a SigningInput) -> Self {
        input.to_backend_input()
    }
}

impl<'a> From<crate::backend::SigningInput<'a>> for SigningInput {
    fn from(input: crate::backend::SigningInput<'a>) -> Self {
        match input {
            crate::backend::SigningInput::Digest32(d) => Self::Digest32(*d),
            crate::backend::SigningInput::Message(m) => Self::Message(m.to_vec()),
            crate::backend::SigningInput::TaprootDigest32(d) => Self::TaprootDigest32(*d),
        }
    }
}

impl From<[u8; 32]> for SigningInput {
    fn from(bytes: [u8; 32]) -> Self {
        Self::Digest32(bytes)
    }
}

impl From<Vec<u8>> for SigningInput {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Message(bytes)
    }
}

/// Derived public key material supplied to chain codecs during decoding.
///
/// Single-key chains (EVM, Solana, Tron, XRPL) take a single public key slice.
/// Multi-input chains (Bitcoin PSBT with multiple derivation paths) provide multiple keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedKeys<'a> {
    /// Single derived public key slice (e.g. 33-byte compressed secp256k1 or 32-byte Ed25519).
    Single(&'a [u8]),
    /// Multiple derived public keys stored as owned vectors.
    Multiple(&'a [Vec<u8>]),
    /// Multiple derived public key slices.
    Slices(&'a [&'a [u8]]),
}

impl<'a> DerivedKeys<'a> {
    /// Returns the single public key or rejects if multiple keys were supplied.
    pub fn single(&self) -> Result<&'a [u8], ChainError> {
        match self {
            Self::Single(pk) => Ok(pk),
            Self::Multiple(keys) => {
                if keys.len() == 1 {
                    Ok(&keys[0])
                } else {
                    Err(ChainError::InvalidKeys(format!(
                        "expected 1 derived public key, got {}",
                        keys.len()
                    )))
                }
            }
            Self::Slices(slices) => {
                if slices.len() == 1 {
                    Ok(slices[0])
                } else {
                    Err(ChainError::InvalidKeys(format!(
                        "expected 1 derived public key, got {}",
                        slices.len()
                    )))
                }
            }
        }
    }

    /// Returns the public key at `index`, or errors if out of bounds.
    pub fn get_key(&self, index: usize) -> Result<&'a [u8], ChainError> {
        match self {
            Self::Single(pk) => {
                if index == 0 {
                    Ok(pk)
                } else {
                    Err(ChainError::InvalidKeys(format!(
                        "key index {index} out of bounds for single key"
                    )))
                }
            }
            Self::Multiple(keys) => keys.get(index).map(|k| k.as_slice()).ok_or_else(|| {
                ChainError::InvalidKeys(format!(
                    "key index {index} out of bounds (total keys: {})",
                    keys.len()
                ))
            }),
            Self::Slices(slices) => slices.get(index).copied().ok_or_else(|| {
                ChainError::InvalidKeys(format!(
                    "key index {index} out of bounds (total keys: {})",
                    slices.len()
                ))
            }),
        }
    }

    /// Returns the total number of derived keys.
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(k) => k.len(),
            Self::Slices(s) => s.len(),
        }
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> From<&'a [u8]> for DerivedKeys<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Self::Single(slice)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for DerivedKeys<'a> {
    fn from(arr: &'a [u8; N]) -> Self {
        Self::Single(arr.as_slice())
    }
}

impl<'a> From<&'a Vec<u8>> for DerivedKeys<'a> {
    fn from(v: &'a Vec<u8>) -> Self {
        Self::Single(v.as_slice())
    }
}

impl<'a> From<&'a [Vec<u8>]> for DerivedKeys<'a> {
    fn from(v: &'a [Vec<u8>]) -> Self {
        Self::Multiple(v)
    }
}

impl<'a> From<&'a Vec<Vec<u8>>> for DerivedKeys<'a> {
    fn from(v: &'a Vec<Vec<u8>>) -> Self {
        Self::Multiple(v.as_slice())
    }
}

impl<'a> From<&'a [&'a [u8]]> for DerivedKeys<'a> {
    fn from(slices: &'a [&'a [u8]]) -> Self {
        Self::Slices(slices)
    }
}

/// Result of decoding a transaction through a [`ChainCodec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedTx {
    /// Decoded common summary shape.
    pub parsed: ParsedTx,
    /// Primary signing input payload.
    pub signing_input: SigningInput,
    /// Formatted signer address matching the derived key.
    pub signer_address: String,
    /// Additional signing inputs for multi-input transactions (e.g. Bitcoin PSBT).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_signing_inputs: Vec<SigningInput>,
}

impl DecodedTx {
    /// Constructs a new [`DecodedTx`].
    pub fn new(
        parsed: ParsedTx,
        signing_input: SigningInput,
        signer_address: impl Into<String>,
    ) -> Self {
        Self {
            parsed,
            signing_input,
            signer_address: signer_address.into(),
            additional_signing_inputs: Vec::new(),
        }
    }

    /// Attaches additional signing inputs (e.g. for multi-input Bitcoin transactions).
    pub fn with_additional_inputs(
        mut self,
        additional: impl IntoIterator<Item = SigningInput>,
    ) -> Self {
        self.additional_signing_inputs.extend(additional);
        self
    }

    /// Returns an iterator/vector over all signing inputs (primary + additional).
    pub fn all_signing_inputs(&self) -> Vec<&SigningInput> {
        let mut list = Vec::with_capacity(1 + self.additional_signing_inputs.len());
        list.push(&self.signing_input);
        list.extend(self.additional_signing_inputs.iter());
        list
    }

    /// Destructures into the 3 core items: `(parsed, signing_input, signer_address)`.
    pub fn into_parts(self) -> (ParsedTx, SigningInput, String) {
        (self.parsed, self.signing_input, self.signer_address)
    }
}

impl From<DecodedTx> for (ParsedTx, SigningInput, String) {
    fn from(tx: DecodedTx) -> Self {
        tx.into_parts()
    }
}

/// Errors returned by chain codecs and transaction dispatching.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Transaction payload or instruction is unsupported by policy or codec.
    #[error("unsupported transaction: {0}")]
    UnsupportedTransaction(String),

    /// Transaction internal chain/network ID does not match the request `chain`.
    #[error("chain mismatch: expected '{expected}', found '{actual}'")]
    ChainMismatch {
        /// Expected chain identifier from request envelope.
        expected: String,
        /// Actual chain identifier decoded from inside the transaction.
        actual: String,
    },

    /// The CAIP-2 chain namespace is unsupported.
    #[error("unsupported chain namespace: '{0}'")]
    UnsupportedChain(String),

    /// Raw transaction payload could not be parsed (malformed RLP, protobuf, binary, or PSBT).
    #[error("malformed transaction: {0}")]
    MalformedTransaction(String),

    /// The derived key does not match the transaction signer/sender.
    #[error("key mismatch: {0}")]
    KeyMismatch(String),

    /// Invalid public key material passed to the codec.
    #[error("invalid keys: {0}")]
    InvalidKeys(String),

    /// Cryptographic error during address recovery or digest calculation.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl ChainError {
    /// Returns the stable RFC 9457 error reason code specified in Section 6 of `Specs.md`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedTransaction(_) => "unsupported_transaction",
            Self::ChainMismatch { .. } => "chain_mismatch",
            Self::UnsupportedChain(_) => "unsupported_transaction",
            Self::MalformedTransaction(_) => "unsupported_transaction",
            Self::KeyMismatch(_) => "key_mismatch",
            Self::InvalidKeys(_) => "invalid_keys",
            Self::Crypto(_) => "crypto_error",
        }
    }
}

impl From<crate::backend::BackendError> for ChainError {
    fn from(err: crate::backend::BackendError) -> Self {
        Self::Crypto(err.to_string())
    }
}

impl From<serde_json::Error> for ChainError {
    fn from(err: serde_json::Error) -> Self {
        Self::MalformedTransaction(err.to_string())
    }
}

/// Supported blockchain namespaces identified from CAIP-2 chain identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainNamespace {
    /// Ethereum and EVM networks (`eip155:<chain_id>`).
    Evm,
    /// Solana networks (`solana:<cluster_or_genesis>`).
    Solana,
    /// Tron networks (`tron:<network>`).
    Tron,
    /// XRP Ledger networks (`xrpl:<network>`).
    Xrpl,
    /// Bitcoin networks (`bip122:<genesis_hash>` or `bitcoin:<network>`).
    Bitcoin,
}

impl ChainNamespace {
    /// Resolves the [`ChainNamespace`] from a CAIP-2 chain identifier (e.g. `"eip155:1"`).
    pub fn from_chain_id(chain: &str) -> Result<Self, ChainError> {
        let (namespace, _) = parse_caip2(chain)?;
        match namespace {
            "eip155" => Ok(Self::Evm),
            "solana" => Ok(Self::Solana),
            "tron" => Ok(Self::Tron),
            "xrpl" => Ok(Self::Xrpl),
            "bip122" | "bitcoin" => Ok(Self::Bitcoin),
            other => Err(ChainError::UnsupportedChain(other.to_string())),
        }
    }

    /// Returns the canonical CAIP-2 prefix for this chain namespace.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Evm => "eip155",
            Self::Solana => "solana",
            Self::Tron => "tron",
            Self::Xrpl => "xrpl",
            Self::Bitcoin => "bip122",
        }
    }
}

/// Parses a CAIP-2 chain identifier into its `(namespace, reference)` tuple.
pub fn parse_caip2(chain: &str) -> Result<(&str, &str), ChainError> {
    let mut parts = chain.splitn(2, ':');
    let ns = parts.next().unwrap_or("");
    let ref_id = parts.next().unwrap_or("");
    if ns.is_empty() || ref_id.is_empty() {
        return Err(ChainError::UnsupportedTransaction(format!(
            "invalid CAIP-2 chain identifier '{chain}', expected 'namespace:reference'"
        )));
    }
    Ok((ns, ref_id))
}

/// Chain codec interface implemented by chain-specific decoders.
///
/// Decodes a raw unsigned transaction for `chain` using the derived public key(s),
/// verifying network identifiers and sender bindings, and producing [`DecodedTx`].
pub trait ChainCodec: Send + Sync {
    /// Decodes a raw transaction into summary (`ParsedTx`), `SigningInput`, and `signer_address`.
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError>;
}

impl<F> ChainCodec for F
where
    F: Fn(&str, &[u8], &DerivedKeys) -> Result<DecodedTx, ChainError> + Send + Sync,
{
    fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        self(chain, raw_tx_bytes, keys)
    }
}

/// Registry and router dispatching transactions to registered [`ChainCodec`] implementations.
pub struct CodecDispatcher {
    codecs: HashMap<ChainNamespace, Box<dyn ChainCodec>>,
}

impl CodecDispatcher {
    /// Constructs a new, empty [`CodecDispatcher`].
    pub fn new() -> Self {
        Self {
            codecs: HashMap::new(),
        }
    }

    /// Constructs a [`CodecDispatcher`] pre-configured with all built-in chain codecs (Bitcoin, EVM, Solana, Tron, XRPL).
    pub fn with_builtin_codecs() -> Self {
        let mut dispatcher = Self::new();
        dispatcher.register(ChainNamespace::Bitcoin, Box::new(crate::chains::bitcoin::BitcoinCodec::new()));
        dispatcher.register(ChainNamespace::Evm, Box::new(crate::chains::evm::EvmCodec::new()));
        dispatcher.register(ChainNamespace::Solana, Box::new(crate::chains::solana::SolanaCodec::new()));
        dispatcher.register(ChainNamespace::Tron, Box::new(crate::chains::tron::TronCodec::new()));
        dispatcher.register(ChainNamespace::Xrpl, Box::new(crate::chains::xrpl::XrplCodec::new()));
        dispatcher
    }

    /// Registers a [`ChainCodec`] for a specific [`ChainNamespace`].
    pub fn register(&mut self, namespace: ChainNamespace, codec: Box<dyn ChainCodec>) {
        self.codecs.insert(namespace, codec);
    }

    /// Returns a reference to the registered [`ChainCodec`] for `namespace`, if present.
    pub fn get(&self, namespace: ChainNamespace) -> Option<&dyn ChainCodec> {
        self.codecs.get(&namespace).map(|c| c.as_ref())
    }

    /// Dispatches decoding of `raw_tx_bytes` for `chain` to the appropriate registered codec.
    pub fn decode(
        &self,
        chain: &str,
        raw_tx_bytes: &[u8],
        keys: &DerivedKeys,
    ) -> Result<DecodedTx, ChainError> {
        let namespace = ChainNamespace::from_chain_id(chain)?;
        let codec = self.get(namespace).ok_or_else(|| {
            ChainError::UnsupportedTransaction(format!(
                "no codec registered for chain '{chain}' (namespace: {namespace:?})"
            ))
        })?;
        codec.decode(chain, raw_tx_bytes, keys)
    }
}

impl Default for CodecDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsed_tx_json_serialization_matches_spec() {
        let transfer = Transfer::new(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "1000000000000000000",
            "ETH",
        );
        let fee = FeeSummary::new("21000", "wei");
        let sequence = SequenceField::nonce(42);
        let details = serde_json::json!({
            "chain_id": 1,
            "gas_limit": 21000,
            "max_fee_per_gas": "20000000000",
            "max_priority_fee_per_gas": "1000000000"
        });

        let parsed = ParsedTx::new(vec![transfer], fee, sequence, details);

        let json_value = serde_json::to_value(&parsed).expect("must serialize");
        assert!(json_value.get("transfers").is_some());
        assert!(json_value.get("fee").is_some());
        assert!(json_value.get("sequence").is_some());
        assert!(json_value.get("details").is_some());

        // Verify transfers array
        let transfers = json_value["transfers"].as_array().expect("transfers is array");
        assert_eq!(transfers.len(), 1);
        assert_eq!(
            transfers[0]["from"],
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert_eq!(
            transfers[0]["to"],
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(transfers[0]["amount"], "1000000000000000000");
        assert_eq!(transfers[0]["asset"], "ETH");

        // Verify fee
        assert_eq!(json_value["fee"]["amount"], "21000");
        assert_eq!(json_value["fee"]["asset"], "wei");

        // Verify sequence
        assert_eq!(json_value["sequence"]["nonce"], 42);

        // Verify roundtrip deserialization
        let roundtrip: ParsedTx = serde_json::from_value(json_value).expect("must deserialize");
        assert_eq!(roundtrip, parsed);
    }

    #[test]
    fn test_sequence_field_variants_and_helpers() {
        // Nonce
        let nonce = SequenceField::nonce(10);
        assert_eq!(nonce.as_nonce(), Some(10));
        assert_eq!(nonce.as_sequence(), None);
        assert_eq!(nonce.as_recent_blockhash(), None);
        let json_nonce = serde_json::to_string(&nonce).expect("serialize nonce");
        assert_eq!(json_nonce, r#"{"nonce":10}"#);
        let de_nonce: SequenceField = serde_json::from_str(&json_nonce).expect("deserialize");
        assert_eq!(de_nonce, nonce);

        // Sequence
        let seq = SequenceField::sequence(555);
        assert_eq!(seq.as_sequence(), Some(555));
        assert_eq!(seq.as_nonce(), None);
        let json_seq = serde_json::to_string(&seq).expect("serialize seq");
        assert_eq!(json_seq, r#"{"sequence":555}"#);
        let de_seq: SequenceField = serde_json::from_str(&json_seq).expect("deserialize");
        assert_eq!(de_seq, seq);

        // Recent Blockhash
        let blockhash = SequenceField::recent_blockhash("4vJ9JU1bJJE96Dn6sHSdP13epS886EdNvEKKBxNmTib3");
        assert_eq!(
            blockhash.as_recent_blockhash(),
            Some("4vJ9JU1bJJE96Dn6sHSdP13epS886EdNvEKKBxNmTib3")
        );
        let json_bh = serde_json::to_string(&blockhash).expect("serialize bh");
        assert_eq!(
            json_bh,
            r#"{"recent_blockhash":"4vJ9JU1bJJE96Dn6sHSdP13epS886EdNvEKKBxNmTib3"}"#
        );
        let de_bh: SequenceField = serde_json::from_str(&json_bh).expect("deserialize");
        assert_eq!(de_bh, blockhash);
    }

    #[test]
    fn test_fee_summary_unit_alias() {
        // Deserializing JSON with "unit" instead of "asset"
        let json_unit = r#"{"amount":"5000","unit":"lamports"}"#;
        let fee: FeeSummary = serde_json::from_str(json_unit).expect("deserialize with unit");
        assert_eq!(fee.amount, "5000");
        assert_eq!(fee.asset, "lamports");
        assert_eq!(fee.unit(), "lamports");

        // Serializing produces "asset"
        let serialized = serde_json::to_string(&fee).expect("serialize");
        assert!(serialized.contains(r#""asset":"lamports""#));
    }

    #[test]
    fn test_signing_input_conversions() {
        let digest = [0xabu8; 32];
        let input_digest = SigningInput::digest32(digest);
        let backend_digest = input_digest.to_backend_input();
        match backend_digest {
            crate::backend::SigningInput::Digest32(d) => assert_eq!(d, &digest),
            _ => panic!("expected Digest32"),
        }

        let message = b"solana-raw-tx-message".to_vec();
        let input_msg = SigningInput::message(message.clone());
        let backend_msg = input_msg.to_backend_input();
        match backend_msg {
            crate::backend::SigningInput::Message(m) => assert_eq!(m, message.as_slice()),
            _ => panic!("expected Message"),
        }

        let taproot_digest = [0xefu8; 32];
        let input_tr = SigningInput::taproot_digest32(taproot_digest);
        let backend_tr = input_tr.to_backend_input();
        match backend_tr {
            crate::backend::SigningInput::TaprootDigest32(d) => assert_eq!(d, &taproot_digest),
            _ => panic!("expected TaprootDigest32"),
        }

        // Roundtrip from backend SigningInput
        let from_backend: SigningInput = backend_digest.into();
        assert_eq!(from_backend, input_digest);
    }

    #[test]
    fn test_derived_keys_single_and_multiple() {
        let key1 = [1u8; 33];
        let key2 = [2u8; 33];

        // Single key from array / slice
        let dk_single = DerivedKeys::from(&key1);
        assert_eq!(dk_single.len(), 1);
        assert!(!dk_single.is_empty());
        assert_eq!(dk_single.single().unwrap(), key1.as_slice());
        assert_eq!(dk_single.get_key(0).unwrap(), key1.as_slice());
        assert!(dk_single.get_key(1).is_err());

        // Multiple keys from slice of Vec
        let keys_vec = vec![key1.to_vec(), key2.to_vec()];
        let dk_multiple = DerivedKeys::from(keys_vec.as_slice());
        assert_eq!(dk_multiple.len(), 2);
        assert!(dk_multiple.single().is_err()); // rejects single() when multiple
        assert_eq!(dk_multiple.get_key(0).unwrap(), key1.as_slice());
        assert_eq!(dk_multiple.get_key(1).unwrap(), key2.as_slice());
        assert!(dk_multiple.get_key(2).is_err());

        // Slices variant
        let key1_ref = key1.as_slice();
        let key2_ref = key2.as_slice();
        let slices = [key1_ref, key2_ref];
        let dk_slices = DerivedKeys::from(slices.as_slice());
        assert_eq!(dk_slices.len(), 2);
        assert_eq!(dk_slices.get_key(1).unwrap(), key2.as_slice());
    }

    #[test]
    fn test_decoded_tx_and_additional_inputs() {
        let parsed = ParsedTx::new(
            vec![],
            FeeSummary::new("1000", "satoshis"),
            SequenceField::sequence(0),
            serde_json::Value::Null,
        );
        let primary_sig = SigningInput::digest32([1u8; 32]);
        let additional1 = SigningInput::digest32([2u8; 32]);
        let additional2 = SigningInput::taproot_digest32([3u8; 32]);

        let decoded = DecodedTx::new(parsed.clone(), primary_sig.clone(), "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
            .with_additional_inputs(vec![additional1.clone(), additional2.clone()]);

        assert_eq!(decoded.signer_address, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        assert_eq!(decoded.all_signing_inputs().len(), 3);
        assert_eq!(decoded.all_signing_inputs()[0], &primary_sig);
        assert_eq!(decoded.all_signing_inputs()[1], &additional1);
        assert_eq!(decoded.all_signing_inputs()[2], &additional2);

        // Destructure into parts
        let (p, s, addr) = decoded.into_parts();
        assert_eq!(p, parsed);
        assert_eq!(s, primary_sig);
        assert_eq!(addr, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
    }

    #[test]
    fn test_chain_namespace_and_caip2_parsing() {
        assert_eq!(
            ChainNamespace::from_chain_id("eip155:1").unwrap(),
            ChainNamespace::Evm
        );
        assert_eq!(
            ChainNamespace::from_chain_id("eip155:137").unwrap(),
            ChainNamespace::Evm
        );
        assert_eq!(
            ChainNamespace::from_chain_id("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").unwrap(),
            ChainNamespace::Solana
        );
        assert_eq!(
            ChainNamespace::from_chain_id("solana:mainnet").unwrap(),
            ChainNamespace::Solana
        );
        assert_eq!(
            ChainNamespace::from_chain_id("tron:0x2b6653dc").unwrap(),
            ChainNamespace::Tron
        );
        assert_eq!(
            ChainNamespace::from_chain_id("xrpl:0").unwrap(),
            ChainNamespace::Xrpl
        );
        assert_eq!(
            ChainNamespace::from_chain_id("bip122:000000000019d6689c085ae165831e93").unwrap(),
            ChainNamespace::Bitcoin
        );
        assert_eq!(
            ChainNamespace::from_chain_id("bitcoin:mainnet").unwrap(),
            ChainNamespace::Bitcoin
        );

        // Rejections
        assert!(ChainNamespace::from_chain_id("cosmos:cosmoshub-4").is_err());
        assert!(ChainNamespace::from_chain_id("invalid_no_colon").is_err());
        assert!(ChainNamespace::from_chain_id(":reference_only").is_err());
    }

    #[test]
    fn test_chain_error_reason_codes() {
        assert_eq!(
            ChainError::UnsupportedTransaction("unknown opcode".into()).reason_code(),
            "unsupported_transaction"
        );
        assert_eq!(
            ChainError::ChainMismatch {
                expected: "eip155:1".into(),
                actual: "eip155:137".into(),
            }
            .reason_code(),
            "chain_mismatch"
        );
        assert_eq!(
            ChainError::UnsupportedChain("polkadot".into()).reason_code(),
            "unsupported_transaction"
        );
        assert_eq!(
            ChainError::MalformedTransaction("bad rlp".into()).reason_code(),
            "unsupported_transaction"
        );
        assert_eq!(
            ChainError::KeyMismatch("wrong sender".into()).reason_code(),
            "key_mismatch"
        );
        assert_eq!(
            ChainError::InvalidKeys("empty keys".into()).reason_code(),
            "invalid_keys"
        );
    }

    #[test]
    fn test_codec_dispatcher_flow() {
        let mut dispatcher = CodecDispatcher::new();

        // Register a mock EVM codec closure
        let mock_evm_codec = |chain: &str, raw_tx: &[u8], keys: &DerivedKeys| -> Result<DecodedTx, ChainError> {
            if chain != "eip155:1" {
                return Err(ChainError::ChainMismatch {
                    expected: chain.to_string(),
                    actual: "eip155:1".to_string(),
                });
            }
            let _pubkey = keys.single()?;
            let parsed = ParsedTx::new(
                vec![Transfer::new("0xfrom", "0xto", "100", "ETH")],
                FeeSummary::new("21000", "wei"),
                SequenceField::nonce(1),
                serde_json::json!({ "raw_len": raw_tx.len() }),
            );
            Ok(DecodedTx::new(
                parsed,
                SigningInput::digest32([0x42u8; 32]),
                "0xfrom",
            ))
        };

        dispatcher.register(ChainNamespace::Evm, Box::new(mock_evm_codec));

        let pubkey = [0x02u8; 33];
        let derived_keys = DerivedKeys::from(&pubkey);

        // Successful decode through dispatcher
        let decoded = dispatcher
            .decode("eip155:1", b"dummy-tx-bytes", &derived_keys)
            .expect("must decode");
        assert_eq!(decoded.signer_address, "0xfrom");
        assert_eq!(decoded.parsed.fee.amount, "21000");

        // Rejection on unregistered namespace (Solana)
        let err_solana = dispatcher.decode("solana:mainnet", b"msg", &derived_keys);
        match err_solana {
            Err(ChainError::UnsupportedTransaction(msg)) => {
                assert!(msg.contains("no codec registered"));
            }
            other => panic!("expected UnsupportedTransaction, got {other:?}"),
        }

        // Rejection on chain mismatch inside codec
        let err_mismatch = dispatcher.decode("eip155:137", b"tx", &derived_keys);
        match err_mismatch {
            Err(ChainError::ChainMismatch { expected, actual }) => {
                assert_eq!(expected, "eip155:137");
                assert_eq!(actual, "eip155:1");
            }
            other => panic!("expected ChainMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_codec_dispatcher_with_builtin_codecs() {
        let dispatcher = CodecDispatcher::with_builtin_codecs();
        assert!(dispatcher.get(ChainNamespace::Evm).is_some());
        assert!(dispatcher.get(ChainNamespace::Solana).is_some());
        assert!(dispatcher.get(ChainNamespace::Tron).is_some());
        assert!(dispatcher.get(ChainNamespace::Xrpl).is_some());
        assert!(dispatcher.get(ChainNamespace::Bitcoin).is_some());
    }
}
