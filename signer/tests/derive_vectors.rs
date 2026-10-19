//! Integration tests validating key derivation against published BIP32 and SLIP10 test vectors.
//!
//! Vectors are loaded from `vectors/bip32.json` and `vectors/slip10.json`.

use serde::Deserialize;
use signer::derive::{
    derive_bip32, derive_bip32_pair, derive_bip32_str, derive_slip10, derive_slip10_pair,
    derive_slip10_str, DerivationPath,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Bip32Vector {
    vector: u32,
    seed: String,
    chains: Vec<Bip32Chain>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Bip32Chain {
    path: String,
    #[serde(default)]
    chain_code: Option<String>,
    public_key: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Slip10Vector {
    vector: u32,
    #[serde(default)]
    curve: String,
    seed: String,
    chains: Vec<Slip10Chain>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Slip10Chain {
    path: String,
    #[serde(default)]
    chain_code: Option<String>,
    public_key: String,
    private_key: String,
}

fn get_vectors_dir() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().unwrap().join("vectors")
}

#[test]
fn test_bip32_published_vectors() {
    let vector_path = get_vectors_dir().join("bip32.json");
    let content = std::fs::read_to_string(&vector_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vector_path.display()));

    let vectors: Vec<Bip32Vector> =
        serde_json::from_str(&content).expect("failed to deserialize vectors/bip32.json");

    assert!(
        vectors.len() >= 3,
        "expected at least 3 BIP32 vectors, found {}",
        vectors.len()
    );

    let mut total_chains_tested = 0;

    for tv in &vectors {
        let seed = hex::decode(&tv.seed)
            .unwrap_or_else(|err| panic!("invalid seed hex for vector {}: {err}", tv.vector));

        for chain in &tv.chains {
            let parsed_path = DerivationPath::parse_str(&chain.path).unwrap_or_else(|err| {
                panic!(
                    "failed to parse path '{}' in vector {}: {err}",
                    chain.path, tv.vector
                )
            });

            // Test derive_bip32_str
            let derived = derive_bip32_str(&seed, &chain.path).unwrap_or_else(|err| {
                panic!(
                    "derive_bip32_str failed for vector {} path '{}': {err}",
                    tv.vector, chain.path
                )
            });

            let pub_hex = hex::encode(derived.public_key());
            let priv_hex = hex::encode(&**derived.private_key());

            assert_eq!(
                pub_hex.to_lowercase(),
                chain.public_key.to_lowercase(),
                "BIP32 vector {} path '{}' public key mismatch",
                tv.vector,
                chain.path
            );
            assert_eq!(
                priv_hex.to_lowercase(),
                chain.private_key.to_lowercase(),
                "BIP32 vector {} path '{}' private key mismatch",
                tv.vector,
                chain.path
            );

            // Cross-verify with derive_bip32 and derive_bip32_pair
            let derived_obj = derive_bip32(&seed, &parsed_path).unwrap();
            assert_eq!(derived, derived_obj);

            let (pair_priv, pair_pub) = derive_bip32_pair(&seed, &parsed_path).unwrap();
            assert_eq!(&*pair_priv, &**derived.private_key());
            assert_eq!(pair_pub, *derived.public_key());

            total_chains_tested += 1;
        }
    }

    assert!(
        total_chains_tested >= 14,
        "expected at least 14 BIP32 chains tested, got {total_chains_tested}"
    );
}

#[test]
fn test_slip10_published_vectors() {
    let vector_path = get_vectors_dir().join("slip10.json");
    let content = std::fs::read_to_string(&vector_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", vector_path.display()));

    let vectors: Vec<Slip10Vector> =
        serde_json::from_str(&content).expect("failed to deserialize vectors/slip10.json");

    assert!(
        vectors.len() >= 2,
        "expected at least 2 SLIP10 vectors, found {}",
        vectors.len()
    );

    let mut total_chains_tested = 0;

    for tv in &vectors {
        let seed = hex::decode(&tv.seed)
            .unwrap_or_else(|err| panic!("invalid seed hex for vector {}: {err}", tv.vector));

        for chain in &tv.chains {
            let parsed_path = DerivationPath::parse_str(&chain.path).unwrap_or_else(|err| {
                panic!(
                    "failed to parse path '{}' in vector {}: {err}",
                    chain.path, tv.vector
                )
            });

            // Test derive_slip10_str
            let derived = derive_slip10_str(&seed, &chain.path).unwrap_or_else(|err| {
                panic!(
                    "derive_slip10_str failed for vector {} path '{}': {err}",
                    tv.vector, chain.path
                )
            });

            let pub_hex = hex::encode(derived.public_key());
            let priv_hex = hex::encode(&**derived.private_key());

            assert_eq!(
                pub_hex.to_lowercase(),
                chain.public_key.to_lowercase(),
                "SLIP10 vector {} path '{}' public key mismatch",
                tv.vector,
                chain.path
            );
            assert_eq!(
                priv_hex.to_lowercase(),
                chain.private_key.to_lowercase(),
                "SLIP10 vector {} path '{}' private key mismatch",
                tv.vector,
                chain.path
            );

            // Cross-verify with derive_slip10 and derive_slip10_pair
            let derived_obj = derive_slip10(&seed, &parsed_path).unwrap();
            assert_eq!(derived, derived_obj);

            let (pair_priv, pair_pub) = derive_slip10_pair(&seed, &parsed_path).unwrap();
            assert_eq!(&*pair_priv, &**derived.private_key());
            assert_eq!(pair_pub, *derived.public_key());

            total_chains_tested += 1;
        }
    }

    assert!(
        total_chains_tested >= 12,
        "expected at least 12 SLIP10 chains tested, got {total_chains_tested}"
    );
}
