//! Key derivation modules (BIP32, SLIP10, path parser).

pub mod bip32;
pub mod path;
pub mod slip10;

pub use bip32::{
    derive_bip32, derive_bip32_pair, derive_bip32_str, public_key_from_private, Bip32Error,
    Bip32Key, BIP32_SEED_KEY, CHAIN_CODE_LEN, COMPRESSED_PUBKEY_LEN, MAX_SEED_LEN,
    MIN_SEED_LEN, PRIVATE_KEY_LEN,
};
pub use path::{
    is_hardened, to_hardened, unhardened_index, validate_path, DerivationPath, DerivationScheme,
    PathError, HARDENED_FLAG, MAX_DEPTH,
};
pub use slip10::{
    derive_slip10, derive_slip10_ed25519, derive_slip10_ed25519_pair, derive_slip10_ed25519_str,
    derive_slip10_pair, derive_slip10_str, public_key_from_private_ed25519, Slip10Error,
    Slip10Key, ED25519_PRIVATE_KEY_LEN, ED25519_PUBKEY_LEN, SLIP10_ED25519_SEED_KEY,
};

/// Errors encountered during the startup derivation self-test.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DerivationSelfTestError {
    #[error("BIP32 self-test derivation failed: {0}")]
    Bip32(#[from] Bip32Error),
    #[error("BIP32 self-test mismatch: {0}")]
    Bip32Mismatch(String),
    #[error("SLIP10 self-test derivation failed: {0}")]
    Slip10(#[from] Slip10Error),
    #[error("SLIP10 self-test mismatch: {0}")]
    Slip10Mismatch(String),
}

/// Executes built-in BIP32 (secp256k1, vectors 1–3) and SLIP10 (ed25519, vectors 1–2)
/// vector self-tests embedded at compile time.
///
/// Intended to be invoked at startup by the startup capability probe
/// (`signer/src/backend/generic/probe.rs` in Task 11) to fail-closed on any
/// derivation divergence without requiring runtime filesystem access.
pub fn run_derivation_self_test() -> Result<(), DerivationSelfTestError> {
    // Published BIP32 Test Vectors 1, 2, and 3 (all 14 chains)
    let bip32_vectors: &[(&str, &str, &[(&str, &str, &str)])] = &[
        (
            "TV1",
            "000102030405060708090a0b0c0d0e0f",
            &[
                (
                    "m",
                    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                ),
                (
                    "m/0'",
                    "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
                    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                ),
                (
                    "m/0'/1",
                    "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
                    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                ),
                (
                    "m/0'/1/2'",
                    "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
                    "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                ),
                (
                    "m/0'/1/2'/2",
                    "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
                    "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                ),
                (
                    "m/0'/1/2'/2/1000000000",
                    "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
                    "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                ),
            ],
        ),
        (
            "TV2",
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            &[
                (
                    "m",
                    "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
                    "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                ),
                (
                    "m/0",
                    "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
                    "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                ),
                (
                    "m/0/2147483647'",
                    "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
                    "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                ),
                (
                    "m/0/2147483647'/1",
                    "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
                    "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                ),
                (
                    "m/0/2147483647'/1/2147483646'",
                    "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
                    "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                ),
                (
                    "m/0/2147483647'/1/2147483646'/2",
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
                    "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                ),
            ],
        ),
        (
            "TV3",
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            &[
                (
                    "m",
                    "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669",
                    "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
                ),
                (
                    "m/0'",
                    "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2",
                    "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
                ),
            ],
        ),
    ];

    for (tv_name, seed_hex, chains) in bip32_vectors {
        let seed = zeroize::Zeroizing::new(hex::decode(seed_hex).unwrap());
        for (path, exp_pub, exp_priv) in *chains {
            let key = derive_bip32_str(&seed, path)?;
            let pub_hex = hex::encode(key.public_key());
            let priv_hex = zeroize::Zeroizing::new(hex::encode(&**key.private_key()));
            if pub_hex != *exp_pub {
                return Err(DerivationSelfTestError::Bip32Mismatch(format!(
                    "{tv_name} ({path}) public key mismatch: got {pub_hex}"
                )));
            }
            if *priv_hex != *exp_priv {
                return Err(DerivationSelfTestError::Bip32Mismatch(format!(
                    "{tv_name} ({path}) private key mismatch"
                )));
            }
        }
    }

    // Published SLIP10 ed25519 Test Vectors 1 and 2 (all 12 chains)
    let slip10_vectors: &[(&str, &str, &[(&str, &str, &str)])] = &[
        (
            "TV1",
            "000102030405060708090a0b0c0d0e0f",
            &[
                (
                    "m",
                    "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                ),
                (
                    "m/0'",
                    "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                ),
                (
                    "m/0'/1'",
                    "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                ),
                (
                    "m/0'/1'/2'",
                    "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                ),
                (
                    "m/0'/1'/2'/2'",
                    "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                ),
                (
                    "m/0'/1'/2'/2'/1000000000'",
                    "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                ),
            ],
        ),
        (
            "TV2",
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            &[
                (
                    "m",
                    "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                ),
                (
                    "m/0'",
                    "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                ),
                (
                    "m/0'/2147483647'",
                    "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                ),
                (
                    "m/0'/2147483647'/1'",
                    "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                ),
                (
                    "m/0'/2147483647'/1'/2147483646'",
                    "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                ),
                (
                    "m/0'/2147483647'/1'/2147483646'/2'",
                    "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                    "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                ),
            ],
        ),
    ];

    for (tv_name, seed_hex, chains) in slip10_vectors {
        let seed = zeroize::Zeroizing::new(hex::decode(seed_hex).unwrap());
        for (path, exp_pub, exp_priv) in *chains {
            let key = derive_slip10_str(&seed, path)?;
            let pub_hex = hex::encode(key.public_key());
            let priv_hex = zeroize::Zeroizing::new(hex::encode(&**key.private_key()));
            if pub_hex != *exp_pub {
                return Err(DerivationSelfTestError::Slip10Mismatch(format!(
                    "{tv_name} ({path}) public key mismatch: got {pub_hex}"
                )));
            }
            if *priv_hex != *exp_priv {
                return Err(DerivationSelfTestError::Slip10Mismatch(format!(
                    "{tv_name} ({path}) private key mismatch"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_self_test() {
        assert!(run_derivation_self_test().is_ok());
    }
}
