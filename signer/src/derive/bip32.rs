//! BIP32 hierarchical deterministic key derivation for `secp256k1`.
//!
//! Complies with BIP-0032 specification:
//! - Master key generation from seed (16 to 64 bytes) via HMAC-SHA512 (`Bitcoin seed`).
//! - Iterative child key derivation (hardened and non-hardened).
//! - All intermediate secrets, chain codes, and private keys wrapped in `Zeroizing`.
//! - Chain codes are strictly kept internal and never exposed in public API returns.
//! - Invalid child keys (`IL >= n` or `key == 0`) fail explicitly with the child index.

use std::fmt;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, SecretKey};
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

use super::path::{is_hardened, DerivationPath, DerivationScheme, PathError};

/// HMAC-SHA512 key for BIP32 master key generation.
pub const BIP32_SEED_KEY: &[u8] = b"Bitcoin seed";

/// Minimum recommended BIP32 seed length in bytes (128 bits).
pub const MIN_SEED_LEN: usize = 16;

/// Maximum recommended BIP32 seed length in bytes (512 bits).
pub const MAX_SEED_LEN: usize = 64;

/// SEC1 compressed public key length in bytes for secp256k1.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Private key scalar length in bytes for secp256k1.
pub const PRIVATE_KEY_LEN: usize = 32;

/// Chain code length in bytes.
pub const CHAIN_CODE_LEN: usize = 32;

type HmacSha512 = Hmac<Sha512>;

/// Errors occurring during BIP32 key derivation.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum Bip32Error {
    /// Seed length is outside the valid range of 16 to 64 bytes (128 to 512 bits).
    #[error("invalid seed length {length} bytes; must be between {min} and {max} bytes")]
    InvalidSeedLength {
        length: usize,
        min: usize,
        max: usize,
    },

    /// Master key generation failed because derived IL >= curve order n or IL == 0.
    #[error("invalid master key derived from seed (IL >= curve order or key == 0)")]
    InvalidMasterKey,

    /// Child key derivation failed for an invalid child key.
    #[error("invalid child key at index {index} (0x{index:08x}): {reason}")]
    InvalidChildKey {
        index: u32,
        reason: &'static str,
    },

    /// Failed to construct public key from private key scalar.
    #[error("failed to compute public key: {0}")]
    PublicKeyComputationFailed(String),

    /// Derivation path error.
    #[error("derivation path error: {0}")]
    Path(#[from] PathError),
}

/// Derived BIP32 key pair containing the 32-byte zeroized private key
/// and 33-byte compressed SEC1 public key.
///
/// Note: Chain codes are intentionally omitted to prevent accidental leakage.
#[derive(Clone, PartialEq, Eq)]
pub struct Bip32Key {
    /// Derived 32-byte secp256k1 private key, wrapped in `Zeroizing`.
    pub private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    /// Derived 33-byte compressed SEC1 public key (`0x02` or `0x03` prefix + 32-byte X coordinate).
    pub public_key: [u8; COMPRESSED_PUBKEY_LEN],
}

impl fmt::Debug for Bip32Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bip32Key")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(self.public_key))
            .finish()
    }
}

impl Bip32Key {
    /// Returns a reference to the zeroized 32-byte private key.
    pub fn private_key(&self) -> &Zeroizing<[u8; PRIVATE_KEY_LEN]> {
        &self.private_key
    }

    /// Returns a reference to the 33-byte compressed SEC1 public key.
    pub fn public_key(&self) -> &[u8; COMPRESSED_PUBKEY_LEN] {
        &self.public_key
    }

    /// Consumes the key struct and returns the private key and public key pair.
    pub fn into_parts(self) -> (Zeroizing<[u8; PRIVATE_KEY_LEN]>, [u8; COMPRESSED_PUBKEY_LEN]) {
        (self.private_key, self.public_key)
    }
}

impl From<Bip32Key> for (Zeroizing<[u8; PRIVATE_KEY_LEN]>, [u8; COMPRESSED_PUBKEY_LEN]) {
    fn from(key: Bip32Key) -> Self {
        key.into_parts()
    }
}

/// Internal extended private key holding private key scalar and chain code.
/// Wipes both on drop.
struct ExtendedPrivateKey {
    key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    chain_code: Zeroizing<[u8; CHAIN_CODE_LEN]>,
}

impl ExtendedPrivateKey {
    /// Creates a master extended private key from a seed slice.
    fn master(seed: &[u8]) -> Result<Self, Bip32Error> {
        if seed.len() < MIN_SEED_LEN || seed.len() > MAX_SEED_LEN {
            return Err(Bip32Error::InvalidSeedLength {
                length: seed.len(),
                min: MIN_SEED_LEN,
                max: MAX_SEED_LEN,
            });
        }

        let mut mac = HmacSha512::new_from_slice(BIP32_SEED_KEY)
            .map_err(|_| Bip32Error::InvalidMasterKey)?;
        mac.update(seed);
        let i = Zeroizing::new(mac.finalize().into_bytes());

        let mut il_bytes = Zeroizing::new([0u8; 32]);
        il_bytes.copy_from_slice(&i[0..32]);
        let mut il_scalar_opt = Option::<Scalar>::from(Scalar::from_repr((*il_bytes).into()));
        let valid = matches!(il_scalar_opt, Some(ref s) if *s != Scalar::ZERO);
        if let Some(ref mut s) = il_scalar_opt {
            zeroize::Zeroize::zeroize(s);
        }
        if !valid {
            return Err(Bip32Error::InvalidMasterKey);
        }

        let mut key = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        let mut chain_code = Zeroizing::new([0u8; CHAIN_CODE_LEN]);
        key.copy_from_slice(&i[0..32]);
        chain_code.copy_from_slice(&i[32..64]);

        Ok(Self { key, chain_code })
    }

    /// Derives a child extended private key at the given index.
    fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let mut data = Zeroizing::new([0u8; 37]);

        if is_hardened(index) {
            // Hardened child: 0x00 || ser_256(k_par) || ser_32(i)
            data[0] = 0x00;
            data[1..33].copy_from_slice(&*self.key);
            data[33..37].copy_from_slice(&index.to_be_bytes());
        } else {
            // Normal child: ser_P(point(k_par)) || ser_32(i)
            let parent_pubkey = public_key_from_private(&*self.key)?;
            data[0..33].copy_from_slice(&parent_pubkey);
            data[33..37].copy_from_slice(&index.to_be_bytes());
        }

        let mut mac = HmacSha512::new_from_slice(&*self.chain_code)
            .map_err(|_| Bip32Error::InvalidChildKey {
                index,
                reason: "invalid parent chain code for HMAC",
            })?;
        mac.update(&*data);
        let i = Zeroizing::new(mac.finalize().into_bytes());

        let mut il_bytes = Zeroizing::new([0u8; 32]);
        il_bytes.copy_from_slice(&i[0..32]);
        let il_scalar_opt = Option::<Scalar>::from(Scalar::from_repr((*il_bytes).into()));
        let mut il_scalar = match il_scalar_opt {
            Some(s) => s,
            None => {
                return Err(Bip32Error::InvalidChildKey {
                    index,
                    reason: "derived intermediate key IL exceeds curve order",
                });
            }
        };

        let mut parent_scalar =
            match Option::<Scalar>::from(Scalar::from_repr((*self.key).into())) {
                Some(s) => s,
                None => {
                    zeroize::Zeroize::zeroize(&mut il_scalar);
                    return Err(Bip32Error::InvalidChildKey {
                        index,
                        reason: "invalid parent private key scalar",
                    });
                }
            };

        let mut child_scalar = il_scalar + parent_scalar;
        zeroize::Zeroize::zeroize(&mut il_scalar);
        zeroize::Zeroize::zeroize(&mut parent_scalar);

        if child_scalar == Scalar::ZERO {
            return Err(Bip32Error::InvalidChildKey {
                index,
                reason: "derived child private key is zero",
            });
        }

        let mut child_key = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        let mut child_chain = Zeroizing::new([0u8; CHAIN_CODE_LEN]);

        let mut child_scalar_bytes = child_scalar.to_bytes();
        zeroize::Zeroize::zeroize(&mut child_scalar);
        child_key.copy_from_slice(child_scalar_bytes.as_ref());
        zeroize::Zeroize::zeroize(AsMut::<[u8]>::as_mut(&mut child_scalar_bytes));
        child_chain.copy_from_slice(&i[32..64]);

        Ok(Self {
            key: child_key,
            chain_code: child_chain,
        })
    }
}

/// Computes the 33-byte compressed SEC1 public key for a 32-byte secp256k1 private key.
pub fn public_key_from_private(
    private_key: &[u8; PRIVATE_KEY_LEN],
) -> Result<[u8; COMPRESSED_PUBKEY_LEN], Bip32Error> {
    let secret_key = SecretKey::from_slice(private_key)
        .map_err(|e| Bip32Error::PublicKeyComputationFailed(e.to_string()))?;
    let public_key = secret_key.public_key();
    let encoded_point = public_key.to_encoded_point(true);
    let mut out = [0u8; COMPRESSED_PUBKEY_LEN];
    out.copy_from_slice(encoded_point.as_bytes());
    Ok(out)
}

/// Derives a BIP32 child key pair from a seed and derivation path.
///
/// Returns `Bip32Key` containing the derived 32-byte private key inside `Zeroizing`
/// and 33-byte compressed SEC1 public key.
///
/// If any derived child key is invalid (`IL >= n` or `key == 0`), an explicit
/// `Bip32Error::InvalidChildKey` is returned naming the offending child index.
pub fn derive_bip32(seed: &[u8], path: &DerivationPath) -> Result<Bip32Key, Bip32Error> {
    path.validate_for_scheme(DerivationScheme::Bip32)?;

    let mut ext_key = ExtendedPrivateKey::master(seed)?;

    for &index in path.as_slice() {
        ext_key = ext_key.derive_child(index)?;
    }

    let public_key = public_key_from_private(&*ext_key.key)?;

    Ok(Bip32Key {
        private_key: ext_key.key,
        public_key,
    })
}

/// Derives a BIP32 child key pair from a seed and derivation path, returning
/// a raw tuple `(Zeroizing<[u8; 32]>, [u8; 33])`.
pub fn derive_bip32_pair(
    seed: &[u8],
    path: &DerivationPath,
) -> Result<(Zeroizing<[u8; PRIVATE_KEY_LEN]>, [u8; COMPRESSED_PUBKEY_LEN]), Bip32Error> {
    derive_bip32(seed, path).map(|k| k.into_parts())
}

/// Helper function to parse a derivation path string and derive the BIP32 key.
pub fn derive_bip32_str(seed: &[u8], path_str: &str) -> Result<Bip32Key, Bip32Error> {
    let path = DerivationPath::parse_str(path_str)?;
    derive_bip32(seed, &path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::path::HARDENED_FLAG;

    // BIP32 Test Vector 1
    // Seed: 000102030405060708090a0b0c0d0e0f
    const TV1_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn test_bip32_vector_1() {
        let seed = hex::decode(TV1_SEED_HEX).unwrap();

        // m
        let k_m = derive_bip32_str(&seed, "m").unwrap();
        assert_eq!(
            hex::encode(k_m.public_key()),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
        assert_eq!(
            hex::encode(&**k_m.private_key()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );

        // m/0'
        let k_0h = derive_bip32_str(&seed, "m/0'").unwrap();
        assert_eq!(
            hex::encode(k_0h.public_key()),
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
        );
        assert_eq!(
            hex::encode(&**k_0h.private_key()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );

        // m/0'/1
        let k_0h_1 = derive_bip32_str(&seed, "m/0'/1").unwrap();
        assert_eq!(
            hex::encode(k_0h_1.public_key()),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
        );
        assert_eq!(
            hex::encode(&**k_0h_1.private_key()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );

        // m/0'/1/2'
        let k_0h_1_2h = derive_bip32_str(&seed, "m/0'/1/2'").unwrap();
        assert_eq!(
            hex::encode(k_0h_1_2h.public_key()),
            "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
        );
        assert_eq!(
            hex::encode(&**k_0h_1_2h.private_key()),
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
        );

        // m/0'/1/2'/2
        let k_0h_1_2h_2 = derive_bip32_str(&seed, "m/0'/1/2'/2").unwrap();
        assert_eq!(
            hex::encode(k_0h_1_2h_2.public_key()),
            "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
        );
        assert_eq!(
            hex::encode(&**k_0h_1_2h_2.private_key()),
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
        );

        // m/0'/1/2'/2/1000000000
        let k_deep = derive_bip32_str(&seed, "m/0'/1/2'/2/1000000000").unwrap();
        assert_eq!(
            hex::encode(k_deep.public_key()),
            "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
        );
        assert_eq!(
            hex::encode(&**k_deep.private_key()),
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        );
    }

    // BIP32 Test Vector 2
    // Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    const TV2_SEED_HEX: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn test_bip32_vector_2() {
        let seed = hex::decode(TV2_SEED_HEX).unwrap();

        // m
        let k_m = derive_bip32_str(&seed, "m").unwrap();
        assert_eq!(
            hex::encode(k_m.public_key()),
            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
        );
        assert_eq!(
            hex::encode(&**k_m.private_key()),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );

        // m/0
        let k_0 = derive_bip32_str(&seed, "m/0").unwrap();
        assert_eq!(
            hex::encode(k_0.public_key()),
            "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
        );
        assert_eq!(
            hex::encode(&**k_0.private_key()),
            "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
        );

        // m/0/2147483647'
        let k_0_maxh = derive_bip32_str(&seed, "m/0/2147483647'").unwrap();
        assert_eq!(
            hex::encode(k_0_maxh.public_key()),
            "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"
        );
        assert_eq!(
            hex::encode(&**k_0_maxh.private_key()),
            "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
        );

        // m/0/2147483647'/1
        let k_0_maxh_1 = derive_bip32_str(&seed, "m/0/2147483647'/1").unwrap();
        assert_eq!(
            hex::encode(k_0_maxh_1.public_key()),
            "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"
        );
        assert_eq!(
            hex::encode(&**k_0_maxh_1.private_key()),
            "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
        );

        // m/0/2147483647'/1/2147483646'
        let k_0_maxh_1_prevh = derive_bip32_str(&seed, "m/0/2147483647'/1/2147483646'").unwrap();
        assert_eq!(
            hex::encode(k_0_maxh_1_prevh.public_key()),
            "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
        );
        assert_eq!(
            hex::encode(&**k_0_maxh_1_prevh.private_key()),
            "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
        );

        // m/0/2147483647'/1/2147483646'/2
        let k_final = derive_bip32_str(&seed, "m/0/2147483647'/1/2147483646'/2").unwrap();
        assert_eq!(
            hex::encode(k_final.public_key()),
            "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
        );
        assert_eq!(
            hex::encode(&**k_final.private_key()),
            "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
        );
    }

    // BIP32 Test Vector 3
    // Seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    const TV3_SEED_HEX: &str = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";

    #[test]
    fn test_bip32_vector_3() {
        let seed = hex::decode(TV3_SEED_HEX).unwrap();

        // m: master private key has leading zero (00ddb80b...)
        let k_m = derive_bip32_str(&seed, "m").unwrap();
        assert_eq!(
            hex::encode(k_m.public_key()),
            "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669"
        );
        assert_eq!(
            hex::encode(&**k_m.private_key()),
            "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32"
        );

        // m/0'
        let k_0h = derive_bip32_str(&seed, "m/0'").unwrap();
        assert_eq!(
            hex::encode(k_0h.public_key()),
            "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2"
        );
        assert_eq!(
            hex::encode(&**k_0h.private_key()),
            "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef"
        );
    }

    // BIP32 Test Vector 4
    // Seed: 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678
    const TV4_SEED_HEX: &str = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";

    #[test]
    fn test_bip32_vector_4() {
        let seed = hex::decode(TV4_SEED_HEX).unwrap();

        // m
        let k_m = derive_bip32_str(&seed, "m").unwrap();
        assert_eq!(
            hex::encode(k_m.public_key()),
            "026f6fedc9240f61daa9c7144b682a430a3a1366576f840bf2d070101fcbc9a02d"
        );
        assert_eq!(
            hex::encode(&**k_m.private_key()),
            "12c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215"
        );

        // m/0'
        let k_0h = derive_bip32_str(&seed, "m/0'").unwrap();
        assert_eq!(
            hex::encode(k_0h.public_key()),
            "039382d2b6003446792d2917f7ac4b3edf079a1a94dd4eb010dc25109dda680a9d"
        );
        assert_eq!(
            hex::encode(&**k_0h.private_key()),
            "00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e"
        );

        // m/0'/1'
        let k_0h_1h = derive_bip32_str(&seed, "m/0'/1'").unwrap();
        assert_eq!(
            hex::encode(k_0h_1h.public_key()),
            "032edaf9e591ee27f3c69c36221e3c54c38088ef34e93fbb9bb2d4d9b92364cbbd"
        );
        assert_eq!(
            hex::encode(&**k_0h_1h.private_key()),
            "3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d"
        );
    }

    #[test]
    fn test_seed_length_validation() {
        // Less than 16 bytes rejected
        let short_seed = [0u8; 15];
        let path = DerivationPath::parse_str("m/0'").unwrap();
        let err = derive_bip32(&short_seed, &path).unwrap_err();
        match err {
            Bip32Error::InvalidSeedLength { length, min, max } => {
                assert_eq!(length, 15);
                assert_eq!(min, 16);
                assert_eq!(max, 64);
            }
            other => panic!("expected InvalidSeedLength, got {other:?}"),
        }

        // More than 64 bytes rejected
        let long_seed = [0u8; 65];
        let err2 = derive_bip32(&long_seed, &path).unwrap_err();
        match err2 {
            Bip32Error::InvalidSeedLength { length, min, max } => {
                assert_eq!(length, 65);
                assert_eq!(min, 16);
                assert_eq!(max, 64);
            }
            other => panic!("expected InvalidSeedLength, got {other:?}"),
        }

        // Exact bounds 16 and 64 pass seed length validation
        let seed_16 = [1u8; 16];
        assert!(derive_bip32(&seed_16, &path).is_ok());

        let seed_64 = [1u8; 64];
        assert!(derive_bip32(&seed_64, &path).is_ok());
    }

    #[test]
    fn test_pair_and_conversion() {
        let seed = hex::decode(TV1_SEED_HEX).unwrap();
        let path = DerivationPath::parse_str("m/0'/1").unwrap();

        let (priv_key, pub_key) = derive_bip32_pair(&seed, &path).unwrap();
        assert_eq!(
            hex::encode(pub_key),
            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
        );
        assert_eq!(
            hex::encode(&*priv_key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn test_invalid_child_key_error_naming_index() {
        // Construct an invalid child key test directly verifying the error formatting
        let err = Bip32Error::InvalidChildKey {
            index: 42 | HARDENED_FLAG,
            reason: "derived intermediate key IL exceeds curve order",
        };
        let formatted = format!("{err}");
        assert!(formatted.contains("index 2147483690"));
        assert!(formatted.contains("0x8000002a"));
        assert!(formatted.contains("derived intermediate key IL exceeds curve order"));
    }

    #[test]
    fn test_debug_redacts_private_key() {
        let seed = hex::decode(TV1_SEED_HEX).unwrap();
        let key = derive_bip32_str(&seed, "m").unwrap();
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"));
        assert!(debug_str.contains("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"));
    }
}
