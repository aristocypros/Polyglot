//! SLIP10 key derivation for `ed25519`.
//!
//! Complies with the SLIP-0010 specification:
//! - Master key generation from seed (16 to 64 bytes) via HMAC-SHA512 (`ed25519 seed`).
//! - Iterative hardened-only child key derivation on curve `ed25519`.
//! - Non-hardened child indices are strictly rejected before HMAC evaluation.
//! - All intermediate secrets, chain codes, and derived private key seeds are wrapped in `Zeroizing`.
//! - Chain codes are strictly kept internal and never exposed in public API returns.
//! - 32-byte compressed Ed25519 public keys are computed via `ed25519-dalek`.

use std::fmt;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use thiserror::Error;
use zeroize::Zeroizing;

use super::path::{is_hardened, DerivationPath, DerivationScheme, PathError};

/// HMAC-SHA512 key for SLIP10 ed25519 master key generation.
pub const SLIP10_ED25519_SEED_KEY: &[u8] = b"ed25519 seed";

/// Minimum recommended SLIP10 seed length in bytes (128 bits).
pub const MIN_SEED_LEN: usize = 16;

/// Maximum recommended SLIP10 seed length in bytes (512 bits).
pub const MAX_SEED_LEN: usize = 64;

/// Ed25519 public key length in bytes (compressed Edwards point).
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 private key scalar/seed length in bytes.
pub const ED25519_PRIVATE_KEY_LEN: usize = 32;

/// Chain code length in bytes.
pub const CHAIN_CODE_LEN: usize = 32;

type HmacSha512 = Hmac<Sha512>;

/// Errors occurring during SLIP10 key derivation.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum Slip10Error {
    /// Seed length is outside the valid range of 16 to 64 bytes (128 to 512 bits).
    #[error("invalid seed length {length} bytes; must be between {min} and {max} bytes")]
    InvalidSeedLength {
        length: usize,
        min: usize,
        max: usize,
    },

    /// Master key generation failed.
    #[error("failed to derive master key from seed")]
    InvalidMasterKey,

    /// Non-hardened derivation is not permitted for ed25519 under SLIP10.
    #[error("non-hardened index {index} (0x{index:08x}) is not allowed for SLIP10 (ed25519)")]
    NonHardenedIndexNotAllowed {
        index: u32,
    },

    /// Child key derivation failed for an invalid child key or HMAC error.
    #[error("invalid child key at index {index} (0x{index:08x}): {reason}")]
    InvalidChildKey {
        index: u32,
        reason: &'static str,
    },

    /// Derivation path error.
    #[error("derivation path error: {0}")]
    Path(#[from] PathError),
}

/// Derived SLIP10 key pair containing the 32-byte zeroized Ed25519 private key seed
/// and 32-byte compressed Ed25519 public key.
///
/// Note: Chain codes are intentionally omitted to prevent accidental leakage.
#[derive(Clone, PartialEq, Eq)]
pub struct Slip10Key {
    /// Derived 32-byte Ed25519 private key seed, wrapped in `Zeroizing`.
    pub private_key: Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>,
    /// Derived 32-byte compressed Ed25519 public key.
    pub public_key: [u8; ED25519_PUBKEY_LEN],
}

impl fmt::Debug for Slip10Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slip10Key")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(self.public_key))
            .finish()
    }
}

impl Slip10Key {
    /// Returns a reference to the zeroized 32-byte private key.
    pub fn private_key(&self) -> &Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]> {
        &self.private_key
    }

    /// Returns a reference to the 32-byte compressed Ed25519 public key.
    pub fn public_key(&self) -> &[u8; ED25519_PUBKEY_LEN] {
        &self.public_key
    }

    /// Consumes the key struct and returns the private key and public key pair.
    pub fn into_parts(self) -> (Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>, [u8; ED25519_PUBKEY_LEN]) {
        (self.private_key, self.public_key)
    }
}

impl From<Slip10Key> for (Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>, [u8; ED25519_PUBKEY_LEN]) {
    fn from(key: Slip10Key) -> Self {
        key.into_parts()
    }
}

/// Internal extended private key holding private key seed and chain code.
/// Wipes both on drop.
struct ExtendedPrivateKey {
    key: Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>,
    chain_code: Zeroizing<[u8; CHAIN_CODE_LEN]>,
}

impl fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("key", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .finish()
    }
}

impl ExtendedPrivateKey {
    /// Creates a master extended private key from a seed slice.
    fn master(seed: &[u8]) -> Result<Self, Slip10Error> {
        if seed.len() < MIN_SEED_LEN || seed.len() > MAX_SEED_LEN {
            return Err(Slip10Error::InvalidSeedLength {
                length: seed.len(),
                min: MIN_SEED_LEN,
                max: MAX_SEED_LEN,
            });
        }

        let mut mac = HmacSha512::new_from_slice(SLIP10_ED25519_SEED_KEY)
            .map_err(|_| Slip10Error::InvalidMasterKey)?;
        mac.update(seed);
        let i = Zeroizing::new(mac.finalize().into_bytes());

        let mut key = Zeroizing::new([0u8; ED25519_PRIVATE_KEY_LEN]);
        let mut chain_code = Zeroizing::new([0u8; CHAIN_CODE_LEN]);
        key.copy_from_slice(&i[0..32]);
        chain_code.copy_from_slice(&i[32..64]);

        Ok(Self { key, chain_code })
    }

    /// Derives a hardened child extended private key at the given index.
    ///
    /// Rejects non-hardened child indices before HMAC evaluation.
    fn derive_child(&self, index: u32) -> Result<Self, Slip10Error> {
        if !is_hardened(index) {
            return Err(Slip10Error::NonHardenedIndexNotAllowed { index });
        }

        // Hardened child data: 0x00 || ser_256(k_par) || ser_32(i) (37 bytes total)
        let mut data = Zeroizing::new([0u8; 37]);
        data[0] = 0x00;
        data[1..33].copy_from_slice(&*self.key);
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&*self.chain_code)
            .map_err(|_| Slip10Error::InvalidChildKey {
                index,
                reason: "invalid parent chain code for HMAC",
            })?;
        mac.update(&*data);
        let i = Zeroizing::new(mac.finalize().into_bytes());

        let mut child_key = Zeroizing::new([0u8; ED25519_PRIVATE_KEY_LEN]);
        let mut child_chain = Zeroizing::new([0u8; CHAIN_CODE_LEN]);
        child_key.copy_from_slice(&i[0..32]);
        child_chain.copy_from_slice(&i[32..64]);

        Ok(Self {
            key: child_key,
            chain_code: child_chain,
        })
    }
}

/// Computes the 32-byte compressed Ed25519 public key for a 32-byte Ed25519 private key seed.
pub fn public_key_from_private(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
) -> [u8; ED25519_PUBKEY_LEN] {
    let signing_key = SigningKey::from_bytes(private_key);
    let verifying_key = signing_key.verifying_key();
    verifying_key.to_bytes()
}

/// Alias for `public_key_from_private` specifically indicating Ed25519.
pub fn public_key_from_private_ed25519(
    private_key: &[u8; ED25519_PRIVATE_KEY_LEN],
) -> [u8; ED25519_PUBKEY_LEN] {
    public_key_from_private(private_key)
}

/// Derives a SLIP10 ed25519 child key pair from a seed and derivation path.
///
/// Returns `Slip10Key` containing the derived 32-byte private key seed inside `Zeroizing`
/// and the 32-byte compressed Ed25519 public key.
///
/// Strictly rejects non-hardened child indices before HMAC computation.
pub fn derive_slip10_ed25519(seed: &[u8], path: &DerivationPath) -> Result<Slip10Key, Slip10Error> {
    path.validate_for_scheme(DerivationScheme::Slip10)?;

    let mut ext_key = ExtendedPrivateKey::master(seed)?;

    for &index in path.as_slice() {
        ext_key = ext_key.derive_child(index)?;
    }

    let public_key = public_key_from_private(&*ext_key.key);

    Ok(Slip10Key {
        private_key: ext_key.key,
        public_key,
    })
}

/// Alias for `derive_slip10_ed25519`.
pub fn derive_slip10(seed: &[u8], path: &DerivationPath) -> Result<Slip10Key, Slip10Error> {
    derive_slip10_ed25519(seed, path)
}

/// Derives a SLIP10 ed25519 child key pair from a seed and derivation path, returning
/// a raw tuple `(Zeroizing<[u8; 32]>, [u8; 32])`.
pub fn derive_slip10_ed25519_pair(
    seed: &[u8],
    path: &DerivationPath,
) -> Result<(Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>, [u8; ED25519_PUBKEY_LEN]), Slip10Error> {
    let key = derive_slip10_ed25519(seed, path)?;
    Ok(key.into_parts())
}

/// Alias for `derive_slip10_ed25519_pair`.
pub fn derive_slip10_pair(
    seed: &[u8],
    path: &DerivationPath,
) -> Result<(Zeroizing<[u8; ED25519_PRIVATE_KEY_LEN]>, [u8; ED25519_PUBKEY_LEN]), Slip10Error> {
    derive_slip10_ed25519_pair(seed, path)
}

/// Derives a SLIP10 ed25519 child key pair from a seed and a path string (e.g. `m/44'/501'/0'/0'`).
pub fn derive_slip10_ed25519_str(seed: &[u8], path_str: &str) -> Result<Slip10Key, Slip10Error> {
    let path = DerivationPath::parse_str(path_str)?;
    derive_slip10_ed25519(seed, &path)
}

/// Alias for `derive_slip10_ed25519_str`.
pub fn derive_slip10_str(seed: &[u8], path_str: &str) -> Result<Slip10Key, Slip10Error> {
    derive_slip10_ed25519_str(seed, path_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Vector 1 from official SLIP-0010 specification for ed25519.
    /// Seed: 000102030405060708090a0b0c0d0e0f
    #[test]
    fn test_slip10_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // Chain m (Master)
        let master = derive_slip10_str(&seed, "m").expect("master derivation failed");
        assert_eq!(
            hex::encode(master.private_key().as_ref()),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(master.public_key()),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );

        // Chain m/0H
        let child_0h = derive_slip10_str(&seed, "m/0'").expect("m/0' derivation failed");
        assert_eq!(
            hex::encode(child_0h.private_key().as_ref()),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(child_0h.public_key()),
            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"
        );

        // Also test "m/0H" notation
        let child_0h_notation = derive_slip10_str(&seed, "m/0H").expect("m/0H derivation failed");
        assert_eq!(child_0h, child_0h_notation);

        // Chain m/0H/1H
        let grandchild_1h = derive_slip10_str(&seed, "m/0'/1'").expect("m/0'/1' derivation failed");
        assert_eq!(
            hex::encode(grandchild_1h.private_key().as_ref()),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(grandchild_1h.public_key()),
            "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"
        );

        // Test with "m/0H/1H"
        let grandchild_h_notation = derive_slip10_str(&seed, "m/0H/1H").unwrap();
        assert_eq!(grandchild_1h, grandchild_h_notation);
    }

    /// Test Vector 2 from official SLIP-0010 specification for ed25519.
    /// Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    #[test]
    fn test_slip10_vector_2() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();

        // Chain m
        let m = derive_slip10_str(&seed, "m").expect("m derivation failed");
        assert_eq!(
            hex::encode(m.private_key().as_ref()),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
        );
        assert_eq!(
            hex::encode(m.public_key()),
            "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"
        );

        // Chain m/0H
        let m_0h = derive_slip10_str(&seed, "m/0'").expect("m/0' derivation failed");
        assert_eq!(
            hex::encode(m_0h.private_key().as_ref()),
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
        );
        assert_eq!(
            hex::encode(m_0h.public_key()),
            "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"
        );

        // Chain m/0H/2147483647H
        let m_0h_max = derive_slip10_str(&seed, "m/0'/2147483647'").expect("m/0'/2147483647' derivation failed");
        assert_eq!(
            hex::encode(m_0h_max.private_key().as_ref()),
            "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"
        );
        assert_eq!(
            hex::encode(m_0h_max.public_key()),
            "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"
        );

        // Chain m/0H/2147483647H/1H
        let m_deep = derive_slip10_str(&seed, "m/0'/2147483647'/1'").expect("depth 3 derivation failed");
        assert_eq!(
            hex::encode(m_deep.private_key().as_ref()),
            "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"
        );
        assert_eq!(
            hex::encode(m_deep.public_key()),
            "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"
        );

        // Chain m/0H/2147483647H/1H/2147483646H
        let m_deep4 = derive_slip10_str(&seed, "m/0'/2147483647'/1'/2147483646'").expect("depth 4 derivation failed");
        assert_eq!(
            hex::encode(m_deep4.private_key().as_ref()),
            "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"
        );
        assert_eq!(
            hex::encode(m_deep4.public_key()),
            "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b"
        );
    }

    #[test]
    fn test_non_hardened_rejection() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // Non-hardened index in path string
        let err = derive_slip10_str(&seed, "m/0").unwrap_err();
        match err {
            Slip10Error::Path(PathError::NonHardenedIndexNotAllowed { position, index }) => {
                assert_eq!(position, 0);
                assert_eq!(index, 0);
            }
            other => panic!("expected NonHardenedIndexNotAllowed, got: {other:?}"),
        }

        // Non-hardened child in multi-segment path
        let err = derive_slip10_str(&seed, "m/44'/501'/0'/0").unwrap_err();
        match err {
            Slip10Error::Path(PathError::NonHardenedIndexNotAllowed { position, index }) => {
                assert_eq!(position, 3);
                assert_eq!(index, 0);
            }
            other => panic!("expected NonHardenedIndexNotAllowed, got: {other:?}"),
        }

        // Direct call to derive_child with unhardened index
        let ext_master = ExtendedPrivateKey::master(&seed).unwrap();
        let direct_err = ext_master.derive_child(0).unwrap_err();
        assert_eq!(
            direct_err,
            Slip10Error::NonHardenedIndexNotAllowed { index: 0 }
        );
    }

    #[test]
    fn test_seed_length_validation() {
        // Less than 16 bytes (15 bytes)
        let short_seed = vec![0x42u8; 15];
        let err = derive_slip10_str(&short_seed, "m").unwrap_err();
        assert_eq!(
            err,
            Slip10Error::InvalidSeedLength {
                length: 15,
                min: 16,
                max: 64
            }
        );

        // Exactly 16 bytes (valid)
        let min_seed = vec![0x42u8; 16];
        assert!(derive_slip10_str(&min_seed, "m").is_ok());

        // Exactly 64 bytes (valid)
        let max_seed = vec![0x42u8; 64];
        assert!(derive_slip10_str(&max_seed, "m").is_ok());

        // More than 64 bytes (65 bytes)
        let long_seed = vec![0x42u8; 65];
        let err = derive_slip10_str(&long_seed, "m").unwrap_err();
        assert_eq!(
            err,
            Slip10Error::InvalidSeedLength {
                length: 65,
                min: 16,
                max: 64
            }
        );
    }

    #[test]
    fn test_debug_redacts_private_key() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = derive_slip10_str(&seed, "m").unwrap();
        let debug_str = format!("{key:?}");

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"));
        assert!(debug_str.contains("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"));
    }

    #[test]
    fn test_pair_and_conversion() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let path = DerivationPath::parse_str("m/0'").unwrap();

        let key = derive_slip10(&seed, &path).unwrap();
        let (priv_pair, pub_pair) = derive_slip10_pair(&seed, &path).unwrap();

        assert_eq!(key.private_key().as_ref(), priv_pair.as_ref());
        assert_eq!(key.public_key(), &pub_pair);

        let (priv_into, pub_into): (Zeroizing<[u8; 32]>, [u8; 32]) = key.clone().into();
        assert_eq!(priv_into.as_ref(), key.private_key().as_ref());
        assert_eq!(&pub_into, key.public_key());
    }

    #[test]
    fn test_solana_derivation_path() {
        // Solana standard derivation path: m/44'/501'/0'/0'
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let solana_key = derive_slip10_str(&seed, "m/44'/501'/0'/0'").expect("Solana derivation failed");
        assert_eq!(solana_key.public_key().len(), 32);
        assert_eq!(solana_key.private_key().len(), 32);
    }
}
