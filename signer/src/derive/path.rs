//! Derivation path parser, validator, and formatter.
//!
//! Supports BIP32/SLIP10 derivation paths in both string notation
//! (`m/44'/0'/0'/0/5` or `m/44h/0h/...`) and raw 32-bit index arrays (`[u32]`),
//! where bit 31 (`0x8000_0000`) marks hardened indices.
//!
//! Maximum supported depth is 255 (matching Thales Luna HSM limits).

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Bit flag set on 32-bit child index to denote hardened key derivation.
pub const HARDENED_FLAG: u32 = 0x8000_0000;

/// Maximum allowed derivation depth (matches Thales Luna HSM limit).
pub const MAX_DEPTH: usize = 255;

/// Derivation schemes supported by the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DerivationScheme {
    /// BIP32 hierarchical deterministic key derivation (secp256k1).
    /// Supports both hardened and non-hardened child indices.
    #[serde(alias = "Bip32", alias = "bip32", alias = "BIP32")]
    Bip32,

    /// SLIP10 key derivation for Ed25519.
    /// Strictly requires all child indices in the path to be hardened.
    #[serde(alias = "Slip10", alias = "slip10", alias = "SLIP10")]
    Slip10,
}

impl fmt::Display for DerivationScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivationScheme::Bip32 => write!(f, "bip32"),
            DerivationScheme::Slip10 => write!(f, "slip10"),
        }
    }
}

/// Errors occurring during derivation path parsing or scheme validation.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PathError {
    /// Path depth exceeds the maximum allowed depth of 255.
    #[error("path depth {depth} exceeds maximum allowed depth of {max}")]
    ExceedsMaxDepth { depth: usize, max: usize },

    /// Path does not start with standard 'm' or 'M' prefix.
    #[error("path must begin with 'm' or 'M' prefix, got '{0}'")]
    MissingMasterPrefix(String),

    /// An empty segment was encountered in the path string (e.g. `m//0` or `m/0/`).
    #[error("empty path segment at position {position}")]
    EmptySegment { position: usize },

    /// An index in the path string could not be parsed.
    #[error("invalid index '{value}' at position {position}: {reason}")]
    InvalidIndex {
        position: usize,
        value: String,
        reason: String,
    },

    /// An index exceeds the maximum 31-bit child index (0x7FFFFFFF).
    #[error("index '{value}' at position {position} exceeds maximum 31-bit child index (0x7FFFFFFF)")]
    IndexOverflow { position: usize, value: String },

    /// A non-hardened index was encountered where only hardened derivation is permitted (SLIP10).
    #[error("non-hardened index {index} at position {position} is not allowed for SLIP10 (ed25519)")]
    NonHardenedIndexNotAllowed { position: usize, index: u32 },
}

/// Returns true if the child index has the hardened bit (`0x8000_0000`) set.
#[inline]
pub fn is_hardened(index: u32) -> bool {
    (index & HARDENED_FLAG) != 0
}

/// Sets the hardened bit on a 31-bit child index.
///
/// Returns `Err(PathError::IndexOverflow)` if the value already exceeds `0x7FFF_FFFF`.
pub fn to_hardened(index: u32) -> Result<u32, PathError> {
    if (index & HARDENED_FLAG) != 0 {
        return Err(PathError::IndexOverflow {
            position: 0,
            value: index.to_string(),
        });
    }
    Ok(index | HARDENED_FLAG)
}

/// Strips the hardened bit, returning the raw 31-bit index.
#[inline]
pub fn unhardened_index(index: u32) -> u32 {
    index & !HARDENED_FLAG
}

/// Validates an array of derivation indices for depth and scheme compliance.
pub fn validate_path(indices: &[u32], scheme: DerivationScheme) -> Result<(), PathError> {
    if indices.len() > MAX_DEPTH {
        return Err(PathError::ExceedsMaxDepth {
            depth: indices.len(),
            max: MAX_DEPTH,
        });
    }
    match scheme {
        DerivationScheme::Bip32 => Ok(()),
        DerivationScheme::Slip10 => {
            for (pos, &idx) in indices.iter().enumerate() {
                if !is_hardened(idx) {
                    return Err(PathError::NonHardenedIndexNotAllowed {
                        position: pos,
                        index: idx,
                    });
                }
            }
            Ok(())
        }
    }
}

/// A parsed and validated key derivation path.
///
/// Internally stores indices as 32-bit unsigned integers with `0x8000_0000`
/// marking hardened indices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DerivationPath {
    indices: Vec<u32>,
}

impl DerivationPath {
    /// Creates a `DerivationPath` from a vector of 32-bit indices.
    ///
    /// Validates that the depth does not exceed `MAX_DEPTH` (255).
    pub fn new(indices: Vec<u32>) -> Result<Self, PathError> {
        if indices.len() > MAX_DEPTH {
            return Err(PathError::ExceedsMaxDepth {
                depth: indices.len(),
                max: MAX_DEPTH,
            });
        }
        Ok(Self { indices })
    }

    /// Creates a `DerivationPath` from a slice of 32-bit indices.
    pub fn from_slice(indices: &[u32]) -> Result<Self, PathError> {
        Self::new(indices.to_vec())
    }

    /// Creates a master (empty) derivation path of depth 0.
    pub fn master() -> Self {
        Self {
            indices: Vec::new(),
        }
    }

    /// Parses a derivation path string.
    ///
    /// Accepted formats:
    /// - `"m"` or `"M"` for master key (depth 0).
    /// - `"m/44'/0'/0'/0/5"` (standard apostrophe for hardened indices).
    /// - `"m/44h/0h/0h/0/5"` or `"m/44H/0H/..."` (`h`/`H` notation for hardened).
    ///
    /// Returns `PathError` if the string is malformed, has negative/overflow indices,
    /// or exceeds maximum depth.
    pub fn parse_str(s: &str) -> Result<Self, PathError> {
        let trimmed = s.trim();

        if trimmed.is_empty() {
            return Err(PathError::MissingMasterPrefix(s.to_string()));
        }

        if trimmed == "m" || trimmed == "M" {
            return Ok(Self::master());
        }

        let rest = if let Some(stripped) = trimmed.strip_prefix("m/") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("M/") {
            stripped
        } else {
            return Err(PathError::MissingMasterPrefix(s.to_string()));
        };

        let segments: Vec<&str> = rest.split('/').collect();
        if segments.len() > MAX_DEPTH {
            return Err(PathError::ExceedsMaxDepth {
                depth: segments.len(),
                max: MAX_DEPTH,
            });
        }

        let mut indices = Vec::with_capacity(segments.len());

        for (pos, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                return Err(PathError::EmptySegment { position: pos });
            }

            let (num_str, hardened) = if let Some(stripped) = seg.strip_suffix('\'') {
                (stripped, true)
            } else if let Some(stripped) = seg.strip_suffix('h') {
                (stripped, true)
            } else if let Some(stripped) = seg.strip_suffix('H') {
                (stripped, true)
            } else {
                (*seg, false)
            };

            if num_str.is_empty() {
                return Err(PathError::InvalidIndex {
                    position: pos,
                    value: (*seg).to_string(),
                    reason: "empty index before hardening marker".to_string(),
                });
            }

            if num_str.starts_with('-') || num_str.starts_with('+') {
                return Err(PathError::InvalidIndex {
                    position: pos,
                    value: (*seg).to_string(),
                    reason: "sign character not allowed".to_string(),
                });
            }

            let value: u64 = num_str.parse().map_err(|e| PathError::InvalidIndex {
                position: pos,
                value: (*seg).to_string(),
                reason: format!("failed to parse integer: {e}"),
            })?;

            if value > 0x7FFF_FFFF {
                return Err(PathError::IndexOverflow {
                    position: pos,
                    value: (*seg).to_string(),
                });
            }

            let mut idx = value as u32;
            if hardened {
                idx |= HARDENED_FLAG;
            }
            indices.push(idx);
        }

        Ok(Self { indices })
    }

    /// Returns the indices as a slice of `u32`.
    pub fn as_slice(&self) -> &[u32] {
        &self.indices
    }

    /// Consumes the path and returns the underlying `Vec<u32>`.
    pub fn into_indices(self) -> Vec<u32> {
        self.indices
    }

    /// Returns the depth of the derivation path (number of child levels).
    pub fn depth(&self) -> usize {
        self.indices.len()
    }

    /// Returns true if the path is the master path (depth 0).
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Validates that the path conforms to the rules of the given derivation scheme.
    ///
    /// - `Bip32`: accepts hardened and non-hardened child indices.
    /// - `Slip10`: strictly requires all child indices to be hardened.
    pub fn validate_for_scheme(&self, scheme: DerivationScheme) -> Result<(), PathError> {
        validate_path(&self.indices, scheme)
    }

    /// Formats the derivation path into string notation.
    ///
    /// If `use_h` is true, hardened indices use the `h` suffix (e.g. `m/44h/0h/...`).
    /// Otherwise, standard apostrophe `'` is used (e.g. `m/44'/0'/...`).
    pub fn to_string_formatted(&self, use_h: bool) -> String {
        if self.indices.is_empty() {
            return "m".to_string();
        }

        let suffix = if use_h { "h" } else { "'" };
        let mut out = String::from("m");

        for &idx in &self.indices {
            out.push('/');
            if is_hardened(idx) {
                let base = unhardened_index(idx);
                out.push_str(&format!("{base}{suffix}"));
            } else {
                out.push_str(&idx.to_string());
            }
        }

        out
    }
}

impl Deref for DerivationPath {
    type Target = [u32];

    fn deref(&self) -> &Self::Target {
        &self.indices
    }
}

impl AsRef<[u32]> for DerivationPath {
    fn as_ref(&self) -> &[u32] {
        &self.indices
    }
}

impl FromStr for DerivationPath {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

impl TryFrom<&[u32]> for DerivationPath {
    type Error = PathError;

    fn try_from(slice: &[u32]) -> Result<Self, Self::Error> {
        Self::from_slice(slice)
    }
}

impl TryFrom<Vec<u32>> for DerivationPath {
    type Error = PathError;

    fn try_from(vec: Vec<u32>) -> Result<Self, Self::Error> {
        Self::new(vec)
    }
}

impl From<DerivationPath> for Vec<u32> {
    fn from(path: DerivationPath) -> Self {
        path.indices
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_formatted(false))
    }
}

impl Serialize for DerivationPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.indices.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DerivationPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DerivationPathVisitor;

        impl<'de> Visitor<'de> for DerivationPathVisitor {
            type Value = DerivationPath;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a derivation path string (e.g. \"m/44'/0'/0'/0/5\") or array of 32-bit indices",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                DerivationPath::from_str(v).map_err(de::Error::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut indices = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(elem) = seq.next_element()? {
                    indices.push(elem);
                }
                DerivationPath::new(indices).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(DerivationPathVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_apostrophe_paths() {
        let path = DerivationPath::parse_str("m/44'/0'/0'/0/5").unwrap();
        assert_eq!(path.depth(), 5);
        assert_eq!(
            path.as_slice(),
            &[
                44 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                5
            ]
        );
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/5");

        // Ethereum path
        let eth_path = DerivationPath::parse_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(
            eth_path.as_slice(),
            &[
                44 | HARDENED_FLAG,
                60 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                0
            ]
        );
    }

    #[test]
    fn test_valid_h_and_h_uppercase_paths() {
        let path_h = DerivationPath::parse_str("m/44h/0h/0h/0/5").unwrap();
        assert_eq!(
            path_h.as_slice(),
            &[
                44 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0 | HARDENED_FLAG,
                0,
                5
            ]
        );
        assert_eq!(path_h.to_string_formatted(true), "m/44h/0h/0h/0/5");

        let path_cap_h = DerivationPath::parse_str("m/44H/0H/0H/0/5").unwrap();
        assert_eq!(path_cap_h.as_slice(), path_h.as_slice());

        // Capital M prefix
        let path_m = DerivationPath::parse_str("M/44'/0'/0'/0/5").unwrap();
        assert_eq!(path_m.as_slice(), path_h.as_slice());
    }

    #[test]
    fn test_master_path() {
        let path_m = DerivationPath::parse_str("m").unwrap();
        assert_eq!(path_m.depth(), 0);
        assert!(path_m.is_empty());
        assert_eq!(path_m.to_string(), "m");

        let path_cap_m = DerivationPath::parse_str("M").unwrap();
        assert_eq!(path_cap_m.depth(), 0);
        assert!(path_cap_m.is_empty());
    }

    #[test]
    fn test_depth_255_pass() {
        let indices: Vec<u32> = (0..255).map(|i| i | HARDENED_FLAG).collect();
        let path = DerivationPath::new(indices.clone()).unwrap();
        assert_eq!(path.depth(), 255);

        let path_slice = DerivationPath::from_slice(&indices).unwrap();
        assert_eq!(path_slice.depth(), 255);

        // String round-trip for 255 depth
        let s = path.to_string();
        let parsed = DerivationPath::parse_str(&s).unwrap();
        assert_eq!(parsed.depth(), 255);
        assert_eq!(parsed.as_slice(), indices.as_slice());
    }

    #[test]
    fn test_depth_256_rejection() {
        let indices: Vec<u32> = (0..256).map(|i| i | HARDENED_FLAG).collect();
        let err = DerivationPath::new(indices).unwrap_err();
        assert_eq!(
            err,
            PathError::ExceedsMaxDepth {
                depth: 256,
                max: 255
            }
        );

        // String parsing depth 256
        let path_str = (0..256)
            .map(|i| format!("{i}'"))
            .collect::<Vec<_>>()
            .join("/");
        let full_str = format!("m/{path_str}");
        let parse_err = DerivationPath::parse_str(&full_str).unwrap_err();
        assert_eq!(
            parse_err,
            PathError::ExceedsMaxDepth {
                depth: 256,
                max: 255
            }
        );
    }

    #[test]
    fn test_negative_and_sign_index_rejection() {
        let err_neg = DerivationPath::parse_str("m/44'/-1/0").unwrap_err();
        match err_neg {
            PathError::InvalidIndex {
                position, reason, ..
            } => {
                assert_eq!(position, 1);
                assert!(reason.contains("sign character"));
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }

        let err_plus = DerivationPath::parse_str("m/+44'/0/0").unwrap_err();
        match err_plus {
            PathError::InvalidIndex {
                position, reason, ..
            } => {
                assert_eq!(position, 0);
                assert!(reason.contains("sign character"));
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn test_index_overflow_rejection() {
        // Exceeds 0x7FFFFFFF (2147483648)
        let err_overflow_hardened = DerivationPath::parse_str("m/2147483648'").unwrap_err();
        assert_eq!(
            err_overflow_hardened,
            PathError::IndexOverflow {
                position: 0,
                value: "2147483648'".to_string()
            }
        );

        let err_overflow_unhardened = DerivationPath::parse_str("m/2147483648").unwrap_err();
        assert_eq!(
            err_overflow_unhardened,
            PathError::IndexOverflow {
                position: 0,
                value: "2147483648".to_string()
            }
        );

        // Value > u64::MAX or unparseable u64
        let err_huge = DerivationPath::parse_str("m/99999999999999999999999999'").unwrap_err();
        match err_huge {
            PathError::InvalidIndex { position, .. } => assert_eq!(position, 0),
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn test_malformed_string_rejection() {
        // Empty string
        assert_eq!(
            DerivationPath::parse_str(""),
            Err(PathError::MissingMasterPrefix("".to_string()))
        );

        // Missing m
        assert_eq!(
            DerivationPath::parse_str("44'/0'/0'"),
            Err(PathError::MissingMasterPrefix("44'/0'/0'".to_string()))
        );

        // Empty segments
        assert_eq!(
            DerivationPath::parse_str("m//0"),
            Err(PathError::EmptySegment { position: 0 })
        );
        assert_eq!(
            DerivationPath::parse_str("m/0/"),
            Err(PathError::EmptySegment { position: 1 })
        );

        // Invalid characters
        match DerivationPath::parse_str("m/abc'/0").unwrap_err() {
            PathError::InvalidIndex { position, .. } => assert_eq!(position, 0),
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn test_bip32_validation() {
        // BIP32 allows both hardened and non-hardened
        let path = DerivationPath::parse_str("m/44'/0'/0'/0/5").unwrap();
        assert!(path.validate_for_scheme(DerivationScheme::Bip32).is_ok());

        let all_hardened = DerivationPath::parse_str("m/44'/0'/0'").unwrap();
        assert!(all_hardened
            .validate_for_scheme(DerivationScheme::Bip32)
            .is_ok());

        let all_unhardened = DerivationPath::parse_str("m/0/1/2").unwrap();
        assert!(all_unhardened
            .validate_for_scheme(DerivationScheme::Bip32)
            .is_ok());
    }

    #[test]
    fn test_slip10_validation() {
        // SLIP10 requires all indices to be hardened
        let valid_solana = DerivationPath::parse_str("m/44'/501'/0'/0'").unwrap();
        assert!(valid_solana
            .validate_for_scheme(DerivationScheme::Slip10)
            .is_ok());

        // Non-hardened at end
        let invalid_end = DerivationPath::parse_str("m/44'/501'/0'/0").unwrap();
        assert_eq!(
            invalid_end.validate_for_scheme(DerivationScheme::Slip10),
            Err(PathError::NonHardenedIndexNotAllowed {
                position: 3,
                index: 0,
            })
        );

        // Non-hardened in middle
        let invalid_mid = DerivationPath::parse_str("m/44'/0/0'").unwrap();
        assert_eq!(
            invalid_mid.validate_for_scheme(DerivationScheme::Slip10),
            Err(PathError::NonHardenedIndexNotAllowed {
                position: 1,
                index: 0,
            })
        );
    }

    #[test]
    fn test_serde_json_compatibility() {
        // Deserialize from string
        let from_str: DerivationPath = serde_json::from_str("\"m/44'/0'/0'/0/5\"").unwrap();
        assert_eq!(
            from_str.as_slice(),
            &[2147483692, 2147483648, 2147483648, 0, 5]
        );

        // Deserialize from u32 array (as specified in Specs.md section 6)
        let json_arr = "[2147483692, 2147483648, 2147483648, 0, 5]";
        let from_arr: DerivationPath = serde_json::from_str(json_arr).unwrap();
        assert_eq!(from_arr, from_str);

        // Serializes as JSON array
        let serialized = serde_json::to_string(&from_arr).unwrap();
        assert_eq!(serialized, "[2147483692,2147483648,2147483648,0,5]");
        let round_trip: DerivationPath = serde_json::from_str(&serialized).unwrap();
        assert_eq!(round_trip, from_arr);
    }

    #[test]
    fn test_helper_functions() {
        assert!(is_hardened(0x8000_0000));
        assert!(is_hardened(0x8000_002C));
        assert!(!is_hardened(0));
        assert!(!is_hardened(44));

        assert_eq!(to_hardened(44).unwrap(), 44 | HARDENED_FLAG);
        assert_eq!(unhardened_index(44 | HARDENED_FLAG), 44);
        assert_eq!(unhardened_index(44), 44);

        assert!(to_hardened(0x8000_0000).is_err());
    }
}
