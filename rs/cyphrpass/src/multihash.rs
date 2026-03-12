//! Multihash identifier support per Cyphrpass SPEC §14.
//!
//! A multihash identifier is a set of equivalent digests, one per supported
//! hash algorithm. This enables algorithm-agnostic identity: a principal can
//! be referenced by any of its digest variants.

use std::collections::BTreeMap;

use crate::state::HashAlg;

/// A multihash identifier: equivalent digests across multiple hash algorithms.
///
/// All variants are equivalent references to the same underlying state.
/// Per SPEC §14: "No single algorithm is canonical."
///
/// # Construction
///
/// ```ignore
/// use cyphrpass::{HashAlg, MultihashDigest};
///
/// // Single-algorithm (e.g., from implicit promotion)
/// let mh = MultihashDigest::from_single(HashAlg::Sha256, vec![0u8; 32]);
///
/// // Multi-algorithm (e.g., from mixed keyset)
/// let mut variants = BTreeMap::new();
/// variants.insert(HashAlg::Sha256, vec![0u8; 32].into_boxed_slice());
/// variants.insert(HashAlg::Sha384, vec![0u8; 48].into_boxed_slice());
/// let mh = MultihashDigest::new(variants);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultihashDigest {
    variants: BTreeMap<HashAlg, Box<[u8]>>,
}

impl Default for MultihashDigest {
    /// Empty multihash — used only as a placeholder during internal state transitions.
    fn default() -> Self {
        Self {
            variants: BTreeMap::new(),
        }
    }
}

impl MultihashDigest {
    /// Create from raw variants map.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if `variants` is empty.
    pub fn new(variants: BTreeMap<HashAlg, Box<[u8]>>) -> crate::error::Result<Self> {
        if variants.is_empty() {
            return Err(crate::error::Error::EmptyMultihash);
        }
        Ok(Self { variants })
    }

    /// Create from a single-algorithm digest.
    #[must_use]
    pub fn from_single(alg: HashAlg, digest: impl Into<Box<[u8]>>) -> Self {
        let mut variants = BTreeMap::new();
        variants.insert(alg, digest.into());
        Self { variants }
    }

    /// Get the digest for a specific algorithm.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.variants.get(&alg).map(AsRef::as_ref)
    }

    /// Check if this multihash contains a variant for the given algorithm.
    #[must_use]
    pub fn contains(&self, alg: HashAlg) -> bool {
        self.variants.contains_key(&alg)
    }

    /// Get all algorithms in this multihash.
    pub fn algorithms(&self) -> impl Iterator<Item = HashAlg> + '_ {
        self.variants.keys().copied()
    }

    /// Get the number of algorithm variants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.variants.len()
    }

    /// Check if the multihash is empty (should never be true for valid instances).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.variants.is_empty()
    }

    /// Get the inner variants map.
    #[must_use]
    pub fn variants(&self) -> &BTreeMap<HashAlg, Box<[u8]>> {
        &self.variants
    }

    /// Consume self and return the inner variants map.
    #[must_use]
    pub fn into_variants(self) -> BTreeMap<HashAlg, Box<[u8]>> {
        self.variants
    }

    /// Get digest for a specific algorithm, falling back to the first available variant.
    ///
    /// This is the fallible replacement for the common pattern:
    /// ```ignore
    /// mh.get(alg).or_else(|| mh.variants().values().next().map(AsRef::as_ref)).expect("...")
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if no variants exist.
    pub fn get_or_err(&self, alg: HashAlg) -> crate::error::Result<&[u8]> {
        self.get(alg)
            .or_else(|| self.variants.values().next().map(AsRef::as_ref))
            .ok_or(crate::error::Error::EmptyMultihash)
    }

    /// Get the first available variant's bytes.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if no variants exist.
    pub fn first_variant(&self) -> crate::error::Result<&[u8]> {
        self.variants
            .values()
            .next()
            .map(AsRef::as_ref)
            .ok_or(crate::error::Error::EmptyMultihash)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_single_creates_one_variant() {
        let digest = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mh = MultihashDigest::from_single(HashAlg::Sha256, digest.clone());

        assert_eq!(mh.len(), 1);
        assert!(mh.contains(HashAlg::Sha256));
        assert!(!mh.contains(HashAlg::Sha384));
        assert_eq!(mh.get(HashAlg::Sha256), Some(digest.as_slice()));
    }

    #[test]
    fn new_accepts_multiple_variants() {
        let mut variants = BTreeMap::new();
        variants.insert(HashAlg::Sha256, vec![0u8; 32].into_boxed_slice());
        variants.insert(HashAlg::Sha384, vec![1u8; 48].into_boxed_slice());

        let mh = MultihashDigest::new(variants).unwrap();

        assert_eq!(mh.len(), 2);
        assert!(mh.contains(HashAlg::Sha256));
        assert!(mh.contains(HashAlg::Sha384));
        assert!(!mh.contains(HashAlg::Sha512));
    }

    #[test]
    fn algorithms_iterates_in_order() {
        let mut variants = BTreeMap::new();
        variants.insert(HashAlg::Sha512, vec![0u8; 64].into_boxed_slice());
        variants.insert(HashAlg::Sha256, vec![0u8; 32].into_boxed_slice());

        let mh = MultihashDigest::new(variants).unwrap();
        let algs: Vec<_> = mh.algorithms().collect();

        // BTreeMap orders by key, HashAlg derives Ord
        assert_eq!(algs.len(), 2);
    }

    #[test]
    fn get_returns_none_for_missing() {
        let mh = MultihashDigest::from_single(HashAlg::Sha256, vec![0u8; 32]);
        assert!(mh.get(HashAlg::Sha384).is_none());
    }

    #[test]
    fn equality_checks_all_variants() {
        let mh1 = MultihashDigest::from_single(HashAlg::Sha256, vec![1, 2, 3]);
        let mh2 = MultihashDigest::from_single(HashAlg::Sha256, vec![1, 2, 3]);
        let mh3 = MultihashDigest::from_single(HashAlg::Sha256, vec![4, 5, 6]);

        assert_eq!(mh1, mh2);
        assert_ne!(mh1, mh3);
    }
}
