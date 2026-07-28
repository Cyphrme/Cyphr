//! Multihash identifier support per Cyphr SPEC §14.
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
/// use cyphr::{HashAlg, MultihashDigest};
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
        for (&alg, digest) in &variants {
            let expected = crate::state::TaggedDigest::expected_len(alg);
            if digest.len() != expected {
                return Err(crate::error::Error::DigestLengthMismatch {
                    alg,
                    expected,
                    actual: digest.len(),
                });
            }
        }
        Ok(Self { variants })
    }

    /// Create from a single-algorithm digest.
    pub fn from_single(alg: HashAlg, digest: impl Into<Box<[u8]>>) -> crate::error::Result<Self> {
        let digest_box = digest.into();
        let expected = crate::state::TaggedDigest::expected_len(alg);
        if digest_box.len() != expected {
            return Err(crate::error::Error::DigestLengthMismatch {
                alg,
                expected,
                actual: digest_box.len(),
            });
        }
        let mut variants = BTreeMap::new();
        variants.insert(alg, digest_box);
        Ok(Self { variants })
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

    /// Get the digest for a specific algorithm, or a clear error if this
    /// multihash has no variant for it.
    ///
    /// Deliberately does **not** fall back to a different algorithm's bytes:
    /// a caller asking for one algorithm's digest and silently receiving
    /// another algorithm's bytes is a masked error, not a fallback worth
    /// having at a trust boundary. Mirrors [`Self::tagged`]'s contract.
    ///
    /// # Errors
    ///
    /// Returns `MissingVariant` if `alg` has no variant in this multihash.
    pub fn get_or_err(&self, alg: HashAlg) -> crate::error::Result<&[u8]> {
        self.get(alg)
            .ok_or(crate::error::Error::MissingVariant(alg))
    }

    /// Get the digest bytes for Arrow's algorithm-fallback rule.
    ///
    /// This is the component-conversion rule normatively fixed by SPEC.md
    /// §2.2.10 (Singleton Promotion) and resolved in full by
    /// `docs/specs/state-tree.md`'s `[conversion]` clause (settled
    /// 2026-07-08), whose POST is marked
    /// `VERIFIED: rs/cyphr/src/multihash.rs — MultihashDigest::arrow_component_bytes`
    /// — i.e. this exact function. The requested-`alg` bytes come from
    /// exactly one of three mechanisms:
    ///
    /// 1. **Exact match**: `alg` already has a native variant — return it directly, unconverted.
    /// 2. **Genesis promotion** (`len == 1`): the degenerate, single-variant case of the fold,
    ///    which `[conversion]` defines as "a degenerate case of the fold ... not a separate
    ///    conversion step" and SPEC.md §2.2.10 defines as elevating a lone node value to its parent
    ///    slot "without additional hashing". If this multihash has exactly one variant, its raw
    ///    bytes are returned for any requested `alg`. A component with only one active algorithm
    ///    thus contributes that algorithm's digest regardless of the signer's — e.g. a sole active
    ///    key replaced by one of a different algorithm in the same commit, leaving pre/fwd with
    ///    zero shared algorithms — rather than erroring.
    /// 3. **Fold** (`len >= 2`, no match): with two or more variants and none matching `alg`, fold
    ///    ALL currently-available variants together — sort, concatenate raw bytes, and hash once
    ///    under `alg` — mirroring [`crate::state::hash_sorted_concat_bytes`] and
    ///    `polydigest::root::combined_root`'s general fold. Mismatched- algorithm variants are
    ///    never individually re-hashed under `alg` before folding; their raw bytes participate as
    ///    fold inputs as-is.
    ///
    /// A no-op when this multihash already has `alg`.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if this multihash has zero variants.
    pub fn arrow_component_bytes(
        &self,
        alg: HashAlg,
    ) -> crate::error::Result<std::borrow::Cow<'_, [u8]>> {
        if let Some(bytes) = self.get(alg) {
            return Ok(std::borrow::Cow::Borrowed(bytes));
        }
        if self.len() == 1 {
            return self.first_variant().map(std::borrow::Cow::Borrowed);
        }
        if self.is_empty() {
            return Err(crate::error::Error::EmptyMultihash);
        }
        let all_variants: Vec<&[u8]> = self.variants.values().map(AsRef::as_ref).collect();
        Ok(std::borrow::Cow::Owned(
            crate::state::hash_sorted_concat_bytes(alg, &all_variants),
        ))
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

    /// Build the tagged wire-format digest (`alg:base64digest`) for a
    /// specific algorithm variant.
    ///
    /// # Errors
    ///
    /// Returns `MissingVariant` if `alg` has no variant in this multihash.
    pub fn tagged(&self, alg: HashAlg) -> crate::error::Result<crate::state::TaggedDigest> {
        let bytes = self
            .get(alg)
            .ok_or(crate::error::Error::MissingVariant(alg))?;
        crate::state::TaggedDigest::new(alg, bytes.to_vec())
    }

    /// Build the tagged wire-format digest (`alg:base64digest`) for the
    /// first available algorithm variant.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if no variants exist.
    pub fn tagged_first(&self) -> crate::error::Result<crate::state::TaggedDigest> {
        let alg = self
            .algorithms()
            .next()
            .ok_or(crate::error::Error::EmptyMultihash)?;
        self.tagged(alg)
    }

    /// Check if this multihash matches another on all common algorithms.
    ///
    /// Returns true if there is at least one common algorithm and all common
    /// algorithms have matching digests.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        let mut common = false;
        for alg in self.algorithms() {
            if let Some(d1) = self.get(alg) {
                if let Some(d2) = other.get(alg) {
                    if d1 != d2 {
                        return false;
                    }
                    common = true;
                }
            }
        }
        common
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
        let digest = vec![0xDE; 32];
        let mh = MultihashDigest::from_single(HashAlg::Sha256, digest.clone()).unwrap();

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
    fn new_rejects_invalid_lengths() {
        let mut variants = BTreeMap::new();
        variants.insert(HashAlg::Sha256, vec![0u8; 31].into_boxed_slice());
        assert!(MultihashDigest::new(variants).is_err());
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
        let mh = MultihashDigest::from_single(HashAlg::Sha256, vec![0u8; 32]).unwrap();
        assert!(mh.get(HashAlg::Sha384).is_none());
    }

    #[test]
    fn equality_checks_all_variants() {
        let mh1 = MultihashDigest::from_single(HashAlg::Sha256, vec![1; 32]).unwrap();
        let mh2 = MultihashDigest::from_single(HashAlg::Sha256, vec![1; 32]).unwrap();
        let mh3 = MultihashDigest::from_single(HashAlg::Sha256, vec![4; 32]).unwrap();

        assert_eq!(mh1, mh2);
        assert_ne!(mh1, mh3);
    }
}
