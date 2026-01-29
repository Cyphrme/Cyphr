//! State computation and digest types.
//!
//! Implements SPEC §7 state calculation semantics.

use std::collections::BTreeMap;

use coz::digest::Digest;
use coz::sha2::{Sha256, Sha384, Sha512};
use coz::{Cad, Czd, Thumbprint};

use crate::multihash::MultihashDigest;

// ============================================================================
// State newtypes
// ============================================================================

/// Key State (KS) - SPEC §7.2
///
/// Digest of active key thumbprints.
/// Single key with no nonce: KS = tmb (implicit promotion).
///
/// Now holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState(pub crate::multihash::MultihashDigest);

impl KeyState {
    /// Get the full multihash.
    #[must_use]
    pub fn as_multihash(&self) -> &crate::multihash::MultihashDigest {
        &self.0
    }

    /// Get a specific algorithm variant as bytes.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

/// Transaction State (TS) - SPEC §7.3
///
/// Digest of transaction `czd`s.
///
/// Now holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionState(pub crate::multihash::MultihashDigest);

impl TransactionState {
    /// Get the full multihash.
    #[must_use]
    pub fn as_multihash(&self) -> &crate::multihash::MultihashDigest {
        &self.0
    }

    /// Get a specific algorithm variant as bytes.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

/// Auth State (AS) - SPEC §7.5
///
/// Authentication state: `H(sort(KS, TS?, RS?))` or promoted if only KS.
///
/// Now holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthState(pub MultihashDigest);

impl AuthState {
    /// Get the full multihash.
    #[must_use]
    pub fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }

    /// Get a specific algorithm variant as bytes.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

/// Data State (DS) - SPEC §7.4
///
/// State of user actions (Level 4+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataState(pub Cad);

impl DataState {
    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
    }
}

/// Principal State (PS) - SPEC §7.6
///
/// Current top-level state: `H(sort(AS, DS?))` or promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalState(pub MultihashDigest);

impl PrincipalState {
    /// Get the full multihash.
    #[must_use]
    pub fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }

    /// Get a specific algorithm variant as bytes.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

/// Principal Root (PR) - SPEC §7.7
///
/// The first PS ever computed. Permanent, never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRoot(pub MultihashDigest);

impl PrincipalRoot {
    /// Create a PrincipalRoot from raw bytes (e.g., for testing).
    /// Assumes SHA-256 algorithm for single-variant construction.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(MultihashDigest::from_single(HashAlg::Sha256, bytes))
    }

    /// Create PR from the initial principal state (at genesis).
    pub fn from_initial(ps: &PrincipalState) -> Self {
        Self(ps.0.clone())
    }

    /// Get the full multihash.
    #[must_use]
    pub fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }

    /// Get a specific algorithm variant as bytes.
    #[must_use]
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

// ============================================================================
// Hash algorithm dispatch
// ============================================================================

/// Hash algorithm for state computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    /// SHA-256 (ES256)
    Sha256,
    /// SHA-384 (ES384)
    Sha384,
    /// SHA-512 (ES512, Ed25519)
    Sha512,
}

impl HashAlg {
    /// Get hash algorithm from signing algorithm name.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedAlgorithm` if the algorithm is not recognized.
    pub fn from_alg(alg: &str) -> crate::error::Result<Self> {
        match alg {
            "ES256" => Ok(Self::Sha256),
            "ES384" => Ok(Self::Sha384),
            "ES512" | "Ed25519" => Ok(Self::Sha512),
            _ => Err(crate::error::Error::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    /// Get hash algorithm from Coz signing algorithm.
    ///
    /// This is the infallible variant using the type-safe `coz::Alg` enum.
    #[must_use]
    pub const fn from_coz_alg(alg: coz::Alg) -> Self {
        match alg {
            coz::Alg::ES256 => Self::Sha256,
            coz::Alg::ES384 => Self::Sha384,
            coz::Alg::ES512 | coz::Alg::Ed25519 => Self::Sha512,
        }
    }

    /// Get digest size in bytes.
    #[must_use]
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

// ============================================================================
// Core state computation algorithm (SPEC §7.1)
// ============================================================================

/// Compute `H(sort(components...))` per SPEC §7.1.
///
/// 1. Collect component digests
/// 2. Sort lexicographically (byte comparison)
/// 3. Concatenate sorted digests
/// 4. Hash using specified algorithm
fn hash_sorted_concat(alg: HashAlg, components: &[&[u8]]) -> Cad {
    Cad::from_bytes(hash_sorted_concat_bytes(alg, components))
}

/// Compute `H(sort(components...))` returning raw bytes.
///
/// Same as [`hash_sorted_concat`] but returns raw bytes for MultihashDigest construction.
fn hash_sorted_concat_bytes(alg: HashAlg, components: &[&[u8]]) -> Vec<u8> {
    // Sort lexicographically
    let mut sorted: Vec<&[u8]> = components.to_vec();
    sorted.sort();

    // Hash based on algorithm
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            for c in sorted {
                h.update(c);
            }
            h.finalize().to_vec()
        },
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            for c in sorted {
                h.update(c);
            }
            h.finalize().to_vec()
        },
        HashAlg::Sha512 => {
            let mut h = Sha512::new();
            for c in sorted {
                h.update(c);
            }
            h.finalize().to_vec()
        },
    }
}

// ============================================================================
// State computation functions
// ============================================================================

/// Compute Key State (SPEC §7.2).
///
/// - Single key, no nonce: KS = tmb (implicit promotion to single-variant multihash)
/// - Otherwise: KS = H(sort(tmb₀, tmb₁, nonce?, ...)) for each algorithm
///
/// The `algs` slice specifies which hash algorithms to include in the multihash.
/// For single-algorithm keysets, pass a single-element slice.
pub fn compute_ks(thumbprints: &[&Thumbprint], nonce: Option<&[u8]>, algs: &[HashAlg]) -> KeyState {
    use crate::multihash::MultihashDigest;
    use std::collections::BTreeMap;

    debug_assert!(
        !algs.is_empty(),
        "compute_ks requires at least one algorithm"
    );

    // Implicit promotion: single key, no nonce
    // The thumbprint becomes the single-variant multihash
    if thumbprints.len() == 1 && nonce.is_none() {
        // Use the first algorithm for the promoted thumbprint
        let alg = algs[0];
        return KeyState(MultihashDigest::from_single(
            alg,
            thumbprints[0].as_bytes().to_vec(),
        ));
    }

    // Collect components
    let mut components: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    KeyState(MultihashDigest::new(variants))
}

/// Compute Transaction State (SPEC §7.3).
///
/// - No transactions: TS = None
/// - Single transaction, no nonce: TS = czd (implicit promotion)
/// - Otherwise: TS = H(sort(czd₀, czd₁, nonce?, ...))
pub fn compute_ts(
    czds: &[&Czd],
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> Option<TransactionState> {
    if czds.is_empty() && nonce.is_none() {
        return None;
    }

    // Implicit promotion: single czd, no nonce
    // Store the czd bytes as the digest for all algorithm variants
    if czds.len() == 1 && nonce.is_none() {
        let czd_bytes = czds[0].as_bytes();
        return Some(TransactionState(MultihashDigest::from_single(
            // Use first algorithm for single-variant multihash
            algs.first().copied().unwrap_or(HashAlg::Sha256),
            czd_bytes.to_vec(),
        )));
    }

    let mut components: Vec<&[u8]> = czds.iter().map(|c| c.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Some(TransactionState(MultihashDigest::new(variants)))
}

/// Compute Auth State (SPEC §7.5).
///
/// - Only KS, no TS/RS/nonce: AS = KS (implicit promotion)
/// - Otherwise: AS = H(sort(KS, TS?, RS?, nonce?))
pub fn compute_as(
    ks: &KeyState,
    ts: Option<&TransactionState>,
    // rs: Option<&RuleState>,  // Level 5, not yet implemented
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> AuthState {
    // Implicit promotion: only KS, nothing else
    // Clone the KeyState multihash directly
    if ts.is_none() && nonce.is_none() {
        return AuthState(ks.0.clone());
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        // Get KS variant for this algorithm, falling back to first available
        let ks_bytes = ks
            .get(alg)
            .or_else(|| ks.0.variants().values().next().map(AsRef::as_ref))
            .expect("KeyState must have at least one variant");

        // Collect non-nil components
        let mut components: Vec<&[u8]> = vec![ks_bytes];
        if let Some(t) = ts {
            // Get TS variant for this algorithm, falling back to first available
            let ts_bytes = t
                .get(alg)
                .or_else(|| t.0.variants().values().next().map(AsRef::as_ref))
                .expect("TransactionState must have at least one variant");
            components.push(ts_bytes);
        }
        if let Some(n) = nonce {
            components.push(n);
        }

        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    AuthState(MultihashDigest::new(variants))
}

/// Compute Data State (SPEC §7.4).
///
/// - No actions, no nonce: DS = None
/// - Single action, no nonce: DS = czd (implicit promotion)
/// - Otherwise: DS = H(sort(czd₀, czd₁, nonce?, ...))
pub fn compute_ds(action_czds: &[&Czd], nonce: Option<&[u8]>, alg: HashAlg) -> Option<DataState> {
    if action_czds.is_empty() && nonce.is_none() {
        return None;
    }

    // Implicit promotion
    if action_czds.len() == 1 && nonce.is_none() {
        return Some(DataState(Cad::from_bytes(
            action_czds[0].as_bytes().to_vec(),
        )));
    }

    let mut components: Vec<&[u8]> = action_czds.iter().map(|c| c.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    Some(DataState(hash_sorted_concat(alg, &components)))
}

/// Compute Principal State (SPEC §7.6).
///
/// - Only AS, no DS/nonce: PS = AS (implicit promotion)
/// - Otherwise: PS = H(sort(AS, DS?, nonce?)) for each algorithm
///
/// Accepts multiple hash algorithms and produces a variant for each.
pub fn compute_ps(
    auth_state: &AuthState,
    ds: Option<&DataState>,
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> PrincipalState {
    // Implicit promotion: only AS, nothing else
    // Clone the AuthState multihash directly
    if ds.is_none() && nonce.is_none() {
        return PrincipalState(auth_state.0.clone());
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        // Get AS variant for this algorithm, falling back to first available
        let as_bytes = auth_state
            .get(alg)
            .or_else(|| auth_state.0.variants().values().next().map(AsRef::as_ref))
            .expect("AuthState must have at least one variant");

        // Collect non-nil components
        let mut components: Vec<&[u8]> = vec![as_bytes];
        if let Some(d) = ds {
            components.push(d.0.as_bytes());
        }
        if let Some(n) = nonce {
            components.push(n);
        }

        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    PrincipalState(MultihashDigest::new(variants))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ks_single_key_promotion() {
        // Single key: KS = tmb (no hashing), stored as single-variant multihash
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]);

        // Should have exactly one variant
        assert_eq!(ks.0.len(), 1);
        // The variant value should equal the thumbprint bytes
        assert_eq!(ks.get(HashAlg::Sha256).unwrap(), tmb.as_bytes());
    }

    #[test]
    fn ks_multi_key_hashes() {
        // Multiple keys: KS = H(sort(tmb₀, tmb₁))
        let tmb1 = Thumbprint::from_bytes(vec![1, 2, 3]);
        let tmb2 = Thumbprint::from_bytes(vec![4, 5, 6]);
        let ks = compute_ks(&[&tmb1, &tmb2], None, &[HashAlg::Sha256]);

        let digest = ks.get(HashAlg::Sha256).unwrap();
        // Should be hashed SHA-256 output
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, tmb1.as_bytes());
    }

    #[test]
    fn ks_with_nonce_hashes() {
        // Single key with nonce: still hashes (no promotion)
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let nonce = vec![0xAA, 0xBB];
        let ks = compute_ks(&[&tmb], Some(&nonce), &[HashAlg::Sha256]);

        let digest = ks.get(HashAlg::Sha256).unwrap();
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, tmb.as_bytes());
    }

    #[test]
    fn ts_empty_is_none() {
        let ts = compute_ts(&[], None, &[HashAlg::Sha256]);
        assert!(ts.is_none());
    }

    #[test]
    fn ts_single_czd_promotion() {
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let ts = compute_ts(&[&czd], None, &[HashAlg::Sha256]);
        let ts_bytes = ts.as_ref().map(|t| t.get(HashAlg::Sha256).unwrap());
        assert_eq!(ts_bytes.unwrap(), czd.as_bytes());
    }

    #[test]
    fn as_promotion_from_ks() {
        // Only KS, no TS: AS = KS (the specified algorithm variant)
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]);
        let auth_state = compute_as(&ks, None, None, &[HashAlg::Sha256]);

        // AS should equal the KS variant for this algorithm
        assert_eq!(
            auth_state.get(HashAlg::Sha256).unwrap(),
            ks.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn as_with_ts_hashes() {
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]);
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let ts = compute_ts(&[&czd], None, &[HashAlg::Sha256]).unwrap();

        let auth_state = compute_as(&ks, Some(&ts), None, &[HashAlg::Sha256]);

        // Should be hashed combination
        let as_bytes = auth_state.get(HashAlg::Sha256).unwrap();
        assert_eq!(as_bytes.len(), 32);
        assert_ne!(as_bytes, ks.get(HashAlg::Sha256).unwrap());
    }

    #[test]
    fn ps_promotion_from_as() {
        // Only AS, no DS: PS = AS
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]);
        let auth_state = compute_as(&ks, None, None, &[HashAlg::Sha256]);
        let ps = compute_ps(&auth_state, None, None, &[HashAlg::Sha256]);

        assert_eq!(
            ps.get(HashAlg::Sha256).unwrap(),
            auth_state.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn full_promotion_chain() {
        // Level 1: PR = PS = AS = KS = tmb
        let tmb = Thumbprint::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]);
        let auth_state = compute_as(&ks, None, None, &[HashAlg::Sha256]);
        let ps = compute_ps(&auth_state, None, None, &[HashAlg::Sha256]);
        let pr = PrincipalRoot::from_initial(&ps);

        // All should be identical to tmb
        let ks_bytes = ks.get(HashAlg::Sha256).unwrap();
        let as_bytes = auth_state.get(HashAlg::Sha256).unwrap();
        assert_eq!(ks_bytes, tmb.as_bytes());
        assert_eq!(as_bytes, tmb.as_bytes());
        assert_eq!(ps.get(HashAlg::Sha256).unwrap(), tmb.as_bytes());
        assert_eq!(pr.get(HashAlg::Sha256).unwrap(), tmb.as_bytes());
    }
}
