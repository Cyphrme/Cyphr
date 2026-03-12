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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

/// Commit ID — SPEC §8.5
///
/// Digest of transaction `czd`s within a single commit.
/// Previously named `TransactionState`; renamed to reflect its role as
/// the identity of a commit rather than a state-tree node.
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitID(pub crate::multihash::MultihashDigest);

impl CommitID {
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

/// Auth State (AS) — SPEC §8.4
///
/// Authentication state: `AS = MR(KS, RS?)` or promoted if only KS.
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

/// Commit State (CS) — SPEC §8.5
///
/// The Principal Tree minus CommitID: `CS = MR(AS, DS?)`.
/// CS captures all non-commit-specific state. CommitID is excluded to avoid
/// circular dependencies (CS is embedded in cozies before CommitID is known).
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommitState(pub MultihashDigest);

impl CommitState {
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

/// Principal State (PS) — SPEC §8.3
///
/// Current top-level state: `PS = MR(AS, CommitID?, DS?)`.
/// PS includes CommitID directly, unlike CS which excludes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
// Hash algorithm dispatch (re-export from coz)
// ============================================================================

// Re-export HashAlg from coz - single source of truth for algorithm mapping
pub use coz::HashAlg;

// ============================================================================
// Tagged Digest (algorithm-prefixed digest with parse-time validation)
// ============================================================================

/// A cryptographic digest with explicit algorithm tag.
///
/// Format: `<alg>:<digest>` (e.g., `SHA-256:U5XUZots-WmQ...`)
///
/// Validated during parsing - invalid algorithm/length combinations fail early.
/// This implements "Parse, Don't Validate" - once constructed, the digest is
/// guaranteed to have the correct length for its algorithm.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TaggedDigest {
    alg: HashAlg,
    digest: Vec<u8>,
}

impl TaggedDigest {
    /// Returns the hash algorithm of this digest.
    #[must_use]
    pub fn alg(&self) -> HashAlg {
        self.alg
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the expected digest length in bytes for a given algorithm.
    #[must_use]
    pub const fn expected_len(alg: HashAlg) -> usize {
        match alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// Parses a hash algorithm name string (e.g., "SHA-256").
    fn parse_alg(s: &str) -> Result<HashAlg, crate::error::Error> {
        match s {
            "SHA-256" => Ok(HashAlg::Sha256),
            "SHA-384" => Ok(HashAlg::Sha384),
            "SHA-512" => Ok(HashAlg::Sha512),
            _ => Err(crate::error::Error::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

impl std::str::FromStr for TaggedDigest {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (alg_str, digest_b64) =
            s.split_once(':')
                .ok_or(crate::error::Error::MalformedDigest(
                    "missing ':' separator",
                ))?;

        let alg = Self::parse_alg(alg_str)?;

        // Decode base64 into a buffer sized for the expected algorithm output
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let expected = Self::expected_len(alg);

        // Allocate buffer for max possible digest (SHA-512 = 64 bytes)
        let mut buf = [0u8; 64];
        let decoded = Base64UrlUnpadded::decode(digest_b64, &mut buf)
            .map_err(|_| crate::error::Error::MalformedDigest("invalid base64"))?;

        // Validate length matches algorithm
        if decoded.len() != expected {
            return Err(crate::error::Error::DigestLengthMismatch {
                alg,
                expected,
                actual: decoded.len(),
            });
        }

        Ok(Self {
            alg,
            digest: decoded.to_vec(),
        })
    }
}

impl std::fmt::Display for TaggedDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        write!(
            f,
            "{}:{}",
            self.alg,
            Base64UrlUnpadded::encode_string(&self.digest)
        )
    }
}

impl serde::Serialize for TaggedDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for TaggedDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Get hash algorithm from signing algorithm name (string).
///
/// Prefer `coz::Alg::from_str(s).map(|a| a.hash_alg())` when possible.
///
/// # Errors
///
/// Returns `UnsupportedAlgorithm` if the algorithm is not recognized.
pub fn hash_alg_from_str(alg: &str) -> crate::error::Result<HashAlg> {
    coz::Alg::from_str(alg)
        .map(coz::Alg::hash_alg)
        .ok_or_else(|| crate::error::Error::UnsupportedAlgorithm(alg.to_string()))
}

/// Derive the set of hash algorithms from a keyset (SPEC §14).
///
/// For each unique key algorithm, returns the corresponding hash algorithm.
/// The result is sorted for deterministic ordering.
///
/// # Example
///
/// ```ignore
/// use cyphrpass::state::derive_hash_algs;
/// // ES256 key -> [Sha256]
/// // ES256 + ES384 keys -> [Sha256, Sha384]
/// ```
pub fn derive_hash_algs(keys: &[&crate::Key]) -> Vec<HashAlg> {
    use std::collections::BTreeSet;

    let algs: BTreeSet<HashAlg> = keys
        .iter()
        .filter(|k| k.is_active())
        .filter_map(|k| hash_alg_from_str(&k.alg).ok())
        .collect();

    algs.into_iter().collect()
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

/// Compute `H(components...)` in array order (no sort).
///
/// Used for CommitID where transaction order is significant (SPEC §8.5).
fn hash_concat_bytes(alg: HashAlg, components: &[&[u8]]) -> Vec<u8> {
    // Hash based on algorithm — no sort, preserve insertion order
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            for c in components {
                h.update(c);
            }
            h.finalize().to_vec()
        },
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            for c in components {
                h.update(c);
            }
            h.finalize().to_vec()
        },
        HashAlg::Sha512 => {
            let mut h = Sha512::new();
            for c in components {
                h.update(c);
            }
            h.finalize().to_vec()
        },
    }
}

/// Hash raw bytes using the specified algorithm (SPEC §14.2 conversion).
///
/// Used when converting a czd from one algorithm to another.
fn hash_bytes(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(data);
            h.finalize().to_vec()
        },
        HashAlg::Sha384 => {
            let mut h = Sha384::new();
            h.update(data);
            h.finalize().to_vec()
        },
        HashAlg::Sha512 => {
            let mut h = Sha512::new();
            h.update(data);
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
///
/// # Errors
///
/// Returns `NoActiveKeys` if `algs` is empty.
pub fn compute_ks(
    thumbprints: &[&Thumbprint],
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<KeyState> {
    use crate::multihash::MultihashDigest;
    use std::collections::BTreeMap;

    if algs.is_empty() {
        return Err(crate::error::Error::NoActiveKeys);
    }

    // Implicit promotion: single key, no nonce
    // The thumbprint becomes the single-variant multihash
    if thumbprints.len() == 1 && nonce.is_none() {
        // Use the first algorithm for the promoted thumbprint
        let alg = algs[0];
        return Ok(KeyState(MultihashDigest::from_single(
            alg,
            thumbprints[0].as_bytes().to_vec(),
        )));
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

    Ok(KeyState(MultihashDigest::new(variants)?))
}

/// Compute Commit ID (formerly Transaction State) — SPEC §8.5.
///
/// The Commit ID is the Merkle root of the czds within a single commit.
///
/// - No transactions: CommitID = None
/// - Single transaction, no nonce: CommitID = czd (implicit promotion)
/// - Otherwise: CommitID = H(czd₀ ‖ czd₁ ‖ nonce? ‖ ...) — array order, no sort
pub fn compute_commit_id(
    czds: &[&Czd],
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> Option<CommitID> {
    if czds.is_empty() && nonce.is_none() {
        return None;
    }

    // Implicit promotion: single czd, no nonce
    // Store the czd bytes as the digest for all algorithm variants
    if czds.len() == 1 && nonce.is_none() {
        let czd_bytes = czds[0].as_bytes();
        return Some(CommitID(MultihashDigest::from_single(
            // Use first algorithm for single-variant multihash
            algs.first().copied().unwrap_or(HashAlg::Sha256),
            czd_bytes.to_vec(),
        )));
    }

    let mut components: Vec<&[u8]> = czds.iter().map(|c| c.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    // Compute hash for each algorithm variant (array order, no sort)
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let digest = hash_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Some(CommitID(MultihashDigest::new(variants).ok()?))
}

/// A czd tagged with its source hash algorithm.
///
/// Used for cross-algorithm state computation where czds from different
/// signing algorithms need to be converted to a common hash algorithm.
#[derive(Debug, Clone)]
pub struct TaggedCzd<'a> {
    /// The raw czd bytes.
    pub czd: &'a Czd,
    /// Hash algorithm that produced this czd (from signing key).
    pub alg: HashAlg,
}

impl<'a> TaggedCzd<'a> {
    /// Create a new tagged czd.
    pub fn new(czd: &'a Czd, alg: HashAlg) -> Self {
        Self { czd, alg }
    }

    /// Convert this czd to target algorithm.
    ///
    /// If source and target algorithms match, returns the raw bytes.
    /// Otherwise, re-hashes the czd bytes with the target algorithm.
    pub fn convert_to(&self, target: HashAlg) -> Vec<u8> {
        if self.alg == target {
            // Same algorithm: use raw bytes
            self.czd.as_bytes().to_vec()
        } else {
            // Different algorithm: re-hash (SPEC §14.2 conversion)
            hash_bytes(target, self.czd.as_bytes())
        }
    }
}

/// Compute Commit ID with cross-algorithm conversion (SPEC §14.2).
///
/// Like [`compute_commit_id`], but accepts czds tagged with their source algorithm.
/// When computing a target hash variant, czds from different algorithms
/// are converted (re-hashed) to the target algorithm.
///
/// - No transactions: CommitID = None
/// - Single transaction, no nonce: CommitID = czd (implicit promotion)
/// - Otherwise: CommitID = H(converted_czd₀ ‖ converted_czd₁ ‖ nonce? ‖ ...) — array order
pub fn compute_commit_id_tagged(
    czds: &[TaggedCzd<'_>],
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> Option<CommitID> {
    if czds.is_empty() && nonce.is_none() {
        return None;
    }

    // Implicit promotion: single czd, no nonce
    // For single czd, convert to first target algorithm if needed
    if czds.len() == 1 && nonce.is_none() {
        let target_alg = algs.first().copied().unwrap_or(HashAlg::Sha256);
        let converted = czds[0].convert_to(target_alg);
        return Some(CommitID(MultihashDigest::from_single(
            target_alg, converted,
        )));
    }

    // Compute hash for each target algorithm variant
    let mut variants = BTreeMap::new();
    for &target_alg in algs {
        // Convert each czd to target algorithm
        let converted: Vec<Vec<u8>> = czds.iter().map(|tc| tc.convert_to(target_alg)).collect();

        // Add nonce if present
        let mut components: Vec<&[u8]> = converted.iter().map(|v| v.as_slice()).collect();
        if let Some(n) = nonce {
            components.push(n);
        }

        // Hash in array order (no sort — CommitID preserves transaction order)
        let digest = hash_concat_bytes(target_alg, &components);
        variants.insert(target_alg, digest.into_boxed_slice());
    }

    Some(CommitID(MultihashDigest::new(variants).ok()?))
}

/// Compute Auth State — SPEC §8.4.
///
/// `AS = MR(KS, RS?)` — authentication state derived from the keyset.
///
/// - Only KS, no RS/nonce: AS = KS (implicit promotion)
/// - Otherwise: AS = H(sort(KS, RS?, nonce?))
///
/// # Errors
///
/// Returns `EmptyMultihash` if the KeyState contains no variants.
pub fn compute_as(
    ks: &KeyState,
    // rs: Option<&RuleState>,  // Level 5, not yet implemented
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<AuthState> {
    // Implicit promotion: only KS, nothing else
    // Clone the KeyState multihash directly
    if nonce.is_none() {
        return Ok(AuthState(ks.0.clone()));
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let ks_bytes = ks.0.get_or_err(alg)?;

        // Collect non-nil components
        let mut components: Vec<&[u8]> = vec![ks_bytes];
        // TODO: Level 5 — add RS component here when RuleState is implemented
        if let Some(n) = nonce {
            components.push(n);
        }

        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(AuthState(MultihashDigest::new(variants)?))
}

/// Compute Commit State — SPEC §8.5.
///
/// `CS = MR(AS, DS?)` — the Principal Tree minus CommitID.
/// CommitID is excluded from CS to avoid circular dependencies.
///
/// - If ds is None (no actions): CS promotes from AS
/// - Otherwise: CS = H(sort(AS, DS)) for each algorithm
///
/// # Errors
///
/// Returns `EmptyMultihash` if AuthState contains no variants.
pub fn compute_cs(
    auth_state: &AuthState,
    ds: Option<&DataState>,
    algs: &[HashAlg],
) -> crate::error::Result<CommitState> {
    // Implicit promotion: no DS → CS = AS
    let ds_inner = match ds {
        Some(d) => d,
        None => return Ok(CommitState(auth_state.0.clone())),
    };

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let as_bytes = auth_state.0.get_or_err(alg)?;

        let components: Vec<&[u8]> = vec![as_bytes, ds_inner.0.as_bytes()];
        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(CommitState(MultihashDigest::new(variants)?))
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

/// Compute Principal State — SPEC §8.3.
///
/// `PS = MR(AS, CommitID?, DS?)` — top-level state including CommitID directly.
/// PS is computed from raw components, NOT from CS.
///
/// - Only AS, no CommitID/DS/nonce: PS = AS (implicit promotion)
/// - Otherwise: PS = H(sort(AS, CommitID?, DS?, nonce?)) for each algorithm
///
/// Accepts multiple hash algorithms and produces a variant for each.
///
/// # Errors
///
/// Returns `EmptyMultihash` if the AuthState contains no variants.
pub fn compute_ps(
    auth_state: &AuthState,
    commit_id: Option<&CommitID>,
    ds: Option<&DataState>,
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<PrincipalState> {
    // Implicit promotion: only AS, nothing else
    if commit_id.is_none() && ds.is_none() && nonce.is_none() {
        return Ok(PrincipalState(auth_state.0.clone()));
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let as_bytes = auth_state.0.get_or_err(alg)?;

        // Collect non-nil components
        let mut components: Vec<&[u8]> = vec![as_bytes];
        if let Some(cid) = commit_id {
            components.push(cid.0.get_or_err(alg)?);
        }
        if let Some(d) = ds {
            components.push(d.0.as_bytes());
        }
        if let Some(n) = nonce {
            components.push(n);
        }

        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(PrincipalState(MultihashDigest::new(variants)?))
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
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]).unwrap();

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
        let ks = compute_ks(&[&tmb1, &tmb2], None, &[HashAlg::Sha256]).unwrap();

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
        let ks = compute_ks(&[&tmb], Some(&nonce), &[HashAlg::Sha256]).unwrap();

        let digest = ks.get(HashAlg::Sha256).unwrap();
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, tmb.as_bytes());
    }

    #[test]
    fn commit_id_empty_is_none() {
        let cid = compute_commit_id(&[], None, &[HashAlg::Sha256]);
        assert!(cid.is_none());
    }

    #[test]
    fn commit_id_single_czd_promotion() {
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let cid = compute_commit_id(&[&czd], None, &[HashAlg::Sha256]);
        let cid_bytes = cid.as_ref().map(|c| c.get(HashAlg::Sha256).unwrap());
        assert_eq!(cid_bytes.unwrap(), czd.as_bytes());
    }

    #[test]
    fn as_promotion_from_ks() {
        // Only KS, no RS: AS = KS (the specified algorithm variant)
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]).unwrap();
        let auth_state = compute_as(&ks, None, &[HashAlg::Sha256]).unwrap();

        // AS should equal the KS variant for this algorithm
        assert_eq!(
            auth_state.get(HashAlg::Sha256).unwrap(),
            ks.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn cs_with_ds_hashes() {
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]).unwrap();
        let auth_state = compute_as(&ks, None, &[HashAlg::Sha256]).unwrap();
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let ds = compute_ds(&[&czd], None, HashAlg::Sha256).unwrap();

        let cs = compute_cs(&auth_state, Some(&ds), &[HashAlg::Sha256]).unwrap();

        // Should be hashed combination
        let cs_bytes = cs.get(HashAlg::Sha256).unwrap();
        assert_eq!(cs_bytes.len(), 32);
        assert_ne!(cs_bytes, auth_state.get(HashAlg::Sha256).unwrap());
    }

    #[test]
    fn ps_promotion_from_as() {
        // Only AS, no CommitID, no DS: PS = AS
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]).unwrap();
        let auth_state = compute_as(&ks, None, &[HashAlg::Sha256]).unwrap();
        let ps = compute_ps(&auth_state, None, None, None, &[HashAlg::Sha256]).unwrap();

        assert_eq!(
            ps.get(HashAlg::Sha256).unwrap(),
            auth_state.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn full_promotion_chain() {
        // Level 1: PR = PS = CS = AS = KS = tmb
        let tmb = Thumbprint::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let ks = compute_ks(&[&tmb], None, &[HashAlg::Sha256]).unwrap();
        let auth_state = compute_as(&ks, None, &[HashAlg::Sha256]).unwrap();
        let _cs = compute_cs(&auth_state, None, &[HashAlg::Sha256]).unwrap();
        let ps = compute_ps(&auth_state, None, None, None, &[HashAlg::Sha256]).unwrap();
        let pr = PrincipalRoot::from_initial(&ps);

        // All should be identical to tmb
        let ks_bytes = ks.get(HashAlg::Sha256).unwrap();
        let as_bytes = auth_state.get(HashAlg::Sha256).unwrap();
        assert_eq!(ks_bytes, tmb.as_bytes());
        assert_eq!(as_bytes, tmb.as_bytes());
        assert_eq!(ps.get(HashAlg::Sha256).unwrap(), tmb.as_bytes());
        assert_eq!(pr.get(HashAlg::Sha256).unwrap(), tmb.as_bytes());
    }

    /// SPEC §14.2 Cross-Algorithm Conversion Test
    ///
    /// When computing a Merkle root with mixed-size digests, smaller digests
    /// are fed directly into larger hash functions. This test verifies:
    ///
    /// 1. Mixed-size thumbprints (32B ES256, 48B ES384, 64B Ed25519) can be
    ///    combined in a single KS computation
    /// 2. Each algorithm variant processes all thumbprints correctly
    /// 3. The resulting multihash contains variants for all active algorithms
    #[test]
    fn cross_algorithm_conversion_spec_14_2() {
        // Simulate real thumbprint sizes from different key algorithms:
        // ES256 → SHA-256 → 32 bytes
        // ES384 → SHA-384 → 48 bytes
        // Ed25519 → SHA-512 → 64 bytes
        let tmb_es256 = Thumbprint::from_bytes(vec![0xAA; 32]); // 32-byte ES256 tmb
        let tmb_es384 = Thumbprint::from_bytes(vec![0xBB; 48]); // 48-byte ES384 tmb
        let tmb_ed25519 = Thumbprint::from_bytes(vec![0xCC; 64]); // 64-byte Ed25519 tmb

        // Compute KS with all three algorithms active
        let all_algs = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];
        let ks = compute_ks(&[&tmb_es256, &tmb_es384, &tmb_ed25519], None, &all_algs).unwrap();

        // Verify all algorithm variants are present
        let sha256_variant = ks.get(HashAlg::Sha256);
        let sha384_variant = ks.get(HashAlg::Sha384);
        let sha512_variant = ks.get(HashAlg::Sha512);

        assert!(sha256_variant.is_some(), "SHA-256 variant should exist");
        assert!(sha384_variant.is_some(), "SHA-384 variant should exist");
        assert!(sha512_variant.is_some(), "SHA-512 variant should exist");

        // Verify each variant has the correct digest size
        assert_eq!(
            sha256_variant.unwrap().len(),
            32,
            "SHA-256 digest is 32 bytes"
        );
        assert_eq!(
            sha384_variant.unwrap().len(),
            48,
            "SHA-384 digest is 48 bytes"
        );
        assert_eq!(
            sha512_variant.unwrap().len(),
            64,
            "SHA-512 digest is 64 bytes"
        );

        // Verify all three variants are different (not trivially identical)
        assert_ne!(sha256_variant, sha384_variant);
        assert_ne!(sha384_variant, sha512_variant);
        assert_ne!(sha256_variant, sha512_variant);

        // Key insight: The 32-byte ES256 thumbprint is "converted" (fed directly)
        // into SHA-384 and SHA-512 computations. The implementation handles this
        // by concatenating all bytes regardless of size and hashing with each
        // target algorithm—exactly as SPEC §14.2 specifies.
    }

    // ========================================================================
    // TaggedDigest tests
    // ========================================================================

    #[test]
    fn tagged_digest_parse_valid_sha256() {
        // 32 bytes = 43 chars base64url (no padding)
        let input = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let digest: super::TaggedDigest = input.parse().expect("valid digest");

        assert_eq!(digest.alg(), super::HashAlg::Sha256);
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn tagged_digest_display_roundtrip() {
        let input = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let digest: super::TaggedDigest = input.parse().expect("valid digest");
        let output = digest.to_string();

        assert_eq!(input, output);
    }

    #[test]
    fn tagged_digest_serde_roundtrip() {
        let input = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let digest: super::TaggedDigest = input.parse().expect("valid digest");

        // Serialize to JSON
        let json = serde_json::to_string(&digest).expect("serialize");
        assert_eq!(json, format!("\"{}\"", input));

        // Deserialize from JSON
        let parsed: super::TaggedDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(digest, parsed);
    }

    #[test]
    fn tagged_digest_missing_separator() {
        let input = "SHA-256U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::MalformedDigest(_)),
            "expected MalformedDigest, got {:?}",
            err
        );
    }

    #[test]
    fn tagged_digest_unknown_algorithm() {
        let input = "SHA-999:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::UnsupportedAlgorithm(_)),
            "expected UnsupportedAlgorithm, got {:?}",
            err
        );
    }

    #[test]
    fn tagged_digest_length_mismatch() {
        // SHA-256 expects 32 bytes, but this is only 16 bytes
        // 16 bytes = 22 chars base64url (AAAAAAAAAAAAAAAAAAAAAA)
        let input = "SHA-256:AAAAAAAAAAAAAAAAAAAAAA";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::DigestLengthMismatch {
                    alg: super::HashAlg::Sha256,
                    expected: 32,
                    actual: 16,
                }
            ),
            "expected DigestLengthMismatch, got {:?}",
            err
        );
    }
}
