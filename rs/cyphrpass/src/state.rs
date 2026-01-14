//! State computation and digest types.
//!
//! Implements SPEC §7 state calculation semantics.

use coz::digest::Digest;
use coz::sha2::{Sha256, Sha384, Sha512};
use coz::{Cad, Czd, Thumbprint};

// ============================================================================
// State newtypes
// ============================================================================

/// Key State (KS) - SPEC §7.2
///
/// Digest of active key thumbprints.
/// Single key with no nonce: KS = tmb (implicit promotion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState(pub Cad);

impl KeyState {
    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
    }
}

/// Transaction State (TS) - SPEC §7.3
///
/// Digest of transaction `czd`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionState(pub Cad);

impl TransactionState {
    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
    }
}

/// Auth State (AS) - SPEC §7.5
///
/// Authentication state: `H(sort(KS, TS?, RS?))` or promoted if only KS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthState(pub Cad);

impl AuthState {
    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
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
pub struct PrincipalState(pub Cad);

impl PrincipalState {
    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
    }
}

/// Principal Root (PR) - SPEC §7.7
///
/// The first PS ever computed. Permanent, never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRoot(pub Cad);

impl PrincipalRoot {
    /// Create a PrincipalRoot from raw bytes (e.g., for testing).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Cad::from_bytes(bytes))
    }

    /// Create PR from the initial principal state (at genesis).
    pub fn from_initial(ps: &PrincipalState) -> Self {
        Self(ps.0.clone())
    }

    /// Get the inner Cad.
    pub fn as_cad(&self) -> &Cad {
        &self.0
    }
}

// ============================================================================
// Hash algorithm dispatch
// ============================================================================

/// Hash algorithm for state computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    // Sort lexicographically
    let mut sorted: Vec<&[u8]> = components.to_vec();
    sorted.sort();

    // Hash based on algorithm
    let bytes = match alg {
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
    };

    Cad::from_bytes(bytes)
}

// ============================================================================
// State computation functions
// ============================================================================

/// Compute Key State (SPEC §7.2).
///
/// - Single key, no nonce: KS = tmb (implicit promotion)
/// - Otherwise: KS = H(sort(tmb₀, tmb₁, nonce?, ...))
pub fn compute_ks(thumbprints: &[&Thumbprint], nonce: Option<&[u8]>, alg: HashAlg) -> KeyState {
    // Implicit promotion: single key, no nonce
    if thumbprints.len() == 1 && nonce.is_none() {
        return KeyState(Cad::from_bytes(thumbprints[0].as_bytes().to_vec()));
    }

    // Collect components
    let mut components: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    KeyState(hash_sorted_concat(alg, &components))
}

/// Compute Transaction State (SPEC §7.3).
///
/// - No transactions: TS = None
/// - Single transaction, no nonce: TS = czd (implicit promotion)
/// - Otherwise: TS = H(sort(czd₀, czd₁, nonce?, ...))
pub fn compute_ts(czds: &[&Czd], nonce: Option<&[u8]>, alg: HashAlg) -> Option<TransactionState> {
    if czds.is_empty() && nonce.is_none() {
        return None;
    }

    // Implicit promotion: single czd, no nonce
    if czds.len() == 1 && nonce.is_none() {
        return Some(TransactionState(Cad::from_bytes(
            czds[0].as_bytes().to_vec(),
        )));
    }

    let mut components: Vec<&[u8]> = czds.iter().map(|c| c.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    Some(TransactionState(hash_sorted_concat(alg, &components)))
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
    alg: HashAlg,
) -> AuthState {
    // Implicit promotion: only KS, nothing else
    if ts.is_none() && nonce.is_none() {
        return AuthState(ks.0.clone());
    }

    // Collect non-nil components
    let mut components: Vec<&[u8]> = vec![ks.0.as_bytes()];
    if let Some(t) = ts {
        components.push(t.0.as_bytes());
    }
    if let Some(n) = nonce {
        components.push(n);
    }

    AuthState(hash_sorted_concat(alg, &components))
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
/// - Otherwise: PS = H(sort(AS, DS?, nonce?))
pub fn compute_ps(
    auth_state: &AuthState,
    ds: Option<&DataState>,
    nonce: Option<&[u8]>,
    alg: HashAlg,
) -> PrincipalState {
    // Implicit promotion: only AS, nothing else
    if ds.is_none() && nonce.is_none() {
        return PrincipalState(auth_state.0.clone());
    }

    let mut components: Vec<&[u8]> = vec![auth_state.0.as_bytes()];
    if let Some(d) = ds {
        components.push(d.0.as_bytes());
    }
    if let Some(n) = nonce {
        components.push(n);
    }

    PrincipalState(hash_sorted_concat(alg, &components))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ks_single_key_promotion() {
        // Single key: KS = tmb (no hashing)
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, HashAlg::Sha256);
        assert_eq!(ks.0.as_bytes(), tmb.as_bytes());
    }

    #[test]
    fn ks_multi_key_hashes() {
        // Multiple keys: KS = H(sort(tmb₀, tmb₁))
        let tmb1 = Thumbprint::from_bytes(vec![1, 2, 3]);
        let tmb2 = Thumbprint::from_bytes(vec![4, 5, 6]);
        let ks = compute_ks(&[&tmb1, &tmb2], None, HashAlg::Sha256);

        // Should be hashed, not just concatenated
        assert_eq!(ks.0.as_bytes().len(), 32); // SHA-256 output
        assert_ne!(ks.0.as_bytes(), tmb1.as_bytes());
    }

    #[test]
    fn ks_with_nonce_hashes() {
        // Single key with nonce: still hashes (no promotion)
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let nonce = vec![0xAA, 0xBB];
        let ks = compute_ks(&[&tmb], Some(&nonce), HashAlg::Sha256);

        assert_eq!(ks.0.as_bytes().len(), 32);
        assert_ne!(ks.0.as_bytes(), tmb.as_bytes());
    }

    #[test]
    fn ts_empty_is_none() {
        let ts = compute_ts(&[], None, HashAlg::Sha256);
        assert!(ts.is_none());
    }

    #[test]
    fn ts_single_czd_promotion() {
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let ts = compute_ts(&[&czd], None, HashAlg::Sha256);
        assert_eq!(ts.unwrap().0.as_bytes(), czd.as_bytes());
    }

    #[test]
    fn as_promotion_from_ks() {
        // Only KS, no TS: AS = KS
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, HashAlg::Sha256);
        let auth_state = compute_as(&ks, None, None, HashAlg::Sha256);
        assert_eq!(auth_state.0.as_bytes(), ks.0.as_bytes());
    }

    #[test]
    fn as_with_ts_hashes() {
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, HashAlg::Sha256);
        let czd = Czd::from_bytes(vec![10, 20, 30]);
        let ts = compute_ts(&[&czd], None, HashAlg::Sha256).unwrap();

        let auth_state = compute_as(&ks, Some(&ts), None, HashAlg::Sha256);

        // Should be hashed combination
        assert_eq!(auth_state.0.as_bytes().len(), 32);
        assert_ne!(auth_state.0.as_bytes(), ks.0.as_bytes());
    }

    #[test]
    fn ps_promotion_from_as() {
        // Only AS, no DS: PS = AS
        let tmb = Thumbprint::from_bytes(vec![1, 2, 3, 4]);
        let ks = compute_ks(&[&tmb], None, HashAlg::Sha256);
        let auth_state = compute_as(&ks, None, None, HashAlg::Sha256);
        let ps = compute_ps(&auth_state, None, None, HashAlg::Sha256);

        assert_eq!(ps.0.as_bytes(), auth_state.0.as_bytes());
    }

    #[test]
    fn full_promotion_chain() {
        // Level 1: PR = PS = AS = KS = tmb
        let tmb = Thumbprint::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let ks = compute_ks(&[&tmb], None, HashAlg::Sha256);
        let auth_state = compute_as(&ks, None, None, HashAlg::Sha256);
        let ps = compute_ps(&auth_state, None, None, HashAlg::Sha256);
        let pr = PrincipalRoot::from_initial(&ps);

        // All should be identical to tmb
        assert_eq!(ks.0.as_bytes(), tmb.as_bytes());
        assert_eq!(auth_state.0.as_bytes(), tmb.as_bytes());
        assert_eq!(ps.0.as_bytes(), tmb.as_bytes());
        assert_eq!(pr.0.as_bytes(), tmb.as_bytes());
    }
}
