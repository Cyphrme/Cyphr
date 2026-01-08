//! State computation and digest types.
//!
//! Implements SPEC §7 state calculation semantics.

use coz::Cad;

/// Key State (KS) - SPEC §7.2
///
/// Digest of active key thumbprints.
/// Single key with no nonce: KS = tmb (implicit promotion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyState(pub Cad);

/// Transaction State (TS) - SPEC §7.3
///
/// Digest of transaction `czd`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionState(pub Cad);

/// Auth State (AS) - SPEC §7.5
///
/// Authentication state: `H(sort(KS, TS?, RS?))` or promoted if only KS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthState(pub Cad);

/// Data State (DS) - SPEC §7.4
///
/// State of user actions (Level 4+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataState(pub Cad);

/// Principal State (PS) - SPEC §7.6
///
/// Current top-level state: `H(sort(AS, DS?))` or promoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalState(pub Cad);

/// Principal Root (PR) - SPEC §7.7
///
/// The first PS ever computed. Permanent, never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRoot(pub Cad);

impl PrincipalRoot {
    /// Create PR from the initial principal state (at genesis).
    pub fn from_initial(ps: &PrincipalState) -> Self {
        Self(ps.0.clone())
    }
}

// TODO: Implement compute_ks, compute_ts, compute_as, compute_ds, compute_ps
// These require the hash_sorted_concat helper which we'll add in C6.
