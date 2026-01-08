//! Principal (identity) types.

use indexmap::IndexMap;

use crate::key::Key;
use crate::state::{AuthState, KeyState, PrincipalRoot, PrincipalState, TransactionState};
use crate::transaction::Transaction;

/// Auth ledger holding keys and transactions.
#[derive(Debug, Clone, Default)]
pub struct AuthLedger {
    /// Active keys (tmb b64 string → Key).
    pub keys: IndexMap<String, Key>,
    /// Revoked keys for historical verification.
    pub revoked: IndexMap<String, Key>,
    /// Signed transactions.
    pub transactions: Vec<Transaction>,
}

/// Feature level of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Single static key.
    L1,
    /// Key replacement.
    L2,
    /// Multi-key.
    L3,
    /// Data layer (AAA).
    L4,
}

/// A Cyphrpass Principal (self-sovereign identity).
#[derive(Debug, Clone)]
pub struct Principal {
    /// Principal Root - permanent, set at genesis.
    pr: PrincipalRoot,
    /// Current Principal State.
    ps: PrincipalState,
    /// Current Key State.
    ks: KeyState,
    /// Current Transaction State.
    ts: Option<TransactionState>,
    /// Current Auth State.
    auth_state: AuthState,
    /// Auth ledger.
    auth: AuthLedger,
    /// Primary algorithm (from first key).
    alg: String,
}

impl Principal {
    /// Get the Principal Root.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
    }

    /// Get the current Principal State.
    pub fn ps(&self) -> &PrincipalState {
        &self.ps
    }

    /// Get the current Auth State.
    pub fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }
}

// TODO: Implement Principal::implicit, Principal::explicit genesis
// TODO: Implement add_key, revoke_key, etc.
