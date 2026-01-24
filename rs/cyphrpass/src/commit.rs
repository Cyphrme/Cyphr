//! Commit types for atomic transaction bundles.
//!
//! Per SPEC §4.2.1, a Commit is an atomic bundle of transactions.
//! The Transaction State (TS) is computed as the Merkle root of only
//! the transactions in a single commit, not cumulatively.

use crate::state::{AuthState, HashAlg, PrincipalState, TransactionState, compute_ts};
use crate::transaction::VerifiedTransaction;

// ============================================================================
// Commit
// ============================================================================

/// A finalized, atomic bundle of transactions.
///
/// Per SPEC §4.2.1:
/// - `TS = MR(sort(czd₀, czd₁, ...))` for transactions in this commit only
/// - The last transaction has `commit: true` in its payload
/// - `pre` of first transaction references previous commit's AS (or PR for genesis)
///
/// A Commit is immutable once finalized.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The verified transactions in this commit.
    transactions: Vec<VerifiedTransaction>,
    /// Transaction State: Merkle root of transaction czds.
    ts: TransactionState,
    /// Auth State at the end of this commit.
    auth_state: AuthState,
    /// Principal State at the end of this commit.
    ps: PrincipalState,
}

impl Commit {
    /// Create a new finalized commit from transactions and computed states.
    ///
    /// # Panics
    ///
    /// Panics if `transactions` is empty. Use `PendingCommit::finalize` for
    /// the normal flow which validates this invariant.
    pub(crate) fn new(
        transactions: Vec<VerifiedTransaction>,
        ts: TransactionState,
        auth_state: AuthState,
        ps: PrincipalState,
    ) -> Self {
        debug_assert!(
            !transactions.is_empty(),
            "Commit must contain at least one transaction"
        );
        Self {
            transactions,
            ts,
            auth_state,
            ps,
        }
    }

    /// Get the transactions in this commit.
    pub fn transactions(&self) -> &[VerifiedTransaction] {
        &self.transactions
    }

    /// Get the Transaction State (Merkle root of this commit's czds).
    pub fn ts(&self) -> &TransactionState {
        &self.ts
    }

    /// Get the Auth State at the end of this commit.
    pub fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }

    /// Get the Principal State at the end of this commit.
    pub fn ps(&self) -> &PrincipalState {
        &self.ps
    }

    /// Get the number of transactions in this commit.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the commit is empty (should never be true for valid commits).
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

// ============================================================================
// PendingCommit
// ============================================================================

/// A commit that is being built but not yet finalized.
///
/// Transactions can be added to a pending commit until the final transaction
/// with `commit: true` is received, at which point `finalize()` converts it
/// to an immutable `Commit`.
///
/// Per SPEC §4.2.1, the state during a pending commit is "transitory" and
/// cannot be referenced by external transactions until finalized.
#[derive(Debug, Clone)]
pub struct PendingCommit {
    /// Accumulated transactions (not yet finalized).
    transactions: Vec<VerifiedTransaction>,
    /// Hash algorithm for state computation.
    hash_alg: HashAlg,
}

impl PendingCommit {
    /// Create a new empty pending commit.
    pub fn new(hash_alg: HashAlg) -> Self {
        Self {
            transactions: Vec::new(),
            hash_alg,
        }
    }

    /// Add a transaction to the pending commit.
    ///
    /// Returns whether this transaction has the `commit: true` finalizer.
    /// The caller should call `finalize()` after adding a finalizing transaction.
    pub fn push(&mut self, tx: VerifiedTransaction) -> bool {
        let is_finalizer = tx.is_finalizer();
        self.transactions.push(tx);
        is_finalizer
    }

    /// Get the current list of pending transactions.
    pub fn transactions(&self) -> &[VerifiedTransaction] {
        &self.transactions
    }

    /// Check if the pending commit is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get the number of pending transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Compute the Transaction State for the current pending transactions.
    ///
    /// Returns `None` if no transactions have been added.
    pub fn compute_ts(&self) -> Option<TransactionState> {
        if self.transactions.is_empty() {
            return None;
        }
        let czds: Vec<&coz::Czd> = self.transactions.iter().map(|t| t.czd()).collect();
        compute_ts(&czds, None, self.hash_alg)
    }

    /// Finalize the pending commit into an immutable `Commit`.
    ///
    /// # Arguments
    ///
    /// * `auth_state` - The computed Auth State after all transactions
    /// * `ps` - The computed Principal State after all transactions
    ///
    /// # Errors
    ///
    /// Returns `None` if no transactions exist or if the last transaction
    /// does not have the `commit: true` finalizer.
    pub fn finalize(self, auth_state: AuthState, ps: PrincipalState) -> Option<Commit> {
        if self.transactions.is_empty() {
            return None;
        }

        // Verify last transaction is a finalizer
        let last = self.transactions.last()?;
        if !last.is_finalizer() {
            return None;
        }

        // Compute TS from all transaction czds
        let czds: Vec<&coz::Czd> = self.transactions.iter().map(|t| t.czd()).collect();
        let ts = compute_ts(&czds, None, self.hash_alg)?;

        Some(Commit::new(self.transactions, ts, auth_state, ps))
    }

    /// Consume the pending commit and return the transactions.
    ///
    /// Use this for rollback or when abandoning a pending commit.
    pub fn into_transactions(self) -> Vec<VerifiedTransaction> {
        self.transactions
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require the Transaction is_finalizer() method to be implemented
    // TODO: Add comprehensive tests after Task 1.2 completes

    #[test]
    fn pending_commit_empty_state() {
        let pending = PendingCommit::new(HashAlg::Sha256);
        assert!(pending.is_empty());
        assert_eq!(pending.len(), 0);
        assert!(pending.compute_ts().is_none());
    }
}
