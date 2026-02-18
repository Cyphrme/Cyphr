//! Commit types for atomic transaction bundles.
//!
//! Per SPEC §4, a Commit is an atomic bundle of transactions.
//! The Commit ID is the Merkle root of only the transactions in a
//! single commit, not cumulatively.

use crate::state::{
    AuthState, CommitID, CommitState, HashAlg, PrincipalState, TaggedCzd, compute_commit_id_tagged,
};
use crate::transaction::VerifiedTransaction;

// ============================================================================
// Commit
// ============================================================================

/// A finalized, atomic bundle of transactions.
///
/// Per SPEC §4:
/// - `Commit ID = MR(sort(czd₀, czd₁, ...))` for transactions in this commit only
/// - `CS = MR(AS, Commit ID)` binds the auth state to the commit
/// - `pre` of first transaction references previous commit's CS (or promoted AS for genesis)
///
/// A Commit is immutable once finalized.
#[derive(Debug, Clone)]
pub struct Commit {
    /// The verified transactions in this commit.
    transactions: Vec<VerifiedTransaction>,
    /// Commit ID: Merkle root of transaction czds.
    commit_id: CommitID,
    /// Auth State at the end of this commit.
    auth_state: AuthState,
    /// Commit State: MR(AS, Commit ID).
    cs: CommitState,
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
        commit_id: CommitID,
        auth_state: AuthState,
        cs: CommitState,
        ps: PrincipalState,
    ) -> Self {
        debug_assert!(
            !transactions.is_empty(),
            "Commit must contain at least one transaction"
        );
        Self {
            transactions,
            commit_id,
            auth_state,
            cs,
            ps,
        }
    }

    /// Get the transactions in this commit.
    pub fn transactions(&self) -> &[VerifiedTransaction] {
        &self.transactions
    }

    /// Get the Commit ID (Merkle root of this commit's czds).
    pub fn commit_id(&self) -> &CommitID {
        &self.commit_id
    }

    /// Get the Commit State: MR(AS, Commit ID).
    pub fn cs(&self) -> &CommitState {
        &self.cs
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
    pub fn push(&mut self, tx: VerifiedTransaction) {
        self.transactions.push(tx);
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

    /// Compute the Commit ID for the current pending transactions.
    ///
    /// Returns `None` if no transactions have been added.
    pub fn compute_commit_id(&self) -> Option<CommitID> {
        if self.transactions.is_empty() {
            return None;
        }
        // Collect czds with their source algorithms for cross-algorithm conversion
        let tagged_czds: Vec<TaggedCzd<'_>> = self
            .transactions
            .iter()
            .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
            .collect();
        compute_commit_id_tagged(&tagged_czds, None, &[self.hash_alg])
    }

    /// Finalize the pending commit into an immutable `Commit`.
    ///
    /// # Arguments
    ///
    /// * `auth_state` - The computed Auth State after all transactions
    /// * `cs` - The computed Commit State: MR(AS, Commit ID)
    /// * `ps` - The computed Principal State after all transactions
    ///
    /// # Errors
    ///
    /// Returns `None` if no transactions exist.
    pub fn finalize(
        self,
        auth_state: AuthState,
        cs: CommitState,
        ps: PrincipalState,
    ) -> Option<Commit> {
        if self.transactions.is_empty() {
            return None;
        }

        // Compute Commit ID from all transaction czds with algorithm tagging
        let tagged_czds: Vec<TaggedCzd<'_>> = self
            .transactions
            .iter()
            .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
            .collect();
        let commit_id = compute_commit_id_tagged(&tagged_czds, None, &[self.hash_alg])?;

        Some(Commit::new(
            self.transactions,
            commit_id,
            auth_state,
            cs,
            ps,
        ))
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
    use crate::multihash::MultihashDigest;
    use crate::transaction::{Transaction, VerifiedTransaction};
    use coz::{Czd, PayBuilder, Thumbprint};
    use serde_json::json;

    // Valid alg:digest format for 32-byte SHA-256 digests
    const TEST_PRE: &str = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    const TEST_ID: &str = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";

    /// Create a test transaction with specified finalizer flag.
    fn make_test_tx(is_finalizer: bool, czd_byte: u8) -> VerifiedTransaction {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));
        if is_finalizer {
            pay.extra.insert("commit".into(), json!(true));
        }

        let czd = Czd::from_bytes(vec![czd_byte; 32]);
        let raw = coz::CozJson {
            pay: serde_json::to_value(&pay).unwrap(),
            sig: vec![0; 64],
        };
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, raw).unwrap();
        VerifiedTransaction::from_transaction_unsafe(tx, None)
    }

    // ========================================================================
    // PendingCommit Tests
    // ========================================================================

    #[test]
    fn pending_commit_empty_state() {
        let pending = PendingCommit::new(HashAlg::Sha256);
        assert!(pending.is_empty());
        assert_eq!(pending.len(), 0);
        assert!(pending.compute_commit_id().is_none());
    }

    #[test]
    fn pending_commit_push_adds_transactions() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);

        // Push transactions
        let tx1 = make_test_tx(false, 0x01);
        pending.push(tx1);
        assert_eq!(pending.len(), 1);

        let tx2 = make_test_tx(true, 0x02);
        pending.push(tx2);
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn pending_commit_compute_commit_id_returns_merkle_root() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let tx1 = make_test_tx(false, 0x01);
        pending.push(tx1);

        let commit_id = pending.compute_commit_id();
        assert!(commit_id.is_some());
        // Commit ID should be 32 bytes (SHA256)
        assert_eq!(commit_id.unwrap().get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn pending_commit_finalize_succeeds_with_finalizer() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let tx = make_test_tx(true, 0x01);
        pending.push(tx);

        let auth_state = AuthState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let cs = CommitState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending.finalize(auth_state.clone(), cs.clone(), ps.clone());
        assert!(commit.is_some());

        let commit = commit.unwrap();
        assert_eq!(commit.len(), 1);
        assert_eq!(commit.auth_state(), &auth_state);
        assert_eq!(commit.cs(), &cs);
        assert_eq!(commit.ps(), &ps);
    }

    #[test]
    fn pending_commit_finalize_succeeds_without_finalizer_marker() {
        // Per protocol simplification, commit: true is no longer required
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let tx = make_test_tx(false, 0x01); // No finalizer marker, but finalize should succeed
        pending.push(tx);

        let auth_state = AuthState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let cs = CommitState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let result = pending.finalize(auth_state, cs, ps);
        assert!(
            result.is_some(),
            "finalize should succeed without finalizer marker"
        );
    }

    #[test]
    fn pending_commit_finalize_fails_when_empty() {
        let pending = PendingCommit::new(HashAlg::Sha256);

        let auth_state = AuthState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let cs = CommitState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let result = pending.finalize(auth_state, cs, ps);
        assert!(result.is_none(), "should fail when empty");
    }

    #[test]
    fn pending_commit_into_transactions_returns_accumulated() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(false, 0x01));
        pending.push(make_test_tx(true, 0x02));

        let txs = pending.into_transactions();
        assert_eq!(txs.len(), 2);
    }

    // ========================================================================
    // Commit Tests
    // ========================================================================

    #[test]
    fn commit_accessors_return_correct_values() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(true, 0x01));

        let auth_state = AuthState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let cs = CommitState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending
            .finalize(auth_state.clone(), cs.clone(), ps.clone())
            .unwrap();

        // Test all accessors
        assert_eq!(commit.transactions().len(), 1);
        assert!(!commit.is_empty());
        assert_eq!(commit.len(), 1);
        assert_eq!(commit.auth_state(), &auth_state);
        assert_eq!(commit.cs(), &cs);
        assert_eq!(commit.ps(), &ps);
        assert_eq!(commit.commit_id().get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn commit_multi_transaction_computes_correct_commit_id() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(false, 0x01));
        pending.push(make_test_tx(false, 0x02));
        pending.push(make_test_tx(true, 0x03)); // finalizer

        let auth_state = AuthState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let cs = CommitState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalState(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending.finalize(auth_state, cs, ps).unwrap();
        assert_eq!(commit.len(), 3);

        // Commit ID should be Merkle root of all 3 transaction czds
        let cid = commit.commit_id();
        assert_eq!(cid.get(HashAlg::Sha256).unwrap().len(), 32);
    }
}
