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
    /// # Errors
    ///
    /// Returns `EmptyCommit` if `transactions` is empty.
    pub(crate) fn new(
        transactions: Vec<VerifiedTransaction>,
        commit_id: CommitID,
        auth_state: AuthState,
        cs: CommitState,
        ps: PrincipalState,
    ) -> crate::error::Result<Self> {
        if transactions.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }
        Ok(Self {
            transactions,
            commit_id,
            auth_state,
            cs,
            ps,
        })
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
    /// Returns `EmptyCommit` if no transactions exist.
    pub fn finalize(
        self,
        auth_state: AuthState,
        cs: CommitState,
        ps: PrincipalState,
    ) -> crate::error::Result<Commit> {
        if self.transactions.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }

        // Compute Commit ID from all transaction czds with algorithm tagging
        let tagged_czds: Vec<TaggedCzd<'_>> = self
            .transactions
            .iter()
            .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
            .collect();
        let commit_id = compute_commit_id_tagged(&tagged_czds, None, &[self.hash_alg])
            .ok_or(crate::error::Error::EmptyCommit)?;

        Commit::new(self.transactions, commit_id, auth_state, cs, ps)
    }

    /// Consume the pending commit and return the transactions.
    ///
    /// Use this for rollback or when abandoning a pending commit.
    pub fn into_transactions(self) -> Vec<VerifiedTransaction> {
        self.transactions
    }
}

// ============================================================================
// CommitScope
// ============================================================================

/// A scoped commit builder that holds an exclusive borrow of a `Principal`.
///
/// Created via [`Principal::begin_commit()`]. Transactions are applied with
/// [`apply()`](Self::apply), and the commit is finalized by calling
/// [`finalize()`](Self::finalize) which consumes the scope and returns a
/// reference to the new [`Commit`].
///
/// # Typestate Enforcement
///
/// The borrow checker ensures that while a `CommitScope` exists:
/// - No external code can read or mutate the `Principal`
/// - Intermediate state (after apply but before finalize) is unobservable
///
/// This structurally prevents the "pending commit trap" where consumers
/// forget to finalize after applying transactions.
///
/// # Single-Transaction Convenience
///
/// For the common case of applying a single transaction as an atomic commit,
/// use [`Principal::apply_transaction()`] instead of creating a scope manually.
///
/// # Example
///
/// ```ignore
/// // Multi-transaction commit:
/// let mut scope = principal.begin_commit();
/// scope.apply(vtx1)?;
/// scope.apply(vtx2)?;
/// let commit = scope.finalize()?;
///
/// // Single-transaction commit (convenience):
/// let commit = principal.apply_transaction(vtx)?;
/// ```
#[must_use = "a CommitScope must be finalized via .finalize() to produce a Commit"]
pub struct CommitScope<'a> {
    principal: &'a mut crate::principal::Principal,
    pending: PendingCommit,
}

impl<'a> CommitScope<'a> {
    /// Create a new commit scope for the given principal.
    ///
    /// This is called by [`Principal::begin_commit()`].
    pub(crate) fn new(principal: &'a mut crate::principal::Principal) -> Self {
        let hash_alg = principal.hash_alg();
        Self {
            principal,
            pending: PendingCommit::new(hash_alg),
        }
    }

    /// Apply a verified transaction within this commit scope.
    ///
    /// The transaction mutates the principal's state eagerly (keys, timestamps,
    /// etc.). The borrow checker ensures no external code can observe this
    /// intermediate state.
    ///
    /// The transaction is accumulated in the pending commit for finalization.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Transaction timestamp is older than latest seen
    /// - `TimestampFuture`: Transaction timestamp is too far in the future
    /// - `InvalidPrior`: Transaction's `pre` doesn't match current CS
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply(&mut self, vtx: VerifiedTransaction) -> crate::error::Result<()> {
        self.principal.apply_verified_internal(vtx.clone())?;
        self.pending.push(vtx);
        Ok(())
    }

    /// Finalize the commit scope, producing an immutable `Commit`.
    ///
    /// Consumes this scope and returns a reference to the newly created
    /// `Commit` within the principal's auth ledger.
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if no transactions were applied.
    pub fn finalize(self) -> crate::error::Result<&'a Commit> {
        self.principal.finalize_commit(self.pending)
    }

    /// Verify a transaction signature and apply it within this commit scope.
    ///
    /// This combines signature verification and application in one call,
    /// analogous to `Principal::verify_and_apply_transaction` but within
    /// a multi-transaction commit scope.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this transaction
    /// * `new_key` - New key to add (required for KeyCreate/KeyReplace)
    pub fn verify_and_apply(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<crate::key::Key>,
    ) -> crate::error::Result<()> {
        use crate::transaction::verify_transaction;

        // Parse Pay to get signer thumbprint
        let pay: coz::Pay =
            serde_json::from_slice(pay_json).map_err(|_| crate::error::Error::MalformedPayload)?;
        let signer_tmb = pay
            .tmb
            .as_ref()
            .ok_or(crate::error::Error::MalformedPayload)?;

        // Signer must be an ACTIVE key (not revoked)
        if !self.principal.is_key_active(signer_tmb) {
            if self.principal.is_key_revoked(signer_tmb) {
                return Err(crate::error::Error::KeyRevoked);
            }
            return Err(crate::error::Error::UnknownKey);
        }

        // Look up signer key
        let signer_key = self
            .principal
            .get_key(signer_tmb)
            .ok_or(crate::error::Error::UnknownKey)?;

        // Verify signature and parse transaction
        let vtx = verify_transaction(pay_json, sig, signer_key, czd, new_key)?;

        // Apply within this scope
        self.apply(vtx)
    }

    /// Get the principal's primary hash algorithm.
    pub fn principal_hash_alg(&self) -> crate::state::HashAlg {
        self.principal.hash_alg()
    }
    /// Get the number of transactions applied so far.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if no transactions have been applied yet.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Finalize the commit by signing the last transaction with `commit:<CS>`.
    ///
    /// This is the creation-path API (Option A). It:
    /// 1. Parses the unsigned pay to determine the mutation
    /// 2. Applies the mutation eagerly
    /// 3. Computes CS = MR(AS', DS') from post-mutation state
    /// 4. Injects `"commit":<CS>` into the pay (in lexicographic key order)
    /// 5. Signs the complete pay via `coz::sign_json`
    /// 6. Computes czd from the signed message
    /// 7. Creates the final Transaction with commit_state
    /// 8. Pushes to pending and calls finalize_commit
    ///
    /// # Arguments
    ///
    /// * `pay` - Pay fields as a JSON Value (object, without `commit` key)
    /// * `alg` - Algorithm string (e.g. "ES256")
    /// * `prv_key` - Private key bytes
    /// * `pub_key` - Public key bytes
    /// * `new_key` - Optional new key for KeyCreate/KeyReplace
    ///
    /// # Errors
    ///
    /// - `MalformedPayload`: Pay missing required fields
    /// - `InvalidPrior`: `pre` doesn't match current PS
    /// - Signing failures (from coz)
    pub fn finalize_with_commit(
        mut self,
        mut pay: serde_json::Value,
        alg: &str,
        prv_key: &[u8],
        pub_key: &[u8],
        new_key: Option<crate::key::Key>,
    ) -> crate::error::Result<&'a Commit> {
        use crate::state::{
            compute_as, compute_cs, compute_ks, derive_hash_algs, hash_alg_from_str,
        };
        use crate::transaction::{Transaction, VerifiedTransaction};
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // 1. Parse pay to get mutation kind
        let parsed_pay: coz::Pay = serde_json::from_value(pay.clone())
            .map_err(|_| crate::error::Error::MalformedPayload)?;
        let hash_alg = hash_alg_from_str(alg)?;

        // 2. Create a preliminary Transaction (with placeholder czd) to apply mutation
        let placeholder_czd = coz::Czd::from_bytes(vec![0u8; 32]);
        let placeholder_raw = coz::CozJson {
            pay: pay.clone(),
            sig: vec![],
        };
        let prelim_tx =
            Transaction::from_pay(&parsed_pay, placeholder_czd, hash_alg, placeholder_raw)?;
        let prelim_vtx = VerifiedTransaction::from_parts(prelim_tx, new_key.clone());

        // Apply mutation (verify_pre, key mutations, etc.)
        self.principal.apply_verified_internal(prelim_vtx)?;

        // 3. Compute CS post-mutation
        let key_refs: Vec<&crate::key::Key> = self.principal.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);

        let thumbprints: Vec<&coz::Thumbprint> =
            self.principal.auth.keys.values().map(|k| &k.tmb).collect();
        let ks = compute_ks(&thumbprints, None, &active_algs)?;
        let auth_state = compute_as(&ks, None, &active_algs)?;
        let cs = compute_cs(&auth_state, self.principal.ds.as_ref(), &active_algs)?;

        // 4. Inject commit:<CS> into pay as alg:b64(digest) tagged string
        // Per Coz semantics, digest references in pay align with the signer's algorithm.
        let signer_hash_alg = hash_alg_from_str(alg)?;
        let cs_bytes = cs.0.get_or_err(signer_hash_alg)?;
        let cs_tagged = format!(
            "{}:{}",
            signer_hash_alg,
            Base64UrlUnpadded::encode_string(cs_bytes)
        );

        if let Some(obj) = pay.as_object_mut() {
            obj.insert("commit".to_string(), serde_json::Value::String(cs_tagged));
            // Re-sort keys for Coz canonical ordering.
            // serde_json with `preserve_order` appends new keys at the end;
            // we need lexicographic order for deterministic serialization.
            obj.sort_keys();
        } else {
            return Err(crate::error::Error::MalformedPayload);
        }

        // 5. Serialize and sign
        let pay_json =
            serde_json::to_vec(&pay).map_err(|_| crate::error::Error::MalformedPayload)?;
        let (sig_bytes, cad) = coz::sign_json(&pay_json, alg, prv_key, pub_key)
            .ok_or(crate::error::Error::InvalidSignature)?;

        // 6. Compute czd
        let czd =
            coz::czd_for_alg(&cad, &sig_bytes, alg).ok_or(crate::error::Error::InvalidSignature)?;

        // 7. Create the real Transaction (with commit_state and real czd)
        let raw = coz::CozJson {
            pay: pay.clone(),
            sig: sig_bytes,
        };
        let real_pay: coz::Pay =
            serde_json::from_value(pay).map_err(|_| crate::error::Error::MalformedPayload)?;
        let final_tx = Transaction::from_pay(&real_pay, czd, hash_alg, raw)?;
        let final_vtx = VerifiedTransaction::from_parts(final_tx, new_key);

        // 8. Push to pending and finalize
        self.pending.push(final_vtx);
        self.principal.finalize_commit(self.pending)
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
        assert!(commit.is_ok());

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
            result.is_ok(),
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
        assert!(result.is_err(), "should fail when empty");
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
