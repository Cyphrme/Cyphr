//! Commit types for atomic coz bundles.
//!
//! Per SPEC §4, a Commit is an atomic bundle of cozies.
//! The Commit ID is the Merkle root of only the cozies in a
//! single commit, not cumulatively.

use crate::parsed_coz::VerifiedCoz;
use crate::state::{AuthRoot, HashAlg, PrincipalRoot, StateRoot, TaggedCzd};

// ============================================================================
// Commit
// ============================================================================

/// A finalized, atomic bundle of cozies.
///
/// Per SPEC §4:
/// - `Commit ID = MR(sort(czd₀, czd₁, ...))` for cozies in this commit only
/// - `CS = MR(AS, Commit ID)` binds the auth state to the commit
/// - `pre` of first coz references previous commit's CS (or promoted AS for genesis)
///
/// A Commit is immutable once finalized.
#[derive(Debug, Clone)]
pub struct Commit {
    /// Transactions in this commit.
    pub(crate) transactions: Vec<crate::transaction::Transaction>,
    /// The terminal commit transaction.
    pub(crate) commit_tx: crate::transaction::CommitTransaction,
    /// Transaction Root: Merkle root of coz czds.
    tr: crate::transaction_root::TransactionRoot,
    /// Auth State at the end of this commit.
    auth_root: AuthRoot,
    /// State Root at the end of this commit.
    sr: StateRoot,
    /// Principal State at the end of this commit.
    ps: PrincipalRoot,
}

impl Commit {
    /// Create a new finalized commit from cozies and computed states.
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if `cozies` is empty.
    pub(crate) fn new(
        transactions: Vec<crate::transaction::Transaction>,
        commit_tx: crate::transaction::CommitTransaction,
        tr: crate::transaction_root::TransactionRoot,
        auth_root: AuthRoot,
        sr: StateRoot,
        ps: PrincipalRoot,
    ) -> crate::error::Result<Self> {
        if transactions.is_empty() && commit_tx.0.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }
        Ok(Self {
            transactions,
            commit_tx,
            tr,
            auth_root,
            sr,
            ps,
        })
    }

    /// Get the cozies in this commit.
    pub fn transactions(&self) -> &[crate::transaction::Transaction] {
        &self.transactions
    }
    pub fn commit_tx(&self) -> &crate::transaction::CommitTransaction {
        &self.commit_tx
    }
    /// Returns a flat vector of all cozies (mutations + commit).
    pub fn all_cozies(&self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
    }
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.0.iter())
            .chain(self.commit_tx.0.iter())
    }

    /// Get the Commit ID (Merkle root of this commit's czds).
    pub fn tr(&self) -> &crate::transaction_root::TransactionRoot {
        &self.tr
    }

    /// Get the State Root at the end of this commit.
    pub fn sr(&self) -> &StateRoot {
        &self.sr
    }

    /// Get the Auth State at the end of this commit.
    pub fn auth_root(&self) -> &AuthRoot {
        &self.auth_root
    }

    /// Get the Principal State at the end of this commit.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.ps
    }

    /// Get the number of cozies in this commit.
    pub fn len(&self) -> usize {
        self.iter_all_cozies().count()
    }

    /// Check if the commit is empty (should never be true for valid commits).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// PendingCommit
// ============================================================================

/// A commit that is being built but not yet finalized.
/// A commit being built.
/// Accumulates cozies before finalization.
#[derive(Debug, Clone)]
pub struct PendingCommit {
    pub(crate) transactions: Vec<crate::transaction::Transaction>,
    pub(crate) commit_tx: Option<crate::transaction::CommitTransaction>,
    pub(crate) raw: Vec<coz::CozJson>,
    pub(crate) hash_alg: HashAlg,
}

impl PendingCommit {
    /// Create a new empty pending commit with a specific hash algorithm.
    pub fn new(hash_alg: HashAlg) -> Self {
        Self {
            transactions: Vec::new(),
            commit_tx: None,
            raw: Vec::new(),
            hash_alg,
        }
    }

    /// Add a coz to the pending commit.
    pub fn push(&mut self, cz: VerifiedCoz) {
        if cz.arrow().is_some() {
            self.commit_tx = Some(crate::transaction::CommitTransaction(vec![cz]));
        } else {
            self.transactions
                .push(crate::transaction::Transaction(vec![cz]));
        }
    }

    /// Get the current list of pending cozies.
    pub fn transactions(&self) -> &[crate::transaction::Transaction] {
        &self.transactions
    }
    pub fn commit_tx(&self) -> Option<&crate::transaction::CommitTransaction> {
        self.commit_tx.as_ref()
    }
    /// Returns a flat vector of all cozies (mutations + commit).
    pub fn all_cozies(&self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
    }
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.0.iter())
            .chain(self.commit_tx.iter().flat_map(|ctx| ctx.0.iter()))
    }

    /// Check if the pending commit is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of pending cozies.
    pub fn len(&self) -> usize {
        self.iter_all_cozies().count()
    }

    /// Compute the Transaction Roots (TMR, TCR, TR) for the current pending cozies.
    pub fn compute_roots(
        &self,
    ) -> (
        Option<crate::transaction_root::TransactionMutationRoot>,
        Option<crate::transaction_root::TransactionCommitRoot>,
        Option<crate::transaction_root::TransactionRoot>,
    ) {
        if self.is_empty() {
            return (None, None, None);
        }

        let algs = &[self.hash_alg];

        let mut tx_roots = Vec::new();
        for tx in &self.transactions {
            let tx_czds: Vec<TaggedCzd<'_>> =
                tx.0.iter()
                    .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
                    .collect();
            if let Some(mh) = crate::transaction_root::compute_tx(&tx_czds, algs) {
                tx_roots.push(mh);
            }
        }
        let tx_refs: Vec<&crate::multihash::MultihashDigest> = tx_roots.iter().collect();
        let tmr = crate::transaction_root::compute_tmr(&tx_refs, algs);

        if let Some(ctx) = &self.commit_tx {
            let ctx_czds: Vec<TaggedCzd<'_>> = ctx
                .0
                .iter()
                .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
                .collect();
            if let Some(tcr) = crate::transaction_root::compute_tcr(&ctx_czds, algs) {
                let tr = crate::transaction_root::compute_tr(tmr.as_ref(), &tcr, algs);
                return (tmr, Some(tcr), tr);
            }
        }
        (tmr, None, None)
    }

    /// Compute the Transaction Root (TR) for the current pending cozies.
    pub fn compute_tr(&self) -> Option<crate::transaction_root::TransactionRoot> {
        self.compute_roots().2
    }

    /// Finalize the pending commit into an immutable `Commit`.
    ///
    /// # Arguments
    ///
    /// * `auth_root` - The computed Auth State after all cozies
    /// * `sr` - The computed State Root: MR(AR, DR?, embedding?)
    /// * `ps` - The computed Principal State after all cozies
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if no cozies exist.
    pub fn finalize(
        self,
        auth_root: AuthRoot,
        sr: StateRoot,
        ps: PrincipalRoot,
    ) -> crate::error::Result<Commit> {
        if self.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }

        let commit_tx = self
            .commit_tx
            .clone()
            .ok_or(crate::error::Error::MalformedPayload)?; // Must have a commit tx to finalize

        let tr = self.compute_tr().ok_or(crate::error::Error::EmptyCommit)?;

        Commit::new(self.transactions, commit_tx, tr, auth_root, sr, ps)
    }

    /// Consume the pending commit and return the cozies.
    ///
    /// Use this for rollback or when abandoning a pending commit.
    pub fn into_transactions(self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
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
/// forget to finalize after applying cozies.
///
/// # Single-ParsedCoz Convenience
///
/// For the common case of applying a single coz as an atomic commit,
/// use [`Principal::apply_transaction()`] instead of creating a scope manually.
///
/// # Example
///
/// ```ignore
/// // Multi-coz commit:
/// let mut scope = principal.begin_commit();
/// scope.apply(vtx1)?;
/// scope.apply(vtx2)?;
/// let commit = scope.finalize()?;
///
/// // Single-coz commit (convenience):
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

    /// Apply a verified coz within this commit scope.
    ///
    /// The coz mutates the principal's state eagerly (keys, timestamps,
    /// etc.). The borrow checker ensures no external code can observe this
    /// intermediate state.
    ///
    /// The coz is accumulated in the pending commit for finalization.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `InvalidPrior`: ParsedCoz's `pre` doesn't match current CS
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply(&mut self, vtx: VerifiedCoz) -> crate::error::Result<()> {
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
    /// Returns `EmptyCommit` if no cozies were applied.
    pub fn finalize(self) -> crate::error::Result<&'a Commit> {
        self.principal.finalize_commit(self.pending)
    }

    /// Verify a coz signature and apply it within this commit scope.
    ///
    /// This combines signature verification and application in one call,
    /// analogous to `Principal::verify_and_apply_transaction` but within
    /// a multi-coz commit scope.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this coz
    /// * `new_key` - New key to add (required for KeyCreate/KeyReplace)
    pub fn verify_and_apply(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<crate::key::Key>,
    ) -> crate::error::Result<()> {
        use crate::parsed_coz::verify_coz;

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

        // Verify signature and parse coz
        let vtx = verify_coz(pay_json, sig, signer_key, czd, new_key)?;

        // Apply within this scope
        self.apply(vtx)
    }

    /// Get the principal's primary hash algorithm.
    pub fn principal_hash_alg(&self) -> crate::state::HashAlg {
        self.principal.hash_alg()
    }
    /// Get the number of cozies applied so far.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if no cozies have been applied yet.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Finalize the commit by generating and signing a `commit/create` coz with the `arrow` field.
    ///
    /// This replaces `finalize_with_commit` and splits the mutation from finality.
    /// The caller MUST have previously applied transactions via `verify_and_apply` or `apply`.
    ///
    /// # Arguments
    ///
    /// * `alg` - Signer algorithm string (e.g. "ES256")
    /// * `prv_key` - Private key bytes for signing the Arrow
    /// * `pub_key` - Public key bytes
    /// * `tmb` - The thumbprint of the signer key
    /// * `now` - Timestamp for the commit coz
    ///
    /// # Errors
    ///
    /// - `EmptyCommit`: if no mutations exist.
    pub fn finalize_with_arrow(
        mut self,
        alg: &str,
        prv_key: &[u8],
        pub_key: &[u8],
        tmb: &coz::Thumbprint,
        now: i64,
    ) -> crate::error::Result<&'a Commit> {
        use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
        use crate::state::{
            compute_ar, compute_kr, compute_sr, derive_hash_algs, hash_alg_from_str,
            hash_sorted_concat_bytes,
        };
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        use serde_json::json;

        if self.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }

        let signer_hash_alg = hash_alg_from_str(alg)?;

        // 1. Recompute roots to get TMR and post-mutation SR
        let key_refs: Vec<&crate::key::Key> = self.principal.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);

        let thumbprints: Vec<&coz::Thumbprint> =
            self.principal.auth.keys.values().map(|k| &k.tmb).collect();
        let ks = compute_kr(&thumbprints, None, &active_algs)?;
        let auth_root = compute_ar(&ks, None, None, &active_algs)?;
        let sr = compute_sr(&auth_root, self.principal.ds.as_ref(), None, &active_algs)?;

        // For TMR we just use compute_roots early
        let (tmr, _, _) = self.pending.compute_roots();
        let tmr = tmr.ok_or(crate::error::Error::EmptyCommit)?;

        // 2. Compute Arrow = MR(pre, sr, tmr)
        // Arrow computation requires pre, sr, tmr slices
        // Wait, pre is the principal root of the previous state!
        // Where is pre? It's self.principal.ps!
        let pre = &self.principal.ps;

        let pre_bytes = pre.0.get_or_err(signer_hash_alg)?;
        let sr_bytes = sr.0.get_or_err(signer_hash_alg)?;
        let tmr_bytes = tmr.0.get_or_err(signer_hash_alg)?;

        // Arrow = MR(pre, fwd, TMR)
        let arrow_digest =
            hash_sorted_concat_bytes(signer_hash_alg, &[pre_bytes, sr_bytes, tmr_bytes]);

        // Arrow string format
        let arrow_tagged = format!(
            "{}:{}",
            signer_hash_alg,
            Base64UrlUnpadded::encode_string(&arrow_digest)
        );

        // 3. Construct commit/create payload
        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(alg));
        pay.insert("arrow".to_string(), json!(arrow_tagged));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(tmb.to_b64()));
        pay.insert(
            "typ".to_string(),
            json!(crate::parsed_coz::typ::COMMIT_CREATE),
        );

        let mut pay_obj = serde_json::Value::Object(pay);
        // Ensure deterministic order
        if let Some(obj) = pay_obj.as_object_mut() {
            obj.sort_keys();
        }

        let pay_vec =
            serde_json::to_vec(&pay_obj).map_err(|_| crate::error::Error::MalformedPayload)?;
        let (sig, cad) = coz::sign_json(&pay_vec, alg, prv_key, pub_key)
            .ok_or(crate::error::Error::MalformedPayload)?;
        let czd = coz::czd_for_alg(&cad, &sig, alg).ok_or(crate::error::Error::MalformedPayload)?;

        let raw = coz::CozJson {
            pay: pay_obj.clone(),
            sig: sig.clone(),
        };

        let parsed_pay: coz::Pay = serde_json::from_value(pay_obj.clone())
            .map_err(|_| crate::error::Error::MalformedPayload)?;

        let arrow_tx = ParsedCoz::from_pay(&parsed_pay, czd, signer_hash_alg, raw)?;
        let arrow_vtx = VerifiedCoz::from_parts(arrow_tx, None);

        // 4. Push commit marker and finalize
        self.pending.push(arrow_vtx);
        self.finalize()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multihash::MultihashDigest;
    use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
    use coz::{Czd, PayBuilder, Thumbprint};
    use serde_json::json;

    // Valid alg:digest format for 32-byte SHA-256 digests
    const TEST_PRE: &str = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    const TEST_ID: &str = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";

    /// Create a test coz. When `is_commit` is true, creates a commit/create
    /// coz with an arrow field (routes to commit_tx via push). When false,
    /// creates a mutation coz (routes to transactions).
    fn make_test_tx(is_commit: bool, czd_byte: u8) -> VerifiedCoz {
        let typ = if is_commit {
            "cyphrpass/commit/create"
        } else {
            "cyphr.me/key/create"
        };
        let mut pay = PayBuilder::new()
            .typ(typ)
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        if !is_commit {
            pay.extra.insert("pre".into(), json!(TEST_PRE));
            pay.extra.insert("id".into(), json!(TEST_ID));
        }
        if is_commit {
            pay.extra.insert(
                "arrow".into(),
                json!("SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"),
            );
        }

        let czd = Czd::from_bytes(vec![czd_byte; 32]);
        let raw = coz::CozJson {
            pay: serde_json::to_value(&pay).unwrap(),
            sig: vec![0; 64],
        };
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, raw).unwrap();
        VerifiedCoz::from_transaction_unsafe(cz, None)
    }

    // ========================================================================
    // PendingCommit Tests
    // ========================================================================

    #[test]
    fn pending_commit_empty_state() {
        let pending = PendingCommit::new(HashAlg::Sha256);
        assert!(pending.is_empty());
        assert_eq!(pending.len(), 0);
        assert!(pending.compute_tr().is_none());
    }

    #[test]
    fn pending_commit_push_adds_transactions() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);

        // Push cozies
        let tx1 = make_test_tx(false, 0x01);
        pending.push(tx1);
        assert_eq!(pending.len(), 1);

        let tx2 = make_test_tx(true, 0x02);
        pending.push(tx2);
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn pending_commit_compute_tr_returns_merkle_root() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let tx1 = make_test_tx(false, 0x01);
        pending
            .transactions
            .push(crate::transaction::Transaction(vec![tx1.clone()]));
        let ctx = crate::transaction::CommitTransaction(vec![tx1]);
        pending.commit_tx = Some(ctx);

        let tr = pending.compute_tr();
        assert!(tr.is_some());
        // Commit ID should be 32 bytes (SHA256)
        assert_eq!(
            tr.clone().unwrap().0.get(HashAlg::Sha256).unwrap().len(),
            32
        );
    }

    #[test]
    fn pending_commit_finalize_succeeds_with_finalizer() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let cz = make_test_tx(true, 0x01);
        pending.push(cz);

        let auth_root = AuthRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let sr = StateRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending.finalize(auth_root.clone(), sr.clone(), ps.clone());
        assert!(commit.is_ok());

        let commit = commit.unwrap();
        assert_eq!(commit.len(), 1);
        assert_eq!(commit.auth_root(), &auth_root);
        assert_eq!(commit.sr(), &sr);
        assert_eq!(commit.pr(), &ps);
    }

    #[test]
    fn pending_commit_finalize_fails_without_finalizer_marker() {
        // Finalizer must be present to distinguish the commit transaction
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        let cz = make_test_tx(false, 0x01); // No finalizer marker
        pending.push(cz);

        let auth_root = AuthRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let sr = StateRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let result = pending.finalize(auth_root, sr, ps);
        assert!(
            matches!(result, Err(crate::error::Error::MalformedPayload)),
            "finalize should fail without finalizer marker"
        );
    }

    #[test]
    fn pending_commit_finalize_fails_when_empty() {
        let pending = PendingCommit::new(HashAlg::Sha256);

        let auth_root = AuthRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let sr = StateRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let result = pending.finalize(auth_root, sr, ps);
        assert!(result.is_err(), "should fail when empty");
    }

    #[test]
    fn pending_commit_into_transactions_returns_accumulated() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(false, 0x01));
        pending.push(make_test_tx(true, 0x02));

        let cozies = pending.into_transactions();
        assert_eq!(cozies.len(), 2);
    }

    // ========================================================================
    // Commit Tests
    // ========================================================================

    #[test]
    fn commit_accessors_return_correct_values() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(true, 0x01));

        let auth_root = AuthRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let sr = StateRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending
            .finalize(auth_root.clone(), sr.clone(), ps.clone())
            .unwrap();

        // Test all accessors
        assert_eq!(commit.iter_all_cozies().count(), 1);
        assert!(!commit.is_empty());
        assert_eq!(commit.len(), 1);
        assert_eq!(commit.auth_root(), &auth_root);
        assert_eq!(commit.sr(), &sr);
        assert_eq!(commit.pr(), &ps);
        assert_eq!(commit.tr().0.get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn commit_multi_transaction_computes_correct_tr() {
        let mut pending = PendingCommit::new(HashAlg::Sha256);
        pending.push(make_test_tx(false, 0x01));
        pending.push(make_test_tx(false, 0x02));
        pending.push(make_test_tx(true, 0x03)); // finalizer

        let auth_root = AuthRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xAA; 32],
        ));
        let sr = StateRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xCC; 32],
        ));
        let ps = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xBB; 32],
        ));

        let commit = pending.finalize(auth_root, sr, ps).unwrap();
        assert_eq!(commit.len(), 3);

        // Commit ID should be Merkle root of all 3 coz czds
        let cid = &commit.tr().0;
        assert_eq!(cid.get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn test_cozjson_serialization() {
        let mut pay = json!({"typ": "test", "now": 1234});
        pay.as_object_mut()
            .unwrap()
            .insert("commit".to_string(), json!("SHA-256:abc"));

        // Use coz::CozJson directly to see if it drops the field!
        let raw = coz::CozJson {
            pay: pay.clone(),
            sig: vec![0, 1, 2],
        };

        let out = serde_json::to_string(&raw).unwrap();
        assert!(
            out.contains("commit"),
            "coz::CozJson serialization dropped 'commit'! Output: {}",
            out
        );
    }
}
