//! Commit types for atomic coz bundles.
//!
//! Per SPEC §4, a Commit is an atomic bundle of cozies.
//! The Commit ID is the Merkle root of only the cozies in a
//! single commit, not cumulatively.

use crate::parsed_coz::VerifiedCoz;
use crate::state::{
    AuthRoot, CommitID, HashAlg, PrincipalRoot, StateRoot, TaggedCzd, compute_commit_id_tagged,
};

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
    /// Commit ID: Merkle root of coz czds.
    commit_id: CommitID,
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
        commit_id: CommitID,
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
            commit_id,
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
    pub fn commit_id(&self) -> &CommitID {
        &self.commit_id
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
        if cz.state_root().is_some() {
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

    /// Compute the Commit ID for the current pending cozies.
    ///
    /// Returns `None` if no cozies have been added.
    pub fn compute_commit_id(&self) -> Option<CommitID> {
        if self.is_empty() {
            return None;
        }
        let all = self.iter_all_cozies();
        // Collect czds with their source algorithms for cross-algorithm conversion
        let tagged_czds: Vec<TaggedCzd<'_>> =
            all.map(|t| TaggedCzd::new(t.czd(), t.hash_alg())).collect();
        compute_commit_id_tagged(&tagged_czds, None, &[self.hash_alg])
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
        let all = self.iter_all_cozies();

        // Compute Commit ID from all coz czds with algorithm tagging
        let tagged_czds: Vec<TaggedCzd<'_>> =
            all.map(|t| TaggedCzd::new(t.czd(), t.hash_alg())).collect();
        let commit_id = compute_commit_id_tagged(&tagged_czds, None, &[self.hash_alg])
            .ok_or(crate::error::Error::EmptyCommit)?;

        Commit::new(self.transactions, commit_tx, commit_id, auth_root, sr, ps)
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

    /// Finalize the commit by signing the last coz with `commit:<CS>`.
    ///
    /// This is the creation-path API (Option A). It:
    /// 1. Parses the unsigned pay to determine the mutation
    /// 2. Applies the mutation eagerly
    /// 3. Computes CS = MR(AS', DS') from post-mutation state
    /// 4. Injects `"commit":<CS>` into the pay (in lexicographic key order)
    /// 5. Signs the complete pay via `coz::sign_json`
    /// 6. Computes czd from the signed message
    /// 7. Creates the final ParsedCoz with state_root
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
        use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
        use crate::state::{
            compute_ar, compute_kr, compute_sr, derive_hash_algs, hash_alg_from_str,
        };
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // 1. Parse pay to get mutation kind
        let parsed_pay: coz::Pay = serde_json::from_value(pay.clone())
            .map_err(|_| crate::error::Error::MalformedPayload)?;
        let hash_alg = hash_alg_from_str(alg)?;

        // 2. Create a preliminary ParsedCoz (with placeholder czd) to apply mutation
        let placeholder_czd = coz::Czd::from_bytes(vec![0u8; 32]);
        let placeholder_raw = coz::CozJson {
            pay: pay.clone(),
            sig: vec![],
        };
        let prelim_tx =
            ParsedCoz::from_pay(&parsed_pay, placeholder_czd, hash_alg, placeholder_raw)?;
        let prelim_vtx = VerifiedCoz::from_parts(prelim_tx, new_key.clone());

        // Apply mutation (verify_pre, key mutations, etc.)
        self.principal.apply_verified_internal(prelim_vtx)?;

        // 3. Compute CS post-mutation
        let key_refs: Vec<&crate::key::Key> = self.principal.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);

        let thumbprints: Vec<&coz::Thumbprint> =
            self.principal.auth.keys.values().map(|k| &k.tmb).collect();
        let ks = compute_kr(&thumbprints, None, &active_algs)?;
        let auth_root = compute_ar(&ks, None, None, &active_algs)?;
        let sr = compute_sr(&auth_root, self.principal.ds.as_ref(), None, &active_algs)?;

        // 4. Inject commit:<SR> into pay as alg:b64(digest) tagged string
        // Per Coz semantics, digest references in pay align with the signer's algorithm.
        let signer_hash_alg = hash_alg_from_str(alg)?;
        let sr_bytes = sr.0.get_or_err(signer_hash_alg)?;
        let sr_tagged = format!(
            "{}:{}",
            signer_hash_alg,
            Base64UrlUnpadded::encode_string(sr_bytes)
        );

        if let Some(obj) = pay.as_object_mut() {
            obj.insert("commit".to_string(), serde_json::Value::String(sr_tagged));
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

        // 7. Create the real ParsedCoz (with state_root and real czd)
        let raw = coz::CozJson {
            pay: pay.clone(),
            sig: sig_bytes,
        };
        let real_pay: coz::Pay =
            serde_json::from_value(pay).map_err(|_| crate::error::Error::MalformedPayload)?;
        let final_tx = ParsedCoz::from_pay(&real_pay, czd, hash_alg, raw)?;
        let final_vtx = VerifiedCoz::from_parts(final_tx, new_key);

        // 9. Push to pending sequence
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
    use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
    use coz::{Czd, PayBuilder, Thumbprint};
    use serde_json::json;

    // Valid alg:digest format for 32-byte SHA-256 digests
    const TEST_PRE: &str = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    const TEST_ID: &str = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";

    /// Create a test coz with specified finalizer flag.
    fn make_test_tx(is_finalizer: bool, czd_byte: u8) -> VerifiedCoz {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));
        if is_finalizer {
            pay.extra.insert(
                "commit".into(),
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
        assert!(pending.compute_commit_id().is_none());
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
        assert_eq!(commit.commit_id().get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn commit_multi_transaction_computes_correct_commit_id() {
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
        let cid = commit.commit_id();
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
