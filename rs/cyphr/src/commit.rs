//! Commit types for atomic coz bundles.
//!
//! Per SPEC §4, a Commit is an atomic bundle of cozies.
//! The Commit ID is the Merkle root of only the cozies in a
//! single commit, not cumulatively.

use crate::parsed_coz::VerifiedCoz;
use crate::signer::{Signer, SoftwareSigner};
use crate::state::{AuthRoot, PrincipalRoot, StateRoot};

// ============================================================================
// Commit
// ============================================================================

/// A finalized, atomic bundle of cozies.
///
/// Per SPEC §4:
/// - `Commit ID = MR(sort(czd₀, czd₁, ...))` for cozies in this commit only
/// - `CS = MR(AS, Commit ID)` binds the auth state to the commit
/// - `arrow = MR(pre, fwd, TMR)` on the closing `commit/create` cz references the previous commit's
///   CS (or promoted AS for genesis)
///
/// A Commit is immutable once finalized.
#[derive(Debug, Clone)]
pub struct Commit {
    /// Transactions in this commit.
    pub(crate) transactions: Vec<crate::transaction::Transaction>,
    /// Transaction Root: Merkle root of coz czds.
    tr: crate::transaction_root::TransactionRoot,
    /// Auth Root at the end of this commit; `None` when the commit left no
    /// key (SPEC 3.7: an empty component is omitted).
    ar: Option<AuthRoot>,
    /// State Root at the end of this commit; `None` when the commit left no
    /// key and the principal holds no data.
    sr: Option<StateRoot>,
    /// Principal Root at the end of this commit.
    pr: PrincipalRoot,
}

impl Commit {
    /// Create a new finalized commit from cozies and computed states.
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if `transactions` is empty.
    pub(crate) fn new(
        transactions: Vec<crate::transaction::Transaction>,
        tr: crate::transaction_root::TransactionRoot,
        ar: Option<AuthRoot>,
        sr: Option<StateRoot>,
        pr: PrincipalRoot,
    ) -> crate::error::Result<Self> {
        if transactions.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }
        Ok(Self {
            transactions,
            tr,
            ar,
            sr,
            pr,
        })
    }

    /// Get the cozies in this commit.
    pub fn transactions(&self) -> &[crate::transaction::Transaction] {
        &self.transactions
    }

    /// Returns the commit transaction, which is the final logical transaction of the atomic bundle.
    ///
    /// `Commit::new` (the only constructor) rejects an empty `transactions`
    /// with `Error::EmptyCommit`, and nothing mutates `transactions` after
    /// construction -- a live `Commit` always has at least one.
    pub fn commit_tx(&self) -> &crate::transaction::Transaction {
        self.transactions.last().unwrap()
    }

    /// Returns a flat vector of all cozies (mutations + commit).
    pub fn all_cozies(&self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
    }

    /// Iterates over all cozies in this commit bundle (mutations followed by the commit/create
    /// synthetic coz).
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.transactions.iter().flat_map(|tx| tx.0.iter())
    }

    /// Get the Commit ID (Merkle root of this commit's czds).
    pub fn tr(&self) -> &crate::transaction_root::TransactionRoot {
        &self.tr
    }

    /// Get the State Root at the end of this commit; `None` when the commit
    /// left a principal with no keys and no data.
    pub fn sr(&self) -> Option<&StateRoot> {
        self.sr.as_ref()
    }

    /// Get the Auth Root at the end of this commit; `None` when the commit
    /// left a principal with no keys.
    pub fn auth_root(&self) -> Option<&AuthRoot> {
        self.ar.as_ref()
    }

    /// Get the Principal Root at the end of this commit.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
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
#[derive(Debug, Clone, Default)]
pub struct PendingCommit {
    pub(crate) transactions: Vec<crate::transaction::Transaction>,
}

impl PendingCommit {
    /// Create a new empty pending commit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a grouped transaction to the pending commit.
    pub fn push_tx(&mut self, tx: crate::transaction::Transaction) {
        if tx.0.is_empty() {
            return;
        }
        self.transactions.push(tx);
    }

    /// Get the current list of pending cozies.
    pub fn transactions(&self) -> &[crate::transaction::Transaction] {
        &self.transactions
    }

    /// Returns a flat vector of all cozies (mutations + commit).
    pub fn all_cozies(&self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
    }

    /// Iterates over all current cozies within the pending commit.
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.transactions.iter().flat_map(|tx| tx.0.iter())
    }

    /// Check if the pending commit is empty (contains zero cozies).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the pending commit has no mutation content to finalize.
    ///
    /// True when there are no cozies at all, or when every cozy present
    /// is a finalizer (carries `arrow`, see `Transaction::is_commit`) --
    /// a commit/create with no mutation cozies behind it has no
    /// substance to finalize, matching [commit-one-or-more]'s evident
    /// intent (docs/specs/transactions.md). Subsumes the zero-cozy case
    /// via the same vacuous-truth property `is_empty()` relies on
    /// (`.all()` over an empty iterator is `true`), so callers gating a
    /// finalize on "is there anything to finalize" should use this, not
    /// `is_empty()` -- `is_empty()` keeps the ordinary collection
    /// meaning (`len() == 0`), distinct from "insubstantial."
    pub fn is_finalizer_only(&self) -> bool {
        self.iter_all_cozies().all(|cz| cz.arrow().is_some())
    }

    /// Get the number of pending cozies.
    pub fn len(&self) -> usize {
        self.iter_all_cozies().count()
    }

    /// Compute the Transaction Roots (TMR, TCR, TR) for the current pending cozies.
    pub fn compute_roots(
        &self,
        algs: &[coz::HashAlg],
    ) -> (
        Option<crate::transaction_root::TransactionMutationRoot>,
        Option<crate::transaction_root::TransactionCommitRoot>,
        Option<crate::transaction_root::TransactionRoot>,
    ) {
        if self.is_empty() {
            return (None, None, None);
        }

        let (mutations, commit_tx) = if let Some(last_tx) = self.transactions.last() {
            if last_tx.is_commit() {
                let len = self.transactions.len();
                (&self.transactions[..len - 1], Some(last_tx))
            } else {
                (&self.transactions[..], None)
            }
        } else {
            (&[][..], None)
        };

        let tx_roots: Vec<_> = mutations.iter().filter_map(|tx| tx.id(algs)).collect();
        let tx_refs: Vec<&crate::multihash::MultihashDigest> = tx_roots.iter().collect();

        let tmr = if tx_refs.is_empty() {
            None
        } else {
            crate::transaction_root::compute_tmr(&tx_refs, algs)
        };

        if let Some(ctx) = commit_tx {
            if let Some(tcr) = ctx
                .id(algs)
                .map(crate::transaction_root::TransactionCommitRoot)
            {
                let tr = crate::transaction_root::compute_tr(&tx_refs, &tcr, algs);
                return (tmr, Some(tcr), tr);
            }
        }

        (tmr, None, None)
    }

    /// Compute the Transaction Root (TR) for the current pending cozies.
    pub fn compute_tr(
        &self,
        algs: &[coz::HashAlg],
    ) -> Option<crate::transaction_root::TransactionRoot> {
        self.compute_roots(algs).2
    }

    /// Finalize the pending commit into an immutable `Commit`.
    ///
    /// # Arguments
    ///
    /// * `ar` - The computed Auth Root after all cozies (`None` if no key remains)
    /// * `sr` - The computed State Root: MR(AR?, DR?, embedding?) (`None` if neither exists)
    /// * `pr` - The computed Principal Root after all cozies
    /// * `tx_algs` - Explicit transaction algorithm set footprint (extracted from Arrow)
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if no cozies exist, or if the only cozies
    /// present are finalizers (no mutation content).
    pub fn finalize(
        self,
        ar: Option<AuthRoot>,
        sr: Option<StateRoot>,
        pr: PrincipalRoot,
        tx_algs: &[coz::HashAlg],
    ) -> crate::error::Result<Commit> {
        if self.is_finalizer_only() {
            return Err(crate::error::Error::EmptyCommit);
        }

        // Ensure that the last transaction actually is a commit transaction
        let last_tx = self
            .transactions
            .last()
            .ok_or(crate::error::Error::EmptyCommit)?;
        if !last_tx.is_commit() {
            return Err(crate::error::Error::MissingCommit);
        }

        let tr = self
            .compute_tr(tx_algs)
            .ok_or(crate::error::Error::EmptyCommit)?;

        Commit::new(self.transactions, tr, ar, sr, pr)
    }

    /// Consume the pending commit and return the cozies.
    ///
    /// Use this for rollback or when abandoning a pending commit.
    pub fn into_transactions(self) -> Vec<VerifiedCoz> {
        self.iter_all_cozies().cloned().collect()
    }
}

// ============================================================================
// Arrow
// ============================================================================

/// Compute the Arrow digest `MR(pre, fwd, TMR)` (SPEC §4.4) at `alg`.
///
/// The single definition shared by the write path
/// ([`CommitScope::prepare_commit`]), the pre-finalize check
/// ([`CommitScope::matches_arrow`]) and the verifier
/// (`PrincipalState::stage_commit`), so the Arrow a commit signs and the one
/// it is checked against cannot drift apart. Each component is resolved
/// through [`MultihashDigest::arrow_component_bytes`], which covers a
/// component that does not carry `alg` (e.g. a `pre` predating the
/// signer's algorithm).
///
/// [`MultihashDigest::arrow_component_bytes`]: crate::multihash::MultihashDigest::arrow_component_bytes
///
/// # Errors
///
/// `EmptyMultihash` if a component has no variants.
pub(crate) fn arrow_digest(
    alg: crate::state::HashAlg,
    pre: &PrincipalRoot,
    sr: Option<&StateRoot>,
    tmr: &crate::transaction_root::TransactionMutationRoot,
) -> crate::error::Result<Vec<u8>> {
    let pre_bytes = pre.0.arrow_component_bytes(alg)?;
    let tmr_bytes = tmr.0.arrow_component_bytes(alg)?;
    // The forward SR is absent when the commit leaves no key and no data;
    // an empty component is omitted from the root (SPEC 3.7).
    let sr_bytes = sr.map(|sr| sr.0.arrow_component_bytes(alg)).transpose()?;
    let mut components = vec![pre_bytes.as_ref(), tmr_bytes.as_ref()];
    if let Some(sr_bytes) = sr_bytes.as_ref() {
        components.push(sr_bytes.as_ref());
    }
    Ok(crate::state::hash_sorted_concat_bytes(alg, &components))
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
/// let commit = scope.finalize().await?;
///
/// // Single-coz commit (convenience):
/// let commit = principal.apply_transaction(vtx).await?;
/// ```
#[must_use = "a CommitScope must be finalized via .finalize() to produce a Commit"]
pub struct CommitScope<'a, S: eml::Storage = eml::MemoryStorage> {
    principal: &'a mut crate::principal::Principal<S>,
    pending: PendingCommit,
    /// A copy of the principal's state the cozies are applied to. It holds
    /// no log, so applying never writes; the commit adopts it whole.
    projected: crate::principal::PrincipalState,
}

impl<'a, S: eml::Storage> CommitScope<'a, S> {
    /// Create a new commit scope for the given principal.
    pub(crate) fn new(principal: &'a mut crate::principal::Principal<S>) -> Self {
        let projected = principal.state().clone();
        Self {
            principal,
            pending: PendingCommit::new(),
            projected,
        }
    }

    /// Apply a verified coz within this commit scope.
    ///
    /// The coz is applied to the projected principal state.
    ///
    /// The coz is accumulated in the pending commit for finalization.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply(&mut self, vtx: VerifiedCoz) -> crate::error::Result<()> {
        self.projected.apply_verified_internal(vtx.clone())?;
        self.pending
            .push_tx(crate::transaction::Transaction(vec![vtx]));
        Ok(())
    }

    /// Apply a grouped transaction (multiple cozies) within this commit scope.
    ///
    /// State mutations are applied sequentially to the projected state,
    /// but the cozies are grouped in the Merkle tree.
    ///
    /// # Errors
    ///
    /// `MixedTransactionTyp` if the cozies do not all carry one identical
    /// `typ` (SPEC §4.1); nothing is applied in that case.
    pub fn apply_tx(&mut self, vts: Vec<VerifiedCoz>) -> crate::error::Result<()> {
        let typ_of = |vt: &VerifiedCoz| vt.raw().pay.get("typ").cloned();
        if let Some(first) = vts.first().map(typ_of) {
            if vts.iter().any(|vt| typ_of(vt) != first) {
                return Err(crate::error::Error::MixedTransactionTyp);
            }
        }
        let mut tx = Vec::with_capacity(vts.len());
        for vt in vts {
            self.projected.apply_verified_internal(vt.clone())?;
            tx.push(vt);
        }
        self.pending.push_tx(crate::transaction::Transaction(tx));
        Ok(())
    }

    /// Phase one of the two-phase commit: verify the commit and compute
    /// every root, the commit-log append included, with nothing written.
    ///
    /// The returned [`StagedCommit`] exposes the finalized [`Commit`] and
    /// the roots it produces, so a caller can make the commit durable
    /// elsewhere first (the storage engine records it in the blob store,
    /// its source of truth) and only then write the log with
    /// [`StagedCommit::commit`]. Dropping it instead aborts: the live
    /// principal and its log are as they were.
    ///
    /// # Errors
    ///
    /// Any refusal of the commit (`EmptyCommit`, `MissingCommit`,
    /// `CommitMismatch`, ...); the scope is consumed and nothing changes.
    pub async fn stage(self) -> crate::error::Result<StagedCommit<'a, S>> {
        let Self {
            principal,
            pending,
            mut projected,
        } = self;
        let staged = projected
            .stage_commit(pending, principal.commit_trees())
            .await?;
        Ok(StagedCommit {
            principal,
            projected,
            staged,
        })
    }

    /// Finalize the commit scope, producing an immutable `Commit`: both
    /// phases, [`stage`](Self::stage) then [`StagedCommit::commit`].
    ///
    /// A refusal or a failed log write leaves the live principal and its
    /// log exactly as they were.
    ///
    /// # Errors
    ///
    /// As [`stage`](Self::stage), or `Storage` if the log write fails.
    pub async fn finalize(self) -> crate::error::Result<&'a Commit> {
        self.stage().await?.commit().await
    }

    /// Verify a coz signature against this scope's state, applying
    /// nothing: the coz's signer must be active in the principal or in the
    /// state the cozies applied so far reach. Pass the result to
    /// [`apply`](Self::apply) or, with the other cozies of its transaction,
    /// to [`apply_tx`](Self::apply_tx).
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this coz
    /// * `new_key` - New key to add (required for KeyCreate/KeyReplace)
    ///
    /// # Errors
    ///
    /// `MalformedPayload` for an unreadable pay or one with no `tmb`;
    /// `CozReuse` for a coz this principal already included (checked before
    /// the signer, which that coz may have retired); `UnknownKey` for an
    /// inactive signer; as
    /// [`verify_coz`](crate::parsed_coz::verify_coz) otherwise.
    pub fn verify(
        &self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<crate::key::Key>,
    ) -> crate::error::Result<VerifiedCoz> {
        let pay: coz::Pay =
            serde_json::from_slice(pay_json).map_err(|_| crate::error::Error::MalformedPayload)?;
        let signer_tmb = pay
            .tmb
            .as_ref()
            .ok_or(crate::error::Error::MalformedPayload)?;
        // SPEC 7.6: a coz already included is `COZ_REUSE`. Decided before the
        // signer is resolved, since the coz may have retired its own signer
        // (key/replace, revoke, delete), and from the coz's own bytes, never
        // the caller's `czd`. A pay naming no usable `alg` has no digest to
        // match and falls through to the ordinary refusals.
        if let Some(own) = pay
            .alg
            .as_deref()
            .and_then(|alg| crate::parsed_coz::compute_czd(pay_json, sig, alg))
        {
            if self.projected.included_czds.contains(own.as_bytes()) {
                return Err(crate::error::Error::CozReuse);
            }
        }
        let signer_key = self.resolve_signer(signer_tmb)?;
        crate::parsed_coz::verify_coz(pay_json, sig, signer_key, czd, new_key)
    }

    /// Verify a coz signature and apply it within this commit scope as a
    /// transaction of its own: [`verify`](Self::verify), then
    /// [`apply`](Self::apply).
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify) and [`apply`](Self::apply).
    pub fn verify_and_apply(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<crate::key::Key>,
    ) -> crate::error::Result<()> {
        let vtx = self.verify(pay_json, sig, czd, new_key)?;
        self.apply(vtx)
    }

    /// Get the principal's primary hash algorithm.
    pub fn principal_hash_alg(&self) -> crate::state::HashAlg {
        self.principal.hash_alg()
    }

    /// Check whether `tmb` is an active key in this scope's projected
    /// (post-mutation, pre-finalize) state.
    ///
    /// Lets a caller choosing which key should sign the terminal
    /// `commit/create` coz confirm its intended signer actually survives
    /// the mutations already applied in this commit — e.g. a `key/replace`
    /// or self-revoke earlier in the same commit can retire the very key
    /// (and, if it was the sole key of its algorithm, the hash algorithm)
    /// that would otherwise be used to sign and tag the arrow.
    #[must_use]
    pub fn is_key_active(&self, tmb: &coz::Thumbprint) -> bool {
        self.projected.is_key_active(tmb)
    }

    /// Get the number of cozies applied so far.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if no cozies have been applied yet.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Check if a claimed arrow matches the expected arrow for this commit scope.
    pub fn matches_arrow(&self, claimed_arrow: &crate::multihash::MultihashDigest) -> bool {
        use crate::semantic_tree::derive_state_roots_with_nonces;

        if self.is_empty() {
            return false;
        }

        // 1. Recompute projected state roots
        let active_algs = self.projected.active_algs();
        let leaves: Vec<_> = self
            .projected
            .auth
            .keys
            .values()
            .map(crate::semantic_tree::key_leaf)
            .collect();

        // DR is the `id` its `ds/create` signed (SPEC 4.8.2); a variant it
        // does not carry stays null (12.2).
        let dr = self.projected.dr.clone();

        let Ok((_kr, _ar, sr)) = derive_state_roots_with_nonces(
            &leaves,
            dr.as_ref(),
            &self.projected.nonces,
            &active_algs,
        ) else {
            return false;
        };

        // 2. Compute TMR
        let signer_hash_alg = claimed_arrow
            .algorithms()
            .next()
            .unwrap_or_else(|| self.principal.hash_alg());
        let (tmr, ..) = self.pending.compute_roots(&[signer_hash_alg]);
        let Some(tmr) = tmr else {
            return false;
        };

        // 3. Compute Arrow = MR(pre, sr, tmr)
        let Ok(pre) = self.projected.arrow_pre() else {
            return false;
        };
        let Ok(computed_digest) = arrow_digest(signer_hash_alg, &pre, sr.as_ref(), &tmr) else {
            return false;
        };

        let Some(claimed_digest) = claimed_arrow.get(signer_hash_alg) else {
            return false;
        };

        claimed_digest == computed_digest.as_slice()
    }

    /// Resolve `tmb` to the key authorized to sign in this scope.
    ///
    /// [pre-mutation-key-rule]: authorization is checked against the keys
    /// that were active when this commit began, not the eagerly mutated live
    /// state; keys added during the commit are also accepted. Shared by
    /// mutation verification and the terminal `commit/create` signer so both
    /// obey one rule.
    ///
    /// Both snapshots resolve through the principal's one signer lookup;
    /// a key active in neither is refused as the pre-commit snapshot
    /// classifies it.
    fn resolve_signer(&self, tmb: &coz::Thumbprint) -> crate::error::Result<&crate::key::Key> {
        self.principal
            .active_signer(tmb)
            .or_else(|refusal| self.projected.active_signer(tmb).map_err(|_| refusal))
    }

    /// Step 1 of the three-step finalize: compute the Arrow and the
    /// `commit/create` payload for `signer`'s key, without signing and
    /// without touching the scope. Pass [`PreparedCommit::cad`] to
    /// [`Signer::sign`] on the caller's own executor, then hand the result to
    /// [`finish_commit`](Self::finish_commit).
    ///
    /// # Errors
    ///
    /// - `EmptyCommit`: if no mutations exist.
    pub fn prepare_commit<K: Signer + ?Sized>(
        &self,
        signer: &K,
        now: i64,
        authority: &str,
    ) -> crate::error::Result<PreparedCommit> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        use serde_json::json;

        if self.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }

        // The signer is only a claim: bind it to the principal. The stored
        // key (never the signer's own copy) supplies alg and public key.
        let stored = self.resolve_signer(signer.tmb())?;
        if signer.alg() != stored.alg() {
            return Err(crate::error::Error::InvalidSignature);
        }
        let alg = stored.alg();
        let signer_hash_alg = stored.hash_alg();

        // 1. Recompute KT → AR-node → SR-node to get post-mutation SR for Arrow construction. This
        //    reads the projected state.
        let active_algs = self.projected.active_algs();
        let leaves: Vec<_> = self
            .projected
            .auth
            .keys
            .values()
            .map(crate::semantic_tree::key_leaf)
            .collect();

        // DR is the `id` its `ds/create` signed (SPEC 4.8.2); a variant it
        // does not carry stays null (12.2).
        let dr = self.projected.dr.clone();

        let (_kr, _ar, sr) = crate::semantic_tree::derive_state_roots_with_nonces(
            &leaves,
            dr.as_ref(),
            &self.projected.nonces,
            &active_algs,
        )?;

        // For TMR we just use compute_roots early
        let (tmr, ..) = self.pending.compute_roots(&[signer_hash_alg]);
        let tmr = tmr.ok_or(crate::error::Error::EmptyCommit)?;

        // 2. Compute Arrow = MR(pre, sr, tmr); pre is the previous state's principal root.
        let pre = self.projected.arrow_pre()?;
        let arrow = arrow_digest(signer_hash_alg, &pre, sr.as_ref(), &tmr)?;
        let arrow_tagged = format!(
            "{}:{}",
            signer_hash_alg,
            Base64UrlUnpadded::encode_string(&arrow)
        );

        // 3. Construct commit/create payload
        // Full typ = "{authority}/{suffix}" per SPEC §7.2.
        let commit_typ = format!("{authority}/{}", crate::parsed_coz::typ::COMMIT_CREATE);
        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(alg));
        pay.insert("arrow".to_string(), json!(arrow_tagged));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(stored.tmb().to_b64()));
        pay.insert("typ".to_string(), json!(commit_typ));

        let mut pay_obj = serde_json::Value::Object(pay);
        // Ensure deterministic order
        if let Some(obj) = pay_obj.as_object_mut() {
            obj.sort_keys();
        }

        let pay_vec =
            serde_json::to_vec(&pay_obj).map_err(|_| crate::error::Error::MalformedPayload)?;
        let cad = coz::canonical_hash_for_alg(&pay_vec, alg, None)
            .ok_or(crate::error::Error::MalformedPayload)?;

        Ok(PreparedCommit {
            alg: alg.to_string(),
            pub_key: stored.pub_key().to_vec(),
            signer_hash_alg,
            pay_obj,
            pay_vec,
            cad,
        })
    }

    /// Step 3 of the three-step finalize: verify `sig` over the prepared pay
    /// and commit. A signature that does not verify under the principal's
    /// stored key for the signer (resolved in `prepare_commit`, not the
    /// signer's own copy) (empty, malformed, wrong message, high-S) is
    /// `InvalidSignature` before anything is staged or written; the core
    /// never normalizes S (see [`crate::signer`]).
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: `sig` does not verify.
    /// - As [`finalize`](Self::finalize).
    pub async fn finish_commit(
        mut self,
        prepared: PreparedCommit,
        sig: Vec<u8>,
    ) -> crate::error::Result<&'a Commit> {
        use crate::parsed_coz::{ParsedCoz, VerifiedCoz};

        let PreparedCommit {
            alg,
            pub_key,
            signer_hash_alg,
            pay_obj,
            pay_vec,
            cad,
        } = prepared;

        if coz::verify_json(&pay_vec, &sig, &alg, &pub_key) != Some(true) {
            return Err(crate::error::Error::InvalidSignature);
        }
        let czd =
            coz::czd_for_alg(&cad, &sig, &alg).ok_or(crate::error::Error::MalformedPayload)?;

        let raw = coz::CozJson {
            pay: pay_obj.clone(),
            sig,
        };
        let parsed_pay: coz::Pay =
            serde_json::from_value(pay_obj).map_err(|_| crate::error::Error::MalformedPayload)?;

        let arrow_tx = ParsedCoz::from_pay(&parsed_pay, czd, signer_hash_alg, raw)?;
        let arrow_vtx = VerifiedCoz::from_parts(arrow_tx, None);

        // Push commit marker and finalize
        self.pending
            .push_tx(crate::transaction::Transaction(vec![arrow_vtx]));
        self.finalize().await
    }

    /// Async convenience over prepare, sign, finish. The future is `Send`
    /// only when `signer`'s `sign` future is (see [`crate::signer`]).
    ///
    /// # Errors
    ///
    /// - `Signer`: the backend failed.
    /// - `InvalidSignature`: see [`finish_commit`](Self::finish_commit).
    /// - `EmptyCommit`: if no mutations exist.
    pub async fn finalize_with_signer<K: Signer + ?Sized>(
        self,
        signer: &K,
        now: i64,
        authority: &str,
    ) -> crate::error::Result<&'a Commit> {
        let prepared = self.prepare_commit(signer, now, authority)?;
        let sig = signer.sign(prepared.cad()).await?;
        self.finish_commit(prepared, sig).await
    }

    /// [`finalize_with_signer`](Self::finalize_with_signer) for an
    /// in-memory [`SoftwareSigner`], which never suspends. Its future is
    /// `Send` whenever the storage is, which the generic form cannot
    /// promise for an arbitrary signer.
    ///
    /// # Errors
    ///
    /// As [`finalize_with_signer`](Self::finalize_with_signer).
    pub async fn finalize_with_software(
        self,
        signer: &SoftwareSigner,
        now: i64,
        authority: &str,
    ) -> crate::error::Result<&'a Commit> {
        let prepared = self.prepare_commit(signer, now, authority)?;
        let sig = signer.sign_now(prepared.cad())?;
        self.finish_commit(prepared, sig).await
    }

    /// Prepare, for `signer` (the genesis key) to sign, the `key/create` of
    /// the genesis key, then of each of `others` in order: the genesis key
    /// adds itself, then each further key (SPEC 5.1 steps 1-2, 5.2, 5.3,
    /// 7.7 Example 1). A genesis commit carries these before its
    /// `principal/create`. Sign each [`PreparedCoz::cad`] and apply it, in
    /// order, with [`finish_coz`](Self::finish_coz).
    ///
    /// # Errors
    ///
    /// `UnknownKey` when the genesis key is already created.
    pub fn prepare_genesis_keys<K: Signer + ?Sized>(
        &self,
        signer: &K,
        others: &[crate::key::Key],
        now: i64,
        authority: &str,
    ) -> crate::error::Result<Vec<PreparedCoz>> {
        use serde_json::json;

        let typ = format!("{authority}/{}", crate::parsed_coz::typ::KEY_CREATE);
        let genesis = self
            .projected
            .auth
            .keys
            .get(self.projected.genesis_key())
            .filter(|_| !self.projected.genesis_created)
            .cloned()
            .ok_or(crate::error::Error::UnknownKey)?;
        std::iter::once(genesis)
            .chain(others.iter().cloned())
            .map(|key| {
                let pay = json!({
                    "alg": signer.alg(),
                    "id": key.tmb().to_b64(),
                    "now": now,
                    "tmb": signer.tmb().to_b64(),
                    "typ": typ,
                });
                PreparedCoz::new(pay, signer.alg(), Some(key))
            })
            .collect()
    }

    /// The `id` a `principal/create` applied next in this scope must carry:
    /// the future SR, the state the scope has reached promoted to PR with no
    /// CR (SPEC 5.1 step 3, 5.2 TX1 "ID == PG == SR"), as a tagged digest
    /// in the principal's first active algorithm.
    ///
    /// # Errors
    ///
    /// `NoActiveKeys` if the scope holds no key; a root derivation error
    /// otherwise.
    pub fn genesis_id(&self) -> crate::error::Result<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let pg = self.projected.genesis_pr()?;
        let alg = self
            .projected
            .active_algs()
            .first()
            .copied()
            .unwrap_or_else(|| self.projected.hash_alg());
        let bytes = pg.0.get_or_err(alg)?;
        Ok(format!("{alg}:{}", Base64UrlUnpadded::encode_string(bytes)))
    }

    /// The `id` a signer gives a `ds/create` applied now (SPEC 4.8.2): MR
    /// over every action this principal holds, tagged
    /// `alg:digest` like [`genesis_id`](Self::genesis_id). `None` while DT
    /// is empty.
    ///
    /// # Errors
    ///
    /// As [`compute_dr`](crate::state::compute_dr).
    pub fn data_tree_id(&self) -> crate::error::Result<Option<String>> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let algs = self.projected.active_algs();
        let Some(dt) = self.projected.data.tree_root(&algs)? else {
            return Ok(None);
        };
        let alg = algs
            .first()
            .copied()
            .unwrap_or_else(|| self.projected.hash_alg());
        let bytes = dt.0.get_or_err(alg)?;
        Ok(Some(format!(
            "{alg}:{}",
            Base64UrlUnpadded::encode_string(bytes)
        )))
    }

    /// Prepare, for `signer` to sign, the `principal/create` that closes a
    /// genesis (SPEC 5.1 step 3): its `id` is
    /// [`genesis_id`](Self::genesis_id), the PG-to-be, so prepare it after
    /// the genesis key/creates are applied. Apply it with
    /// [`finish_coz`](Self::finish_coz).
    ///
    /// # Errors
    ///
    /// As [`genesis_id`](Self::genesis_id).
    pub fn prepare_create_principal<K: Signer + ?Sized>(
        &self,
        signer: &K,
        now: i64,
        authority: &str,
    ) -> crate::error::Result<PreparedCoz> {
        let pay = serde_json::json!({
            "alg": signer.alg(),
            "id": self.genesis_id()?,
            "now": now,
            "tmb": signer.tmb().to_b64(),
            "typ": format!("{authority}/{}", crate::parsed_coz::typ::PRINCIPAL_CREATE),
        });
        PreparedCoz::new(pay, signer.alg(), None)
    }

    /// Sign with `signer` (the genesis key) and apply the `key/create` of the
    /// genesis key, then of each of `others` in order: the async convenience
    /// over [`prepare_genesis_keys`](Self::prepare_genesis_keys), `sign` and
    /// [`finish_coz`](Self::finish_coz). Returns each as a wire coz.
    ///
    /// # Errors
    ///
    /// `Signer` if signing fails; otherwise as the two steps.
    pub async fn create_genesis_keys<K: Signer + ?Sized>(
        &mut self,
        signer: &K,
        others: &[crate::key::Key],
        now: i64,
        authority: &str,
    ) -> crate::error::Result<Vec<serde_json::Value>> {
        let mut cozies = Vec::with_capacity(others.len() + 1);
        for prepared in self.prepare_genesis_keys(signer, others, now, authority)? {
            let sig = signer.sign(prepared.cad()).await?;
            cozies.push(self.finish_coz(prepared, sig)?);
        }
        Ok(cozies)
    }

    /// Sign with `signer` and apply the `principal/create` that closes a
    /// genesis: the async convenience over
    /// [`prepare_create_principal`](Self::prepare_create_principal), `sign`
    /// and [`finish_coz`](Self::finish_coz). Returns it as a wire coz.
    ///
    /// # Errors
    ///
    /// `Signer` if signing fails; otherwise as the two steps.
    pub async fn create_principal<K: Signer + ?Sized>(
        &mut self,
        signer: &K,
        now: i64,
        authority: &str,
    ) -> crate::error::Result<serde_json::Value> {
        let prepared = self.prepare_create_principal(signer, now, authority)?;
        let sig = signer.sign(prepared.cad()).await?;
        self.finish_coz(prepared, sig)
    }

    /// Apply a prepared coz with its signature `sig` (the finish step after
    /// [`prepare_genesis_keys`](Self::prepare_genesis_keys) or
    /// [`prepare_create_principal`](Self::prepare_create_principal)), and
    /// return it as a wire coz, `{pay, sig}`. The key a `key/create`
    /// discloses travels in its bundle's `keys` (SPEC 4.6.2), never on the
    /// coz.
    ///
    /// # Errors
    ///
    /// As [`verify_and_apply`](Self::verify_and_apply), e.g.
    /// `InvalidSignature` when `sig` does not verify, `UnknownKey` when the
    /// signer is not the genesis key, `DuplicateKey` when a key repeats.
    pub fn finish_coz(
        &mut self,
        prepared: PreparedCoz,
        sig: Vec<u8>,
    ) -> crate::error::Result<serde_json::Value> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let PreparedCoz {
            pay,
            pay_vec,
            alg,
            cad,
            key,
        } = prepared;
        let czd =
            coz::czd_for_alg(&cad, &sig, &alg).ok_or(crate::error::Error::MalformedPayload)?;
        self.verify_and_apply(&pay_vec, &sig, czd, key)?;
        Ok(serde_json::json!({
            "pay": pay,
            "sig": Base64UrlUnpadded::encode_string(&sig),
        }))
    }
}

/// A transaction coz prepared for signing by a scope's prepare step: its
/// canonical pay and the `cad` to sign, and the key it discloses, if any.
/// Applied with [`CommitScope::finish_coz`].
#[derive(Debug)]
pub struct PreparedCoz {
    pay: serde_json::Value,
    pay_vec: Vec<u8>,
    alg: String,
    cad: coz::Cad,
    key: Option<crate::key::Key>,
}

impl PreparedCoz {
    /// Canonicalize `pay` (keys sorted, the form the signature covers) and
    /// hash it under `alg`.
    fn new(
        mut pay: serde_json::Value,
        alg: &str,
        key: Option<crate::key::Key>,
    ) -> crate::error::Result<Self> {
        if let Some(obj) = pay.as_object_mut() {
            obj.sort_keys();
        }
        let pay_vec =
            serde_json::to_vec(&pay).map_err(|_| crate::error::Error::MalformedPayload)?;
        let cad = coz::canonical_hash_for_alg(&pay_vec, alg, None)
            .ok_or(crate::error::Error::MalformedPayload)?;
        Ok(Self {
            pay,
            pay_vec,
            alg: alg.to_string(),
            cad,
            key,
        })
    }

    /// The canonical hash of the pay: the message to sign.
    pub fn cad(&self) -> &coz::Cad {
        &self.cad
    }

    /// The pay the signature covers.
    pub fn pay(&self) -> &serde_json::Value {
        &self.pay
    }
}

/// Output of [`CommitScope::prepare_commit`]: the unsigned `commit/create`
/// payload awaiting a signature over [`cad`](Self::cad).
#[derive(Debug)]
pub struct PreparedCommit {
    alg: String,
    pub_key: Vec<u8>,
    signer_hash_alg: crate::state::HashAlg,
    pay_obj: serde_json::Value,
    pay_vec: Vec<u8>,
    cad: coz::Cad,
}

impl PreparedCommit {
    /// The canonical hash of the commit pay: the message to sign.
    pub fn cad(&self) -> &coz::Cad {
        &self.cad
    }

    /// The `commit/create` pay the signature covers, for a signer that
    /// carries the coz itself (the wire form is this pay and its `sig`).
    pub fn pay(&self) -> &serde_json::Value {
        &self.pay_obj
    }
}

// Compile-time proof that the commit path's futures are `Send` for every
// storage: `eml::Storage: Send + Sync` and its futures are `Send`, so a
// multi-threaded runtime can drive a commit over any backend, the durable
// one included. A regression (a `!Send` value held across an await) fails
// the build here rather than at a distant server route.
const _: () = {
    fn assert_send<T: Send>(_: &T) {}
    #[allow(dead_code)]
    fn commit_path_is_send<S: eml::Storage>(
        scope: CommitScope<'_, S>,
        principal: &mut crate::principal::Principal<S>,
        signer: &SoftwareSigner,
        bundle: &crate::replay::Bundle,
    ) {
        assert_send(&scope.finalize_with_software(signer, 0, ""));
        assert_send(&crate::replay::replay_bundle(principal, bundle));
    }
};

// ============================================================================
// StagedCommit
// ============================================================================

/// A commit verified and computed, with nothing written: phase one of the
/// two-phase commit ([`CommitScope::stage`]).
///
/// It holds the principal's state as the commit leaves it and the one log
/// write that makes the commit durable. [`Self::commit`] performs that
/// write and adopts the state; dropping it aborts with the principal and
/// its log unchanged. Holding the principal by `&mut` between the two
/// phases is what keeps the staged write valid: nothing else can mutate
/// the log in between.
#[must_use = "a StagedCommit writes nothing until .commit() is awaited"]
pub struct StagedCommit<'a, S: eml::Storage = eml::MemoryStorage> {
    principal: &'a mut crate::principal::Principal<S>,
    projected: crate::principal::PrincipalState,
    /// `None` when the log already holds this commit's leaf (replay over a
    /// durable log): committing then only adopts the state.
    staged: Option<polydigest::Staged<S>>,
}

impl<'a, S: eml::Storage> StagedCommit<'a, S> {
    /// The principal's state once this commit is committed: its roots
    /// (`pr`, `sr`, `cr`, `auth_root`, `pg`) and its last commit, the one
    /// staged here.
    pub fn state(&self) -> &crate::principal::PrincipalState {
        &self.projected
    }

    /// Verify and record a data action on the staged state, as if recorded
    /// right after the commit: a bundle's actions that follow its commit
    /// are checked before the commit is written, so a refused action
    /// leaves nothing durable.
    ///
    /// # Errors
    ///
    /// As [`Principal::verify_and_record_action`](crate::Principal::verify_and_record_action).
    pub fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> crate::error::Result<&PrincipalRoot> {
        self.projected.verify_and_record_action(pay_json, sig, czd)
    }

    /// Phase two: write the staged log append in one atomic
    /// `Storage::apply`, then adopt the staged state with no `.await`
    /// between, so a dropped future either wrote nothing or has adopted.
    ///
    /// # Errors
    ///
    /// `Storage` if the write fails; the principal and its log are then
    /// unchanged.
    pub async fn commit(self) -> crate::error::Result<&'a Commit> {
        self.principal.adopt(self.projected, self.staged).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::base64ct::Encoding;
    use coz::{Czd, PayBuilder, Thumbprint};
    use serde_json::json;

    use super::*;
    use crate::multihash::MultihashDigest;
    use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
    use crate::state::HashAlg;

    const TEST_ID: &str = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";

    /// Create a test coz. When `is_commit` is true, creates a commit/create
    /// coz with an arrow field (routes to commit_tx via push). When false,
    /// creates a mutation coz (routes to transactions).
    fn make_test_tx(is_commit: bool, czd_byte: u8) -> VerifiedCoz {
        let typ = if is_commit {
            "cyphr.me/cyphr/commit/create"
        } else {
            "cyphr.me/cyphr/key/create"
        };
        let mut pay = PayBuilder::new()
            .typ(typ)
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        if !is_commit {
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

    /// Backs SPEC 4.6: a commit with no `commit/create` finalizer is rejected as `MissingCommit`.
    /// Unit: PendingCommit is crate-internal; the signed path always appends the finalizer.
    #[test]
    fn pending_commit_finalize_fails_without_finalizer_marker() {
        // Finalizer must be present to distinguish the commit transaction
        let mut pending = PendingCommit::new();
        let cz = make_test_tx(false, 0x01); // No finalizer marker
        pending.push_tx(crate::transaction::Transaction(vec![cz]));

        let auth_root =
            AuthRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xAA; 32]).unwrap());
        let sr = StateRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xCC; 32]).unwrap());
        let pr =
            PrincipalRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xBB; 32]).unwrap());

        let result = pending.finalize(Some(auth_root), Some(sr), pr, &[coz::HashAlg::Sha256]);
        assert!(
            matches!(result, Err(crate::error::Error::MissingCommit)),
            "finalize should fail without finalizer marker"
        );
    }

    // ========================================================================
    // Commit Tests
    // ========================================================================

    // ========================================================================
    // matches_arrow / arrow_component_bytes multi-variant fold symmetry
    // ========================================================================

    fn fold_pool() -> test_fixtures::Pool {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("should have rs/ parent")
            .parent()
            .expect("should have repo root parent")
            .join("tests")
            .join("keys")
            .join("pool.toml");
        test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
    }

    fn fold_pool_key<'p>(pool: &'p test_fixtures::Pool, name: &str) -> &'p test_fixtures::PoolKey {
        pool.get(name)
            .unwrap_or_else(|| panic!("pool key '{}' not found", name))
    }

    fn fold_domain_key(pk: &test_fixtures::PoolKey) -> crate::key::Key {
        let pub_bytes = coz::base64ct::Base64UrlUnpadded::decode_vec(&pk.pub_key)
            .expect("invalid pool pub key base64");
        let tmb = pk.compute_tmb().expect("failed to compute tmb");
        crate::key::Key::new(pk.alg.clone(), tmb, pub_bytes).expect("key binds its tmb")
    }

    fn fold_prv_bytes(pk: &test_fixtures::PoolKey) -> Vec<u8> {
        let prv_b64 = pk
            .prv
            .as_ref()
            .unwrap_or_else(|| panic!("pool key '{}' has no private key material", pk.name));
        coz::base64ct::Base64UrlUnpadded::decode_vec(prv_b64).expect("invalid pool prv base64")
    }

    fn fold_signed_key_create(
        signer: &test_fixtures::PoolKey,
        signer_tmb_b64: &str,
        target: &test_fixtures::PoolKey,
        now: i64,
    ) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        let target_tmb_b64 = target.compute_tmb_b64().expect("target tmb b64");

        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(signer.alg));
        pay.insert("id".to_string(), json!(target_tmb_b64));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(signer_tmb_b64));
        pay.insert("typ".to_string(), json!("cyphr.me/cyphr/key/create"));
        let mut pay_obj = serde_json::Value::Object(pay);
        pay_obj.as_object_mut().expect("object").sort_keys();
        let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize key/create pay");

        let prv_bytes = fold_prv_bytes(signer);
        let pub_bytes = coz::base64ct::Base64UrlUnpadded::decode_vec(&signer.pub_key)
            .expect("signer pub base64");
        let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
            .expect("sign_json should support pool algorithm");
        let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
            .expect("czd_for_alg should support pool algorithm");
        (pay_vec, sig, czd)
    }

    fn fold_signed_self_revoke(
        signer: &test_fixtures::PoolKey,
        signer_tmb_b64: &str,
        now: i64,
    ) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(signer.alg));
        pay.insert("now".to_string(), json!(now));
        pay.insert("rvk".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(signer_tmb_b64));
        pay.insert("typ".to_string(), json!("cyphr.me/cyphr/key/revoke"));
        let mut pay_obj = serde_json::Value::Object(pay);
        pay_obj.as_object_mut().expect("object").sort_keys();
        let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize key/revoke pay");

        let prv_bytes = fold_prv_bytes(signer);
        let pub_bytes = coz::base64ct::Base64UrlUnpadded::decode_vec(&signer.pub_key)
            .expect("signer pub base64");
        let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
            .expect("sign_json should support pool algorithm");
        let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
            .expect("czd_for_alg should support pool algorithm");
        (pay_vec, sig, czd)
    }

    /// Regression test for the arrow-fold/matches_arrow symmetry fix: a
    /// principal has 3 active algorithms (SHA-256/384/512), then the
    /// SHA-384 signer revokes its own key in the same commit it signs.
    /// Post-mutation SR then has only 2 variants (SHA-256, SHA-512) --
    /// neither matching the SHA-384 signer -- forcing
    /// `arrow_component_bytes`'s multi-variant fold branch.
    /// `finalize_with_software` (construction) must succeed, and
    /// `matches_arrow` (independent verification) must accept the
    /// resulting arrow via the same fallback.
    #[tokio::test]
    async fn matches_arrow_accepts_multi_variant_fold() {
        let pool = fold_pool();
        let genesis = fold_pool_key(&pool, "golden");
        let diana = fold_pool_key(&pool, "diana_es384");
        let eve = fold_pool_key(&pool, "eve_ed25519");

        let genesis_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        let mut principal = crate::principal::Principal::implicit(fold_domain_key(genesis))
            .await
            .expect("genesis principal");
        principal
            .genesis_test(Vec::new())
            .await
            .expect("genesis commit");
        let mut scope = principal.begin_commit();

        let (pay1, sig1, czd1) = fold_signed_key_create(genesis, &genesis_tmb_b64, diana, now);
        scope
            .verify_and_apply(&pay1, &sig1, czd1, Some(fold_domain_key(diana)))
            .expect("diana key/create should apply");
        let (pay2, sig2, czd2) = fold_signed_key_create(genesis, &genesis_tmb_b64, eve, now);
        scope
            .verify_and_apply(&pay2, &sig2, czd2, Some(fold_domain_key(eve)))
            .expect("eve key/create should apply");

        let genesis_prv = fold_prv_bytes(genesis);
        let genesis_pub = coz::base64ct::Base64UrlUnpadded::decode_vec(&genesis.pub_key)
            .expect("genesis pub base64");
        scope
            .finalize_with_software(
                &SoftwareSigner::new(&genesis.alg, &genesis_prv, &genesis_pub, &genesis_tmb),
                now + 1,
                "cyphr.me",
            )
            .await
            .expect("commit1 (key creates) should finalize");

        // Clone post-commit1 state so both branches replay the identical
        // self-revoke bytes onto byte-identical starting states, the same
        // technique properties.rs uses to keep a/b in lockstep without
        // re-signing (ECDSA signing is randomized per call).
        let mut principal_b = principal.fork().await.expect("fork");

        let diana_tmb_b64 = diana.compute_tmb_b64().expect("diana tmb b64");
        let diana_tmb = diana.compute_tmb().expect("diana tmb");
        let (pay3, sig3, czd3) = fold_signed_self_revoke(diana, &diana_tmb_b64, now + 2);

        let mut scope_a = principal.begin_commit();
        scope_a
            .verify_and_apply(&pay3, &sig3, czd3.clone(), None)
            .expect("diana self-revoke should apply to scope_a");
        let mut scope_b = principal_b.begin_commit();
        scope_b
            .verify_and_apply(&pay3, &sig3, czd3, None)
            .expect("diana self-revoke should apply to scope_b");

        let diana_prv = fold_prv_bytes(diana);
        let diana_pub =
            coz::base64ct::Base64UrlUnpadded::decode_vec(&diana.pub_key).expect("diana pub base64");
        let commit2 = scope_a
            .finalize_with_software(
                &SoftwareSigner::new(&diana.alg, &diana_prv, &diana_pub, &diana_tmb),
                now + 3,
                "cyphr.me",
            )
            .await
            .expect("self-revoke commit should finalize via the multi-variant fold");
        let genuine_arrow = commit2
            .commit_tx()
            .0
            .last()
            .expect("commit tx should carry at least one coz")
            .arrow()
            .expect("commit/create coz should carry an arrow")
            .clone();

        assert!(
            scope_b.matches_arrow(&genuine_arrow),
            "matches_arrow must accept a genuinely fallback-constructed (multi-variant fold) arrow"
        );
    }

    fn fold_signed_key_replace(
        signer: &test_fixtures::PoolKey,
        signer_tmb_b64: &str,
        target: &test_fixtures::PoolKey,
        now: i64,
    ) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        let target_tmb_b64 = target.compute_tmb_b64().expect("target tmb b64");

        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(signer.alg));
        pay.insert("id".to_string(), json!(target_tmb_b64));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(signer_tmb_b64));
        pay.insert("typ".to_string(), json!("cyphr.me/cyphr/key/replace"));
        let mut pay_obj = serde_json::Value::Object(pay);
        pay_obj.as_object_mut().expect("object").sort_keys();
        let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize key/replace pay");

        let prv_bytes = fold_prv_bytes(signer);
        let pub_bytes = coz::base64ct::Base64UrlUnpadded::decode_vec(&signer.pub_key)
            .expect("signer pub base64");
        let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
            .expect("sign_json should support pool algorithm");
        let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
            .expect("czd_for_alg should support pool algorithm");
        (pay_vec, sig, czd)
    }

    /// Pinning test for `arrow_component_bytes`' single-variant genesis-
    /// promotion branch -- the branch the multi-variant fold test above
    /// never exercises. Behavior is normatively settled by SPEC.md §2.2.10
    /// (Singleton Promotion) and docs/specs/state-tree.md's [conversion]
    /// clause (a sole variant's raw bytes are returned for any requested
    /// algorithm); this test pins it, it does not choose it.
    ///
    /// A sole-key principal (one active ES384 key => one SHA-384 variant)
    /// does key/replace to an ES256 key (=> one SHA-256 variant), leaving
    /// pre (state before, only SHA-384) and fwd SR (state after, only
    /// SHA-256) with ZERO shared hash algorithms at arrow-computation time.
    /// The fwd side has no SHA-384 variant and len==1, so genesis promotion
    /// returns its lone SHA-256 variant for the requested SHA-384.
    /// `finalize_with_software` (construction) and `matches_arrow` (independent
    /// verification) MUST agree. This is the scenario behind forge issue #51.
    #[tokio::test]
    async fn matches_arrow_accepts_sole_key_algorithm_change() {
        let pool = fold_pool();
        let old_key = fold_pool_key(&pool, "diana_es384"); // ES384 -> SHA-384
        let new_key = fold_pool_key(&pool, "golden"); // ES256 -> SHA-256

        let old_tmb_b64 = old_key.compute_tmb_b64().expect("old tmb b64");
        let old_tmb = old_key.compute_tmb().expect("old tmb");
        let now = 1_700_000_000i64;

        // Sole-key genesis on the ES384 key.
        let mut principal = crate::principal::Principal::implicit(fold_domain_key(old_key))
            .await
            .expect("genesis principal");
        principal
            .genesis_test(Vec::new())
            .await
            .expect("genesis commit");

        // Sign the ES384 -> ES256 key/replace ONCE; replay the identical
        // bytes onto a byte-identical clone so production (scope_a) and
        // verification (scope_b) start from the same state (ECDSA signing
        // is randomized per call).
        let (pay, sig, czd) = fold_signed_key_replace(old_key, &old_tmb_b64, new_key, now);

        let mut principal_b = principal.fork().await.expect("fork");

        let mut scope_a = principal.begin_commit();
        scope_a
            .verify_and_apply(&pay, &sig, czd.clone(), Some(fold_domain_key(new_key)))
            .expect("key/replace should apply to scope_a");
        let mut scope_b = principal_b.begin_commit();
        scope_b
            .verify_and_apply(&pay, &sig, czd, Some(fold_domain_key(new_key)))
            .expect("key/replace should apply to scope_b");

        // The replaced (old ES384) key finalizes the commit it signed --
        // CommitCreate skips the active-key check, so the just-removed
        // signer may still carry the arrow (principal.rs key/replace arm).
        let old_prv = fold_prv_bytes(old_key);
        let old_pub =
            coz::base64ct::Base64UrlUnpadded::decode_vec(&old_key.pub_key).expect("old pub base64");
        let commit = scope_a
            .finalize_with_software(
                &SoftwareSigner::new(&old_key.alg, &old_prv, &old_pub, &old_tmb),
                now + 1,
                "cyphr.me",
            )
            .await
            .expect("sole-key algorithm-change commit should finalize via genesis promotion");
        let genuine_arrow = commit
            .commit_tx()
            .0
            .last()
            .expect("commit tx should carry at least one coz")
            .arrow()
            .expect("commit/create coz should carry an arrow")
            .clone();

        assert!(
            scope_b.matches_arrow(&genuine_arrow),
            "matches_arrow must accept a sole-key algorithm-change arrow built via genesis \
             promotion (zero shared algorithms)"
        );
    }

    // ========================================================================
    // finalize() state-ordering (GitHub issue #77 and its deleted_pending
    // sibling): a stage_commit failure must never leave the live
    // principal reflecting projected mutations that were never durably
    // recorded.
    // ========================================================================

    /// Storage double that delegates to a real in-memory backend until
    /// armed, then fails every operation. Genesis setup (and any mutation
    /// apply, which never touches storage) succeeds normally; arming right
    /// before `finalize`/`finalize_with_software` isolates the injected
    /// failure to `stage_commit`'s own durable-write path.
    #[derive(Debug)]
    struct ToggledFailureStorage {
        inner: eml::MemoryStorage,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[derive(Debug)]
    struct InjectedFinalizeFailure;

    impl std::fmt::Display for InjectedFinalizeFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "injected commit failure")
        }
    }

    impl std::error::Error for InjectedFinalizeFailure {}

    impl ToggledFailureStorage {
        fn new() -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
            let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            (
                Self {
                    inner: eml::MemoryStorage::new(),
                    armed: armed.clone(),
                },
                armed,
            )
        }

        fn check(&self) -> Result<(), InjectedFinalizeFailure> {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                Err(InjectedFinalizeFailure)
            } else {
                Ok(())
            }
        }
    }

    impl eml::Storage for ToggledFailureStorage {
        type Error = InjectedFinalizeFailure;

        async fn get_leaf(&self, index: u64) -> Result<Vec<u8>, Self::Error> {
            self.check()?;
            self.inner
                .get_leaf(index)
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn len(&self) -> Result<u64, Self::Error> {
            self.check()?;
            self.inner.len().await.map_err(|_| InjectedFinalizeFailure)
        }

        async fn get_node(
            &self,
            alg_id: u64,
            left: u64,
            height: u32,
        ) -> Result<Option<Vec<u8>>, Self::Error> {
            self.check()?;
            self.inner
                .get_node(alg_id, left, height)
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn load_algorithm_metas(&self) -> Result<eml::AlgorithmMetas, Self::Error> {
            self.check()?;
            self.inner
                .load_algorithm_metas()
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn append_count(&self) -> Result<u64, Self::Error> {
            self.check()?;
            self.inner
                .append_count()
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn apply(&mut self, ops: &[eml::WriteOp<'_>]) -> Result<(), Self::Error> {
            self.check()?;
            self.inner
                .apply(ops)
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }
    }

    /// RED-first regression test for GitHub issue #77 (and its
    /// `deleted_pending` sibling, same seam): a `stage_commit` failure
    /// must never leave the live principal reflecting projected mutations
    /// that were never durably recorded.
    #[tokio::test]
    async fn finalize_failure_leaves_principal_unmutated() {
        let pool = fold_pool();
        let genesis = fold_pool_key(&pool, "golden");
        let genesis_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        let (storage, armed) = ToggledFailureStorage::new();
        let mut principal = crate::principal::Principal::open(fold_domain_key(genesis), storage)
            .await
            .expect("genesis principal");
        principal
            .genesis_test(Vec::new())
            .await
            .expect("genesis commit");

        // Snapshot observable pre-commit state to compare against after the
        // injected failure.
        let pr_before = principal.pr().clone();
        assert!(
            !principal.is_deleted(),
            "fresh principal must not be deleted"
        );
        assert!(
            !principal.deleted_pending,
            "fresh principal must not have a pending delete"
        );

        // Sign a real principal/delete targeting the genesis PR.
        let id_tagged = pr_before
            .0
            .tagged_first()
            .expect("pr should have at least one variant")
            .to_string();
        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(genesis.alg));
        pay.insert("id".to_string(), json!(id_tagged));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(genesis_tmb_b64));
        pay.insert("typ".to_string(), json!("cyphr.me/cyphr/principal/delete"));
        let mut pay_obj = serde_json::Value::Object(pay);
        pay_obj.as_object_mut().expect("object").sort_keys();
        let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize principal/delete pay");

        let prv_bytes = fold_prv_bytes(genesis);
        let pub_bytes = coz::base64ct::Base64UrlUnpadded::decode_vec(&genesis.pub_key)
            .expect("genesis pub base64");
        let (sig, cad) = coz::sign_json(&pay_vec, &genesis.alg, &prv_bytes, &pub_bytes)
            .expect("sign_json should support pool algorithm");
        let czd = coz::czd_for_alg(&cad, &sig, &genesis.alg)
            .expect("czd_for_alg should support pool algorithm");

        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(&pay_vec, &sig, czd, None)
            .expect("principal/delete should apply");

        // Arm the storage failure only now: genesis setup and the mutation
        // apply above never touch storage, so this isolates the injected
        // failure to stage_commit's own durable-write path.
        armed.store(true, std::sync::atomic::Ordering::SeqCst);

        let signer = SoftwareSigner::new(&genesis.alg, &prv_bytes, &pub_bytes, &genesis_tmb);
        let result = scope
            .finalize_with_software(&signer, now + 1, "cyphr.me")
            .await;

        assert!(
            result.is_err(),
            "finalize_with_software must surface the injected storage failure"
        );
        assert_eq!(
            principal.pr(),
            &pr_before,
            "a failed finalize must not advance the live principal's PR"
        );
        assert!(
            !principal.is_deleted(),
            "a failed finalize must not leave `deleted` set on the live principal (GitHub issue \
             #77)"
        );
        assert!(
            !principal.deleted_pending,
            "a failed finalize must not leave `deleted_pending` set on the live principal — its \
             own sibling of GitHub issue #77"
        );
    }
}
