//! Commit types for atomic coz bundles.
//!
//! Per SPEC §4, a Commit is an atomic bundle of cozies.
//! The Commit ID is the Merkle root of only the cozies in a
//! single commit, not cumulatively.

use crate::parsed_coz::VerifiedCoz;
use crate::state::{AuthRoot, PrincipalRoot, StateRoot, TaggedCzd};

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
    /// Auth State at the end of this commit.
    ar: AuthRoot,
    /// State Root at the end of this commit.
    sr: StateRoot,
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
        ar: AuthRoot,
        sr: StateRoot,
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

    /// Get the State Root at the end of this commit.
    pub fn sr(&self) -> &StateRoot {
        &self.sr
    }

    /// Get the Auth State at the end of this commit.
    pub fn auth_root(&self) -> &AuthRoot {
        &self.ar
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

        let mut tx_roots = Vec::new();
        for tx in mutations {
            let tx_czds: Vec<TaggedCzd<'_>> =
                tx.0.iter()
                    .map(|t| TaggedCzd::new(t.czd(), t.hash_alg()))
                    .collect();
            if let Some(mh) = crate::transaction_root::compute_tx(&tx_czds, algs) {
                tx_roots.push(mh);
            }
        }

        let tmr = if tx_roots.is_empty() {
            None
        } else {
            let tx_refs: Vec<&crate::multihash::MultihashDigest> = tx_roots.iter().collect();
            crate::transaction_root::compute_tmr(&tx_refs, algs)
        };

        if let Some(ctx) = commit_tx {
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
    /// * `auth_root` - The computed Auth State after all cozies
    /// * `sr` - The computed State Root: MR(AR, DR?, embedding?)
    /// * `pr` - The computed Principal Root after all cozies
    /// * `tx_algs` - Explicit transaction algorithm set footprint (extracted from Arrow)
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if no cozies exist.
    pub fn finalize(
        self,
        ar: AuthRoot,
        sr: StateRoot,
        pr: PrincipalRoot,
        tx_algs: &[coz::HashAlg],
    ) -> crate::error::Result<Commit> {
        if self.is_empty() {
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
pub struct CommitScope<'a, S: eml::Storage = eml::MemoryStorage> {
    principal: &'a mut crate::principal::Principal<S>,
    pending: PendingCommit,
    projected: crate::principal::Principal<S>,
}

/// Get `digest`'s bytes for `alg`, falling back to its sole variant when
/// `digest` doesn't carry `alg` but has exactly one variant of a different
/// algorithm.
impl<'a, S: eml::Storage> CommitScope<'a, S> {
    /// Create a new commit scope for the given principal.
    pub(crate) fn new(principal: &'a mut crate::principal::Principal<S>) -> Self {
        let projected = principal.clone();
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
    /// - `NoActiveKeys`: Would leave principal with no active keys
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
    pub fn apply_tx(&mut self, vts: Vec<VerifiedCoz>) -> crate::error::Result<()> {
        let mut tx = Vec::with_capacity(vts.len());
        for vt in vts {
            self.projected.apply_verified_internal(vt.clone())?;
            tx.push(vt);
        }
        self.pending.push_tx(crate::transaction::Transaction(tx));
        Ok(())
    }

    /// Finalize the commit scope, producing an immutable `Commit`.
    ///
    /// Validates and durably records the batch on `projected` — the
    /// independent clone `CommitScope::new` took at scope creation — and
    /// only copies it into the live principal once that succeeds. A
    /// `finalize_commit` failure therefore leaves the live principal
    /// byte-identical to how it was before this call, `deleted_pending`
    /// included: that flag is cleared inside `finalize_commit` itself,
    /// after its durable writes, so folding the whole clone into the live
    /// principal in one gated move carries that clear along with every
    /// other `finalize_commit`-internal mutation (GitHub issue #77 and its
    /// `deleted_pending` sibling — previously this assigned `*self.principal
    /// = self.projected` *before* calling `finalize_commit`, so a failure
    /// partway through left the live principal already mutated).
    ///
    /// # Errors
    ///
    /// Returns `EmptyCommit` if no cozies were applied.
    pub fn finalize(mut self) -> crate::error::Result<&'a Commit> {
        self.projected.finalize_commit(self.pending)?;
        *self.principal = self.projected;

        // `finalize_commit`'s returned reference borrowed `self.projected`,
        // which the move above consumed, so it cannot be reused here. No
        // second clone is needed to recover it: `finalize_commit` always
        // pushes its result as the last entry of `auth.commits` immediately
        // before returning it (`principal.rs`), so re-deriving the
        // reference from the now-live principal yields the identical
        // `Commit`.
        self.principal
            .auth
            .commits
            .last()
            .ok_or(crate::error::Error::EmptyCommit)
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

        let pay: coz::Pay =
            serde_json::from_slice(pay_json).map_err(|_| crate::error::Error::MalformedPayload)?;
        let signer_tmb = pay
            .tmb
            .as_ref()
            .ok_or(crate::error::Error::MalformedPayload)?;

        // [pre-mutation-key-rule]: Check authorization against the snapshot
        // of keys that were active when this commit began, not the eagerly
        // mutated live state. Keys added during the commit are also accepted.
        let signer_key = {
            if self.principal.is_key_active(signer_tmb) {
                self.principal
                    .get_key(signer_tmb)
                    .ok_or(crate::error::Error::UnknownKey)?
            } else if self.projected.is_key_active(signer_tmb) {
                // Key was added during this commit — accept it
                self.projected
                    .get_key(signer_tmb)
                    .ok_or(crate::error::Error::UnknownKey)?
            } else if self.principal.is_key_revoked(signer_tmb) {
                return Err(crate::error::Error::KeyRevoked);
            } else {
                return Err(crate::error::Error::UnknownKey);
            }
        };

        // Verify signature and parse coz
        let vtx = verify_coz(pay_json, sig, signer_key, czd, new_key)?;

        // Apply within this scope
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
        use crate::semantic_tree::derive_state_roots;
        use crate::state::{compute_dr, derive_hash_algs, hash_sorted_concat_bytes};

        if self.is_empty() {
            return false;
        }

        // 1. Recompute projected state roots
        let key_refs: Vec<&crate::key::Key> = self.projected.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);
        let thumbprints: Vec<&coz::Thumbprint> =
            self.projected.auth.keys.values().map(|k| &k.tmb).collect();

        // Refresh DR to the current active_algs rather than trusting the
        // cached value, which may predate a key of a new algorithm (see
        // finalize_commit's identical refresh for the full rationale).
        let action_refs: Vec<&crate::action::Action> = self.projected.data.actions.iter().collect();
        let Ok(dr) = compute_dr(&action_refs, None, &active_algs) else {
            return false;
        };

        let Ok((_kr, _ar, sr)) = derive_state_roots(&thumbprints, dr.as_ref(), &active_algs) else {
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
        let pre = &self.principal.pr;
        let Ok(pre_bytes) = pre.0.arrow_component_bytes(signer_hash_alg) else {
            return false;
        };
        let Ok(sr_bytes) = sr.0.arrow_component_bytes(signer_hash_alg) else {
            return false;
        };
        let Ok(tmr_bytes) = tmr.0.arrow_component_bytes(signer_hash_alg) else {
            return false;
        };

        let computed_digest = hash_sorted_concat_bytes(
            signer_hash_alg,
            &[pre_bytes.as_ref(), sr_bytes.as_ref(), tmr_bytes.as_ref()],
        );

        let Some(claimed_digest) = claimed_arrow.get(signer_hash_alg) else {
            return false;
        };

        claimed_digest == computed_digest.as_slice()
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
        authority: &str,
    ) -> crate::error::Result<&'a Commit> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        use serde_json::json;

        use crate::parsed_coz::{ParsedCoz, VerifiedCoz};
        use crate::state::{compute_dr, hash_alg_from_str, hash_sorted_concat_bytes};

        if self.is_empty() {
            return Err(crate::error::Error::EmptyCommit);
        }

        let signer_hash_alg = hash_alg_from_str(alg)?;

        // 1. Recompute KT → AR-node → SR-node to get post-mutation SR for Arrow construction. This
        //    reads the projected state.
        let key_refs: Vec<&crate::key::Key> = self.projected.auth.keys.values().collect();
        let active_algs = crate::state::derive_hash_algs(&key_refs);
        let thumbprints: Vec<&coz::Thumbprint> =
            self.projected.auth.keys.values().map(|k| &k.tmb).collect();

        // Refresh DR to the current active_algs rather than trusting the
        // cached value, which may predate a key of a new algorithm (see
        // finalize_commit's identical refresh for the full rationale).
        let action_refs: Vec<&crate::action::Action> = self.projected.data.actions.iter().collect();
        let dr = compute_dr(&action_refs, None, &active_algs)?;

        let (_kr, _ar, sr) =
            crate::semantic_tree::derive_state_roots(&thumbprints, dr.as_ref(), &active_algs)?;

        // For TMR we just use compute_roots early
        let (tmr, ..) = self.pending.compute_roots(&[signer_hash_alg]);
        let tmr = tmr.ok_or(crate::error::Error::EmptyCommit)?;

        // 2. Compute Arrow = MR(pre, sr, tmr)
        // Arrow computation requires pre, sr, tmr slices
        // pre is the principal root of the previous state!
        let pre = &self.principal.pr;

        let pre_bytes = pre.0.arrow_component_bytes(signer_hash_alg)?;
        let sr_bytes = sr.0.arrow_component_bytes(signer_hash_alg)?;
        let tmr_bytes = tmr.0.arrow_component_bytes(signer_hash_alg)?;

        // Arrow = MR(pre, fwd, TMR)
        let arrow_digest = hash_sorted_concat_bytes(
            signer_hash_alg,
            &[pre_bytes.as_ref(), sr_bytes.as_ref(), tmr_bytes.as_ref()],
        );

        // Arrow string format
        let arrow_tagged = format!(
            "{}:{}",
            signer_hash_alg,
            Base64UrlUnpadded::encode_string(&arrow_digest)
        );

        // 3. Construct commit/create payload
        // Full typ = "{authority}/{suffix}" per SPEC §7.2.
        let commit_typ = format!("{authority}/{}", crate::parsed_coz::typ::COMMIT_CREATE);
        let mut pay = serde_json::Map::new();
        pay.insert("alg".to_string(), json!(alg));
        pay.insert("arrow".to_string(), json!(arrow_tagged));
        pay.insert("now".to_string(), json!(now));
        pay.insert("tmb".to_string(), json!(tmb.to_b64()));
        pay.insert("typ".to_string(), json!(commit_typ));

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
        self.pending
            .push_tx(crate::transaction::Transaction(vec![arrow_vtx]));
        self.finalize()
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

    #[test]
    fn pending_commit_empty_state() {
        let pending = PendingCommit::new();
        assert!(pending.is_empty());
        assert_eq!(pending.len(), 0);
        assert!(pending.compute_tr(&[coz::HashAlg::Sha256]).is_none());
    }

    #[test]
    fn pending_commit_push_adds_transactions() {
        let mut pending = PendingCommit::new();

        // Push cozies
        let tx1 = make_test_tx(false, 0x01);
        pending.push_tx(crate::transaction::Transaction(vec![tx1]));
        assert_eq!(pending.len(), 1);

        let tx2 = make_test_tx(true, 0x02);
        pending.push_tx(crate::transaction::Transaction(vec![tx2]));
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn pending_commit_compute_tr_returns_merkle_root() {
        let mut pending = PendingCommit::new();
        let tx1 = make_test_tx(false, 0x01);
        pending.push_tx(crate::transaction::Transaction(vec![tx1]));
        let tx2 = make_test_tx(true, 0x02);
        pending.push_tx(crate::transaction::Transaction(vec![tx2]));

        let tr = pending.compute_tr(&[coz::HashAlg::Sha256]);
        assert!(tr.is_some());
        // Commit ID should be 32 bytes (SHA256)
        assert_eq!(
            tr.clone().unwrap().0.get(HashAlg::Sha256).unwrap().len(),
            32
        );
    }

    #[test]
    fn pending_commit_finalize_rejects_finalizer_only() {
        // A commit whose only content is its own commit/create finalizer
        // (no mutation cozies at all) must be rejected -- ruling D1
        // (GitHub issue #74): ambiguity between "reject" and "document as
        // intentional no-op" resolves in favor of reject, aligning with
        // [commit-one-or-more]'s evident intent.
        let mut pending = PendingCommit::new();
        let cz = make_test_tx(true, 0x01);
        pending.push_tx(crate::transaction::Transaction(vec![cz]));

        let auth_root =
            AuthRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xAA; 32]).unwrap());
        let sr = StateRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xCC; 32]).unwrap());
        let pr =
            PrincipalRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xBB; 32]).unwrap());

        let commit = pending.finalize(auth_root, sr, pr, &[coz::HashAlg::Sha256]);
        assert!(
            matches!(commit, Err(crate::error::Error::EmptyCommit)),
            "a finalizer-only commit (no mutation cozies) must be rejected \
             as empty, got {commit:?}"
        );
    }

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

        let result = pending.finalize(auth_root, sr, pr, &[coz::HashAlg::Sha256]);
        assert!(
            matches!(result, Err(crate::error::Error::MissingCommit)),
            "finalize should fail without finalizer marker"
        );
    }

    #[test]
    fn pending_commit_finalize_fails_when_empty() {
        let pending = PendingCommit::new();

        let auth_root =
            AuthRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xAA; 32]).unwrap());
        let sr = StateRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xCC; 32]).unwrap());
        let pr =
            PrincipalRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xBB; 32]).unwrap());

        let result = pending.finalize(auth_root, sr, pr, &[coz::HashAlg::Sha256]);
        assert!(result.is_err(), "should fail when empty");
    }

    #[test]
    fn pending_commit_into_transactions_returns_accumulated() {
        let mut pending = PendingCommit::new();
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            false, 0x01,
        )]));
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            true, 0x02,
        )]));

        let cozies = pending.into_transactions();
        assert_eq!(cozies.len(), 2);
    }

    // ========================================================================
    // Commit Tests
    // ========================================================================

    #[test]
    fn commit_accessors_return_correct_values() {
        let mut pending = PendingCommit::new();
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            true, 0x01,
        )]));

        let auth_root =
            AuthRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xAA; 32]).unwrap());
        let sr = StateRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xCC; 32]).unwrap());
        let pr =
            PrincipalRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xBB; 32]).unwrap());

        let commit = pending
            .finalize(
                auth_root.clone(),
                sr.clone(),
                pr.clone(),
                &[coz::HashAlg::Sha256],
            )
            .unwrap();

        // Test all accessors
        assert_eq!(commit.iter_all_cozies().count(), 1);
        assert!(!commit.is_empty());
        assert_eq!(commit.len(), 1);
        assert_eq!(commit.auth_root(), &auth_root);
        assert_eq!(commit.sr(), &sr);
        assert_eq!(commit.pr(), &pr);
        assert_eq!(commit.tr().0.get(HashAlg::Sha256).unwrap().len(), 32);
    }

    #[test]
    fn commit_multi_transaction_computes_correct_tr() {
        let mut pending = PendingCommit::new();
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            false, 0x01,
        )]));
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            false, 0x02,
        )]));
        pending.push_tx(crate::transaction::Transaction(vec![make_test_tx(
            true, 0x03,
        )])); // finalizer

        let auth_root =
            AuthRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xAA; 32]).unwrap());
        let sr = StateRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xCC; 32]).unwrap());
        let pr =
            PrincipalRoot(MultihashDigest::from_single(HashAlg::Sha256, vec![0xBB; 32]).unwrap());

        let commit = pending
            .finalize(auth_root, sr, pr, &[coz::HashAlg::Sha256])
            .unwrap();
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
        crate::key::Key {
            alg: pk.alg.clone(),
            tmb,
            pub_key: pub_bytes,
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: None,
        }
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
    /// `finalize_with_arrow` (construction) must succeed, and
    /// `matches_arrow` (independent verification) must accept the
    /// resulting arrow via the same fallback.
    #[test]
    fn matches_arrow_accepts_multi_variant_fold() {
        let pool = fold_pool();
        let genesis = fold_pool_key(&pool, "golden");
        let diana = fold_pool_key(&pool, "diana_es384");
        let eve = fold_pool_key(&pool, "eve_ed25519");

        let genesis_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        let mut principal = crate::principal::Principal::implicit(fold_domain_key(genesis))
            .expect("genesis principal");
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
            .finalize_with_arrow(
                &genesis.alg,
                &genesis_prv,
                &genesis_pub,
                &genesis_tmb,
                now + 1,
                "cyphr.me",
            )
            .expect("commit1 (key creates) should finalize");

        // Clone post-commit1 state so both branches replay the identical
        // self-revoke bytes onto byte-identical starting states, the same
        // technique properties.rs uses to keep a/b in lockstep without
        // re-signing (ECDSA signing is randomized per call).
        let mut principal_b = principal.clone();

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
            .finalize_with_arrow(
                &diana.alg,
                &diana_prv,
                &diana_pub,
                &diana_tmb,
                now + 3,
                "cyphr.me",
            )
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

    // ========================================================================
    // finalize() state-ordering (GitHub issue #77 and its deleted_pending
    // sibling): a finalize_commit failure must never leave the live
    // principal reflecting projected mutations that were never durably
    // recorded.
    // ========================================================================

    /// Storage double that delegates to a real in-memory backend until
    /// armed, then fails every operation. Genesis setup (and any mutation
    /// apply, which never touches storage) succeeds normally; arming right
    /// before `finalize`/`finalize_with_arrow` isolates the injected
    /// failure to `finalize_commit`'s own durable-write path.
    #[derive(Debug)]
    struct ToggledFailureStorage {
        inner: eml::MemoryStorage,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[derive(Debug)]
    struct InjectedFinalizeFailure;

    impl std::fmt::Display for InjectedFinalizeFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "injected finalize_commit failure")
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

        async fn store_leaf(&mut self, index: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.check()?;
            self.inner
                .store_leaf(index, data)
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

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

        async fn store_node(
            &mut self,
            alg_id: u64,
            left: u64,
            height: u32,
            hash: &[u8],
        ) -> Result<(), Self::Error> {
            self.check()?;
            self.inner
                .store_node(alg_id, left, height, hash)
                .await
                .map_err(|_| InjectedFinalizeFailure)
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

        async fn store_algorithm_meta(
            &mut self,
            alg_id: u64,
            epochs: &[(u64, u64)],
        ) -> Result<(), Self::Error> {
            self.check()?;
            self.inner
                .store_algorithm_meta(alg_id, epochs)
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

        async fn load_log_meta(&self) -> Result<Option<(u64, u8)>, Self::Error> {
            self.check()?;
            self.inner
                .load_log_meta()
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn load_checkpoint_roots(&self) -> Result<Vec<(u64, Vec<u8>)>, Self::Error> {
            self.check()?;
            self.inner
                .load_checkpoint_roots()
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }

        async fn write_batch(
            &mut self,
            leaves: &[(u64, &[u8])],
            nodes: &[(u64, u64, u32, &[u8])],
            algorithm_metas: &[(u64, &[(u64, u64)])],
            log_meta: Option<(u64, u8)>,
            checkpoint_roots: &[(u64, &[u8])],
        ) -> Result<(), Self::Error> {
            self.check()?;
            self.inner
                .write_batch(leaves, nodes, algorithm_metas, log_meta, checkpoint_roots)
                .await
                .map_err(|_| InjectedFinalizeFailure)
        }
    }

    /// RED-first regression test for GitHub issue #77 (and its
    /// `deleted_pending` sibling, same seam): a `finalize_commit` failure
    /// must never leave the live principal reflecting projected mutations
    /// that were never durably recorded.
    #[test]
    fn finalize_failure_leaves_principal_unmutated() {
        let pool = fold_pool();
        let genesis = fold_pool_key(&pool, "golden");
        let genesis_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        let (storage, armed) = ToggledFailureStorage::new();
        let mut principal =
            crate::principal::Principal::implicit_with_storage(fold_domain_key(genesis), storage)
                .expect("genesis principal");

        // Snapshot observable pre-commit state to compare against after the
        // injected failure.
        let pr_before = principal.pr().clone();
        assert!(!principal.is_deleted(), "fresh principal must not be deleted");
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
        // failure to finalize_commit's own durable-write path.
        armed.store(true, std::sync::atomic::Ordering::SeqCst);

        let result = scope.finalize_with_arrow(
            &genesis.alg,
            &prv_bytes,
            &pub_bytes,
            &genesis_tmb,
            now + 1,
            "cyphr.me",
        );

        assert!(
            result.is_err(),
            "finalize_with_arrow must surface the injected storage failure"
        );
        assert_eq!(
            principal.pr(),
            &pr_before,
            "a failed finalize must not advance the live principal's PR"
        );
        assert!(
            !principal.is_deleted(),
            "a failed finalize must not leave `deleted` set on the live \
             principal (GitHub issue #77)"
        );
        assert!(
            !principal.deleted_pending,
            "a failed finalize must not leave `deleted_pending` set on \
             the live principal — its own sibling of GitHub issue #77"
        );
    }
}
