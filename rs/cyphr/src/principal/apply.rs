//! Transaction application and commit finalization.

use coz::Thumbprint;

use super::Principal;
use crate::commit::{Commit, CommitScope, PendingCommit};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::semantic_tree::derive_state_roots_with_nonces;
use crate::state::{HashAlg, PrincipalGenesis};

impl<S: eml::Storage> Principal<S> {
    /// Begin a new commit scope.
    ///
    /// Returns a `CommitScope` that holds an exclusive borrow of this principal.
    /// Transactions are applied via `CommitScope::apply()`, and the commit is
    /// finalized by calling `CommitScope::finalize()` which consumes the scope.
    ///
    /// The borrow checker ensures no external code can observe the principal's
    /// intermediate state during the commit.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut scope = principal.begin_commit();
    /// scope.apply(vtx1)?;
    /// scope.apply(vtx2)?;
    /// let commit = scope.finalize()?;
    /// ```
    pub fn begin_commit(&mut self) -> CommitScope<'_, S> {
        CommitScope::new(self)
    }

    /// Apply a single verified coz as an atomic commit.
    ///
    /// This is the convenience method for the common single-coz case.
    /// It internally creates a commit scope, applies the coz, and
    /// finalizes the commit in one call.
    ///
    /// For multi-coz commits, use `begin_commit()` instead.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `DuplicateKey`: Adding key already in KS
    /// - `CozReuse`: This principal already included this coz (SPEC §7.6)
    pub fn apply_transaction(&mut self, vtx: crate::parsed_coz::VerifiedCoz) -> Result<&Commit> {
        let mut scope = self.begin_commit();
        scope.apply(vtx)?;
        scope.finalize()
    }

    /// Commit this principal's genesis (SPEC 5.1-5.3), signed by `signer`,
    /// the genesis key: its `key/create` of itself and of every further
    /// genesis key, the `principal/create` and the `commit/create`.
    ///
    /// Returns the commit's wire cozies in order; each `key/create`
    /// discloses its key, so the genesis reads from the cozies alone.
    ///
    /// # Errors
    ///
    /// As [`CommitScope::create_genesis_keys`],
    /// [`CommitScope::create_principal`] and
    /// [`CommitScope::finalize_with_software`]; `UnknownKey` when `signer`
    /// is not the genesis key or the genesis is already committed.
    pub fn commit_genesis(
        &mut self,
        signer: &crate::signer::SoftwareSigner,
        now: i64,
        authority: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut scope = self.begin_commit();
        let mut cozies = scope.create_genesis_keys(signer, now, authority)?;
        cozies.push(scope.create_principal(signer, now, authority)?);
        let commit = scope.finalize_with_software(signer, now, authority)?;
        let closing = commit.commit_tx().0.first().ok_or(Error::MissingCommit)?;
        let closing = serde_json::to_value(closing.raw()).map_err(|_| Error::MalformedPayload)?;
        cozies.push(closing);
        Ok(cozies)
    }

    // ========================================================================
    // ParsedCoz application (internal)
    // ========================================================================

    /// Apply a verified coz to mutate principal state (internal).
    ///
    /// Called by `CommitScope::apply()`. This mutates the principal eagerly;
    /// the commit scope holds `&mut self` preventing external observation
    /// of intermediate state.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `DuplicateKey`: Adding key already in KS
    /// - `CozReuse`: This principal already included this coz (SPEC §7.6)
    pub(crate) fn apply_verified_internal(
        &mut self,
        vtx: crate::parsed_coz::VerifiedCoz,
    ) -> Result<()> {
        self.apply_transaction_internal(vtx)?;
        Ok(())
    }

    /// Apply a coz without prior signature verification (test-only).
    ///
    /// Pushes the mutation coz to `transactions` (without arrow), then
    /// creates a separate synthetic `commit/create` coz with the correctly
    /// computed arrow and pushes it to `commit_tx`. This mirrors the
    /// protocol structure per SPEC §4.4.
    #[cfg(test)]
    pub(crate) fn apply_transaction_test(
        &mut self,
        cz: crate::parsed_coz::ParsedCoz,
        new_key: Option<Key>,
    ) -> Result<&Commit> {
        self.commit_test(vec![(cz, new_key)])
    }

    /// Commit the genesis without signatures (test-only): the first
    /// genesis key creates itself and every other genesis key, then signs
    /// the `principal/create` (SPEC 5.1). Unit tests build principals from
    /// dummy keys that cannot sign, so they reach an established principal
    /// through this rather than through a signed genesis commit.
    #[cfg(test)]
    pub(crate) fn genesis_test(&mut self) -> Result<&Commit> {
        use crate::parsed_coz::{CozKind, ParsedCoz};
        use crate::state::AuthRoot;

        // The earliest `now` every later coz may still use (SPEC 14.1: `now`
        // is at least 1 and never earlier than the latest seen).
        let now = self.latest_timestamp.max(1);
        let signer = self
            .auth
            .keys
            .get(self.genesis_keys.first().ok_or(Error::NoActiveKeys)?)
            .ok_or(Error::UnknownKey)?
            .tmb()
            .clone();
        let coz = |kind, byte: u8| ParsedCoz {
            kind,
            signer: signer.clone(),
            now,
            czd: coz::Czd::from_bytes(vec![byte; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw: coz::CozJson {
                pay: serde_json::json!({ "typ": "cyphr.me/test", "alg": "ES256", "now": now }),
                sig: vec![0; 64],
            },
        };
        let mut cozies = Vec::new();
        for (i, tmb) in self.uncreated_genesis.iter().enumerate() {
            let key = self.auth.keys.get(tmb).ok_or(Error::UnknownKey)?.clone();
            let kind = CozKind::KeyCreate {
                id: key.tmb().clone(),
            };
            cozies.push((coz(kind, 0xF0 - i as u8), Some(key)));
        }
        // `id` is the PR the creates leave, which is the genesis PR: they
        // add no key the KT does not already hold.
        let id = AuthRoot(self.pr.0.clone());
        cozies.push((coz(CozKind::PrincipalCreate { id }, 0xF1), None));
        self.commit_test(cozies)
    }

    /// Apply `cozies` without signature verification and close them with
    /// a synthetic `commit/create` (test-only).
    #[cfg(test)]
    fn commit_test(
        &mut self,
        cozies: Vec<(crate::parsed_coz::ParsedCoz, Option<Key>)>,
    ) -> Result<&Commit> {
        use crate::commit::PendingCommit;
        use crate::multihash::MultihashDigest;
        use crate::parsed_coz::{CozKind, ParsedCoz, VerifiedCoz};

        let mut pending = PendingCommit::new();
        let mut last = None;
        for (cz, new_key) in cozies {
            // Apply mutation eagerly (same as apply_verified_internal)
            let mutation_vtx = VerifiedCoz::from_transaction_unsafe(cz.clone(), new_key);
            self.apply_verified_internal(mutation_vtx)?;
            // Push mutation coz to transactions (no arrow)
            pending.push_tx(crate::transaction::Transaction(vec![
                VerifiedCoz::from_transaction_unsafe(cz.clone(), None),
            ]));
            last = Some(cz);
        }
        let cz = last.ok_or(Error::EmptyCommit)?;

        // KT → AR-node → SR-node from post-mutation key set (local, does not
        // mutate self). DR is refreshed to the current active_algs rather
        // than trusting the cached value, which may predate a key of a new
        // algorithm (see finalize_commit's identical refresh).
        let active_algs = self.active_algs();
        let thumbprints: Vec<&coz::Thumbprint> = self.auth.keys.values().map(|k| k.tmb()).collect();
        let dr = self.data.included_root(&active_algs)?;
        let (_kr, _ar, sr) =
            derive_state_roots_with_nonces(&thumbprints, dr.as_ref(), &self.nonces, &active_algs)?;

        // Prefer the signer's own algorithm for the arrow, but a self-revoke
        // of the last key of that algorithm retires it from active_algs —
        // `sr` (rebuilt just above from the post-mutation key set) then has
        // no variant for it. Fall back to a surviving algorithm so the
        // arrow's three components (pre, sr, tmr) always share one that
        // `sr` actually has, rather than hitting `get_or_err`'s
        // `MissingVariant` on an algorithm this commit just retired.
        let tx_alg = if active_algs.contains(&cz.hash_alg) {
            cz.hash_alg
        } else {
            active_algs.first().copied().unwrap_or(cz.hash_alg)
        };

        // Compute TMR from pending transactions
        let (tmr_opt, _tcr, _tr) = pending.compute_roots(&[tx_alg]);
        let tmr = tmr_opt.ok_or(Error::EmptyCommit)?;

        let pre = self.arrow_pre()?;
        let arrow_digest = crate::commit::arrow_digest(tx_alg, &pre, sr.as_ref(), &tmr)?;
        let arrow_md = MultihashDigest::from_single(tx_alg, arrow_digest)?;
        // Create synthetic commit/create coz with arrow
        let commit_coz = ParsedCoz {
            kind: CozKind::CommitCreate {
                arrow: arrow_md.clone(),
            },
            signer: cz.signer.clone(),
            now: cz.now,
            czd: cz.czd.clone(),
            hash_alg: cz.hash_alg,
            arrow: Some(arrow_md),
            raw: cz.raw.clone(),
        };
        let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);
        pending.push_tx(crate::transaction::Transaction(vec![commit_vtx]));

        self.finalize_commit(pending)
    }

    /// The genesis signer rule. Before the genesis commit has created a
    /// key, KR is empty, so a transaction can only verify as the genesis
    /// key's own `key/create` (SPEC 5.1 steps 1-2, 5.3 "a genesis key
    /// constructs AT by adding itself", 13.2 step 3 "`tmb` belongs to a
    /// key in current KR"). After it, a genesis key signs only once its
    /// own `key/create` has been applied; any key so created may create
    /// another (SPEC 3.3).
    ///
    /// The genesis keys sit in the KT from construction so the PG is known
    /// before the genesis commit is signed (`principal/create` carries it
    /// as `id`); `uncreated_genesis` is what tells those seeded keys apart
    /// from keys in KR. A principal that never commits (Levels 1 and 2)
    /// signs data actions with its key uncreated; this rule binds
    /// transactions only.
    fn check_genesis_signer(&self, cz: &crate::parsed_coz::ParsedCoz) -> Result<()> {
        use crate::parsed_coz::CozKind;

        let signer = cz.signer.to_b64();
        if self.uncreated_genesis.len() == self.genesis_keys.len() {
            let opens = matches!(&cz.kind, CozKind::KeyCreate { id } if id.to_b64() == signer)
                && self.genesis_keys.first() == Some(&signer);
            if !opens {
                return Err(Error::UnknownKey);
            }
        } else if self.uncreated_genesis.contains(&signer) {
            return Err(Error::UnknownKey);
        }
        Ok(())
    }

    /// Internal coz application logic.
    fn apply_transaction_internal(&mut self, vtx: crate::parsed_coz::VerifiedCoz) -> Result<()> {
        use crate::parsed_coz::CozKind;

        // Access the underlying ParsedCoz via Deref
        let cz = &*vtx;

        // SPEC §7.6: a transaction coz this principal already included is
        // rejected; the first inclusion is authoritative. Checked first so a
        // replay is typed COZ_REUSE whatever state or timestamp it meets.
        if self.included_czds.contains(cz.czd.as_bytes()) {
            return Err(Error::CozReuse);
        }

        // Validate timestamp is not in the past (SPEC §14.1)
        if cz.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        self.check_now(cz.now)?;

        // Verify signer is an active key.
        // Exceptions:
        //   - SelfRevoke: handled specially (revoking oneself)
        //   - CommitCreate: finality marker; authorization was already verified against the
        //     pre-commit key snapshot in CommitScope::verify_and_apply. The signer may have been
        //     replaced by a prior mutation in this commit.
        let skip_active_check = matches!(
            &cz.kind,
            CozKind::SelfRevoke { .. } | CozKind::CommitCreate { .. }
        );
        if !skip_active_check {
            self.active_signer(&cz.signer)?;
        }
        self.check_genesis_signer(cz)?;
        // The PG is the state at the `principal/create`, so nothing but
        // the commit/create may follow it in the genesis commit.
        if self.genesis_pending && !matches!(cz.kind, CozKind::CommitCreate { .. }) {
            return Err(Error::GenesisIncomplete);
        }

        // [no-transactions-on-deleted]: SPEC §11.4 -- "no transactions or
        // actions are possible on a closed account". PrincipalDelete,
        // FreezeCreate, and FreezeDelete manage their own deleted/frozen PRE
        // checks in their match arms below (untouched by this gate).
        // CommitCreate is conditionally exempted (F35 narrowing): it is the
        // mandatory finalizer every commit must carry (finalize_commit
        // rejects a commit whose last cozy lacks the arrow) and its own arm
        // is a pure no-op that grants no mutation power (principal.rs, the
        // CommitCreate match arm below). CommitScope applies cozies
        // sequentially to a projected principal within one commit
        // (commit.rs:319-383), so a commit whose own earlier transaction is
        // principal/delete has already set `self.deleted` by the time its
        // own commit/create finalizer runs here -- rejecting it would make
        // a principal impossible to ever actually close. But that
        // necessity holds only for THIS SAME, still-open commit:
        // `deleted_pending` is true exactly while such a commit is open
        // (set by the PrincipalDelete arm, cleared at the end of a
        // successful `finalize_commit`), so a commit/create in a LATER,
        // separately-finalized commit against an already-deleted principal
        // -- where `deleted` is true but `deleted_pending` is false -- is
        // not exempted. Every other variant has no such mandatory-
        // finalizer property, so is gated by default.
        //
        // Exhaustive by construction, not `matches!` over an allow-list: a
        // future 10th CozKind variant must be classified HERE explicitly
        // (compile error otherwise) rather than silently inheriting
        // "gated" from an unmatched wildcard on this security-critical
        // check.
        let skip_deleted_check = match &cz.kind {
            CozKind::PrincipalDelete { .. }
            | CozKind::FreezeCreate { .. }
            | CozKind::FreezeDelete { .. } => true,
            CozKind::CommitCreate { .. } => self.deleted_pending,
            CozKind::KeyCreate { .. }
            | CozKind::KeyDelete { .. }
            | CozKind::KeyReplace { .. }
            | CozKind::SelfRevoke { .. }
            | CozKind::NonceCreate { .. }
            | CozKind::NonceDelete { .. }
            | CozKind::Merge(_)
            | CozKind::MergeAck(_)
            | CozKind::PrincipalCreate { .. }
            | CozKind::DataRootCreate { .. } => false,
        };
        if self.deleted && !skip_deleted_check {
            return Err(Error::AlreadyDeleted);
        }

        // SPEC §2.3.2, §11.2, §4.1: a frozen principal takes no mutation
        // until thawed, so every transaction is refused except the ones that
        // manage the lifecycle themselves: freeze/delete (the thaw) and
        // freeze/create (typed AlreadyFrozen in its arm), principal/delete
        // (close is permitted from Frozen, SPEC §11.4; R1/F5), and
        // CommitCreate, the finalizer of the commit that froze or thawed.
        // Exhaustive, so a new CozKind must be classified here.
        let frozen_exempt = match &cz.kind {
            CozKind::FreezeCreate { .. }
            | CozKind::FreezeDelete { .. }
            | CozKind::PrincipalDelete { .. }
            | CozKind::CommitCreate { .. } => true,
            CozKind::KeyCreate { .. }
            | CozKind::KeyDelete { .. }
            | CozKind::KeyReplace { .. }
            | CozKind::SelfRevoke { .. }
            | CozKind::NonceCreate { .. }
            | CozKind::NonceDelete { .. }
            | CozKind::Merge(_)
            | CozKind::MergeAck(_)
            | CozKind::PrincipalCreate { .. }
            | CozKind::DataRootCreate { .. } => false,
        };
        if self.frozen && !frozen_exempt {
            return Err(Error::Frozen);
        }

        match &cz.kind {
            CozKind::KeyCreate { id } => {
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb().to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // The signed pay binds only `tmb`; the sidecar `pub` is unsigned.
                // SPEC §6.4: a revoked key is never trusted again. Only a
                // deleted key may be re-added (§6.2).
                if self.auth.revoked.contains_key(&id.to_b64()) {
                    return Err(Error::KeyRevoked);
                }
                let tmb = id.to_b64();
                let uncreated = self.uncreated_genesis.iter().position(|t| *t == tmb);
                if let Some(at) = uncreated.filter(|_| self.auth.keys.contains_key(&tmb)) {
                    // SPEC 5.1 step 1, 5.3, 7.7 Example 1: a genesis key is
                    // in the KT from construction, and its `key/create` is
                    // the explicit add the genesis carries; the key it
                    // discloses must be the one held. Who may sign it is
                    // `check_genesis_signer`'s rule.
                    if self.auth.keys.get(&tmb).map(Key::pub_key) != Some(key.pub_key()) {
                        return Err(Error::UnknownKey);
                    }
                    self.core_mut().uncreated_genesis.remove(at);
                } else if self.auth.keys.contains_key(&tmb) {
                    return Err(Error::DuplicateKey);
                } else {
                    self.add_key(key, cz.now);
                }
            },
            CozKind::KeyDelete { id } => {
                self.remove_key(id)?;
            },
            CozKind::KeyReplace { id } => {
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb().to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // The signed pay binds only `tmb`; the sidecar `pub` is unsigned.
                // SPEC §6.4: a revoked key is never trusted again.
                if self.auth.revoked.contains_key(&id.to_b64()) {
                    return Err(Error::KeyRevoked);
                }
                // Atomic swap: add new key first, then remove signer
                // This allows Level 2 single-key accounts to replace their key
                self.add_key(key, cz.now);
                // The signer is removed outright: it is not a delete of a key
                // (a key was just added, so the set cannot empty)
                self.core_mut().auth.keys.shift_remove(&cz.signer.to_b64());
            },
            CozKind::SelfRevoke { rvk } => {
                self.revoke_key(&cz.signer, *rvk, None)?;
            },
            // SPEC §10.1: nonces are accepted at every lifecycle stage a
            // mutation is, a nascent principal included (§5.1: a nonce
            // gives a reused authentication component its own PG). Roots
            // are recomputed at finalize from the nonce sets.
            CozKind::NonceCreate { level, nonce } => {
                self.core_mut().nonces.insert(*level, nonce)?;
            },
            CozKind::NonceDelete { level, nonce } => {
                self.core_mut().nonces.remove(*level, nonce)?;
            },
            CozKind::PrincipalCreate { id } => {
                // Genesis finalization (SPEC 5.1): signed by the genesis key
                // (the first key; 5.2 TX1, 5.3 TX2), so the rule reads the
                // same however the producer seeded the other keys.
                if self.genesis_keys.first() != Some(&cz.signer.to_b64()) {
                    return Err(Error::UnknownKey);
                }
                // SPEC 7.7 Example 1: genesis does not create a key
                // implicitly. A genesis key still active without its
                // `key/create` is a key the genesis never created.
                if self
                    .uncreated_genesis
                    .iter()
                    .any(|tmb| self.auth.keys.contains_key(tmb))
                {
                    return Err(Error::GenesisIncomplete);
                }
                // SPEC 5.1 step 3, 5.2 TX1 "ID == PG == SR": `id` is the
                // future SR, the state every genesis mutation before this
                // one reached (keys, nonces), promoted to PR with no CR.
                let pg = self.genesis_pr()?;
                if !id.0.matches(&pg.0) {
                    return Err(Error::StateMismatch);
                }
                // establish_pg() is the ONLY code path that transitions
                // Nascent → Established.
                self.establish_pg(PrincipalGenesis::from_initial(&pg))?;
                self.core_mut().genesis_pending = true;
            },
            // SPEC 11.5.1: a merge and its ack are each the signer's own
            // statement, accepted into the signer's chain alone. Neither
            // touches keys, AT or the other principal; whether they make
            // a merge is `merge_status`, which needs both chains. Each
            // names a PR the signer must actually have held: the source
            // merges from PRs of its own, the target acks a PR of its own.
            CozKind::Merge(claim) => {
                if !claim.from.iter().all(|pr| self.has_held(pr)) {
                    return Err(Error::StateMismatch);
                }
            },
            CozKind::MergeAck(claim) => {
                if !self.has_held(&claim.to_pr) {
                    return Err(Error::StateMismatch);
                }
            },
            CozKind::CommitCreate { .. } => {
                // Finalize commit marker does not mutate state other than marking completion
                // State references are verified during commit finalization
            },
            CozKind::PrincipalDelete { id } => {
                // Close (SPEC §11.4, R1/F5 ruling): permitted from Active or
                // Frozen, rejected if already Deleted
                // ([no-transactions-on-deleted] applied to itself).
                if self.deleted {
                    return Err(Error::AlreadyDeleted);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                let core = self.core_mut();
                core.deleted = true;
                core.deleted_pending = true;
                // Deleted subsumes Frozen (SPEC.md:1974-1978 mutual
                // exclusivity; R1/F5): unconditionally clear frozen even if
                // it was set going in.
                core.frozen = false;
            },
            CozKind::FreezeCreate { id } => {
                // Self-freeze (SPEC §14.9.1, R1/F5 ruling): rejected if
                // already Deleted or already Frozen.
                if self.deleted {
                    return Err(Error::AlreadyDeleted);
                }
                if self.frozen {
                    return Err(Error::AlreadyFrozen);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                self.core_mut().frozen = true;
            },
            CozKind::FreezeDelete { id } => {
                // Thaw (SPEC §14.9.3, R1/F5 ruling): requires currently
                // Frozen.
                if !self.frozen {
                    return Err(Error::NotFrozen);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                self.core_mut().frozen = false;
            },
            CozKind::DataRootCreate { id } => {
                // SPEC 4.8.2: `id` is the computed new DR = MR(DT), over
                // every action recorded so far. Matching one variant
                // suffices, as for every tagged `id` (all variants name the
                // same content); DR itself is folded into SR at finalize.
                // A stale or foreign DR is the same refusal as any other
                // `id` that names a state the principal is not in.
                let core = self.core_mut();
                let algs = core.active_algs();
                let dt = core.data.tree_root(&algs)?;
                if !dt.is_some_and(|dt| id.0.matches(&dt.0)) {
                    return Err(Error::StateMismatch);
                }
                core.data.include_all();
            },
        }

        // Update signer's last_used timestamp
        self.update_last_used(&cz.signer, cz.now);

        // Update latest timestamp
        let core = self.core_mut();
        core.included_czds.insert(cz.czd.as_bytes().to_vec());
        if cz.now > core.latest_timestamp {
            core.latest_timestamp = cz.now;
        }

        Ok(())
    }

    /// Finalize a commit with proper state recomputation.
    ///
    /// This is called by `CommitScope::finalize()` with the accumulated
    /// `PendingCommit`. Recomputes all state digests and appends the
    /// finalized commit to the auth ledger.
    pub(crate) fn finalize_commit(&mut self, pending: PendingCommit) -> Result<&Commit> {
        if pending.is_finalizer_only() {
            return Err(Error::EmptyCommit);
        }
        if self.pg().is_none() {
            return Err(Error::GenesisIncomplete);
        }

        // Validate arrow field placement: only last cz may have it,
        // and last cz MUST have it (SPEC §4.4).
        let cozies = pending.all_cozies();
        for (i, vtx) in cozies.iter().enumerate() {
            let is_last = i == cozies.len() - 1;
            if vtx.arrow().is_some() && !is_last {
                return Err(Error::CommitNotLast);
            }
            if vtx.arrow().is_none() && is_last {
                return Err(Error::MissingCommit);
            }
        }

        let core = self.core_mut();

        // Re-derive active algorithms from post-mutation key set.
        // Per [alg-set-evolution], state digests for this commit use the
        // algorithms supported by the post-mutation key set; a commit that
        // leaves no key hashes under the set in force before it
        // (`active_algs` falls back to the pre-commit PR's).
        let active_algs = core.active_algs();

        // Extract tx algorithm set from the commit coz (independent of state chain).
        // TX extraction reads only cozies/pending — no dependency on KR/AR/SR —
        // so it is hoisted here; its prior placement between KR+AR and SR was incidental.
        let tx_algs: Vec<coz::HashAlg> = if let Some(last_coz) = cozies.last() {
            if let Some(arrow) = last_coz.arrow() {
                arrow.algorithms().collect()
            } else {
                vec![last_coz.hash_alg()]
            }
        } else {
            vec![active_algs.first().copied().unwrap_or(HashAlg::Sha256)]
        };

        // TR carries a variant for the signer's algorithms AND every active
        // algorithm. The commit-log leaf is this TR, and each algorithm's
        // MALT hasher reads only its own variant: a missing one hashes to a
        // constant and freezes that algorithm's CR variant (SPEC §12.1: all
        // variants name the same content). The arrow still binds only
        // `tx_algs` (computed separately below).
        let mut tr_algs = tx_algs.clone();
        tr_algs.extend(active_algs.iter().copied().filter(|a| !tx_algs.contains(a)));
        let tr = pending.compute_tr(&tr_algs).ok_or(Error::EmptyCommit)?;
        core.tr = Some(tr.clone());

        // Refresh DR's algorithm coverage to the post-mutation active_algs
        // before folding it into SR-node. DR was last computed under
        // whatever active_algs were live at its `ds/create`; a key of a NEW
        // algorithm added since then would otherwise leave DR missing that
        // algorithm's variant, and StateTree::build's cell payload would hit
        // MultihashDigest::get_or_err's `MissingVariant` error for the new
        // algorithm. Only the actions a `ds/create` included count
        // (SPEC 4.8.2): ones recorded since are in DT, not yet in DR.
        core.dr = core.data.included_root(&active_algs)?;

        // KT → AR-node → SR-node (post-mutation key set, refreshed DR).
        // PR is computed below, after Arrow validation and CR assembly.
        let thumbprints: Vec<&Thumbprint> = core.auth.keys.values().map(|k| k.tmb()).collect();
        let (kr, ar, sr) = derive_state_roots_with_nonces(
            &thumbprints,
            core.dr.as_ref(),
            &core.nonces,
            &active_algs,
        )?;
        core.kr = kr;
        core.ar = ar;
        // core.sr/core.pt are NOT written yet — the arrow validation below
        // uses the local `sr`, and core.pr must still hold the pre-commit
        // value (see the comment there). Both are written together with CR
        // at the end of this function, via write_pt_sr_cr.

        // Validate arrow field matches independently computed Arrow.
        // Arrow = MR(pre, fwd_SR, TMR)
        // Compare at the signer's specific algorithm, mirroring Go.
        let last_coz = cozies.last().ok_or(Error::EmptyCommit)?;
        if let Some(claimed_arrow) = last_coz.arrow() {
            let (tmr, _tcr, _tr) = pending.compute_roots(&tx_algs);
            let tmr = tmr.ok_or(Error::EmptyCommit)?;

            // pre is the PR *before* this commit (core.pr is updated only at
            // the end of this function), or in the genesis commit the
            // genesis key's own PR (`arrow_pre`).
            let tx_alg = tx_algs[0];
            let pre = core.arrow_pre()?;
            let computed_digest = crate::commit::arrow_digest(tx_alg, &pre, sr.as_ref(), &tmr)?;

            let claimed_digest = claimed_arrow.get(tx_alg).ok_or(Error::CommitMismatch)?;
            if claimed_digest != computed_digest.as_slice() {
                return Err(Error::CommitMismatch);
            }
        }

        // Ensure all active algorithms are registered in the unified EML Log.
        let algs = active_algs.clone();
        for &alg in &algs {
            let alg_id = crate::commit_root::hash_alg_to_u64(alg);
            if !core.commit_trees.has_algorithm(alg_id) {
                let hasher = Box::new(crate::commit_root::MaltHasher::new(alg));
                core.commit_trees
                    .add_algorithm(alg_id, hasher)
                    .map_err(|e| Error::Storage(e.to_string()))?;
            }
        }

        // This commit's 0-based position in the append-only commit
        // sequence. For a live/first-time commit this always equals the
        // durable log's current leaf count (each call appends exactly one
        // leaf in lockstep with `core.auth.commits`), so `already_durable`
        // is always false on that path — replay is the only path where a
        // durable log opened via `CommitTrees::open` can already carry
        // this leaf from a prior session.
        let leaf_index = core.auth.commits.len() as u64;
        let already_durable = leaf_index < core.commit_trees.global_size();

        // Serialize this commit's TR once — used both to append a fresh
        // leaf and, on the already_durable path, as the value to
        // byte-compare a pre-existing leaf against.
        let serialized = crate::commit_root::commit_leaf(&tr.0, &active_algs)?;

        let cr = if already_durable {
            // A prior durable session already appended a leaf at this
            // position — re-appending would duplicate it. But a crash
            // between a prior `finalize_commit`'s durable EML append and
            // its index write can leave an ORPHAN leaf here instead of
            // this commit's own TR: byte-compare before trusting it,
            // rather than silently deriving CR from whatever leaf already
            // occupies the position.
            let stored = core
                .commit_trees
                .get_leaf(leaf_index)
                .map_err(|e| Error::Storage(e.to_string()))?;
            if stored != serialized {
                return Err(Error::DurableLeafMismatch(leaf_index));
            }

            // Read the historical root as of this leaf's position instead.
            crate::commit_root::commit_root_from_trees_at(
                &core.commit_trees,
                &algs,
                leaf_index + 1,
            )?
        } else {
            // Append current TR once to the unified EML Log.
            core.commit_trees
                .append(&serialized)
                .map_err(|e| Error::Storage(e.to_string()))?;

            // Assemble CR from the EML Log for all active algorithms.
            crate::commit_root::commit_root_from_trees(&core.commit_trees, &algs)?
        };

        // Write SR into cell 0 and CR into cell 1 of the Principal Tree, and
        // recompute PR from the tree (EpochTree::root(alg_id) per algorithm).
        core.pr = core.write_pt_sr_cr(sr.as_ref(), &cr, &active_algs)?;
        core.held_prs.push(core.pr.clone());

        // Finalize the pending commit with computed states
        let commit = pending.finalize(core.ar.clone(), sr, core.pr.clone(), &tr_algs)?;

        core.auth.commits.push(commit);

        // This commit is now durably finalized: any principal/delete it
        // carried is no longer "this commit's own pending delete" for a
        // future commit's CommitCreate exemption (skip_deleted_check).
        core.deleted_pending = false;
        core.genesis_pending = false;

        // The borrow is safe: we just pushed, so last() is guaranteed Some.
        core.auth.commits.last().ok_or(Error::EmptyCommit)
    }

    /// Verify signature and apply a coz as an atomic commit.
    ///
    /// This is the primary method for processing incoming single-coz
    /// commits. It verifies the signature, parses the coz, applies
    /// the mutation, and finalizes the commit in one call.
    ///
    /// For multi-coz commits, use `begin_commit()` with manual
    /// scope control.
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
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `MalformedPayload`: Missing required fields
    #[must_use = "coz application may fail; handle the Result"]
    pub fn verify_and_apply_transaction(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<Key>,
    ) -> Result<&Commit> {
        use crate::parsed_coz::verify_coz;

        // Parse Pay to get signer thumbprint
        let pay: coz::Pay =
            serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;
        let signer_tmb = pay.tmb.as_ref().ok_or(Error::MalformedPayload)?;

        // Signer must be an ACTIVE key (not revoked)
        let signer_key = self.active_signer(signer_tmb)?;

        // Verify signature and parse coz
        let vtx = verify_coz(pay_json, sig, signer_key, czd, new_key)?;

        // Apply as single-cz atomic commit
        self.apply_transaction(vtx)
    }

    /// Add a key to the active key set.
    ///
    /// Sets `first_seen` to the given timestamp.
    fn add_key(&mut self, mut key: Key, first_seen: i64) {
        key.set_first_seen(first_seen);
        let tmb_b64 = key.tmb().to_b64();
        self.core_mut().auth.keys.insert(tmb_b64, key);
    }

    /// Remove a key from the active key set (delete, not revoke). Deleting
    /// the last key is accepted and leaves the principal Dead (SPEC 11.2:
    /// Dead is a consequence of any condition that leaves no keys).
    fn remove_key(&mut self, tmb: &Thumbprint) -> Result<()> {
        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();
        if core.auth.keys.shift_remove(&tmb_b64).is_none() {
            return Err(Error::UnknownKey);
        }
        Ok(())
    }

    /// Revoke a key (marks as revoked, moves to revoked set). Revoking the
    /// last key is accepted and leaves the principal Dead.
    ///
    /// # Errors
    ///
    /// - `UnknownKey`: Key not found in active set
    fn revoke_key(&mut self, tmb: &Thumbprint, rvk: i64, by: Option<Thumbprint>) -> Result<()> {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();

        // Check if key exists
        if !core.auth.keys.contains_key(&tmb_b64) {
            return Err(Error::UnknownKey);
        }

        // Revoking the last key is accepted and leaves the principal Dead
        // (SPEC 3.1, 11): refusing it would leave a compromised key live,
        // and 14.1 makes services that ignore a revoke non-compliant.
        let mut key = core
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .ok_or(Error::UnknownKey)?;
        key.set_revocation(Revocation { rvk, by });

        // Move to revoked set for historical verification
        core.auth.revoked.insert(tmb_b64, key);

        Ok(())
    }

    /// Update a key's last_used timestamp.
    ///
    /// Called after successful coz or action signing.
    pub(super) fn update_last_used(&mut self, tmb: &Thumbprint, timestamp: i64) {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.core_mut().auth.keys.get_mut(&tmb_b64) {
            key.set_last_used(timestamp);
        }
    }
}
