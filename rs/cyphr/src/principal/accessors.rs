//! Read-only views of a principal's state, and its configuration.

use coz::Thumbprint;

use super::{Clock, Level, MAX_NOW, Principal, PrincipalState};
use crate::action::Action;
use crate::commit::Commit;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::parsed_coz::VerifiedCoz;
use crate::state::{
    AuthRoot, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot,
};

impl PrincipalState {
    /// Get the Principal Genesis, or None if not yet established (L1/L2).
    ///
    /// PG is only set when principal/create is processed (Level 3+, SPEC §5.1).
    /// For Established principals, this always returns `Some`.
    pub fn pg(&self) -> Option<&PrincipalGenesis> {
        self.pg.as_ref()
    }

    /// Get the current Principal Root.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
    }

    /// Whether this principal has ever held `pr` (SPEC 11.5.1), compared by
    /// value on every algorithm the two share.
    pub fn has_held(&self, pr: &PrincipalRoot) -> bool {
        self.held_prs.iter().any(|h| h.0.matches(&pr.0))
    }

    /// Get the current Auth Root; `None` for a Dead principal, which has
    /// no keys and so no AR (SPEC 3.7: empty components are omitted).
    pub fn auth_root(&self) -> Option<&AuthRoot> {
        self.ar.as_ref()
    }

    /// Get the current Principal State as a tagged digest string (alg:digest format).
    ///
    /// Uses the lexicographically first algorithm from active_algs for deterministic output.
    /// This is the canonical tagged-digest format used e.g. for `principal/create`'s
    /// `id` field (SPEC §4.3, §5.1).
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if the state digest has no variants.
    pub fn pr_tagged(&self) -> Result<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let first_alg = self
            .active_algs()
            .first()
            .copied()
            .unwrap_or_else(|| self.hash_alg());
        let bytes = self.pr.0.get_or_err(first_alg)?;

        Ok(format!(
            "{}:{}",
            first_alg,
            Base64UrlUnpadded::encode_string(bytes)
        ))
    }

    /// Get the current Key Root; `None` for a Dead principal (see
    /// [`Self::auth_root`]).
    pub fn key_root(&self) -> Option<&KeyRoot> {
        self.kr.as_ref()
    }

    /// Get the hash algorithm used by this principal.
    pub fn hash_alg(&self) -> HashAlg {
        self.active_algs()
            .first()
            .copied()
            .unwrap_or(HashAlg::Sha256)
    }

    /// Get the active hash algorithms derived from current active keys (SPEC §14).
    pub fn active_algs(&self) -> Vec<HashAlg> {
        self.core.active_algs()
    }

    /// The base64 thumbprint of this principal's genesis key, the key it
    /// was constructed from (SPEC 5.1 step 1).
    pub fn genesis_key(&self) -> &str {
        &self.core.genesis_key
    }

    /// Get a key by thumbprint.
    pub fn get_key(&self, tmb: &Thumbprint) -> Option<&Key> {
        let key = tmb.to_b64();
        self.auth
            .keys
            .get(&key)
            .or_else(|| self.auth.revoked.get(&key))
    }

    /// Check if a key is currently active.
    pub fn is_key_active(&self, tmb: &Thumbprint) -> bool {
        self.auth.keys.contains_key(&tmb.to_b64())
    }

    /// Get all active keys.
    pub fn active_keys(&self) -> impl Iterator<Item = &Key> {
        self.auth.keys.values()
    }

    /// Get number of active keys.
    pub fn active_key_count(&self) -> usize {
        self.auth.keys.len()
    }

    /// Check if a key has been revoked.
    pub fn is_key_revoked(&self, tmb: &Thumbprint) -> bool {
        self.auth.revoked.contains_key(&tmb.to_b64())
    }

    /// Get all cozies (across all commits).
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.auth.commits.iter().flat_map(|c| c.iter_all_cozies())
    }

    /// Get all finalized commits.
    pub fn commits(&self) -> impl Iterator<Item = &Commit> {
        self.auth.commits.iter()
    }

    /// How many shared segments the chain's commits are held in.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn commit_segments(&self) -> usize {
        self.auth.commits.segments()
    }

    /// How many commits the chain holds.
    pub fn commit_count(&self) -> usize {
        self.auth.commits.len()
    }

    /// The commit at chain position `index`, from 0.
    pub fn commit_at(&self, index: usize) -> Option<&Commit> {
        self.auth.commits.get(index)
    }

    /// Get the TR of the current commit (if any).
    pub fn current_tr(&self) -> Option<&crate::transaction_root::TransactionRoot> {
        self.tr.as_ref()
    }

    /// Get the current Commit Root (CR).
    pub fn cr(&self) -> Option<&crate::commit_root::CommitRoot> {
        self.cr.as_ref()
    }

    /// Get the current State Root.
    ///
    /// Returns `None` only if no state has been computed (shouldn't happen
    /// after genesis). At genesis, SR is promoted from AR.
    pub fn sr(&self) -> Option<&StateRoot> {
        self.sr.as_ref()
    }

    /// The actions DT shows, in the order SPEC 4.8.1 gives it (by `now`, then
    /// `czd`): the held actions whose signer authorized them at their own
    /// `now` (SPEC 6.2, 6.5), read from the key timeline as it stands. An
    /// action a later commit dated before it takes out of DT is held
    /// still, and is back if a later commit restores its key.
    pub fn actions(&self) -> impl Iterator<Item = &Action> {
        let hidden = self.hidden();
        self.data
            .actions
            .iter()
            .filter_map(move |(key, a)| (!hidden.contains(key)).then_some(a))
    }

    /// Determine the current feature level.
    pub fn level(&self) -> Level {
        // Level 4: a Data Tree (SPEC 3.0, 3.4): DR in the Principal Tree,
        // set by a signed `ds/create`, or data actions recorded in DT.
        if self.dr.is_some() || !self.data.actions.is_empty() {
            return Level::L4;
        }
        // Level 3: multiple keys or has commits
        if self.auth.keys.len() > 1 || !self.auth.commits.is_empty() {
            return Level::L3;
        }
        // Level 2 if any key/replace occurred (detected by commit history)
        // For now, single key with no commits = Level 1
        Level::L1
    }

    /// Whether `principal/delete` has been signed (SPEC.md §11.1 `Deleted`).
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Whether `freeze/create` is active and not yet undone by
    /// `freeze/delete` (SPEC.md §11.1 `Frozen`).
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Whether the Key Tree holds a digest that is not a key: a nonce, or
    /// an embedded principal (SPEC §10.1, §10.3), which no one can tell
    /// apart until the verifier reveals it.
    pub fn has_kt_digests(&self) -> bool {
        !self
            .nonces
            .at_level(crate::nonce::NonceLevel::Kt)
            .is_empty()
    }

    /// Whether a fork or invalid chain has been detected (SPEC.md §11.1
    /// `Errored`). Orthogonal to [`Principal::lifecycle_state`]: any base
    /// state may be errored (SPEC.md §11.1).
    pub fn is_errored(&self) -> bool {
        self.errored
    }

    /// Derive the current lifecycle base state (SPEC.md §11.2).
    ///
    /// `CanDataAction` is wired as `level() >= L4 && HasActiveKeys` — the
    /// active-keys conjunct is non-load-bearing for any state reachable
    /// below Level 5 (see [`crate::lifecycle::derive_lifecycle_state`]'s doc
    /// comment): `CanDataAction` only distinguishes Zombie from Dead, and
    /// Zombie is unreachable below Level 5.
    pub fn lifecycle_state(&self) -> crate::lifecycle::LifecycleState {
        let has_active_keys = self.active_key_count() > 0;
        let can_data_action = self.level() >= Level::L4 && has_active_keys;
        crate::lifecycle::derive_lifecycle_state(
            self.deleted,
            self.frozen,
            has_active_keys,
            can_data_action,
        )
    }

    /// Bound a coz or action `now` (SPEC 6.4, 14.1, 15.9) for every entry
    /// path, commit, action and push alike. Replay needs no exemption: a
    /// chain's past timestamps are below the clock, so only a message from
    /// the future is refused.
    ///
    /// Below 1 is reported as `TimestampPast` and above 2^53 - 1 as
    /// `TimestampFuture`, so no new error variant is needed.
    pub(crate) fn check_now(&self, now: i64) -> Result<()> {
        if now < 1 {
            return Err(Error::TimestampPast);
        }
        // Saturating: `now` can be up to i64::MAX and the skew is caller-set.
        let ceiling = ((self.clock)().saturating_add_unsigned(self.max_clock_skew)).min(MAX_NOW);
        if now > ceiling {
            return Err(Error::TimestampFuture);
        }
        Ok(())
    }

    /// The DR the Principal Tree holds: `None` until a `ds/create`
    /// includes the Data Tree (SPEC 4.8.2), and unchanged by actions
    /// recorded since the last one.
    pub fn data_root(&self) -> Option<&DataRoot> {
        self.dr.as_ref()
    }

    /// The number of actions DT shows ([`Self::actions`]).
    pub fn action_count(&self) -> usize {
        self.data.actions.len() - self.hidden().len()
    }

    /// MR over the actions DT shows: the `id` a `ds/create` signed now would
    /// name.
    pub(crate) fn data_root_of_view(&self, algs: &[HashAlg]) -> Result<Option<DataRoot>> {
        let actions: Vec<&Action> = self.actions().collect();
        crate::state::compute_dr(&actions, None, algs)
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Pre-revoke a key (for test setup).
    ///
    /// This moves the key from active to revoked set WITHOUT recomputing state.
    /// Used for setting up error condition tests where we need a revoked key.
    ///
    /// # Errors
    ///
    /// Returns `UnknownKey` if the key is not found in the active set.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn pre_revoke_key(&mut self, tmb: &Thumbprint, rvk: i64) -> Result<()> {
        use crate::error::Error;
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();
        let mut key = core
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .ok_or(Error::UnknownKey)?;
        key.set_revocation(Revocation { rvk, by: None });
        core.auth.revoked.insert(tmb_b64, key);
        core.key_timeline.revoke(tmb, rvk);
        Ok(())
    }

    /// Make this principal believe it once held `pr`.
    ///
    /// Test setup for a forged `principal/merge-ack`: an honest client's
    /// own verifier refuses an ack naming a PR it never held, so no honest
    /// client can put such a commit on the wire. A test authors one on a
    /// copy that believes otherwise and pushes it to the real chain.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn pretend_held(&mut self, pr: PrincipalRoot) {
        self.state.core_unjudged_mut().held_prs.push(pr);
    }

    /// Get a reference to the per-algorithm MALT trees.
    ///
    /// Exposes the Commit Tree's root and proof queries.
    pub fn commit_trees(&self) -> &crate::commit_root::CommitTrees<S> {
        &self.log
    }

    /// Configure the tolerance for a `now` ahead of the verifier clock.
    ///
    /// A `now` greater than `clock() + seconds` is refused with
    /// `TimestampFuture`. The default is `DEFAULT_MAX_CLOCK_SKEW`; 0 means
    /// no tolerance, not "unchecked": the bound cannot be turned off.
    /// Unsigned, so a skew that would refuse a `now` at or before the
    /// verifier clock cannot be expressed.
    pub fn set_max_clock_skew(&mut self, seconds: u64) {
        self.state.core_unjudged_mut().max_clock_skew = seconds;
    }

    /// Install the verifier's time source (Unix seconds).
    ///
    /// The default reads the system clock where one exists. On
    /// wasm32-unknown-unknown the default reads 0 and so refuses every
    /// `now`: the host must install a clock (for example one over
    /// `Date.now`) before applying anything. Until it does, a wasm verifier
    /// cannot replay a peer chain either, since replay applies each coz
    /// through the same bound.
    pub fn set_clock(&mut self, clock: Clock) {
        self.state.core_unjudged_mut().clock = clock;
    }
}
