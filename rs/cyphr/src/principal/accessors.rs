//! Read-only views of a principal's state, and its configuration.

use coz::Thumbprint;

use super::{Level, Principal, PrincipalKind};
use crate::action::Action;
use crate::commit::Commit;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::parsed_coz::VerifiedCoz;
use crate::state::{
    AuthRoot, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot,
};

impl<S: eml::Storage> Principal<S> {
    /// Get the Principal Genesis, or None if not yet established (L1/L2).
    ///
    /// PG is only set when principal/create is processed (Level 3+, SPEC §5.1).
    /// For Established principals, this always returns `Some`.
    pub fn pg(&self) -> Option<&PrincipalGenesis> {
        match self.kind() {
            PrincipalKind::Established { pg, .. } => Some(pg),
            PrincipalKind::Nascent(_) => None,
        }
    }

    /// Get the current Principal Root.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
    }

    /// Get the current Auth State.
    pub fn auth_root(&self) -> &AuthRoot {
        &self.ar
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

    /// Get the current Key State.
    pub fn key_root(&self) -> &KeyRoot {
        &self.kr
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
        match self.kind() {
            PrincipalKind::Nascent(core) => core.active_algs(),
            PrincipalKind::Established { core, .. } => core.active_algs(),
        }
    }

    /// Get the genesis keys of this principal.
    pub fn genesis_keys(&self) -> &[String] {
        match self.kind() {
            PrincipalKind::Nascent(core) => &core.genesis_keys,
            PrincipalKind::Established { core, .. } => &core.genesis_keys,
        }
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

    /// Get mutable access to all active keys.
    ///
    /// This is primarily for test setup (e.g., pre-revoking keys).
    /// Use with caution - direct mutation bypasses state recomputation.
    pub fn active_keys_mut(&mut self) -> impl Iterator<Item = &mut Key> {
        self.core_mut().auth.keys.values_mut()
    }

    /// Get number of active keys.
    pub fn active_key_count(&self) -> usize {
        self.auth.keys.len()
    }

    /// Check if a key has been revoked.
    pub fn is_key_revoked(&self, tmb: &Thumbprint) -> bool {
        self.auth.revoked.contains_key(&tmb.to_b64())
    }

    /// Pre-revoke a key (for test setup).
    ///
    /// This moves the key from active to revoked set WITHOUT recomputing state.
    /// Used for setting up error condition tests where we need a revoked key.
    ///
    /// # Errors
    ///
    /// Returns `UnknownKey` if the key is not found in the active set.
    pub fn pre_revoke_key(&mut self, tmb: &Thumbprint, rvk: i64) -> Result<()> {
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
        Ok(())
    }

    /// Get all cozies (across all commits).
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.auth.commits.iter().flat_map(|c| c.iter_all_cozies())
    }

    /// Get all finalized commits.
    pub fn commits(&self) -> impl Iterator<Item = &Commit> {
        self.auth.commits.iter()
    }

    /// Get the TR of the current commit (if any).
    pub fn current_tr(&self) -> Option<&crate::transaction_root::TransactionRoot> {
        self.tr.as_ref()
    }

    /// Get the current Commit Root (CR).
    pub fn cr(&self) -> Option<&crate::commit_root::CommitRoot> {
        self.cr.as_ref()
    }

    /// Get a reference to the per-algorithm MALT trees.
    ///
    /// Used by checkpoint export to persist MALT state for later
    /// restoration via `Principal::from_checkpoint`.
    pub fn commit_trees(&self) -> &crate::commit_root::CommitTrees<S> {
        &self.commit_trees
    }

    /// Get the current State Root.
    ///
    /// Returns `None` only if no state has been computed (shouldn't happen
    /// after genesis). At genesis, SR is promoted from AR.
    pub fn sr(&self) -> Option<&StateRoot> {
        self.sr.as_ref()
    }

    /// Get all actions.
    pub fn actions(&self) -> impl Iterator<Item = &Action> {
        self.data.actions.iter()
    }

    /// Determine the current feature level.
    pub fn level(&self) -> Level {
        // Level 4: has actions
        if !self.data.actions.is_empty() {
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

    /// Configure the maximum allowed clock skew for future timestamps.
    ///
    /// Transactions with `now > server_time + max_clock_skew` will be rejected
    /// with `TimestampFuture` error. Set to 0 to disable future timestamp checking (default).
    ///
    /// Recommended value: 300 (5 minutes).
    pub fn set_max_clock_skew(&mut self, seconds: i64) {
        self.core_mut().max_clock_skew = seconds;
    }

    /// Get the current Data State (None if no actions).
    pub fn data_root(&self) -> Option<&DataRoot> {
        self.dr.as_ref()
    }

    /// Get the number of recorded actions.
    pub fn action_count(&self) -> usize {
        self.data.actions.len()
    }
}
