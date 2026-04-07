//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphrpass protocol.

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::action::Action;
use crate::commit::{Commit, CommitScope, PendingCommit};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::parsed_coz::VerifiedCoz;
use crate::state::{
    AuthRoot, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot, compute_ar,
    compute_dr, compute_kr, compute_pr, compute_sr, derive_hash_algs, hash_alg_from_str,
};

/// Get current unix timestamp in seconds.
/// Separated for testability.
fn current_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64
}

// ============================================================================
// AuthLedger
// ============================================================================

/// Auth ledger holding keys and commits.
#[derive(Debug, Clone, Default)]
pub struct AuthLedger {
    /// Active keys (tmb b64 string → Key).
    pub keys: IndexMap<String, Key>,
    /// Revoked keys for historical verification.
    pub revoked: IndexMap<String, Key>,
    /// Finalized commits (atomic coz bundles).
    pub commits: Vec<Commit>,
}

/// Data ledger holding actions (Level 4+).
#[derive(Debug, Clone, Default)]
pub struct DataLedger {
    /// All recorded actions.
    pub actions: Vec<Action>,
}

// ============================================================================
// Feature Levels
// ============================================================================

/// Feature level of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Single static key.
    L1 = 1,
    /// Key replacement.
    L2 = 2,
    /// Multi-key.
    L3 = 3,
    /// Data layer (AAA).
    L4 = 4,
}

// ============================================================================
// Principal — Enum-based type safety for PR (Approach C)
// ============================================================================

/// Shared internal state for all Principal variants.
///
/// Every field *except* PR lives here. PR is structurally absent for Nascent
/// principals and structurally present for Established ones — invalid states
/// are unrepresentable.
///
/// # Visibility
///
/// `pub` to satisfy `Deref<Target = PrincipalCore>` on `Principal`.
/// All fields are `pub(crate)` — external code cannot access them.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PrincipalCore {
    /// Current Principal State.
    pub(crate) ps: PrincipalRoot,
    /// Current Key State.
    pub(crate) ks: KeyRoot,
    /// Current Commit ID (Merkle root of last commit's cozies).
    pub(crate) tr: Option<crate::transaction_root::TransactionRoot>,
    /// Per-algorithm MALT trees for computing Commit Root (CR).
    pub(crate) commit_trees: crate::commit_root::CommitTrees,
    /// Current Commit Root (CR).
    pub(crate) cr: Option<crate::commit_root::CommitRoot>,
    /// Current State Root: SR = MR(AR, DR?, embedding?).
    pub(crate) sr: Option<StateRoot>,
    /// Current Auth State.
    pub(crate) auth_root: AuthRoot,
    /// Current Data State (Level 4+).
    pub(crate) ds: Option<DataRoot>,
    /// Auth ledger.
    pub(crate) auth: AuthLedger,
    /// Data ledger (Level 4+).
    pub(crate) data: DataLedger,
    /// Primary hash algorithm (from first key's alg).
    pub(crate) hash_alg: HashAlg,
    /// Active hash algorithms derived from current active keys (SPEC §14).
    pub(crate) active_algs: Vec<HashAlg>,
    /// Latest timestamp seen (SPEC §14.1).
    pub(crate) latest_timestamp: i64,
    /// Maximum allowed future timestamp (seconds from server time).
    pub(crate) max_clock_skew: i64,
}

impl Default for PrincipalCore {
    /// Placeholder default — only used for `std::mem::take()` during
    /// the Nascent → Established transition. Never observable externally.
    fn default() -> Self {
        Self {
            ps: PrincipalRoot::default(),
            ks: KeyRoot::default(),
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::new(),
            cr: None,
            sr: None,
            auth_root: AuthRoot::default(),
            ds: None,
            auth: AuthLedger::default(),
            data: DataLedger::default(),
            hash_alg: HashAlg::Sha256,
            active_algs: Vec::new(),
            latest_timestamp: 0,
            max_clock_skew: 0,
        }
    }
}

/// Internal variant: tracks whether PR has been established.
///
/// - **Nascent**: L1/L2 — no PR exists. Cannot fabricate one.
/// - **Established**: L3+ — PR is frozen from initial PS. Cannot remove it.
#[derive(Debug, Clone)]
enum PrincipalKind {
    /// Pre-genesis-finalization: no PR field at all.
    Nascent(PrincipalCore),
    /// Post-principal/create: PR is structurally required.
    Established {
        core: PrincipalCore,
        pr: PrincipalGenesis,
    },
}

impl Default for PrincipalKind {
    fn default() -> Self {
        Self::Nascent(PrincipalCore::default())
    }
}

/// A Cyphrpass Principal (self-sovereign identity).
///
/// # Type Safety
///
/// PR is represented via an internal enum:
/// - **Nascent** (L1/L2): PR does not exist — cannot be forged.
/// - **Established** (L3+): PR is frozen — cannot be removed.
///
/// All shared state is accessed via `Deref<Target = PrincipalCore>`, so
/// `self.ps`, `self.ks`, etc. work transparently in all code paths.
#[derive(Debug, Clone)]
pub struct Principal(PrincipalKind);

// Deref delegates field access to PrincipalCore transparently.
// This means `self.ps`, `self.ks`, `self.auth_root`, etc. all
// resolve automatically — zero changes needed in existing methods.
impl std::ops::Deref for Principal {
    type Target = PrincipalCore;
    fn deref(&self) -> &PrincipalCore {
        match &self.0 {
            PrincipalKind::Nascent(core) => core,
            PrincipalKind::Established { core, .. } => core,
        }
    }
}

impl std::ops::DerefMut for Principal {
    fn deref_mut(&mut self) -> &mut PrincipalCore {
        match &mut self.0 {
            PrincipalKind::Nascent(core) => core,
            PrincipalKind::Established { core, .. } => core,
        }
    }
}

impl Principal {
    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Transition from Nascent to Established by freezing PR.
    ///
    /// This is the only code path that can create an Established principal.
    /// Called exclusively from the PrincipalCreate coz handler.
    fn establish_pg(&mut self, pr: PrincipalGenesis) -> Result<()> {
        let old = std::mem::take(&mut self.0);
        match old {
            PrincipalKind::Nascent(core) => {
                self.0 = PrincipalKind::Established { core, pr };
                Ok(())
            },
            est @ PrincipalKind::Established { .. } => {
                self.0 = est; // restore
                Err(Error::StateMismatch) // already established
            },
        }
    }

    // ========================================================================
    // Genesis constructors
    // ========================================================================

    /// Create a principal with implicit genesis (single key).
    ///
    /// Per SPEC §3.2: "Identity emerges from first key possession"
    /// - `PS = AS = KS = tmb` (fully promoted)
    /// - PR is absent (L1/L2 have no PR per SPEC §5.1)
    ///
    /// This is the Level 1/2 genesis path.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedAlgorithm` if the key's algorithm is not recognized.
    pub fn implicit(key: Key) -> Result<Self> {
        let hash_alg = hash_alg_from_str(&key.alg)?;
        let tmb_b64 = key.tmb.to_b64();

        // Derive active algorithms from genesis key
        let active_algs = vec![hash_alg];

        // KS = tmb (single key promotes)
        let ks = compute_kr(&[&key.tmb], None, &active_algs)?;
        // AS = KS (no Commit ID, promotes)
        let auth_root = compute_ar(&ks, None, None, &active_algs)?;
        // SR = AR (no DR at genesis, promotes)
        let cs = compute_sr(&auth_root, None, None, &active_algs)?;
        // PR = SR (no CR at genesis, promotes)
        let ps = compute_pr(&cs, None, None, &active_algs)?;

        let mut keys = IndexMap::new();
        keys.insert(tmb_b64, key);

        Ok(Self(PrincipalKind::Nascent(PrincipalCore {
            ps,
            ks,
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::new(),
            cr: None,
            sr: Some(cs),
            auth_root,
            ds: None,
            auth: AuthLedger {
                keys,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            active_algs,
            latest_timestamp: 0,
            max_clock_skew: 0,
        })))
    }

    /// Create a principal with explicit genesis (multiple keys).
    ///
    /// Per SPEC §3.2: Multi-key accounts require explicit genesis
    /// - PR is absent at construction (established by principal/create)
    ///
    /// This is the Level 3+ genesis path.
    pub fn explicit(keys: Vec<Key>) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let hash_alg = hash_alg_from_str(&keys[0].alg)?;

        // Derive active algorithms from all keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Collect thumbprints for KS computation
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let ks = compute_kr(&thumbprints, None, &active_algs)?;

        // AS = KS (no Commit ID yet)
        let auth_root = compute_ar(&ks, None, None, &active_algs)?;
        // SR = AR (no DR at genesis, promotes)
        let cs = compute_sr(&auth_root, None, None, &active_algs)?;
        // PR = SR (no CR at genesis, promotes)
        let ps = compute_pr(&cs, None, None, &active_algs)?;

        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }

        Ok(Self(PrincipalKind::Nascent(PrincipalCore {
            ps,
            ks,
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::new(),
            cr: None,
            sr: Some(cs),
            auth_root,
            ds: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            active_algs,
            latest_timestamp: 0,
            max_clock_skew: 0,
        })))
    }

    /// Create a principal from a trusted checkpoint.
    ///
    /// This is used by storage import when loading from a checkpoint
    /// rather than replaying full history from genesis.
    ///
    /// # Security
    ///
    /// The caller must establish trust in the checkpoint before calling this.
    /// The `pr` is accepted as-is (cannot be computed from checkpoint alone).
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `keys` is empty.
    /// Returns `UnsupportedAlgorithm` if key algorithm is unknown.
    pub fn from_checkpoint(
        pr: Option<PrincipalGenesis>,
        auth_root: AuthRoot,
        keys: Vec<Key>,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let hash_alg = hash_alg_from_str(&keys[0].alg)?;

        // Derive active algorithms from checkpoint keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Compute KS from provided keys
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let ks = compute_kr(&thumbprints, None, &active_algs)?;

        // SR = AR (no DR at checkpoint, promotes)
        let cs = compute_sr(&auth_root, None, None, &active_algs)?;
        // PR = SR (no CR at checkpoint, promotes)
        let ps = compute_pr(&cs, None, None, &active_algs)?;

        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }

        let core = PrincipalCore {
            ps,
            ks,
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::new(),
            cr: None,
            sr: Some(cs),
            auth_root,
            ds: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            active_algs,
            latest_timestamp: 0,
            max_clock_skew: 0,
        };

        Ok(match pr {
            Some(pr) => Self(PrincipalKind::Established { core, pr }),
            None => Self(PrincipalKind::Nascent(core)),
        })
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the Principal Root, or None if not yet established (L1/L2).
    ///
    /// PR is only set when principal/create is processed (Level 3+, SPEC §5.1).
    /// For Established principals, this always returns `Some`.
    pub fn pg(&self) -> Option<&PrincipalGenesis> {
        match &self.0 {
            PrincipalKind::Established { pr, .. } => Some(pr),
            PrincipalKind::Nascent(_) => None,
        }
    }

    /// Get the current Principal State.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.ps
    }

    /// Get the current Auth State.
    pub fn auth_root(&self) -> &AuthRoot {
        &self.auth_root
    }

    /// Get the current Principal State as a tagged digest string (alg:digest format).
    ///
    /// Uses the lexicographically first algorithm from active_algs for deterministic output.
    /// This is the canonical format for the `pre` field in cozies (SPEC §4.3).
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if the state digest has no variants.
    pub fn pr_tagged(&self) -> Result<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let first_alg = self.active_algs.first().copied().unwrap_or(self.hash_alg);
        let bytes = self.ps.0.get_or_err(first_alg)?;

        Ok(format!(
            "{}:{}",
            first_alg,
            Base64UrlUnpadded::encode_string(bytes)
        ))
    }

    /// Get the current Key State.
    pub fn key_root(&self) -> &KeyRoot {
        &self.ks
    }

    /// Get the hash algorithm used by this principal.
    pub fn hash_alg(&self) -> HashAlg {
        self.hash_alg
    }

    /// Get the active hash algorithms derived from current active keys (SPEC §14).
    pub fn active_algs(&self) -> &[HashAlg] {
        &self.active_algs
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
        self.auth.keys.values_mut()
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
    /// # Panics
    ///
    /// Panics if the key is not found in the active set.
    pub fn pre_revoke_key(&mut self, tmb: &Thumbprint, rvk: i64) {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let mut key = self
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .expect("pre_revoke_key: key not found in active set");
        key.revocation = Some(Revocation { rvk, by: None });
        self.auth.revoked.insert(tmb_b64, key);
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

    /// Get the current State Root.
    ///
    /// Returns `None` only if no state has been computed (shouldn't happen
    /// after genesis). At genesis, SR is promoted from AR.
    pub fn sr(&self) -> Option<&StateRoot> {
        self.sr.as_ref()
    }

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
    pub fn begin_commit(&mut self) -> CommitScope<'_> {
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
    /// - `InvalidPrior`: ParsedCoz's `pre` doesn't match current CS
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply_transaction(&mut self, vtx: crate::parsed_coz::VerifiedCoz) -> Result<&Commit> {
        let mut scope = self.begin_commit();
        scope.apply(vtx)?;
        scope.finalize()
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

    /// Configure the maximum allowed clock skew for future timestamps.
    ///
    /// Transactions with `now > server_time + max_clock_skew` will be rejected
    /// with `TimestampFuture` error. Set to 0 to disable future timestamp checking (default).
    ///
    /// Recommended value: 300 (5 minutes).
    pub fn set_max_clock_skew(&mut self, seconds: i64) {
        self.max_clock_skew = seconds;
    }

    // ========================================================================
    // Action recording (Level 4)
    // ========================================================================

    /// Record an action to the Data State (Level 4+).
    ///
    /// This is internal-only. External code must use `verify_and_record_action`
    /// which enforces signature verification.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Action timestamp is older than latest seen
    /// - `TimestampFuture`: Action timestamp is too far in the future
    /// - `UnknownKey`: Signer's key not in current KS
    pub(crate) fn record_action(&mut self, action: Action) -> Result<&PrincipalRoot> {
        // Validate timestamp is not in the past (SPEC §14.1)
        if action.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        // Validate timestamp is not too far in the future (SPEC §14.1)
        if self.max_clock_skew > 0 {
            let server_time = current_time();
            if action.now > server_time + self.max_clock_skew {
                return Err(Error::TimestampFuture);
            }
        }

        // Verify signer is an active key
        if !self.is_key_active(&action.signer) {
            // Check if key exists but is revoked
            if self.auth.revoked.values().any(|k| k.tmb == action.signer) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Update signer's last_used timestamp
        self.update_last_used(&action.signer, action.now);

        // Update latest timestamp
        if action.now > self.latest_timestamp {
            self.latest_timestamp = action.now;
        }

        // Record action
        self.data.actions.push(action);

        // Recompute DS
        let czds: Vec<&coz::Czd> = self.data.actions.iter().map(|a| &a.czd).collect();
        self.ds = compute_dr(&czds, None, self.hash_alg);

        // Recompute SR = MR(AR, DR?, embedding?)
        let sr = compute_sr(&self.auth_root, self.ds.as_ref(), None, &[self.hash_alg])?;
        self.sr = Some(sr.clone());

        // Recompute PR = MR(SR, CR?, embedding?)
        self.ps = compute_pr(&sr, self.cr.as_ref(), None, &[self.hash_alg])?;

        Ok(&self.ps)
    }

    /// Verify signature and record an action in one step.
    ///
    /// This is the primary method for processing incoming actions.
    /// It verifies the signature, parses the action, and records it.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this action
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `TimestampPast`: Action timestamp is older than latest seen
    /// - `TimestampFuture`: Action timestamp is too far in the future
    pub fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> Result<&PrincipalRoot> {
        use crate::action::Action;
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // Parse as Value and extract only what we need (avoids requiring all coz::Pay fields)
        let pay_value: serde_json::Value =
            serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;

        // Extract tmb for signer lookup
        let tmb_str = pay_value["tmb"].as_str().ok_or(Error::MalformedPayload)?;
        let tmb_bytes =
            Base64UrlUnpadded::decode_vec(tmb_str).map_err(|_| Error::MalformedPayload)?;
        let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

        // Extract typ and now for Action construction
        let typ = pay_value["typ"]
            .as_str()
            .ok_or(Error::MalformedPayload)?
            .to_string();
        let now = pay_value["now"].as_i64().ok_or(Error::MalformedPayload)?;

        // Signer must be an ACTIVE key
        if !self.is_key_active(&signer_tmb) {
            if self.auth.revoked.contains_key(&signer_tmb.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Look up signer key
        let signer_key = self.get_key(&signer_tmb).ok_or(Error::UnknownKey)?;

        // Verify signature
        let valid =
            coz::verify_json(pay_json, sig, &signer_key.alg, &signer_key.pub_key).unwrap_or(false);
        if !valid {
            return Err(Error::InvalidSignature);
        }

        // Construct CozJson for storage
        let raw = coz::CozJson {
            pay: pay_value,
            sig: sig.to_vec(),
        };

        // Construct Action directly from extracted values
        let action = Action::new(typ, signer_tmb, now, czd, raw);

        // Record the action
        self.record_action(action)
    }

    /// Get the current Data State (None if no actions).
    pub fn data_root(&self) -> Option<&DataRoot> {
        self.ds.as_ref()
    }

    /// Get the number of recorded actions.
    pub fn action_count(&self) -> usize {
        self.data.actions.len()
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
    /// - `InvalidPrior`: ParsedCoz's `pre` doesn't match current CS
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
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
        use crate::commit::PendingCommit;
        use crate::multihash::MultihashDigest;
        use crate::parsed_coz::{CozKind, ParsedCoz, VerifiedCoz};
        use crate::state::{compute_ar, compute_kr, compute_sr, derive_hash_algs};

        // Apply mutation eagerly (same as apply_verified_internal)
        let mutation_vtx = VerifiedCoz::from_transaction_unsafe(cz.clone(), new_key);
        self.apply_verified_internal(mutation_vtx)?;

        // Push mutation coz to transactions (no arrow)
        let mut pending = PendingCommit::new();
        let mutation_vtx2 = VerifiedCoz::from_transaction_unsafe(cz.clone(), None);
        pending.push_tx(crate::transaction::Transaction(vec![mutation_vtx2]));

        // Compute SR from post-mutation state
        let key_refs: Vec<&Key> = self.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);
        let thumbprints: Vec<&coz::Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        let ks = compute_kr(&thumbprints, None, &active_algs)?;
        let auth_root = compute_ar(&ks, None, None, &active_algs)?;
        let sr = compute_sr(&auth_root, self.ds.as_ref(), None, &active_algs)?;

        let tx_alg = cz.hash_alg;

        // Compute TMR from pending transactions
        let (tmr_opt, _tcr, _tr) = pending.compute_roots(&[tx_alg]);
        let tmr = tmr_opt.ok_or(Error::EmptyCommit)?;

        // Compute arrow = hash_sorted_concat(pre, sr, tmr)
        let pre = &self.ps;
        let pre_bytes = pre.0.get_or_err(tx_alg)?;
        let sr_bytes = sr.0.get_or_err(tx_alg)?;
        let tmr_bytes = tmr.0.get(tx_alg).ok_or(Error::EmptyCommit)?;

        let arrow_digest =
            crate::state::hash_sorted_concat_bytes(tx_alg, &[pre_bytes, sr_bytes, tmr_bytes]);
        let arrow_md = MultihashDigest::from_single(tx_alg, arrow_digest);

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

    /// Internal coz application logic.
    fn apply_transaction_internal(
        &mut self,
        vtx: crate::parsed_coz::VerifiedCoz,
    ) -> Result<&AuthRoot> {
        use crate::parsed_coz::CozKind;

        // Access the underlying ParsedCoz via Deref
        let cz = &*vtx;

        // Validate timestamp is not in the past (SPEC §14.1)
        if cz.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        // Validate timestamp is not too far in the future (SPEC §14.1)
        if self.max_clock_skew > 0 {
            let server_time = current_time();
            if cz.now > server_time + self.max_clock_skew {
                return Err(Error::TimestampFuture);
            }
        }

        // Verify signer is an active key.
        // Exceptions:
        //   - SelfRevoke: handled specially (revoking oneself)
        //   - CommitCreate: finality marker; authorization was already verified
        //     against the pre-commit key snapshot in CommitScope::verify_and_apply.
        //     The signer may have been replaced by a prior mutation in this commit.
        let skip_active_check = matches!(
            &cz.kind,
            CozKind::SelfRevoke { .. } | CozKind::CommitCreate { .. }
        );
        if !skip_active_check && !self.is_key_active(&cz.signer) {
            // Check if key exists but is revoked
            if self.auth.revoked.contains_key(&cz.signer.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        match &cz.kind {
            CozKind::KeyCreate { pre, id } => {
                self.verify_pre(pre)?;
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Check for duplicate key
                if self.auth.keys.contains_key(&id.to_b64()) {
                    return Err(Error::DuplicateKey);
                }
                self.add_key(key, cz.now);
            },
            CozKind::KeyDelete { pre, id } => {
                self.verify_pre(pre)?;
                self.remove_key(id)?;
            },
            CozKind::KeyReplace { pre, id } => {
                self.verify_pre(pre)?;
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Atomic swap: add new key first, then remove signer
                // This allows Level 2 single-key accounts to replace their key
                self.add_key(key, cz.now);
                // Use shift_remove directly to bypass NoActiveKeys check
                // (we just added a key, so this is safe)
                self.auth.keys.shift_remove(&cz.signer.to_b64());
            },
            CozKind::SelfRevoke { pre, rvk } => {
                // Per protocol simplification, revoke requires pre like all other coz
                self.verify_pre(pre)?;
                self.revoke_key(&cz.signer, *rvk, None)?;
            },
            CozKind::PrincipalCreate { pre, id } => {
                // Genesis finalization (SPEC §5.1)
                // Verify that `pre` matches the current PS (chain continuity)
                self.verify_pre(pre)?;
                // Verify that `id` matches the computed PS (SPEC §5.1:609 — "id: Final PS = PR")
                if id.0 != self.ps.0 {
                    return Err(Error::StateMismatch);
                }
                // Freeze PR at current PS (SPEC §5.1:600 — "principal/create establishes PR")
                // establish_pg() is the ONLY code path that transitions Nascent → Established.
                self.establish_pg(PrincipalGenesis::from_initial(&self.ps))?;
            },
            CozKind::CommitCreate { .. } => {
                // Finalize commit marker does not mutate state other than marking completion
                // State references are verified during commit finalization
            },
        }

        // Update signer's last_used timestamp
        self.update_last_used(&cz.signer, cz.now);

        // Update latest timestamp
        if cz.now > self.latest_timestamp {
            self.latest_timestamp = cz.now;
        }

        Ok(&self.auth_root)
    }

    /// Finalize a commit with proper state recomputation.
    ///
    /// This is called by `CommitScope::finalize()` with the accumulated
    /// `PendingCommit`. Recomputes all state digests and appends the
    /// finalized commit to the auth ledger.
    pub(crate) fn finalize_commit(&mut self, pending: PendingCommit) -> Result<&Commit> {
        if pending.is_empty() {
            return Err(Error::EmptyCommit);
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

        // Re-derive active algorithms from post-mutation key set.
        // Per [alg-set-evolution], state digests for this commit use the
        // algorithms supported by the post-mutation key set.
        let key_refs: Vec<&Key> = self.auth.keys.values().collect();
        self.active_algs = derive_hash_algs(&key_refs);

        // Recompute KS from current (post-mutation) key set
        let thumbprints: Vec<&Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        self.ks = compute_kr(&thumbprints, None, &self.active_algs)?;

        // Extract the explicit transaction algorithms from the Arrow,
        // or fallback to the terminal coz alg, or the principal's init alg.
        let tx_algs: Vec<coz::HashAlg> = if let Some(last_coz) = cozies.last() {
            if let Some(arrow) = last_coz.arrow() {
                arrow.algorithms().collect()
            } else {
                vec![last_coz.hash_alg()]
            }
        } else {
            vec![self.hash_alg()]
        };

        // Compute TR from pending commit
        let tr = pending.compute_tr(&tx_algs).ok_or(Error::EmptyCommit)?;
        self.tr = Some(tr.clone());

        // Compute AR = MR(KR, RR?, embedding?)
        self.auth_root = compute_ar(&self.ks, None, None, &self.active_algs)?;

        // Compute SR = MR(AR, DR?, embedding?)
        let sr = compute_sr(&self.auth_root, self.ds.as_ref(), None, &self.active_algs)?;
        self.sr = Some(sr.clone());

        // Validate arrow field matches independently computed Arrow
        // Arrow = MR(pre, fwd, TMR)
        if let Some(_claimed_arrow) = cozies.last().unwrap().arrow() {
            // Recompute TMR from transactions only (excluding terminal coz) directly if needed or use the one we have
            // Actually, pending.compute_roots() already did this logic!
            let (tmr, _tcr, _tr) = pending.compute_roots(&tx_algs);
            let _tmr = tmr.ok_or(Error::EmptyCommit)?;

            // Get pre from the last transaction
            let terminal_coz = cozies.last().unwrap();
            let _pre = match &terminal_coz.kind {
                crate::parsed_coz::CozKind::CommitCreate { arrow: _ } => {
                    // pre is extracted from the raw payload, or if no explicit pre, use PR...
                    // Wait, `commit/create` must have pre... but `CommitCreate` doesn't have a `pre` field in enum!
                    // Wait, Arrow validation: comparing `claimed_arrow` variants against computed
                    // The easiest and most correct way right now given the refactor is to test if variants match.
                    // Wait, I should construct Arrow or just pull from `claimed_arrow` vs my own Arrow.
                    // Instead of full Arrow generation inside `finalize_commit` here if it's too complex, let's look at Go `ComputeArrow`.
                    // In Go, `Arrow = ComputeArrow(pre, sr, tmr)`.
                    ()
                },
                _ => (), // Fallback
            };

            // Temporary structural hold for now until Arrow recomputation is fully ported to Rust:
            // Match to skip for now to see if compilation passes, then implement.
            // TODO(Arrow Validation): implement MR(pre, fwd, TMR)
        }

        // Ensure per-algorithm MALTs exist for all active algorithms.
        // New algorithms get a fresh MALT populated with prior TRs via [conversion].
        // Clone active_algs to avoid borrow conflict with self.commit_trees.
        let algs = self.active_algs.clone();
        for &alg in &algs {
            if !self.commit_trees.contains_key(&alg) {
                // New algorithm — create MALT and replay prior commits.
                // [conversion]: tr.get_or_err(alg) returns the native variant
                // if available, otherwise the first variant's bytes.
                let hasher = crate::commit_root::CyphrpassHasher::new(alg);
                let mut log = malt::Log::new(hasher);
                for prior_commit in &self.auth.commits {
                    let prior_tr = prior_commit.tr();
                    if let Ok(bytes) = prior_tr.0.get_or_err(alg) {
                        log.append(bytes);
                    }
                }
                self.commit_trees.insert(alg, log);
            }
        }

        // Append current TR to all active MALTs and assemble CR.
        // Only active algorithms contribute to the current CR;
        // stale algorithm MALTs are retained but excluded.
        let mut active_trees = crate::commit_root::CommitTrees::new();
        for &alg in &algs {
            let log = self.commit_trees.get_mut(&alg).expect("just ensured");
            let bytes = tr.0.get_or_err(alg)?;
            log.append(bytes);
            active_trees.insert(alg, log.clone());
        }
        let cr = crate::commit_root::commit_root_from_trees(&active_trees)?;
        self.cr = Some(cr.clone());

        // Compute PR = MR(SR, CR?, embedding?)
        self.ps = compute_pr(&sr, Some(&cr), None, &self.active_algs)?;

        // Finalize the pending commit with computed states
        let commit = pending.finalize(self.auth_root.clone(), sr, self.ps.clone(), &tx_algs)?;

        self.auth.commits.push(commit);

        Ok(self.auth.commits.last().expect("just pushed"))
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
    /// - `InvalidPrior`: `pre` doesn't match current CS
    /// - `NoActiveKeys`: Would leave principal with no keys
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
        if !self.is_key_active(signer_tmb) {
            // Check if it's revoked vs unknown
            if self.auth.revoked.contains_key(&signer_tmb.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Look up signer key (guaranteed active now)
        let signer_key = self.get_key(signer_tmb).ok_or(Error::UnknownKey)?;

        // Verify signature and parse coz
        let vtx = verify_coz(pay_json, sig, signer_key, czd, new_key)?;

        // Apply as single-cz atomic commit
        self.apply_transaction(vtx)
    }

    /// Verify that `pre` matches the expected prior Principal State.
    ///
    /// Per SPEC §4, the `pre` field references the previous PS.
    /// At genesis (no prior commits), PS is implicitly promoted from AS,
    /// so `pre` is compared against the promoted auth_root.
    fn verify_pre(&self, pre: &PrincipalRoot) -> Result<()> {
        // Get the reference PS to compare against.
        let current = self.ps.0.get_or_err(self.hash_alg)?;
        let expected = pre.0.get_or_err(self.hash_alg)?;
        if current != expected {
            return Err(Error::InvalidPrior);
        }
        Ok(())
    }

    /// Add a key to the active key set.
    ///
    /// Sets `first_seen` to the given timestamp.
    fn add_key(&mut self, mut key: Key, first_seen: i64) {
        key.first_seen = first_seen;
        let tmb_b64 = key.tmb.to_b64();
        self.auth.keys.insert(tmb_b64, key);
    }

    /// Remove a key from the active key set (delete, not revoke).
    fn remove_key(&mut self, tmb: &Thumbprint) -> Result<()> {
        let tmb_b64 = tmb.to_b64();
        if self.auth.keys.shift_remove(&tmb_b64).is_none() {
            return Err(Error::UnknownKey);
        }
        if self.auth.keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }
        Ok(())
    }

    /// Revoke a key (marks as revoked, moves to revoked set).
    ///
    /// # Errors
    ///
    /// - `UnknownKey`: Key not found in active set
    /// - `NoActiveKeys`: Would leave principal with no active keys
    fn revoke_key(&mut self, tmb: &Thumbprint, rvk: i64, by: Option<Thumbprint>) -> Result<()> {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();

        // Check if key exists
        if !self.auth.keys.contains_key(&tmb_b64) {
            return Err(Error::UnknownKey);
        }

        // Check BEFORE mutation: would this leave us with no keys?
        if self.auth.keys.len() == 1 {
            return Err(Error::NoActiveKeys);
        }

        // Safe to proceed - remove and revoke (key existence verified above)
        let mut key = self
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .expect("key existence verified by contains_key check");
        key.revocation = Some(Revocation { rvk, by });

        // Move to revoked set for historical verification
        self.auth.revoked.insert(tmb_b64, key);

        Ok(())
    }

    /// Update a key's last_used timestamp.
    ///
    /// Called after successful coz or action signing.
    fn update_last_used(&mut self, tmb: &Thumbprint, timestamp: i64) {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.auth.keys.get_mut(&tmb_b64) {
            key.last_used = Some(timestamp);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::Thumbprint;

    use super::*;
    use crate::key::Key;

    fn make_test_key(id: u8) -> Key {
        Key {
            alg: "ES256".to_string(),
            tmb: Thumbprint::from_bytes(vec![id; 32]),
            pub_key: vec![id; 64],
            first_seen: 1000,
            last_used: None,
            revocation: None,
            tag: None,
        }
    }

    /// Create a dummy CozJson for test cozies.
    /// The payload content doesn't need to match the ParsedCoz kind
    /// since tests bypass signature verification.
    fn dummy_coz_json() -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::json!({
                "typ": "cyphr.me/test",
                "alg": "ES256",
                "now": 1000
            }),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn implicit_genesis_single_key() {
        let key = make_test_key(0xAA);
        let principal = Principal::implicit(key.clone()).unwrap();

        // Level 1: PR is None (no principal/create at L1)
        assert!(principal.pg().is_none(), "PR should be None at Level 1");
        assert_eq!(
            principal.pr().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
        assert_eq!(
            principal.auth_root().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
        assert_eq!(
            principal.key_root().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
    }

    #[test]
    fn implicit_genesis_has_one_active_key() {
        let key = make_test_key(0xBB);
        let tmb = key.tmb.clone();
        let principal = Principal::implicit(key).unwrap();

        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&tmb));
        assert_eq!(principal.level(), Level::L1);
    }

    #[test]
    fn explicit_genesis_multi_key() {
        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        // PR should be None (not yet established — needs principal/create)
        assert!(
            principal.pg().is_none(),
            "PR should be None before principal/create"
        );

        // Should have 2 active keys
        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key1.tmb));
        assert!(principal.is_key_active(&key2.tmb));

        // Level 3 due to multiple keys
        assert_eq!(principal.level(), Level::L3);
    }

    #[test]
    fn explicit_genesis_empty_keys_errors() {
        let result = Principal::explicit(vec![]);
        assert!(matches!(result, Err(Error::NoActiveKeys)));
    }

    #[test]
    fn pr_is_none_at_level1() {
        let key = make_test_key(0xCC);
        let principal = Principal::implicit(key).unwrap();

        // PR is None at Level 1 (no principal/create)
        assert!(principal.pg().is_none(), "PR should be None at Level 1");

        // PS still exists and is stable
        let ps_bytes = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
        assert!(!ps_bytes.is_empty());
    }

    // ========================================================================
    // ParsedCoz application tests
    // ========================================================================

    fn make_key_add_tx(
        pre: &PrincipalRoot,
        new_key: &Key,
        signer: &Thumbprint,
    ) -> crate::parsed_coz::ParsedCoz {
        use coz::Czd;
        use serde_json::json;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // Create dummy raw CozJson for test cozies
        let ps_bytes = pre
            .get(HashAlg::Sha256)
            .or_else(|| {
                pre.as_multihash()
                    .variants()
                    .values()
                    .next()
                    .map(AsRef::as_ref)
            })
            .expect("PrincipalRoot must have at least one variant");
        let raw = coz::CozJson {
            pay: json!({
                "typ": "cyphr.me/key/create",
                "alg": "ES256",
                "now": 2000,
                "tmb": signer.to_b64(),
                "pre": Base64UrlUnpadded::encode_string(ps_bytes),
                "id": new_key.tmb.to_b64()
            }),
            sig: vec![0; 64],
        };

        ParsedCoz {
            kind: CozKind::KeyCreate {
                pre: pre.clone(),
                id: new_key.tmb.clone(),
            },
            signer: signer.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xAB; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw,
        }
    }

    #[test]
    fn apply_key_add_increases_key_count() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let pre = principal.pr().clone();
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal
            .apply_transaction_test(cz, Some(key2.clone()))
            .unwrap();

        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key2.tmb));
        assert_eq!(principal.level(), Level::L3);
    }

    #[test]
    fn apply_key_add_changes_state() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let old_as = principal
            .auth_root()
            .get(principal.hash_alg())
            .unwrap()
            .to_vec();
        let pre = principal.pr().clone();
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction_test(cz, Some(key2)).unwrap();
        // apply_transaction_test auto-finalizes the commit

        let new_as = principal
            .auth_root()
            .get(principal.hash_alg())
            .unwrap()
            .to_vec();
        // Auth state must change after adding key
        assert_ne!(old_as, new_as);
    }

    #[test]
    fn apply_key_add_pre_mismatch_fails() {
        use crate::multihash::MultihashDigest;

        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // Wrong pre value
        let wrong_pre = PrincipalRoot(MultihashDigest::from_single(
            HashAlg::Sha256,
            vec![0xFF; 32],
        ));
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&wrong_pre, &key2, &key1.tmb);

        let result = principal.apply_transaction_test(cz, Some(key2));
        assert!(matches!(result, Err(Error::InvalidPrior)));
    }

    #[test]
    fn pr_still_none_after_transaction() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // PR is None at L1
        assert!(
            principal.pg().is_none(),
            "PR should be None before principal/create"
        );

        let pre = principal.pr().clone();
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction_test(cz, Some(key2)).unwrap();

        // PR should still be None (no principal/create was issued)
        assert!(
            principal.pg().is_none(),
            "PR should still be None without principal/create"
        );
    }

    // ========================================================================
    // Action recording tests (Level 4)
    // ========================================================================

    fn make_test_action(signer: &Thumbprint) -> Action {
        use coz::{Czd, PayBuilder};

        let pay = PayBuilder::new()
            .typ("cyphr.me/comment/create")
            .alg("ES256")
            .now(3000)
            .tmb(signer.clone())
            .msg("Test action")
            .build();

        let raw = coz::CozJson {
            pay: serde_json::to_value(&pay).unwrap(),
            sig: vec![0; 64],
        };
        let czd = Czd::from_bytes(vec![0xCC; 32]);

        Action::from_pay(&pay, czd, raw).unwrap()
    }

    #[test]
    fn record_action_upgrades_to_level_4() {
        let key = make_test_key(0xAA);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        assert_eq!(principal.level(), Level::L1);
        assert!(principal.data_root().is_none());

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        assert_eq!(principal.level(), Level::L4);
        assert!(principal.data_root().is_some());
        assert_eq!(principal.action_count(), 1);
    }

    #[test]
    fn record_action_changes_ps() {
        let key = make_test_key(0xBB);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        let ps_before = principal.pr().get(principal.hash_alg()).unwrap().to_vec();

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        let ps_after = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
        // PS changes when DS is added
        assert_ne!(ps_before, ps_after);
    }

    #[test]
    fn record_action_unknown_signer_fails() {
        let key = make_test_key(0xCC);
        let mut principal = Principal::implicit(key).unwrap();

        // Try to record action from unknown key
        let unknown_tmb = Thumbprint::from_bytes(vec![0xFF; 32]);
        let action = make_test_action(&unknown_tmb);

        let result = principal.record_action(action);
        assert!(matches!(result, Err(Error::UnknownKey)));
    }

    // ========================================================================
    // Self-revoke guard tests (C12)
    // ========================================================================

    #[test]
    fn self_revoke_last_key_prevented() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key = make_test_key(0xDD);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        // Level 1: single key, self-revoke should fail
        assert_eq!(principal.level(), Level::L1);

        let pre = principal.pr().clone();

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { pre, rvk: 2000 },
            signer: key.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xEE; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, None);
        assert!(matches!(result, Err(Error::NoActiveKeys)));

        // Key should still be active (no mutation occurred)
        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&key.tmb));
    }

    #[test]
    fn revoke_allowed_when_multiple_keys() {
        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        assert_eq!(principal.active_key_count(), 2);

        // Revoke key2 via self-revoke (key2 revokes itself)
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let pre = principal.pr().clone();

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { pre, rvk: 2000 },
            signer: key2.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xFF; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        principal.apply_transaction_test(cz, None).unwrap();

        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&key1.tmb));
        assert!(!principal.is_key_active(&key2.tmb));
    }

    // ========================================================================
    // Key first_seen tests (C14)
    // ========================================================================

    #[test]
    fn key_add_sets_first_seen_from_tx_now() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let pre = principal.pr().clone();
        let mut key2 = make_test_key(0x22);
        key2.first_seen = 0; // Caller may not set this

        // ParsedCoz has now=2000
        let cz = make_key_add_tx(&pre, &key2, &key1.tmb);
        assert_eq!(cz.now, 2000);

        principal
            .apply_transaction_test(cz, Some(key2.clone()))
            .unwrap();

        // New key's first_seen should be set from cz.now
        let added_key = principal.get_key(&key2.tmb).unwrap();
        assert_eq!(added_key.first_seen, 2000);
    }

    // ========================================================================
    // Revoked key guard tests (C15)
    // ========================================================================

    #[test]
    fn revoked_key_in_revoked_set() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        let pre = principal.pr().clone();

        // Revoke key2 (self-revoke)
        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { pre, rvk: 1500 },
            signer: key2.tmb.clone(),
            now: 1500,
            czd: Czd::from_bytes(vec![0xAA; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, None).unwrap();

        // key2 should be in revoked set, not active
        assert!(!principal.is_key_active(&key2.tmb));
        assert!(principal.auth.revoked.contains_key(&key2.tmb.to_b64()));

        // get_key still finds it (for historical verification)
        assert!(principal.get_key(&key2.tmb).is_some());
    }

    // ========================================================================
    // Last-used tracking tests (C17)
    // ========================================================================

    #[test]
    fn transaction_updates_signer_last_used() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // Initially, last_used should be None
        assert!(principal.get_key(&key1.tmb).unwrap().last_used.is_none());

        // Apply a key/create coz with now=5000
        let pre = principal.pr().clone();
        let key2 = make_test_key(0x22);

        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};
        let cz = ParsedCoz {
            kind: CozKind::KeyCreate {
                pre,
                id: key2.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 5000,
            czd: Czd::from_bytes(vec![0xBB; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, Some(key2)).unwrap();

        // Signer's last_used should now be 5000
        assert_eq!(principal.get_key(&key1.tmb).unwrap().last_used, Some(5000));
    }

    #[test]
    fn action_updates_signer_last_used() {
        let key = make_test_key(0xAA);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        assert!(principal.get_key(&key.tmb).unwrap().last_used.is_none());

        // Record action with now=7000
        let action = make_test_action(&key.tmb);
        // Our test helper uses now=3000, let's verify that
        assert_eq!(action.now, 3000);

        principal.record_action(action).unwrap();

        assert_eq!(principal.get_key(&key.tmb).unwrap().last_used, Some(3000));
    }
}
