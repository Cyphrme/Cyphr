//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphrpass protocol.

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::action::Action;
use crate::commit::{Commit, PendingCommit};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::state::{
    AuthState, DataState, HashAlg, KeyState, PrincipalRoot, PrincipalState, TransactionState,
    compute_as, compute_ds, compute_ks, compute_ps,
};
use crate::transaction::VerifiedTransaction;

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
    /// Finalized commits (atomic transaction bundles).
    pub commits: Vec<Commit>,
    /// Pending commit being built (transitory state).
    pub pending: Option<PendingCommit>,
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
// Principal
// ============================================================================

/// A Cyphrpass Principal (self-sovereign identity).
///
/// Represents a single identity with:
/// - Permanent root (PR) set at genesis
/// - Evolving state (PS) as keys and transactions change
/// - Auth ledger tracking keys and transactions
#[derive(Debug, Clone)]
pub struct Principal {
    /// Principal Root - permanent, set at genesis.
    pr: PrincipalRoot,
    /// Current Principal State.
    ps: PrincipalState,
    /// Current Key State.
    ks: KeyState,
    /// Current Transaction State.
    ts: Option<TransactionState>,
    /// Current Auth State.
    auth_state: AuthState,
    /// Current Data State (Level 4+).
    ds: Option<DataState>,
    /// Auth ledger.
    auth: AuthLedger,
    /// Data ledger (Level 4+).
    data: DataLedger,
    /// Primary hash algorithm (from first key's alg).
    hash_alg: HashAlg,
    /// Latest timestamp seen (SPEC §14.1).
    /// Used to reject timestamps in the past.
    latest_timestamp: i64,
    /// Maximum allowed future timestamp (seconds from server time).
    /// Set to 0 to disable future timestamp checking.
    max_clock_skew: i64,
}

impl Principal {
    // ========================================================================
    // Genesis constructors
    // ========================================================================

    /// Create a principal with implicit genesis (single key).
    ///
    /// Per SPEC §3.2: "Identity emerges from first key possession"
    /// - `PR = PS = AS = KS = tmb` (fully promoted)
    ///
    /// This is the Level 1/2 genesis path.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedAlgorithm` if the key's algorithm is not recognized.
    pub fn implicit(key: Key) -> Result<Self> {
        let hash_alg = HashAlg::from_alg(&key.alg)?;
        let tmb_b64 = key.tmb.to_b64();

        // KS = tmb (single key promotes)
        let ks = compute_ks(&[&key.tmb], None, hash_alg);
        // AS = KS (no TS, promotes)
        let auth_state = compute_as(&ks, None, None, hash_alg);
        // PS = AS (no DS, promotes)
        let ps = compute_ps(&auth_state, None, None, hash_alg);
        // PR = first PS
        let pr = PrincipalRoot::from_initial(&ps);

        let mut keys = IndexMap::new();
        keys.insert(tmb_b64, key);

        Ok(Self {
            pr,
            ps,
            ks,
            ts: None,
            auth_state,
            ds: None,
            auth: AuthLedger {
                keys,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            latest_timestamp: 0,
            max_clock_skew: 0,
        })
    }

    /// Create a principal with explicit genesis (multiple keys).
    ///
    /// Per SPEC §3.2: Multi-key accounts require explicit genesis
    /// - `PR = H(sort(tmb₀, tmb₁, ...))`
    ///
    /// This is the Level 3+ genesis path.
    pub fn explicit(keys: Vec<Key>) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let hash_alg = HashAlg::from_alg(&keys[0].alg)?;

        // Collect thumbprints for KS computation
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let ks = compute_ks(&thumbprints, None, hash_alg);

        // AS = KS (no TS yet)
        let auth_state = compute_as(&ks, None, None, hash_alg);
        // PS = AS (no DS)
        let ps = compute_ps(&auth_state, None, None, hash_alg);
        // PR frozen at genesis
        let pr = PrincipalRoot::from_initial(&ps);

        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }

        Ok(Self {
            pr,
            ps,
            ks,
            ts: None,
            auth_state,
            ds: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            latest_timestamp: 0,
            max_clock_skew: 0,
        })
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
        pr: PrincipalRoot,
        auth_state: AuthState,
        keys: Vec<Key>,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let hash_alg = HashAlg::from_alg(&keys[0].alg)?;

        // Compute KS from provided keys
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let ks = compute_ks(&thumbprints, None, hash_alg);

        // PS = AS (no DS at checkpoint load)
        let ps = compute_ps(&auth_state, None, None, hash_alg);

        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }

        Ok(Self {
            pr,
            ps,
            ks,
            ts: None, // TS is implicit in checkpoint's AS
            auth_state,
            ds: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            hash_alg,
            latest_timestamp: 0,
            max_clock_skew: 0,
        })
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the Principal Root (permanent identifier).
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
    }

    /// Get the current Principal State.
    pub fn ps(&self) -> &PrincipalState {
        &self.ps
    }

    /// Get the current Auth State.
    pub fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }

    /// Get the current Key State.
    pub fn key_state(&self) -> &KeyState {
        &self.ks
    }

    /// Get the hash algorithm used by this principal.
    pub fn hash_alg(&self) -> HashAlg {
        self.hash_alg
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

    /// Get all transactions (across all commits).
    pub fn transactions(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.auth.commits.iter().flat_map(|c| c.transactions())
    }

    /// Get all finalized commits.
    pub fn commits(&self) -> impl Iterator<Item = &Commit> {
        self.auth.commits.iter()
    }

    /// Get the current pending commit, if any.
    pub fn current_commit(&self) -> Option<&PendingCommit> {
        self.auth.pending.as_ref()
    }

    /// Get the Transaction State of the last finalized commit.
    ///
    /// Returns `None` if no commits exist yet.
    pub fn current_ts(&self) -> Option<&TransactionState> {
        self.ts.as_ref()
    }

    /// Begin a new commit bundle.
    ///
    /// Per SPEC §4.2.1, transactions are grouped into atomic commits.
    /// Call this before adding transactions to a bundle, then call
    /// `finalize_commit()` after the last transaction.
    ///
    /// # Errors
    ///
    /// Returns `CommitInProgress` if a pending commit already exists.
    pub fn begin_commit(&mut self) -> Result<()> {
        if self.auth.pending.is_some() {
            return Err(Error::CommitInProgress);
        }
        self.auth.pending = Some(PendingCommit::new(self.hash_alg));
        Ok(())
    }

    /// Finalize the current pending commit.
    ///
    /// Moves the pending commit to the finalized commits list and
    /// recomputes all state digests.
    ///
    /// # Errors
    ///
    /// Returns `NoPendingCommit` if no commit is in progress.
    /// Returns `EmptyCommit` if the pending commit has no transactions.
    pub fn finalize_commit(&mut self) -> Result<&Commit> {
        let pending = self.auth.pending.take().ok_or(Error::NoPendingCommit)?;

        if pending.is_empty() {
            return Err(Error::EmptyCommit);
        }

        // Finalize with current state (will be accurate after recompute)
        let commit = pending
            .finalize(self.auth_state.clone(), self.ps.clone())
            .ok_or(Error::MissingFinalizationMarker)?;

        self.auth.commits.push(commit);
        self.recompute_state();

        // Return reference to the just-added commit
        Ok(self.auth.commits.last().expect("just pushed"))
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
    pub(crate) fn record_action(&mut self, action: Action) -> Result<&PrincipalState> {
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
        self.ds = compute_ds(&czds, None, self.hash_alg);

        // Recompute PS = H(sort(AS, DS?))
        self.ps = compute_ps(&self.auth_state, self.ds.as_ref(), None, self.hash_alg);

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
    ) -> Result<&PrincipalState> {
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
    pub fn data_state(&self) -> Option<&DataState> {
        self.ds.as_ref()
    }

    /// Get the number of recorded actions.
    pub fn action_count(&self) -> usize {
        self.data.actions.len()
    }

    // ========================================================================
    // Transaction application
    // ========================================================================

    /// Apply a verified transaction to mutate principal state.
    ///
    /// This is the safe API for applying transactions. The transaction must have
    /// been created through signature verification, which is enforced by the
    /// `VerifiedTransaction` type.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Transaction timestamp is older than latest seen
    /// - `TimestampFuture`: Transaction timestamp is too far in the future
    /// - `InvalidPrior`: Transaction's `pre` doesn't match current Auth State
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply_verified(
        &mut self,
        vtx: crate::transaction::VerifiedTransaction,
    ) -> Result<&AuthState> {
        self.apply_transaction_internal(vtx)
    }

    /// Apply a transaction without prior signature verification.
    ///
    /// This is internal-only. External code must use `verify_and_apply_transaction`
    /// or `apply_verified` which enforce signature verification.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Transaction timestamp is older than latest seen
    /// - `TimestampFuture`: Transaction timestamp is too far in the future
    /// - `InvalidPrior`: Transaction's `pre` doesn't match current Auth State
    /// - `UnknownKey`: Signer key not in current KS
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `NoActiveKeys`: Would leave principal with no active keys
    #[cfg(test)]
    pub(crate) fn apply_transaction(
        &mut self,
        tx: crate::transaction::Transaction,
        new_key: Option<Key>,
    ) -> Result<&AuthState> {
        use crate::transaction::VerifiedTransaction;
        let vtx = VerifiedTransaction::from_transaction_unsafe(tx, new_key);
        self.apply_transaction_internal(vtx)
    }

    /// Internal transaction application logic.
    fn apply_transaction_internal(
        &mut self,
        vtx: crate::transaction::VerifiedTransaction,
    ) -> Result<&AuthState> {
        use crate::transaction::TransactionKind;

        // Access the underlying Transaction via Deref
        let tx = &*vtx;

        // Validate timestamp is not in the past (SPEC §14.1)
        if tx.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        // Validate timestamp is not too far in the future (SPEC §14.1)
        if self.max_clock_skew > 0 {
            let server_time = current_time();
            if tx.now > server_time + self.max_clock_skew {
                return Err(Error::TimestampFuture);
            }
        }

        // Verify signer is an active key (except for self-revoke which is handled specially)
        if !matches!(&tx.kind, TransactionKind::SelfRevoke { .. })
            && !self.is_key_active(&tx.signer)
        {
            // Check if key exists but is revoked
            if self.auth.revoked.contains_key(&tx.signer.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        match &tx.kind {
            TransactionKind::KeyCreate { pre, id } => {
                self.verify_pre(pre)?;
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Check for duplicate key
                if self.auth.keys.contains_key(&id.to_b64()) {
                    return Err(Error::DuplicateKey);
                }
                self.add_key(key, tx.now);
            },
            TransactionKind::KeyDelete { pre, id } => {
                self.verify_pre(pre)?;
                self.remove_key(id)?;
            },
            TransactionKind::KeyReplace { pre, id } => {
                self.verify_pre(pre)?;
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Atomic swap: add new key first, then remove signer
                // This allows Level 2 single-key accounts to replace their key
                self.add_key(key, tx.now);
                // Use shift_remove directly to bypass NoActiveKeys check
                // (we just added a key, so this is safe)
                self.auth.keys.shift_remove(&tx.signer.to_b64());
            },
            TransactionKind::SelfRevoke { rvk } => {
                self.revoke_key(&tx.signer, *rvk, None)?;
            },
            TransactionKind::OtherRevoke { pre, id, rvk } => {
                self.verify_pre(pre)?;
                self.revoke_key(id, *rvk, Some(tx.signer.clone()))?;
            },
        }

        // Update signer's last_used timestamp
        self.update_last_used(&tx.signer, tx.now);

        // Update latest timestamp
        if tx.now > self.latest_timestamp {
            self.latest_timestamp = tx.now;
        }

        // Record transaction as single-tx commit and recompute state
        // TODO: Commit 2 will wire proper pending commit lifecycle
        self.wrap_as_commit(vtx);
        self.recompute_state();

        Ok(&self.auth_state)
    }

    /// Wrap a single transaction as a finalized commit.
    ///
    /// This is temporary scaffolding for backward compatibility during the
    /// commit model refactor. Commit 2 will wire the proper pending commit
    /// lifecycle with explicit begin_commit/finalize_commit calls.
    fn wrap_as_commit(&mut self, vtx: VerifiedTransaction) {
        use crate::state::compute_ts;

        // Compute TS for this single-tx commit
        let czds = [vtx.czd()];
        let ts = compute_ts(&czds, None, self.hash_alg)
            .expect("single transaction should always produce TS");

        // Create the commit with current state (will be recomputed after)
        let commit = Commit::new(vec![vtx], ts, self.auth_state.clone(), self.ps.clone());
        self.auth.commits.push(commit);
    }

    /// Verify signature and apply a transaction in one step.
    ///
    /// This is the primary method for processing incoming transactions.
    /// It verifies the signature against the signer's key, parses the
    /// transaction, and applies it atomically.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this transaction
    /// * `new_key` - New key to add (required for KeyCreate/KeyReplace)
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `MalformedPayload`: Missing required fields
    /// - `InvalidPrior`: `pre` doesn't match current AS
    /// - `NoActiveKeys`: Would leave principal with no keys
    pub fn verify_and_apply_transaction(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<Key>,
    ) -> Result<&AuthState> {
        use crate::transaction::verify_transaction;

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

        // Verify signature and parse transaction
        let vtx = verify_transaction(pay_json, sig, signer_key, czd, new_key)?;

        // Apply verified transaction
        self.apply_verified(vtx)
    }

    /// Verify that `pre` matches the expected prior state.
    ///
    /// Per SPEC §4.2.1, the `pre` reference depends on commit context:
    ///
    /// **Commit-level chaining** (first tx in commit):
    /// - `pre` MUST reference the previous commit's Auth State (AS)
    /// - For genesis commit, `pre` references Principal Root (PR)
    ///
    /// **Transaction-level chaining** (subsequent tx in commit):
    /// - `pre` MUST reference the previous transaction's `czd`
    /// - This ensures ordering within the commit bundle
    ///
    /// **Current implementation**: For backward compatibility during refactor,
    /// this currently validates against current AS only. Full dual-layer
    /// chaining will be implemented when the pending commit flow is wired.
    fn verify_pre(&self, pre: &AuthState) -> Result<()> {
        if self.auth_state.as_cad().as_bytes() != pre.as_cad().as_bytes() {
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

        // Safe to proceed - remove and revoke
        let mut key = self.auth.keys.shift_remove(&tmb_b64).unwrap();
        key.revocation = Some(Revocation { rvk, by });

        // Move to revoked set for historical verification
        self.auth.revoked.insert(tmb_b64, key);

        Ok(())
    }

    /// Update a key's last_used timestamp.
    ///
    /// Called after successful transaction or action signing.
    fn update_last_used(&mut self, tmb: &Thumbprint, timestamp: i64) {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.auth.keys.get_mut(&tmb_b64) {
            key.last_used = Some(timestamp);
        }
    }

    /// Recompute all state digests after mutation.
    fn recompute_state(&mut self) {
        // Recompute KS from active keys
        let thumbprints: Vec<&Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        self.ks = compute_ks(&thumbprints, None, self.hash_alg);

        // TS is from the latest commit (per-commit TS, not cumulative)
        self.ts = self.auth.commits.last().map(|c| c.ts().clone());

        // Recompute AS = H(sort(KS, TS?))
        self.auth_state = compute_as(&self.ks, self.ts.as_ref(), None, self.hash_alg);

        // Recompute PS = H(sort(AS, DS?)) - no DS yet
        self.ps = compute_ps(&self.auth_state, None, None, self.hash_alg);

        // PR never changes
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

    /// Create a dummy CozJson for test transactions.
    /// The payload content doesn't need to match the Transaction kind
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

        // Level 1: PR = PS = AS = KS = tmb
        assert_eq!(principal.pr().as_cad().as_bytes(), key.tmb.as_bytes());
        assert_eq!(principal.ps().as_cad().as_bytes(), key.tmb.as_bytes());
        assert_eq!(
            principal.auth_state().as_cad().as_bytes(),
            key.tmb.as_bytes()
        );
        assert_eq!(
            principal.key_state().as_cad().as_bytes(),
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

        // PR should NOT equal either single tmb (it's a hash)
        assert_ne!(principal.pr().as_cad().as_bytes(), key1.tmb.as_bytes());
        assert_ne!(principal.pr().as_cad().as_bytes(), key2.tmb.as_bytes());

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
    fn pr_is_immutable_across_reference() {
        let key = make_test_key(0xCC);
        let principal = Principal::implicit(key).unwrap();

        // PR should be the same as PS at genesis
        let pr_bytes = principal.pr().as_cad().as_bytes().to_vec();
        let ps_bytes = principal.ps().as_cad().as_bytes().to_vec();
        assert_eq!(pr_bytes, ps_bytes);
    }

    // ========================================================================
    // Transaction application tests
    // ========================================================================

    fn make_key_add_tx(
        pre: &AuthState,
        new_key: &Key,
        signer: &Thumbprint,
    ) -> crate::transaction::Transaction {
        use coz::Czd;
        use serde_json::json;

        use crate::state::AuthState;
        use crate::transaction::{Transaction, TransactionKind};

        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // Create dummy raw CozJson for test transactions
        let raw = coz::CozJson {
            pay: json!({
                "typ": "cyphr.me/key/add",
                "alg": "ES256",
                "now": 2000,
                "tmb": signer.to_b64(),
                "pre": Base64UrlUnpadded::encode_string(pre.as_cad().as_bytes()),
                "id": new_key.tmb.to_b64()
            }),
            sig: vec![0; 64],
        };

        Transaction {
            kind: TransactionKind::KeyCreate {
                pre: AuthState(pre.as_cad().clone()),
                id: new_key.tmb.clone(),
            },
            signer: signer.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xAB; 32]),
            raw,
            is_finalizer: false,
        }
    }

    #[test]
    fn apply_key_add_increases_key_count() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let pre = principal.auth_state().clone();
        let key2 = make_test_key(0x22);
        let tx = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction(tx, Some(key2.clone())).unwrap();

        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key2.tmb));
        assert_eq!(principal.level(), Level::L3);
    }

    #[test]
    fn apply_key_add_changes_state() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let old_as = principal.auth_state().as_cad().as_bytes().to_vec();
        let pre = principal.auth_state().clone();
        let key2 = make_test_key(0x22);
        let tx = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction(tx, Some(key2)).unwrap();

        let new_as = principal.auth_state().as_cad().as_bytes().to_vec();
        // Auth state must change after adding key
        assert_ne!(old_as, new_as);
    }

    #[test]
    fn apply_key_add_pre_mismatch_fails() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // Wrong pre value
        let wrong_pre = AuthState(coz::Cad::from_bytes(vec![0xFF; 32]));
        let key2 = make_test_key(0x22);
        let tx = make_key_add_tx(&wrong_pre, &key2, &key1.tmb);

        let result = principal.apply_transaction(tx, Some(key2));
        assert!(matches!(result, Err(Error::InvalidPrior)));
    }

    #[test]
    fn pr_unchanged_after_transaction() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let pr_before = principal.pr().as_cad().as_bytes().to_vec();
        let pre = principal.auth_state().clone();
        let key2 = make_test_key(0x22);
        let tx = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction(tx, Some(key2)).unwrap();

        let pr_after = principal.pr().as_cad().as_bytes().to_vec();
        // PR is permanent, never changes
        assert_eq!(pr_before, pr_after);
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
        assert!(principal.data_state().is_none());

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        assert_eq!(principal.level(), Level::L4);
        assert!(principal.data_state().is_some());
        assert_eq!(principal.action_count(), 1);
    }

    #[test]
    fn record_action_changes_ps() {
        let key = make_test_key(0xBB);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        let ps_before = principal.ps().as_cad().as_bytes().to_vec();

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        let ps_after = principal.ps().as_cad().as_bytes().to_vec();
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

        use crate::transaction::{Transaction, TransactionKind};

        let key = make_test_key(0xDD);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        // Level 1: single key, self-revoke should fail
        assert_eq!(principal.level(), Level::L1);

        let tx = Transaction {
            kind: TransactionKind::SelfRevoke { rvk: 2000 },
            signer: key.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xEE; 32]),
            raw: dummy_coz_json(),
            is_finalizer: false,
        };

        let result = principal.apply_transaction(tx, None);
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

        // Revoke key2 via other-revoke
        use coz::Czd;

        use crate::transaction::{Transaction, TransactionKind};

        let tx = Transaction {
            kind: TransactionKind::OtherRevoke {
                pre: principal.auth_state().clone(),
                id: key2.tmb.clone(),
                rvk: 2000,
            },
            signer: key1.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xFF; 32]),
            raw: dummy_coz_json(),
            is_finalizer: false,
        };

        principal.apply_transaction(tx, None).unwrap();

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

        let pre = principal.auth_state().clone();
        let mut key2 = make_test_key(0x22);
        key2.first_seen = 0; // Caller may not set this

        // Transaction has now=2000
        let tx = make_key_add_tx(&pre, &key2, &key1.tmb);
        assert_eq!(tx.now, 2000);

        principal.apply_transaction(tx, Some(key2.clone())).unwrap();

        // New key's first_seen should be set from tx.now
        let added_key = principal.get_key(&key2.tmb).unwrap();
        assert_eq!(added_key.first_seen, 2000);
    }

    // ========================================================================
    // Revoked key guard tests (C15)
    // ========================================================================

    #[test]
    fn revoked_key_in_revoked_set() {
        use coz::Czd;

        use crate::transaction::{Transaction, TransactionKind};

        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        // Revoke key2
        let tx = Transaction {
            kind: TransactionKind::OtherRevoke {
                pre: principal.auth_state().clone(),
                id: key2.tmb.clone(),
                rvk: 1500,
            },
            signer: key1.tmb.clone(),
            now: 1500,
            czd: Czd::from_bytes(vec![0xAA; 32]),
            raw: dummy_coz_json(),
            is_finalizer: false,
        };
        principal.apply_transaction(tx, None).unwrap();

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

        // Apply a key/add transaction with now=5000
        let pre = principal.auth_state().clone();
        let key2 = make_test_key(0x22);

        use coz::Czd;

        use crate::transaction::{Transaction, TransactionKind};
        let tx = Transaction {
            kind: TransactionKind::KeyCreate {
                pre,
                id: key2.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 5000,
            czd: Czd::from_bytes(vec![0xBB; 32]),
            raw: dummy_coz_json(),
            is_finalizer: false,
        };
        principal.apply_transaction(tx, Some(key2)).unwrap();

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
