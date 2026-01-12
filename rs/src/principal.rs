//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphrpass protocol.

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::action::Action;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::state::{
    AuthState, DataState, HashAlg, KeyState, PrincipalRoot, PrincipalState, TransactionState,
    compute_as, compute_ds, compute_ks, compute_ps,
};
use crate::transaction::Transaction;

// ============================================================================
// AuthLedger
// ============================================================================

/// Auth ledger holding keys and transactions.
#[derive(Debug, Clone, Default)]
pub struct AuthLedger {
    /// Active keys (tmb b64 string → Key).
    pub keys: IndexMap<String, Key>,
    /// Revoked keys for historical verification.
    pub revoked: IndexMap<String, Key>,
    /// Signed transactions.
    pub transactions: Vec<Transaction>,
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
pub enum Level {
    /// Single static key.
    L1,
    /// Key replacement.
    L2,
    /// Multi-key.
    L3,
    /// Data layer (AAA).
    L4,
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

    /// Get number of active keys.
    pub fn active_key_count(&self) -> usize {
        self.auth.keys.len()
    }

    /// Determine the current feature level.
    pub fn level(&self) -> Level {
        // Level 4: has actions
        if !self.data.actions.is_empty() {
            return Level::L4;
        }
        // Level 3: multiple keys or transactions
        if self.auth.keys.len() > 1 || !self.auth.transactions.is_empty() {
            return Level::L3;
        }
        // Level 2 if any key/replace occurred (detected by Transaction history)
        // For now, single key with no transactions = Level 1
        Level::L1
    }

    // ========================================================================
    // Action recording (Level 4)
    // ========================================================================

    /// Record an action to the Data State (Level 4+).
    ///
    /// Returns the new Principal State after recording the action.
    /// The action signature must be verified before calling this.
    ///
    /// # Errors
    ///
    /// - `UnknownKey`: Signer's key not in current KS
    pub fn record_action(&mut self, action: Action) -> Result<&PrincipalState> {
        // Verify signer is an active key
        if !self.is_key_active(&action.signer) {
            return Err(Error::UnknownKey);
        }

        // Update signer's last_used timestamp
        self.update_last_used(&action.signer, action.now);

        // Record action
        self.data.actions.push(action);

        // Recompute DS
        let czds: Vec<&coz::Czd> = self.data.actions.iter().map(|a| &a.czd).collect();
        self.ds = compute_ds(&czds, None, self.hash_alg);

        // Recompute PS = H(sort(AS, DS?))
        self.ps = compute_ps(&self.auth_state, self.ds.as_ref(), None, self.hash_alg);

        Ok(&self.ps)
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
    /// Returns the new Auth State after applying the transaction.
    /// The transaction must have been verified before calling this.
    ///
    /// # Errors
    ///
    /// - `InvalidPrior`: Transaction's `pre` doesn't match current Auth State
    /// - `UnknownKey`: Signer key not in current KS
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `NoActiveKeys`: Would leave principal with no active keys
    pub fn apply_transaction(
        &mut self,
        tx: Transaction,
        new_key: Option<Key>,
    ) -> Result<&AuthState> {
        use crate::transaction::TransactionKind;

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
            TransactionKind::KeyAdd { pre, id } => {
                self.verify_pre(pre)?;
                let key = new_key.ok_or(Error::MalformedPayload)?;
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
                let key = new_key.ok_or(Error::MalformedPayload)?;
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

        // Record transaction and recompute state
        self.auth.transactions.push(tx);
        self.recompute_state();

        Ok(&self.auth_state)
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
    /// * `new_key` - New key to add (required for KeyAdd/KeyReplace)
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
        use crate::transaction::{Transaction, verify_signature};

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

        // Verify signature
        if !verify_signature(pay_json, sig, signer_key) {
            return Err(Error::InvalidSignature);
        }

        // Parse transaction
        let tx = Transaction::parse(&pay, czd)?;

        // Apply
        self.apply_transaction(tx, new_key)
    }

    /// Verify that `pre` matches current Auth State.
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
        use crate::state::compute_ts;

        // Recompute KS from active keys
        let thumbprints: Vec<&Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        self.ks = compute_ks(&thumbprints, None, self.hash_alg);

        // Recompute TS from transactions
        let czds: Vec<&coz::Czd> = self.auth.transactions.iter().map(|t| &t.czd).collect();
        self.ts = compute_ts(&czds, None, self.hash_alg);

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

    fn make_key_add_tx(pre: &AuthState, new_key: &Key, signer: &Thumbprint) -> Transaction {
        use coz::Czd;

        use crate::state::AuthState;
        use crate::transaction::{Transaction, TransactionKind};

        Transaction {
            kind: TransactionKind::KeyAdd {
                pre: AuthState(pre.as_cad().clone()),
                id: new_key.tmb.clone(),
            },
            signer: signer.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xAB; 32]),
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
        let czd = Czd::from_bytes(vec![0xCC; 32]);

        Action::from_pay(pay, czd).unwrap()
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
            kind: TransactionKind::KeyAdd {
                pre,
                id: key2.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 5000,
            czd: Czd::from_bytes(vec![0xBB; 32]),
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
