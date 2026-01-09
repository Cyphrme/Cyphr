//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphrpass protocol.

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::key::Key;
use crate::state::{
    AuthState, HashAlg, KeyState, PrincipalRoot, PrincipalState, TransactionState, compute_as,
    compute_ks, compute_ps,
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
    /// Auth ledger.
    auth: AuthLedger,
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
    pub fn implicit(key: Key) -> Self {
        let hash_alg = HashAlg::from_alg(&key.alg);
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

        Self {
            pr,
            ps,
            ks,
            ts: None,
            auth_state,
            auth: AuthLedger {
                keys,
                ..Default::default()
            },
            hash_alg,
        }
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

        let hash_alg = HashAlg::from_alg(&keys[0].alg);

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
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
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
        // Level 4 requires data layer (not yet implemented)
        // Level 3 requires multiple keys or transactions
        if self.auth.keys.len() > 1 || !self.auth.transactions.is_empty() {
            return Level::L3;
        }
        // Level 2 if any key/replace occurred (detected by Transaction history)
        // For now, single key with no transactions = Level 1
        Level::L1
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
    /// - `KeyNotFound`: Referenced key doesn't exist
    /// - `NoActiveKeys`: Would leave principal with no active keys
    pub fn apply_transaction(
        &mut self,
        tx: Transaction,
        new_key: Option<Key>,
    ) -> Result<&AuthState> {
        use crate::transaction::TransactionKind;

        match &tx.kind {
            TransactionKind::KeyAdd { pre, id } => {
                self.verify_pre(pre)?;
                let key = new_key.ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                self.add_key(key);
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
                // Remove signer, add new key
                self.remove_key(&tx.signer)?;
                self.add_key(key);
            },
            TransactionKind::SelfRevoke { rvk } => {
                self.revoke_key(&tx.signer, *rvk, None)?;
            },
            TransactionKind::OtherRevoke { pre, id, rvk } => {
                self.verify_pre(pre)?;
                self.revoke_key(id, *rvk, Some(tx.signer.clone()))?;
            },
        }

        // Record transaction and recompute state
        self.auth.transactions.push(tx);
        self.recompute_state();

        Ok(&self.auth_state)
    }

    /// Verify that `pre` matches current Auth State.
    fn verify_pre(&self, pre: &AuthState) -> Result<()> {
        if self.auth_state.as_cad().as_bytes() != pre.as_cad().as_bytes() {
            return Err(Error::InvalidPrior);
        }
        Ok(())
    }

    /// Add a key to the active key set.
    fn add_key(&mut self, key: Key) {
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
    fn revoke_key(&mut self, tmb: &Thumbprint, rvk: i64, by: Option<Thumbprint>) -> Result<()> {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let mut key = self
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .ok_or(Error::UnknownKey)?;

        // Set revocation
        key.revocation = Some(Revocation { rvk, by });

        // Move to revoked set for historical verification
        self.auth.revoked.insert(tmb_b64, key);

        // Can't leave principal with no keys
        if self.auth.keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        Ok(())
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
        let principal = Principal::implicit(key.clone());

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
        let principal = Principal::implicit(key);

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
        let principal = Principal::implicit(key);

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
        let mut principal = Principal::implicit(key1.clone());

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
        let mut principal = Principal::implicit(key1.clone());

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
        let mut principal = Principal::implicit(key1.clone());

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
        let mut principal = Principal::implicit(key1.clone());

        let pr_before = principal.pr().as_cad().as_bytes().to_vec();
        let pre = principal.auth_state().clone();
        let key2 = make_test_key(0x22);
        let tx = make_key_add_tx(&pre, &key2, &key1.tmb);

        principal.apply_transaction(tx, Some(key2)).unwrap();

        let pr_after = principal.pr().as_cad().as_bytes().to_vec();
        // PR is permanent, never changes
        assert_eq!(pr_before, pr_after);
    }
}
