//! Witness registration store and per-principal state logic (SPEC §13.5.1).

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::AppError;

/// Maximum number of active registered witnesses per principal (N1.6 bound).
pub const MAX_WITNESSES_PER_PRINCIPAL: usize = 10;

/// Proof that a signer may mutate a principal's witness set (SPEC §13.5.1:
/// the principal signs its witness registrations).
///
/// Parse, don't validate: the field is private and the only constructors
/// require the evidence itself — either the signer IS the principal
/// (a not-yet-resident principal is managed only by itself), or the
/// signer's key is active in the resident principal's key set. No
/// `witness_id` shape participates: "this witness names my key" was never
/// evidence that the signer may register for the principal. Mutating store
/// operations consume the proof, so no future call site can reach them
/// without having run the authorization parse.
#[derive(Debug)]
pub struct RegistrationAuthority(());

impl RegistrationAuthority {
    /// Direction A: a not-yet-resident principal is managed only by
    /// itself — the signer's thumbprint must BE the principal identifier.
    pub fn self_signer(principal_id: &str, signer_tmb: &str) -> Option<Self> {
        (principal_id == signer_tmb).then_some(Self(()))
    }

    /// A resident principal is managed by its active keys only.
    pub fn active_key<S: eml::Storage>(
        principal: &cyphr::Principal<S>,
        signer: &coz::Thumbprint,
    ) -> Option<Self> {
        principal.is_key_active(signer).then_some(Self(()))
    }
}

/// Per-principal witness state.
#[derive(Debug, Clone, Default)]
pub struct PrincipalRegistrationState {
    /// Authorized key thumbprints (base64url) for this principal.
    pub authorized_keys: Vec<String>,
    /// Currently active witness IDs / PGs (e.g. `SHA-256:...`).
    pub active_witnesses: Vec<String>,
    /// Unix timestamp (seconds) of the most recent update.
    pub last_updated: i64,
}

/// Thread-safe store for witness registrations across principals.
#[derive(Debug, Default)]
pub struct RegistrationStore {
    state: RwLock<HashMap<String, PrincipalRegistrationState>>,
}

impl RegistrationStore {
    /// Construct a new empty `RegistrationStore`.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
        }
    }

    /// Check if authorized keys have been established for `principal_id`.
    pub fn has_authorized_keys(&self, principal_id: &str) -> bool {
        let map = self.state.read().unwrap_or_else(|e| e.into_inner());
        map.get(principal_id)
            .is_some_and(|entry| !entry.authorized_keys.is_empty())
    }

    /// Check if a signer thumbprint `signer_tmb` is authorized for `principal_id`.
    pub fn is_key_authorized(&self, principal_id: &str, signer_tmb: &str) -> bool {
        let map = self.state.read().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get(principal_id) {
            if entry.authorized_keys.is_empty() {
                true
            } else {
                entry.authorized_keys.iter().any(|k| k == signer_tmb)
            }
        } else {
            true
        }
    }

    /// Register a witness for `principal_id`.
    ///
    /// Returns `Err(AppError::bad_request)` if capacity (10 witnesses) is reached.
    pub fn register_witness(
        &self,
        _authority: RegistrationAuthority,
        principal_id: &str,
        witness_id: &str,
        timestamp: i64,
    ) -> Result<PrincipalRegistrationState, AppError> {
        let mut map = self
            .state
            .write()
            .map_err(|_| AppError::internal("registration store lock poisoned"))?;

        let entry = map.entry(principal_id.to_string()).or_default();

        if entry.active_witnesses.iter().any(|w| w == witness_id) {
            entry.last_updated = timestamp;
            return Ok(entry.clone());
        }

        if entry.active_witnesses.len() >= MAX_WITNESSES_PER_PRINCIPAL {
            return Err(AppError::bad_request("witness capacity limit reached"));
        }

        entry.active_witnesses.push(witness_id.to_string());
        entry.last_updated = timestamp;
        Ok(entry.clone())
    }

    /// Revoke (mark inactive) a witness for `principal_id`.
    pub fn revoke_witness(
        &self,
        _authority: RegistrationAuthority,
        principal_id: &str,
        witness_id: &str,
        timestamp: i64,
    ) -> Result<PrincipalRegistrationState, AppError> {
        let mut map = self
            .state
            .write()
            .map_err(|_| AppError::internal("registration store lock poisoned"))?;

        let entry = map.entry(principal_id.to_string()).or_default();
        entry.active_witnesses.retain(|w| w != witness_id);
        entry.last_updated = timestamp;
        Ok(entry.clone())
    }

    /// Get active witnesses and last updated timestamp for `principal_id`.
    pub fn get_witnesses(&self, principal_id: &str) -> (Vec<String>, i64) {
        let map = self.state.read().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get(principal_id) {
            (entry.active_witnesses.clone(), entry.last_updated)
        } else {
            (Vec::new(), 0)
        }
    }
}
