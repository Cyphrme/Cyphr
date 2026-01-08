//! Key type with lifecycle tracking.

use coz::Thumbprint;

/// Revocation information for a key.
#[derive(Debug, Clone)]
pub struct Revocation {
    /// Revocation timestamp (SPEC `rvk` field).
    pub rvk: i64,
    /// Thumbprint of key that performed revocation (None = self-revoke).
    pub by: Option<Thumbprint>,
}

/// Cyphrpass key with lifecycle tracking.
///
/// Extends the Coz key concept with Cyphrpass-specific fields for
/// tracking when keys were added, last used, and revoked.
#[derive(Debug, Clone)]
pub struct Key {
    /// Algorithm identifier (e.g., "ES256").
    pub alg: String,
    /// Key thumbprint.
    pub tmb: Thumbprint,
    /// Public key bytes.
    pub pub_key: Vec<u8>,
    /// When this key was first added to the principal.
    pub first_seen: i64,
    /// When this key last signed a valid transaction/action.
    pub last_used: Option<i64>,
    /// Revocation info (None = active).
    pub revocation: Option<Revocation>,
    /// Optional human-readable label.
    pub tag: Option<String>,
}

impl Key {
    /// Returns true if the key is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revocation.is_none()
    }

    /// Returns true if the key was active at the given timestamp.
    ///
    /// Critical for validating historical transactions.
    pub fn is_active_at(&self, timestamp: i64) -> bool {
        self.revocation.as_ref().map_or(true, |r| timestamp < r.rvk)
    }
}
