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
        self.revocation.as_ref().is_none_or(|r| timestamp < r.rvk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(revocation: Option<Revocation>) -> Key {
        Key {
            alg: "ES256".to_string(),
            tmb: Thumbprint::from_bytes(vec![0u8; 32]),
            pub_key: vec![0u8; 64],
            first_seen: 1000,
            last_used: None,
            revocation,
            tag: None,
        }
    }

    #[test]
    fn is_active_no_revocation() {
        let key = make_key(None);
        assert!(key.is_active());
    }

    #[test]
    fn is_active_with_revocation() {
        let key = make_key(Some(Revocation {
            rvk: 2000,
            by: None,
        }));
        assert!(!key.is_active());
    }

    #[test]
    fn is_active_at_no_revocation() {
        let key = make_key(None);
        // Always active when not revoked
        assert!(key.is_active_at(0));
        assert!(key.is_active_at(1000));
        assert!(key.is_active_at(i64::MAX));
    }

    #[test]
    fn is_active_at_before_revocation() {
        let key = make_key(Some(Revocation {
            rvk: 2000,
            by: None,
        }));
        // Active before revocation time
        assert!(key.is_active_at(1999));
        assert!(key.is_active_at(0));
    }

    #[test]
    fn is_active_at_after_revocation() {
        let key = make_key(Some(Revocation {
            rvk: 2000,
            by: None,
        }));
        // Not active at or after revocation time (SPEC: now >= rvk is invalid)
        assert!(!key.is_active_at(2000));
        assert!(!key.is_active_at(2001));
    }
}
