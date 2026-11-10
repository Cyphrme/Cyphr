//! Key type with lifecycle tracking.

use coz::Thumbprint;

use crate::error::{Error, Result};

/// Revocation information for a key.
#[derive(Debug, Clone)]
pub struct Revocation {
    /// Revocation timestamp (SPEC `rvk` field).
    pub rvk: i64,
    /// Thumbprint of key that performed revocation (None = self-revoke).
    pub by: Option<Thumbprint>,
}

/// Cyphr key with lifecycle tracking.
///
/// Extends the Coz key concept with Cyphr-specific fields for
/// tracking when keys were added, last used, and revoked.
///
/// # Invariant
///
/// `tmb` is the thumbprint of (`alg`, `pub_key`). The fields are private
/// and every constructor establishes this, so no `Key` in existence can
/// pair one key's thumbprint with another key's public bytes. A signed pay
/// and every state root bind only the `tmb`; the public key travels
/// unsigned beside it, so without this invariant anyone able to supply the
/// sidecar could impersonate a thumbprint.
#[derive(Debug, Clone)]
pub struct Key {
    alg: coz::Alg,
    tmb: Thumbprint,
    pub_key: Vec<u8>,
    first_seen: i64,
    last_used: Option<i64>,
    revocation: Option<Revocation>,
    tag: Option<String>,
}

impl Key {
    /// Builds a key from a claimed `tmb`, verifying it is the thumbprint of
    /// (`alg`, `pub_key`). Use this where `tmb` arrives from outside
    /// (wire sidecars, storage, keystores).
    ///
    /// # Errors
    ///
    /// - `UnknownAlg`: `alg` is unknown
    /// - `TmbMismatch`: `tmb` is not the thumbprint of `pub_key` under `alg`
    pub fn new(alg: impl Into<String>, tmb: Thumbprint, pub_key: Vec<u8>) -> Result<Self> {
        let key = Self::from_pub_key(alg, pub_key)?;
        if key.tmb.as_bytes() != tmb.as_bytes() {
            return Err(Error::TmbMismatch);
        }
        Ok(key)
    }

    /// Builds a key from its public bytes, computing `tmb`.
    ///
    /// # Errors
    ///
    /// - `UnknownAlg`: `alg` is unknown or `pub_key` is malformed for it
    pub fn from_pub_key(alg: impl Into<String>, pub_key: Vec<u8>) -> Result<Self> {
        let alg = coz::Alg::from_str(&alg.into()).ok_or(Error::UnknownAlg)?;
        let tmb =
            coz::compute_thumbprint_for_alg(alg.name(), &pub_key).ok_or(Error::UnknownAlg)?;
        Ok(Self {
            alg,
            tmb,
            pub_key,
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: None,
        })
    }

    /// Sets the human-readable label.
    #[must_use]
    pub fn with_tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }

    /// Sets the time the key was first added.
    #[must_use]
    pub fn with_first_seen(mut self, first_seen: i64) -> Self {
        self.first_seen = first_seen;
        self
    }

    /// Marks the key revoked. Revocation never touches the tmb binding.
    #[must_use]
    pub fn with_revocation(mut self, revocation: Revocation) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// Algorithm identifier (e.g., "ES256").
    pub fn alg(&self) -> &str {
        self.alg.name()
    }

    /// The hash algorithm of the key's algorithm: the algorithm its
    /// thumbprint and the digests it signs are in.
    pub fn hash_alg(&self) -> crate::state::HashAlg {
        self.alg.hash_alg()
    }

    /// Key thumbprint.
    pub fn tmb(&self) -> &Thumbprint {
        &self.tmb
    }

    /// Public key bytes.
    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    /// When this key was first added to the principal.
    pub fn first_seen(&self) -> i64 {
        self.first_seen
    }

    /// When this key last signed a valid coz/action.
    pub fn last_used(&self) -> Option<i64> {
        self.last_used
    }

    /// Revocation info (None = active).
    pub fn revocation(&self) -> Option<&Revocation> {
        self.revocation.as_ref()
    }

    /// Optional human-readable label.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    pub(crate) fn set_first_seen(&mut self, first_seen: i64) {
        self.first_seen = first_seen;
    }

    pub(crate) fn set_last_used(&mut self, last_used: i64) {
        self.last_used = Some(last_used);
    }

    pub(crate) fn set_revocation(&mut self, revocation: Revocation) {
        self.revocation = Some(revocation);
    }

    /// Returns true if the key is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revocation.is_none()
    }

    /// Returns true if the key was active at the given timestamp.
    ///
    /// Critical for validating historical cozies.
    pub fn is_active_at(&self, timestamp: i64) -> bool {
        self.revocation.as_ref().is_none_or(|r| timestamp < r.rvk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(revocation: Option<Revocation>) -> Key {
        let mut key = Key::from_pub_key("ES256", vec![0u8; 64])
            .expect("ES256 key")
            .with_first_seen(1000);
        key.revocation = revocation;
        key
    }

    /// Backs SPEC 6.4: a key is active for every instant before its `rvk`.
    /// Unit: needs a revocation at a chosen `rvk` against arbitrary instants, which signed
    /// scenarios cannot dial.
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

    /// Backs SPEC 6.4: `now >= rvk` is not active (the boundary instant itself is dead).
    /// Unit: as above; the end to end consequence is `negative_vectors` and `key_auth`.
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
