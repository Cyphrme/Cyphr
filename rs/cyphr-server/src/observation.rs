//! The durable, server-local global key death-set (SPEC.md §6.4).
//!
//! A witness that accepts a self-signed naked `key/revoke` coz records the
//! revoked key's thumbprint *here*, deliberately not on any principal's chain
//! and not in the rebuildable index:
//!
//! - A naked revoke mutates no PR (SPEC §6.4): the principal's chain is untouched, so the chain is
//!   the wrong home.
//! - The index is a derived projection a reindex rebuilds from blobs (root `AGENTS.md` I1): a death
//!   record kept there would be silently wiped by the next reindex, which is exactly the durability
//!   the acceptance suite pins against.
//!
//! So this is independent, durable, server-local truth: its own fjall
//! database, opened beside the blob store and the index, keyed by the revoked
//! key's thumbprint ALONE. Death is global by thumbprint -- one slot per key,
//! no principal scoping -- so the key is refused for every capability and
//! every principal that holds it.

use std::path::Path;

use coz::Thumbprint;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

/// Failures from the death-set store. A store failure is server
/// infrastructure breaking, never a client error.
#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    /// The underlying fjall store failed.
    #[error("death-set store backend: {0}")]
    Backend(String),
    /// A `spawn_blocking` task failed to join.
    #[error("death-set store task join: {0}")]
    Join(String),
    /// Serializing a death record failed.
    #[error("death-set serialize: {0}")]
    Serialize(String),
}

fn backend(e: fjall::Error) -> ObservationError {
    ObservationError::Backend(e.to_string())
}

/// A durable server-local set of naked-revoked (dead) keys, backed by a
/// dedicated fjall database and keyed by thumbprint.
pub struct ObservationStore {
    /// The backing database. Held so the keyspace outlives it, and used to
    /// force a synchronous journal fsync after a death is recorded (fjall's
    /// per-insert durability is only `PersistMode::Buffer`).
    db: Database,
    dead_keys: Keyspace,
}

impl ObservationStore {
    /// Open or create the death-set store at `path`, owning a dedicated
    /// database (separate from the blob store and the index, so its failure
    /// domain is independent of theirs and a reindex cannot wipe it).
    pub fn open(path: &Path) -> Result<Self, ObservationError> {
        let db = Database::builder(path).open().map_err(backend)?;
        let dead_keys = db
            .keyspace("observations", KeyspaceCreateOptions::default)
            .map_err(backend)?;
        Ok(Self { db, dead_keys })
    }

    /// Record `tmb` as dead, retaining `coz` (the revoke as received) as the
    /// value so the claim can be surfaced later.
    ///
    /// Keyed on the thumbprint alone, so it is idempotent by construction: a
    /// re-revoke of an already-dead key is a no-op (see the short-circuit
    /// below) and changes nothing observable.
    ///
    /// The insert is followed by a synchronous journal fsync
    /// (`PersistMode::SyncAll`) before returning: fjall's default per-insert
    /// durability is only `PersistMode::Buffer`, which leaves the write in OS
    /// buffers, so a crash before the next flush could lose a death record the
    /// caller was already told was recorded. Fsyncing here makes the `recorded`
    /// acknowledgement honest under a power loss, at the cost of one fsync per
    /// *first* revoke of a key -- acceptable for a rare security event.
    ///
    /// A key already dead short-circuits to a read-only `contains_key` before
    /// touching the write path: since a re-revoke changes nothing observable
    /// (the key was already refused everywhere), the redundant insert and its
    /// fsync would only be amplification for whoever calls this -- a revoke is
    /// idempotent and pre-signed replays are accepted, so a cheap repeated
    /// POST would otherwise force one synchronous disk fsync each time.
    pub async fn record(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let value =
            serde_json::to_vec(&coz).map_err(|e| ObservationError::Serialize(e.to_string()))?;
        let dead_keys = self.dead_keys.clone();
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            if dead_keys.contains_key(&key).map_err(backend)? {
                return Ok(());
            }
            dead_keys.insert(key, value).map_err(backend)?;
            db.persist(PersistMode::SyncAll).map_err(backend)
        })
        .await
        .map_err(|e| ObservationError::Join(e.to_string()))?
    }

    /// Whether `tmb` is dead (carries a naked-revoke record). A true here
    /// refuses the key for every capability, even though it may still be
    /// active on-chain.
    pub async fn is_dead(&self, tmb: &Thumbprint) -> Result<bool, ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let dead_keys = self.dead_keys.clone();
        tokio::task::spawn_blocking(move || dead_keys.contains_key(&key).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))?
    }
}
