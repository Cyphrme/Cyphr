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

/// Keyspace and key under which a dedicated fjall store records its format
/// version, as decimal text.
const META_KEYSPACE: &str = "meta";
const VERSION_KEY: &str = "format-version";

/// The format version of the death set and the admission spent set. A store
/// with no recorded version predates versions and is v1 (same layout).
pub(crate) const STORE_FORMAT_VERSION: u32 = 1;

/// A dedicated store's sync has failed: the store is closed to writes
/// until the process restarts ([`SyncLatch`]).
#[derive(Debug)]
pub(crate) struct DurabilityLost(pub(crate) String);

/// Fails a dedicated fjall store closed on a failed sync, as the engine
/// does for the record ([`cyphr_storage::engine::EngineError::DurabilityLost`]).
///
/// fjall poisons its database on a failed write but not on a failed
/// `persist`, and a sync that fails can drop the dirty pages it covered, so
/// a later sync may succeed over them (fsyncgate). From the first failure
/// every write is refused until a restart replays what reached the disk.
/// Syncs run one at a time, so a write queued behind the failing one finds
/// the latch set instead of reporting success over pages that are gone.
#[derive(Default)]
pub(crate) struct SyncLatch {
    lost: std::sync::atomic::AtomicBool,
    one_sync: std::sync::Mutex<()>,
}

impl SyncLatch {
    /// `Err` once a sync has failed. Checked before a write stores
    /// anything, so a failed store adds nothing.
    pub(crate) fn writable(&self) -> Result<(), DurabilityLost> {
        if self.lost.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(DurabilityLost("an earlier sync of the store failed".into()));
        }
        Ok(())
    }

    /// Run `sync`; if it fails, latch the store closed.
    pub(crate) fn sync(
        &self,
        sync: impl FnOnce() -> Result<(), fjall::Error>,
    ) -> Result<(), DurabilityLost> {
        // The mutex guards no data; a panicked holder left nothing to repair.
        let _one_sync = self.one_sync.lock().unwrap_or_else(|p| p.into_inner());
        self.writable()?;
        sync().map_err(|e| {
            self.lost.store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::error!(error = %e, "store sync failed; refusing writes until restart");
            DurabilityLost(e.to_string())
        })
    }
}

/// Why a store's recorded format version could not be accepted.
#[derive(Debug)]
pub(crate) enum StampError {
    /// fjall failed reading or writing the record.
    Backend(String),
    /// The record is not a decimal number.
    NotANumber(String),
    /// The store states a version this build does not read.
    Unsupported { found: u64 },
}

/// Check the format version recorded in `db`'s meta keyspace, stamping
/// [`STORE_FORMAT_VERSION`] when none is recorded (a store from before
/// versions is v1). Called on open, before any data keyspace is read, so a
/// store this build cannot interpret is never mis-decoded.
pub(crate) fn check_store_version(db: &Database) -> Result<(), StampError> {
    let backend = |e: fjall::Error| StampError::Backend(e.to_string());
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .map_err(backend)?;
    match meta.get(VERSION_KEY).map_err(backend)? {
        Some(raw) => {
            let text = String::from_utf8_lossy(&raw);
            let found: u64 = text
                .trim()
                .parse()
                .map_err(|_| StampError::NotANumber(text.into_owned()))?;
            if found == u64::from(STORE_FORMAT_VERSION) {
                Ok(())
            } else {
                Err(StampError::Unsupported { found })
            }
        },
        None => {
            meta.insert(VERSION_KEY, STORE_FORMAT_VERSION.to_string())
                .map_err(backend)?;
            db.persist(PersistMode::SyncAll).map_err(backend)
        },
    }
}

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
    /// A sync of the store failed; it refuses every write until restart.
    #[error("death-set store durability lost: {0}")]
    DurabilityLost(String),
    /// The store records a format version this build does not read. Nothing
    /// was read from it: a mis-decoded death set would un-revoke keys.
    #[error("death set format version {found} is not the supported {supported}")]
    UnsupportedVersion { found: u64, supported: u32 },
    /// The death set already holds the operator's ceiling of keys
    /// (`[limits] max_dead_keys`): a refusal of the new record, not a fault.
    #[error("death set is full ({ceiling} keys)")]
    Full { ceiling: u64 },
}

impl From<DurabilityLost> for ObservationError {
    fn from(e: DurabilityLost) -> Self {
        Self::DurabilityLost(e.0)
    }
}

impl From<StampError> for ObservationError {
    fn from(e: StampError) -> Self {
        match e {
            StampError::Backend(m) => Self::Backend(m),
            StampError::NotANumber(t) => {
                Self::Backend(format!("recorded format version is not a number: {t:?}"))
            },
            StampError::Unsupported { found } => Self::UnsupportedVersion {
                found,
                supported: STORE_FORMAT_VERSION,
            },
        }
    }
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
    /// How many keys the death set holds, guarded so the count and
    /// the insert are one step.
    dead_count: std::sync::Arc<std::sync::Mutex<u64>>,
    /// Closes the store to writes after a failed sync.
    latch: std::sync::Arc<SyncLatch>,
    /// The most keys the death set may hold ([`Self::with_ceiling`]).
    ceiling: u64,
    /// Held across a revoke's ceiling check and both writes, so concurrent
    /// revokes cannot each pass the check and overshoot the ceiling.
    revoke_gate: tokio::sync::Mutex<()>,
}

impl ObservationStore {
    /// Open or create the death-set store at `path`, owning a dedicated
    /// database (separate from the blob store and the index, so its failure
    /// domain is independent of theirs and a reindex cannot wipe it).
    pub fn open(path: &Path) -> Result<Self, ObservationError> {
        let db = Database::builder(path).open().map_err(backend)?;
        check_store_version(&db)?;
        let dead_keys = db
            .keyspace("observations", KeyspaceCreateOptions::default)
            .map_err(backend)?;
        let mut count = 0u64;
        for entry in dead_keys.iter() {
            entry.key().map_err(backend)?;
            count += 1;
        }
        Ok(Self {
            db,
            dead_keys,
            dead_count: std::sync::Arc::new(std::sync::Mutex::new(count)),
            latch: std::sync::Arc::default(),
            ceiling: u64::MAX,
            revoke_gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Serialize a revoke's ceiling check and its writes. Revokes are rare,
    /// so one gate costs nothing and makes the ceiling exact for unheld keys.
    pub async fn revoke_gate(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.revoke_gate.lock().await
    }

    /// Bound the death set to `ceiling` keys for [`Self::check_room`]. A
    /// naked revoke needs no prior knowledge of its key (a Level 1 key
    /// signs nothing a peer could have seen, SPEC 6.4), so revokes of unseen
    /// keys are bounded by this operator quota; past it a new unheld key is
    /// refused [`ObservationError::Full`], while the revoke of a key the
    /// server holds is still recorded (the caller decides, see
    /// [`crate::revoke::record_everywhere`]).
    #[must_use]
    pub fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = ceiling;
        self
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
    /// One revoke stands per key, the first this store accepted: a revoke
    /// of a key already dead short-circuits before the write path, so a
    /// repeated POST forces no fsync and never grows the set. The engine
    /// keeps its own first revoke, and only the engine's receipt time is a
    /// key's cutoff (#203). Every path writes the engine first and this set
    /// second ([`crate::revoke::record_everywhere`]), so two revokes of one
    /// key arriving concurrently can still leave each store holding a
    /// different one: both are verified revokes of the key, and the one
    /// served here need not be the one whose receipt set the engine's
    /// cutoff.
    ///
    /// The ceiling is not enforced here: the caller settles it first
    /// ([`Self::check_room`]), because a key the server holds must be
    /// recorded past it (SPEC 6.4).
    pub async fn record(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        self.insert(tmb, coz).await
    }

    async fn insert(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let value =
            serde_json::to_vec(&coz).map_err(|e| ObservationError::Serialize(e.to_string()))?;
        let dead_keys = self.dead_keys.clone();
        let db = self.db.clone();
        let dead_count = self.dead_count.clone();
        let latch = self.latch.clone();
        tokio::task::spawn_blocking(move || {
            if dead_keys.contains_key(&key).map_err(backend)? {
                return Ok(());
            }
            latch.writable()?;
            let mut count = dead_count.lock().unwrap_or_else(|p| p.into_inner());
            dead_keys.insert(key, value).map_err(backend)?;
            latch.sync(|| db.persist(PersistMode::SyncAll))?;
            *count += 1;
            Ok(())
        })
        .await
        .map_err(|e| ObservationError::Join(e.to_string()))?
    }

    /// Whether a new unheld key `tmb` fits under the ceiling: it is already
    /// dead (nothing new is written) or the set has room. Read before the
    /// engine writes, so a key the ceiling refuses is never recorded in the
    /// engine alone. Not atomic with [`Self::record`]; the caller
    /// serializes the pair ([`Self::revoke_gate`]).
    ///
    /// # Errors
    ///
    /// [`ObservationError::Full`] when `tmb` is new and the set is at its
    /// ceiling.
    pub async fn check_room(&self, tmb: &Thumbprint) -> Result<(), ObservationError> {
        if self.is_dead(tmb).await? {
            return Ok(());
        }
        let count = *self.dead_count.lock().unwrap_or_else(|p| p.into_inner());
        if count >= self.ceiling {
            return Err(ObservationError::Full {
                ceiling: self.ceiling,
            });
        }
        Ok(())
    }

    /// The revoke envelope recorded for `tmb`, as it was received, or
    /// `None` when the key is not dead. Served by `GET /revoked` so a peer's
    /// readers can verify the death themselves.
    pub async fn revoke_of(
        &self,
        tmb: &Thumbprint,
    ) -> Result<Option<serde_json::Value>, ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let dead_keys = self.dead_keys.clone();
        let stored = tokio::task::spawn_blocking(move || dead_keys.get(&key).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))??;
        stored
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|e| ObservationError::Serialize(e.to_string()))
            })
            .transpose()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The only seam for a failed `persist`: fjall's cannot be made to
    /// fail on demand, so the latch both stores route their syncs through
    /// is held to its contract directly.
    #[test]
    fn a_failed_sync_closes_the_store_and_later_syncs_never_run() {
        let latch = SyncLatch::default();
        latch.sync(|| Ok(())).expect("a healthy sync passes");
        latch.writable().expect("and leaves the store writable");

        let failed = latch.sync(|| Err(fjall::Error::Io(std::io::Error::other("disk gone"))));
        assert!(matches!(failed, Err(DurabilityLost(m)) if m.contains("disk gone")));

        let mut ran = false;
        let later = latch.sync(|| {
            ran = true;
            Ok(())
        });
        assert!(later.is_err(), "a sync after a failed one is refused");
        assert!(
            !ran,
            "and is not attempted: its success would be over lost pages"
        );
        assert!(
            latch.writable().is_err(),
            "writes are refused until restart"
        );
    }
}
