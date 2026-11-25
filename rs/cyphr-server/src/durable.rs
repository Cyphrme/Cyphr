//! Shared durability guards for the server's own dedicated fjall stores
//! (today the admission spent set): a format-version stamp checked on open,
//! and a latch that closes a store to writes after a failed sync.
//!
//! The key death-set is not one of them: the engine's revoke records in the
//! blob store are the only copy (root `AGENTS.md` I1).

use fjall::{Database, KeyspaceCreateOptions, PersistMode};

/// Keyspace and key under which a dedicated fjall store records its format
/// version, as decimal text.
const META_KEYSPACE: &str = "meta";
const VERSION_KEY: &str = "format-version";

/// The format version of the admission spent set. A store
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
    /// Makes the next sync fail, so a test can drive a whole store through
    /// a failed `persist`, which fjall cannot be made to do on demand.
    #[cfg(test)]
    fail_next_sync: std::sync::atomic::AtomicBool,
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

    /// Whether a sync has failed: the store refuses every write.
    pub(crate) fn lost(&self) -> bool {
        self.writable().is_err()
    }

    /// Run `sync`; if it fails, latch the store closed.
    pub(crate) fn sync(
        &self,
        sync: impl FnOnce() -> Result<(), fjall::Error>,
    ) -> Result<(), DurabilityLost> {
        // The mutex guards no data; a panicked holder left nothing to repair.
        let _one_sync = self.one_sync.lock().unwrap_or_else(|p| p.into_inner());
        self.writable()?;
        #[cfg(test)]
        let sync = || {
            if self
                .fail_next_sync
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                Err(fjall::Error::Io(std::io::Error::other(
                    "injected sync failure",
                )))
            } else {
                sync()
            }
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The only seam for a failed `persist`: fjall's cannot be made to
    /// fail on demand, so the latch a store routes its syncs through
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
