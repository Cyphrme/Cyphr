//! fjall-backed [`BlobStore`] implementation.
//!
//! Also provides [`EmlLogs`], which keeps every principal's EML log in the
//! *same* fjall [`Database`] a [`FjallBlobStore`] uses — one physical
//! database (one WAL, atomic cross-keyspace batches) shared by the blob
//! and EML keyspaces, per docs/specs/blob-store-fjall.md's
//! `[fjall-single-keyspace]` mandate.

use std::path::Path;

use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
/// Re-exported so a caller wiring up a shared-database
/// [`StorageEngine`](cyphr_storage::engine::StorageEngine) (via
/// [`EmlLogs`]) can name `storage_fjall::FjallStorage` without
/// taking its own direct Cargo dependency on `storage-fjall`.
pub use storage_fjall;
use storage_fjall::LogKeyspaces;

/// Production blob store backed by fjall (LSM-tree).
pub struct FjallBlobStore {
    db: Database,
    blobs: Keyspace,
    max_blob_size: Option<usize>,
}

impl FjallBlobStore {
    /// Open or create a blob store at `path`, owning a dedicated database.
    pub fn open(path: &Path) -> Result<Self, BlobStoreError> {
        let db = Database::builder(path)
            .open()
            .map_err(|e| BlobStoreError::Backend(format!("fjall database open: {e}")))?;
        Self::from_database(db)
    }

    /// Create a fresh disk-backed blob store in a temp dir, for tests.
    #[cfg(test)]
    pub fn temp() -> Result<(Self, tempfile::TempDir), BlobStoreError> {
        let dir =
            tempfile::tempdir().map_err(|e| BlobStoreError::Backend(format!("tempdir: {e}")))?;
        let store = Self::open(dir.path())?;
        Ok((store, dir))
    }

    /// Create a blob store from an existing database (supporting shared-database cooperation).
    pub fn from_database(db: Database) -> Result<Self, BlobStoreError> {
        let blobs = db
            .keyspace("blobs", KeyspaceCreateOptions::default)
            .map_err(|e| BlobStoreError::Backend(format!("fjall keyspace open: {e}")))?;
        Ok(Self {
            db,
            blobs,
            max_blob_size: None,
        })
    }

    /// Configure a maximum blob size limit.
    pub fn with_max_blob_size(mut self, max: usize) -> Self {
        self.max_blob_size = Some(max);
        self
    }

    /// Get the underlying [`Database`] reference, so a caller can open
    /// further keyspaces sharing this same
    /// physical database.
    pub fn database(&self) -> &Database {
        &self.db
    }
}

/// The per-principal EML logs of one database, by generation: a
/// [`LogFactory`](cyphr_storage::engine::LogFactory) for
/// [`StorageEngine::with_log_factory`](cyphr_storage::engine::StorageEngine::with_log_factory).
///
/// Every log of every principal and generation lives in one fixed
/// keyspace triplet ([`LogKeyspaces`]), told apart by a key scope: the
/// principal id bytes followed by the generation as a `u64` big-endian.
/// A keyspace is never created per principal: creating one costs about
/// fourteen fsyncs under a database-wide lock. The current generation is
/// recorded in the `eml_generations` keyspace beside the logs; it names a
/// cache, not chain state (I1).
pub struct EmlLogs {
    keyspaces: LogKeyspaces,
    generations: Keyspace,
    /// Principals whose older generations this process has swept. A crash
    /// can only leave an older generation behind in a process that has
    /// since died, so one sweep per principal per process recovers it, and
    /// later opens skip the prefix scans a sweep costs.
    swept: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// Why [`EmlLogs::new`] failed.
#[derive(Debug)]
pub struct EmlLogsError(String);

impl std::fmt::Display for EmlLogsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EmlLogsError {}

/// Suffixes of the per-principal keyspaces of the layout before the fixed
/// triplet. The fixed names carry no leading underscore, so none ends in
/// one of these.
const LEGACY_SUFFIXES: [&str; 3] = ["_eml_leaves", "_eml_nodes", "_eml_metadata"];

impl EmlLogs {
    /// The logs of `db`, opening the fixed keyspaces once.
    ///
    /// A database written under the per-principal keyspace layout is
    /// migrated by dropping those keyspaces: the logs are caches of the
    /// blobs (I1) and replay rebuilds each on its next load. Generation
    /// records are left as they are; a record then names a scope that is
    /// empty, which replay fills. This costs about seven fsyncs per legacy
    /// keyspace, once, so progress is logged.
    ///
    /// # Errors
    ///
    /// A keyspace does not open, or a legacy one does not delete.
    pub fn new(db: Database) -> Result<Self, EmlLogsError> {
        let err = |what: &str| {
            let what = what.to_owned();
            move |e: &dyn std::fmt::Display| EmlLogsError(format!("{what}: {e}"))
        };
        let generations = db
            .keyspace("eml_generations", KeyspaceCreateOptions::default)
            .map_err(|e| err("opening the generation record")(&e))?;
        let keyspaces =
            LogKeyspaces::open(db.clone()).map_err(|e| err("opening the log keyspaces")(&e))?;
        let legacy: Vec<String> = db
            .list_keyspace_names()
            .into_iter()
            .map(|name| name.to_string())
            .filter(|name| LEGACY_SUFFIXES.iter().any(|s| name.ends_with(s)))
            .collect();
        if !legacy.is_empty() {
            migrate_legacy_layout(&db, &legacy).map_err(EmlLogsError)?;
        }
        Ok(Self {
            keyspaces,
            generations,
            swept: std::sync::Mutex::default(),
        })
    }

    /// The key scope of generation `generation` of `principal_id`'s log.
    /// Fixed-width tail, so injective; `FjallStorage` length-prefixes it.
    fn scope(principal_id: &str, generation: u64) -> Vec<u8> {
        let mut scope = Vec::with_capacity(principal_id.len() + 8);
        scope.extend_from_slice(principal_id.as_bytes());
        scope.extend_from_slice(&generation.to_be_bytes());
        scope
    }

    fn scoped(
        &self,
        principal_id: &str,
        generation: u64,
    ) -> Result<storage_fjall::FjallStorage, String> {
        storage_fjall::FjallStorage::scoped(&self.keyspaces, &Self::scope(principal_id, generation))
            .map_err(|e| e.to_string())
    }

    /// Delete generation `generation` of `principal_id`'s log, if held.
    fn retire(&self, principal_id: &str, generation: u64) -> Result<(), String> {
        self.scoped(principal_id, generation)?
            .drop_scope()
            .map_err(|e| format!("retiring log generation {generation}: {e}"))
    }
}

/// Drop the legacy keyspaces `legacy`. An interrupted drop is finished by
/// the next start, which finds the keyspaces still listed.
fn migrate_legacy_layout(db: &Database, legacy: &[String]) -> Result<(), String> {
    let started = std::time::Instant::now();
    eprintln!(
        "migrating the commit logs to the fixed keyspace layout: dropping {} legacy keyspaces \
         (they rebuild from the blobs on first load)",
        legacy.len()
    );
    for (done, name) in legacy.iter().enumerate() {
        let keyspace = db
            .keyspace(name, KeyspaceCreateOptions::default)
            .map_err(|e| format!("fjall keyspace '{name}' open: {e}"))?;
        db.delete_keyspace(keyspace)
            .map_err(|e| format!("deleting legacy keyspace '{name}': {e}"))?;
        let done = done + 1;
        if done % 30 == 0 || done == legacy.len() {
            eprintln!(
                "  dropped {done}/{} legacy keyspaces, {:.1}s elapsed",
                legacy.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    Ok(())
}

impl cyphr_storage::engine::LogFactory<storage_fjall::FjallStorage> for EmlLogs {
    fn generation(&self, principal_id: &str) -> Result<u64, String> {
        let held = self
            .generations
            .get(principal_id.as_bytes())
            .map_err(|e| format!("reading the log generation of {principal_id}: {e}"))?;
        match held {
            None => Ok(0),
            Some(bytes) => <[u8; 8]>::try_from(bytes.as_ref())
                .map(u64::from_be_bytes)
                .map_err(|_| format!("the log generation of {principal_id} is not a u64")),
        }
    }

    fn open(
        &self,
        principal_id: &str,
        generation: u64,
    ) -> Result<storage_fjall::FjallStorage, String> {
        let current = self.generation(principal_id)?;
        // A generation above the current one is being regenerated: what an
        // interrupted regeneration left there is discarded.
        if generation > current {
            self.retire(principal_id, generation)?;
        }
        // A crash between recording a generation and retiring the one it
        // superseded leaves that one behind; the first open of the current
        // log in this process retires every older generation still held.
        if generation == current && current > 0 {
            // The set only skips work; a poisoned lock holds a usable set.
            let mut swept = self.swept.lock().unwrap_or_else(|e| e.into_inner());
            if !swept.contains(principal_id) {
                for older in 0..current {
                    self.retire(principal_id, older)?;
                }
                swept.insert(principal_id.to_owned());
            }
        }
        self.scoped(principal_id, generation)
    }

    fn retire_below(&self, principal_id: &str, generation: u64) -> Result<(), String> {
        let retired = self.generation(principal_id)?;
        self.generations
            .insert(principal_id.as_bytes(), generation.to_be_bytes())
            .map_err(|e| format!("recording the log generation of {principal_id}: {e}"))?;
        // Older generations were retired when their successors became
        // current, or are swept by the next open if a crash intervened.
        if retired < generation {
            self.retire(principal_id, retired)?;
        }
        Ok(())
    }
}

impl BlobStore for FjallBlobStore {
    fn put(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let max_blob_size = self.max_blob_size;
        let blobs = self.blobs.clone();
        let data = data.to_vec();
        async move {
            if let Some(max) = max_blob_size
                && data.len() > max
            {
                return Err(BlobStoreError::BlobTooLarge {
                    size: data.len(),
                    max,
                });
            }
            let hash = Blake3Hash::from_bytes(*blake3::hash(&data).as_bytes());
            tokio::task::spawn_blocking(move || {
                blobs
                    .insert(hash.as_bytes(), data)
                    .map_err(|e| BlobStoreError::Backend(format!("fjall insert: {e}")))?;
                Ok(hash)
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        }
    }

    fn get(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send {
        let hash = *hash;
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let result = blobs
                    .get(hash.as_bytes())
                    .map_err(|e| BlobStoreError::Backend(format!("fjall get: {e}")))?;
                Ok(result.map(|slice| slice.to_vec()))
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, BlobStoreError>> + Send {
        let hash = *hash;
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                blobs
                    .contains_key(hash.as_bytes())
                    .map_err(|e| BlobStoreError::Backend(format!("fjall contains_key: {e}")))
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }

    fn iter(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>,
            BlobStoreError,
        >,
    > + Send {
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let iter = blobs.iter();
                let mut hashes = Vec::new();
                for guard in iter {
                    let key = guard
                        .key()
                        .map_err(|e| BlobStoreError::Backend(format!("fjall iter: {e}")))?;
                    let key_bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                        BlobStoreError::Backend(format!(
                            "fjall key length {}, expected 32",
                            key.len()
                        ))
                    })?;
                    hashes.push(Blake3Hash::from_bytes(key_bytes));
                }
                let iter: Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send> =
                    Box::new(hashes.into_iter().map(Ok));
                Ok(iter)
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }
}

#[cfg(test)]
mod tests;
