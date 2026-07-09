//! fjall-backed [`BlobStore`] implementation.
//!
//! Also provides [`open_eml_storage`], which opens an EML log storage
//! backend against the *same* fjall [`Database`] a [`FjallBlobStore`]
//! uses — one physical database (one WAL, atomic cross-keyspace
//! batches) shared by the blob and EML keyspaces, per
//! docs/specs/blob-store-fjall.md's `[fjall-single-keyspace]` mandate.

use std::path::Path;

use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};

/// Re-exported so a caller wiring up a shared-database
/// [`StorageEngine`](cyphr_storage::engine::StorageEngine) (via
/// [`open_eml_storage`]) can name `storage_fjall::FjallStorage` without
/// taking its own direct Cargo dependency on `storage-fjall`.
pub use storage_fjall;

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
        let dir = tempfile::tempdir()
            .map_err(|e| BlobStoreError::Backend(format!("tempdir: {e}")))?;
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
    /// further keyspaces (e.g. [`open_eml_storage`]) sharing this same
    /// physical database.
    pub fn database(&self) -> &Database {
        &self.db
    }
}

/// Open an EML log storage backend sharing `db` with a [`FjallBlobStore`]
/// built from the same database — one WAL, atomic cross-keyspace batches,
/// instead of two uncoordinated fjall databases.
///
/// Opens fixed keyspace names, so two logical logs (e.g. two Cyphr
/// principals) sharing one physical `db` would collide on EML's
/// positional leaf/node keys. For more than one principal per database,
/// use [`open_eml_storage_scoped`] instead.
pub fn open_eml_storage(
    db: Database,
) -> Result<storage_fjall::FjallStorage, storage_fjall::FjallStorageError> {
    storage_fjall::FjallStorage::with_database(db)
}

/// Open an EML log storage backend scoped to `prefix`, sharing `db` with a
/// [`FjallBlobStore`] built from the same database.
///
/// Distinct prefixes give each logical log (e.g. each Cyphr principal) its
/// own isolated keyspace triplet within the same physical `db`, safe for
/// more than one principal to share — see
/// [`storage_fjall::FjallStorage::with_database_scoped`] for the collision
/// this avoids.
///
/// `prefix` need not already satisfy `with_database_scoped`'s keyspace-name
/// charset (alphanumeric, `_`, `-`, `.`, `#`, `$`): a Cyphr `principal_id`
/// (e.g. `"SHA-256:U5XUZ..."`) always contains a `:` separator, which is
/// outside it. Any character outside that charset is replaced with `_`
/// before opening, so callers can pass a `principal_id` directly.
pub fn open_eml_storage_scoped(
    db: Database,
    prefix: &str,
) -> Result<storage_fjall::FjallStorage, storage_fjall::FjallStorageError> {
    let sanitized = sanitize_fjall_prefix(prefix);
    storage_fjall::FjallStorage::with_database_scoped(db, &sanitized)
}

/// Replace every character outside fjall's keyspace-name charset
/// (alphanumeric, `_`, `-`, `.`, `#`, `$`) with `_`.
///
/// Not collision-free for arbitrary input (two different inputs could map
/// to the same sanitized output), but is collision-free for this module's
/// actual input shape: a Cyphr `principal_id` is always `"{alg}:{digest}"`
/// where `alg` is alphanumeric/hyphen and `digest` is unpadded base64url
/// (`A-Za-z0-9-_`) — both already within the allowed charset — joined by
/// exactly one `:`, the sole character this replaces.
fn sanitize_fjall_prefix(prefix: &str) -> String {
    prefix
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '#' | '$') {
                c
            } else {
                '_'
            }
        })
        .collect()
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
            if let Some(max) = max_blob_size {
                if data.len() > max {
                    return Err(BlobStoreError::BlobTooLarge {
                        size: data.len(),
                        max,
                    });
                }
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
