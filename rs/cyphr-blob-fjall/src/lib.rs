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
/// this avoids and the prefix charset it requires.
pub fn open_eml_storage_scoped(
    db: Database,
    prefix: &str,
) -> Result<storage_fjall::FjallStorage, storage_fjall::FjallStorageError> {
    storage_fjall::FjallStorage::with_database_scoped(db, prefix)
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
mod tests {
    use eml::Storage as _;

    use super::*;

    #[tokio::test]
    async fn test_fjall_blob_store() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let store = FjallBlobStore::open(dir.path()).expect("failed to open store");

        let data = b"hello fjall store content-addressed";
        let hash = store.put(data).await.expect("put");

        let exists = store.exists(&hash).await.expect("exists");
        assert!(exists);

        let retrieved = store.get(&hash).await.expect("get").expect("found");
        assert_eq!(retrieved, data);

        // test limit
        let limited = store.with_max_blob_size(10);
        let err = limited.put(b"too long payload").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::BlobTooLarge { .. }));
    }

    /// Trivial fixed-width hasher for exercising generic EML log storage in
    /// these tests — unrelated to cyphr's own MALT hashing, which lives in
    /// the `cyphr` crate this storage-layer crate deliberately does not
    /// depend on.
    #[derive(Debug)]
    struct Blake3Hasher;

    impl eml::Hasher for Blake3Hasher {
        fn leaf(&self, data: &[u8]) -> Vec<u8> {
            blake3::hash(data).as_bytes().to_vec()
        }

        fn node(&self, children: &[&[u8]]) -> Vec<u8> {
            let mut hasher = blake3::Hasher::new();
            for child in children {
                hasher.update(child);
            }
            hasher.finalize().as_bytes().to_vec()
        }

        fn empty(&self) -> Vec<u8> {
            blake3::hash(b"").as_bytes().to_vec()
        }

        fn hash(&self, data: &[u8]) -> Vec<u8> {
            blake3::hash(data).as_bytes().to_vec()
        }

        fn clone_box(&self) -> Box<dyn eml::Hasher> {
            Box::new(Blake3Hasher)
        }
    }

    /// The Commit Tree (EML log) must survive a disk write/reload cycle,
    /// genuinely sharing one fjall database with the blob store rather than
    /// opening a second, uncoordinated one.
    #[tokio::test]
    async fn eml_log_survives_disk_reload_sharing_blob_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaves: [&[u8]; 3] = [b"commit-0", b"commit-1", b"commit-2"];

        let (original_root, original_size, blob_hash) = {
            let db = Database::builder(dir.path()).open().expect("open db");
            let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
            let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

            let blob_hash = blob_store.put(b"a blob living beside the log").await.unwrap();

            let mut log = eml::new(eml_storage, Box::new(Blake3Hasher))
                .await
                .expect("new log");
            for leaf in leaves {
                log.append_leaf(leaf).await.expect("append leaf");
            }

            (log.root_for(0).expect("root"), log.size(), blob_hash)
            // `db`, `blob_store`, and `log` all drop here, releasing the
            // on-disk database before it's reopened below.
        };

        // Reopen from scratch at the same path — a fresh `Database`, not a
        // clone of the one above — to prove the state is genuinely durable.
        let db = Database::builder(dir.path()).open().expect("reopen db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

        let reconstructed = eml::from_storage(eml_storage, vec![(0, Box::new(Blake3Hasher))])
            .await
            .expect("reconstruct log from disk");

        assert_eq!(reconstructed.size(), original_size, "leaf count must survive reload");
        assert_eq!(
            reconstructed.root_for(0).expect("root"),
            original_root,
            "root must survive reload byte-for-byte"
        );

        // The blob written in the first session must also still be there,
        // proving the blob and EML partitions truly share one database
        // rather than each independently persisting to its own file.
        let retrieved = blob_store.get(&blob_hash).await.unwrap();
        assert!(retrieved.is_some(), "blob must survive reload in the shared database");
    }

    /// Writes to the blob partition and writes to the EML partitions must
    /// never be observable through each other, even though both live in one
    /// physical fjall database.
    #[tokio::test]
    async fn blob_and_eml_partitions_are_isolated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::builder(dir.path()).open().expect("open db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

        let blob_a = blob_store.put(b"blob-partition-marker-a").await.unwrap();
        let blob_b = blob_store.put(b"blob-partition-marker-b").await.unwrap();

        let mut log = eml::new(eml_storage, Box::new(Blake3Hasher))
            .await
            .expect("new log");
        log.append_leaf(b"eml-partition-marker-0").await.unwrap();
        log.append_leaf(b"eml-partition-marker-1").await.unwrap();
        log.append_leaf(b"eml-partition-marker-2").await.unwrap();

        // The blob partition sees exactly the blobs it was given — no EML
        // leaves leaked in.
        let blob_hashes: Vec<Blake3Hash> = blob_store
            .iter()
            .await
            .expect("iter")
            .collect::<Result<_, _>>()
            .expect("iter items");
        assert_eq!(blob_hashes.len(), 2);
        assert!(blob_hashes.contains(&blob_a));
        assert!(blob_hashes.contains(&blob_b));

        // The EML partition sees exactly its own three leaves — unaffected
        // by the two unrelated blob writes.
        assert_eq!(log.size(), 3);
        assert_eq!(
            log.storage().get_leaf(0).await.unwrap(),
            b"eml-partition-marker-0"
        );
    }

    /// Two principals' EML logs, opened via [`open_eml_storage_scoped`] with
    /// distinct prefixes on the same physical database, must not observe
    /// each other's leaves — the multitenancy counterpart to
    /// `blob_and_eml_partitions_are_isolated` above.
    #[tokio::test]
    async fn scoped_eml_opens_on_one_database_do_not_collide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::builder(dir.path()).open().expect("open db");

        let storage_a =
            open_eml_storage_scoped(db.clone(), "principal-a").expect("scoped storage a");
        let storage_b =
            open_eml_storage_scoped(db.clone(), "principal-b").expect("scoped storage b");

        let mut log_a = eml::new(storage_a, Box::new(Blake3Hasher))
            .await
            .expect("new log a");
        let mut log_b = eml::new(storage_b, Box::new(Blake3Hasher))
            .await
            .expect("new log b");

        log_a.append_leaf(b"a-leaf-0").await.unwrap();
        log_b.append_leaf(b"b-leaf-0").await.unwrap();
        log_b.append_leaf(b"b-leaf-1").await.unwrap();

        assert_eq!(log_a.size(), 1, "tenant a's log must see only its own leaf");
        assert_eq!(log_b.size(), 2, "tenant b's log must see only its own leaves");
        assert_eq!(log_a.storage().get_leaf(0).await.unwrap(), b"a-leaf-0");
        assert_eq!(log_b.storage().get_leaf(0).await.unwrap(), b"b-leaf-0");
        assert_eq!(log_b.storage().get_leaf(1).await.unwrap(), b"b-leaf-1");
    }
}
