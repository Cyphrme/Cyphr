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
/// outside it. Any byte outside that charset is escaped, injectively (see
/// [`sanitize_fjall_prefix`]), before opening, so callers can pass a
/// `principal_id` directly.
pub fn open_eml_storage_scoped(
    db: Database,
    prefix: &str,
) -> Result<storage_fjall::FjallStorage, storage_fjall::FjallStorageError> {
    let sanitized = sanitize_fjall_prefix(prefix);
    storage_fjall::FjallStorage::with_database_scoped(db, &sanitized)
}

/// The per-principal EML logs of one database, by generation: a
/// [`LogFactory`](cyphr_storage::engine::LogFactory) for
/// [`StorageEngine::with_log_factory`](cyphr_storage::engine::StorageEngine::with_log_factory).
///
/// Generation 0 of a principal's log is the keyspace
/// [`open_eml_storage_scoped`] opens, so a log written before generations
/// existed stays current. Generation `g > 0` is scoped by the sanitized
/// principal id followed by `$g` and `g` in decimal: a sanitized id never
/// holds `$` other than as a two-hex-digit escape, so no id and generation
/// pair names another's keyspace. The current generation is recorded in
/// the `eml_generations` keyspace beside the logs; it names a cache, not
/// chain state (I1).
pub struct EmlLogs {
    db: Database,
    generations: Keyspace,
}

impl EmlLogs {
    /// The logs of `db`.
    ///
    /// # Errors
    ///
    /// The generation record's keyspace does not open.
    pub fn new(db: Database) -> Result<Self, fjall::Error> {
        let generations = db.keyspace("eml_generations", KeyspaceCreateOptions::default)?;
        Ok(Self { db, generations })
    }

    /// The scoping prefix of generation `generation` of `principal_id`'s
    /// log.
    fn prefix(principal_id: &str, generation: u64) -> String {
        let sanitized = sanitize_fjall_prefix(principal_id);
        match generation {
            0 => sanitized,
            g => format!("{sanitized}$g{g}"),
        }
    }

    /// Delete generation `generation` of `principal_id`'s log, if held.
    fn retire(&self, principal_id: &str, generation: u64) -> Result<(), String> {
        for keyspace in self.keyspaces(&Self::prefix(principal_id, generation))? {
            self.db
                .delete_keyspace(keyspace)
                .map_err(|e| format!("retiring log generation {generation}: {e}"))?;
        }
        Ok(())
    }

    /// The keyspaces `storage_fjall` opens for `prefix` that exist.
    fn keyspaces(&self, prefix: &str) -> Result<Vec<Keyspace>, String> {
        ["leaves", "nodes", "metadata"]
            .iter()
            .map(|part| format!("{prefix}_eml_{part}"))
            .filter(|name| self.db.keyspace_exists(name))
            .map(|name| {
                self.db
                    .keyspace(&name, KeyspaceCreateOptions::default)
                    .map_err(|e| format!("fjall keyspace '{name}' open: {e}"))
            })
            .collect()
    }
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
        let prefix = Self::prefix(principal_id, generation);
        let current = self.generation(principal_id)?;
        // A generation above the current one is being regenerated: what an
        // interrupted regeneration left there is discarded.
        if generation > current {
            for keyspace in self.keyspaces(&prefix)? {
                keyspace
                    .clear()
                    .map_err(|e| format!("clearing log {prefix}: {e}"))?;
            }
        }
        // A crash between recording a generation and retiring the one it
        // superseded leaves that one behind; the current log's open
        // retires every older generation still held.
        if generation == current {
            for older in 0..current {
                self.retire(principal_id, older)?;
            }
        }
        storage_fjall::FjallStorage::with_database_scoped(self.db.clone(), &prefix)
            .map_err(|e| e.to_string())
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

/// Escape marker [`sanitize_fjall_prefix`] uses for its reversible
/// encoding — reserved out of the passthrough set (see that function) so
/// it can never appear un-escaped in the output.
const FJALL_PREFIX_ESCAPE: char = '$';

/// Map arbitrary bytes into fjall's keyspace-name charset (alphanumeric,
/// `_`, `-`, `.`, `#`, `$`), injectively: distinct inputs always produce
/// distinct output.
///
/// # Why not blind substitution
///
/// An earlier version replaced every disallowed byte with a fixed `_`,
/// which is lossy: e.g. `"a:b"` (colon) and `"a_b"` (literal underscore)
/// both sanitized to `"a_b"`, a genuine same-length collision no length
/// prefix can fix (length-prefixing — the pattern `commit_key` in
/// `cyphr-index-fjall` uses — only disambiguates *variable-length* field
/// boundaries; it does nothing for a same-length, information-losing
/// character map like this one). A Cyphr `principal_id` is always
/// `"{alg}:{digest}"` and so never triggers this in practice, but
/// `principal_id` is caller-supplied and not otherwise validated —
/// multitenancy correctness (root AGENTS.md I2) must not depend on that
/// shape holding.
///
/// # Encoding
///
/// Every allowed byte passes through unchanged, *except* the escape
/// marker `$` itself, which (like every other disallowed byte) is
/// replaced with `$` followed by its two-hex-digit value. Because `$`
/// therefore never appears un-escaped in the output, a `$` encountered
/// left-to-right always starts exactly one two-hex-digit escape unit —
/// the encoding is uniquely decodable (hence injective) with no length
/// prefix needed: two distinct inputs can only produce the same output if
/// some output position is simultaneously a passthrough byte and part of
/// an escape unit, which the reserved marker rules out by construction.
/// See `injectivity` tests below for the adversarial cases this rules out.
fn sanitize_fjall_prefix(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for b in prefix.bytes() {
        let c = b as char;
        if c != FJALL_PREFIX_ESCAPE
            && (c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '#'))
        {
            out.push(c);
        } else {
            out.push(FJALL_PREFIX_ESCAPE);
            out.push_str(&format!("{b:02x}"));
        }
    }
    out
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
