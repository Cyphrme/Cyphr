//! fjall-backed [`Indexer`] implementation.
//!
//! Per the settled KV-not-SQL design (forge #18/#23; root `AGENTS.md` I3):
//! the production index is arbitrary KV tables plus a meta-table tracking
//! them, over the durable fjall store — never a relational database.
//! `cyphr-index-sqlite` was always transitional.
//!
//! ## Layout
//!
//! One dedicated fjall keyspace ("partition") per logical index, plus a
//! `meta` partition recording which partitions exist and their schema
//! version:
//!
//! - `tips` — `principal_id` bytes → [`TipState`] (point lookup only)
//! - `principals` — `principal_id` bytes → [`PrincipalSummary`] (point lookup
//!   only, `list_principals` does a full scan)
//! - `commits` — [`commit_key`] (length-prefixed `principal_id` + big-endian
//!   sequence) → [`CommitRef`] (ordered range scan by sequence)
//! - `digests` — tagged-digest or blob-hash string → [`EntityRef`] (point
//!   lookup; also backs `is_blob_indexed`, mirroring [`MemoryIndexer`]'s
//!   single `digest_index` map rather than `SqliteIndexer`'s separate
//!   `cozies` table, since no `Indexer` method exposes per-coz metadata
//!   directly)
//! - `public_keys` — thumbprint bytes → [`PublicKeyInfo`] (point lookup)
//!
//! `tips` and `principals` key on the raw `principal_id` bytes directly:
//! safe because they're only ever read by exact-key lookup, and distinct
//! byte strings can never collide under equality. `commits` additionally
//! needs range scans (a whole principal's chain, or a sub-range of it),
//! which raw-byte-prefix scoping would NOT make safe — see [`commit_key`]'s
//! docs for why a naive prefix scan reintroduces exactly the kind of
//! injectivity gap `sanitize_fjall_prefix` (F11) left unenforced, and how
//! the length-prefixed encoding here closes it.
//!
//! [`MemoryIndexer`]: cyphr_storage::index::MemoryIndexer

use cyphr::state::TaggedDigest;
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{
    CommitRef, EntityRef, EntityType, IndexableCommit, Indexer, IndexerError, PrincipalSummary,
    PublicKeyInfo, TipState,
};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};

/// Current schema version recorded in the `meta` partition.
const SCHEMA_VERSION: u32 = 1;

/// Fixed key under which the `meta` partition stores its single tracking
/// record.
const META_KEY: &[u8] = b"index-meta";

/// The set of logical index partitions this crate maintains, recorded in
/// the `meta` partition on initialization — the "meta-table tracking
/// [the] arbitrary KV index tables" the settled design calls for (c5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IndexMeta {
    version: u32,
    partitions: Vec<String>,
}

/// Encode a `commits` partition key: `principal_id`'s length (big-endian
/// `u32`) + its raw bytes + `sequence` (big-endian `u64`).
///
/// # Why length-prefixed
///
/// A point lookup on an exact key never collides for distinct byte
/// strings — but `get_commit_chain` needs a *range* scan over every
/// sequence belonging to one `principal_id`, and a naive
/// `principal_id_bytes ++ sequence_bytes` encoding (with no length
/// prefix) is NOT range-safe: querying principal `"alice"`'s range
/// `["alice"+0x00..0x00, "alice"+0xFF..0xFF]` would also contain every key
/// belonging to principal `"alice2"` (or any principal for which
/// `"alice"` is a literal byte-prefix), because `"alice2"`'s extra byte
/// ('2' = 0x32) falls lexicographically between 0x00 and 0xFF at the very
/// position the range brackets. That is exactly the class of bug F11
/// left latent in `sanitize_fjall_prefix`: two distinct principals
/// silently sharing an accessible keyspace.
///
/// Prefixing with `principal_id`'s length first guarantees any two
/// distinct principal IDs of *different* lengths get non-overlapping
/// ranges (the length prefix itself differs and dominates the
/// comparison), and IDs of the *same* length differ at the first
/// differing content byte, which likewise can never be masked by any
/// suffix. See `injectivity` tests below for the adversarial cases this
/// rules out.
fn commit_key(principal_id: &str, sequence: u64) -> Vec<u8> {
    let pid = principal_id.as_bytes();
    let mut key = Vec::with_capacity(4 + pid.len() + 8);
    key.extend_from_slice(&(pid.len() as u32).to_be_bytes());
    key.extend_from_slice(pid);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

/// Inclusive `[from, to]` range of [`commit_key`]s for one `principal_id`.
fn commit_key_range(principal_id: &str, from: u64, to: u64) -> (Vec<u8>, Vec<u8>) {
    (
        commit_key(principal_id, from),
        commit_key(principal_id, to),
    )
}

fn to_backend_err(e: fjall::Error) -> IndexerError {
    IndexerError::Backend(format!("fjall error: {e}"))
}

fn join_err(e: tokio::task::JoinError) -> IndexerError {
    IndexerError::Backend(format!("spawn_blocking join failed: {e}"))
}

fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, IndexerError> {
    serde_json::to_vec(value).map_err(|e| IndexerError::Backend(format!("serialize: {e}")))
}

fn de<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, IndexerError> {
    serde_json::from_slice(bytes).map_err(|e| IndexerError::Backend(format!("deserialize: {e}")))
}

/// Production `Indexer` backed by fjall (LSM-tree KV).
///
/// Reads go directly against fjall's concurrent-safe keyspaces (mirroring
/// `cyphr-blob-fjall::FjallBlobStore`'s established convention: no actor
/// thread, `spawn_blocking` per call). `index_commit`/`clear` additionally
/// hold `write_lock` across their whole read-modify-write critical
/// section: fjall itself doesn't need serialization for individual ops,
/// but computing a principal's next `commit_count`/`created` timestamp is
/// a read-then-write sequence that must not interleave with a concurrent
/// writer for the *same* principal — the same guarantee `MemoryIndexer`
/// gets from one global `RwLock` and `SqliteIndexer` gets from its
/// single-threaded actor, kept here without reintroducing an actor thread
/// fjall doesn't need for anything else.
pub struct FjallIndexer {
    db: Database,
    tips: Keyspace,
    principals: Keyspace,
    commits: Keyspace,
    digests: Keyspace,
    public_keys: Keyspace,
    write_lock: tokio::sync::Mutex<()>,
}

impl FjallIndexer {
    /// Open or create a fjall-backed indexer at `path`, owning a dedicated
    /// database.
    pub fn open(path: &std::path::Path) -> Result<Self, IndexerError> {
        let db = Database::builder(path)
            .open()
            .map_err(|e| IndexerError::Backend(format!("fjall database open: {e}")))?;
        Self::from_database(db)
    }

    /// Create a fresh disk-backed indexer in a temp dir, for tests.
    #[cfg(test)]
    pub fn temp() -> Result<(Self, tempfile::TempDir), IndexerError> {
        let dir = tempfile::tempdir()
            .map_err(|e| IndexerError::Backend(format!("tempdir: {e}")))?;
        let indexer = Self::open(dir.path())?;
        Ok((indexer, dir))
    }

    /// Create an indexer from an existing database, so a caller can share
    /// one physical fjall `Database` with a [`cyphr_blob_fjall::FjallBlobStore`]
    /// (one WAL, atomic cross-keyspace batches) rather than opening a
    /// second, uncoordinated one.
    pub fn from_database(db: Database) -> Result<Self, IndexerError> {
        let open = |name: &str| -> Result<Keyspace, IndexerError> {
            db.keyspace(name, KeyspaceCreateOptions::default)
                .map_err(|e| IndexerError::Backend(format!("fjall keyspace '{name}' open: {e}")))
        };

        let meta = open("index_meta")?;
        let tips = open("index_tips")?;
        let principals = open("index_principals")?;
        let commits = open("index_commits")?;
        let digests = open("index_digests")?;
        let public_keys = open("index_public_keys")?;

        if !meta.contains_key(META_KEY).map_err(to_backend_err)? {
            let record = IndexMeta {
                version: SCHEMA_VERSION,
                partitions: vec![
                    "index_tips".to_string(),
                    "index_principals".to_string(),
                    "index_commits".to_string(),
                    "index_digests".to_string(),
                    "index_public_keys".to_string(),
                ],
            };
            meta.insert(META_KEY, ser(&record)?)
                .map_err(to_backend_err)?;
        }

        Ok(Self {
            db,
            tips,
            principals,
            commits,
            digests,
            public_keys,
            write_lock: tokio::sync::Mutex::new(()),
        })
    }
}

impl Indexer for FjallIndexer {
    fn index_commit(
        &self,
        commit: &IndexableCommit,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        let db = self.db.clone();
        let tips = self.tips.clone();
        let principals = self.principals.clone();
        let commits = self.commits.clone();
        let digests = self.digests.clone();
        let public_keys = self.public_keys.clone();
        async move {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || {
                db_index_commit(&db, &tips, &principals, &commits, &digests, &public_keys, &commit)
            })
            .await
            .map_err(join_err)?
        }
    }

    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let tips = self.tips.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                match tips.get(principal_id.as_bytes()).map_err(to_backend_err)? {
                    Some(bytes) => Ok(Some(de(&bytes)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(join_err)?
        }
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let commits = self.commits.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let (lower, upper) =
                    commit_key_range(&principal_id, from.unwrap_or(0), to.unwrap_or(u64::MAX));
                let mut chain = Vec::new();
                for guard in commits.range(lower..=upper) {
                    let value = guard.value().map_err(to_backend_err)?;
                    chain.push(de(&value)?);
                }
                Ok(chain)
            })
            .await
            .map_err(join_err)?
        }
    }

    fn resolve_digest(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<EntityRef>, IndexerError>> + Send {
        let key = digest.to_string();
        let digests = self.digests.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                match digests.get(key.as_bytes()).map_err(to_backend_err)? {
                    Some(bytes) => Ok(Some(de(&bytes)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(join_err)?
        }
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send {
        let principals = self.principals.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                for guard in principals.iter() {
                    let value = guard.value().map_err(to_backend_err)?;
                    out.push(de(&value)?);
                }
                Ok(out)
            })
            .await
            .map_err(join_err)?
        }
    }

    fn clear(&self) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let tips = self.tips.clone();
        let principals = self.principals.clone();
        let commits = self.commits.clone();
        let digests = self.digests.clone();
        let public_keys = self.public_keys.clone();
        async move {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || {
                tips.clear().map_err(to_backend_err)?;
                principals.clear().map_err(to_backend_err)?;
                commits.clear().map_err(to_backend_err)?;
                digests.clear().map_err(to_backend_err)?;
                public_keys.clear().map_err(to_backend_err)?;
                Ok(())
            })
            .await
            .map_err(join_err)?
        }
    }

    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send {
        let key = hash.to_string();
        let digests = self.digests.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                digests.contains_key(key.as_bytes()).map_err(to_backend_err)
            })
            .await
            .map_err(join_err)?
        }
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send {
        let key = thumbprint.to_string();
        let public_keys = self.public_keys.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                match public_keys.get(key.as_bytes()).map_err(to_backend_err)? {
                    Some(bytes) => Ok(Some(de(&bytes)?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(join_err)?
        }
    }
}

/// Synchronous body of `index_commit`, run inside `spawn_blocking`.
///
/// Mirrors `MemoryIndexer`'s reference semantics (the behavioral baseline
/// per N09-kv-index premise p2): idempotent on an already-indexed
/// `(principal_id, sequence)` (matching `SqliteIndexer`'s `INSERT OR
/// IGNORE`-on-primary-key behavior, which the shared conformance suite's
/// `index_commit_idempotent` test already holds every backend to); tracks
/// each principal's genesis timestamp as `created`, and folds every
/// digest variant (commit IDs, PR/SR/AR/CR, per-coz blob hashes and czds)
/// into one `digests` partition exactly as `MemoryIndexer`'s single
/// `digest_index` map does — not `SqliteIndexer`'s separate `cozies`
/// table, since no `Indexer` method reads per-coz metadata directly.
fn db_index_commit(
    db: &Database,
    tips: &Keyspace,
    principals: &Keyspace,
    commits: &Keyspace,
    digests: &Keyspace,
    public_keys: &Keyspace,
    commit: &IndexableCommit,
) -> Result<(), IndexerError> {
    let key = commit_key(&commit.principal_id, commit.sequence);
    if commits.contains_key(&key).map_err(to_backend_err)? {
        return Ok(());
    }

    let primary_cid = commit.commit_ids.first().cloned().unwrap_or_default();
    let primary_pr = commit.prs.first().cloned().unwrap_or_default();
    let primary_sr = commit.srs.first().cloned().unwrap_or_default();
    let primary_ar = commit.ars.first().cloned().unwrap_or_default();
    let primary_cr = commit.crs.first().cloned().unwrap_or_default();

    let commit_ref = CommitRef {
        commit_id: primary_cid.clone(),
        sequence: commit.sequence,
        pre: commit.pre.clone(),
        pr: primary_pr.clone(),
        sr: primary_sr.clone(),
        ar: primary_ar.clone(),
        cr: primary_cr.clone(),
        blob_hashes: commit.blob_hashes.clone(),
    };

    let pid_key = commit.principal_id.as_bytes();
    let existing_summary: Option<PrincipalSummary> = principals
        .get(pid_key)
        .map_err(to_backend_err)?
        .map(|b| de(&b))
        .transpose()?;

    let commit_count = existing_summary
        .as_ref()
        .map_or(0, |p| p.commit_count)
        + 1;
    let created = existing_summary
        .as_ref()
        .map_or(commit.timestamp, |p| p.created);

    let first_blob_hash = commit
        .blob_hashes
        .first()
        .cloned()
        .ok_or_else(|| IndexerError::Consistency("commit has no blob hashes".into()))?;

    // All writes below land in one atomic batch: a crash mid-`index_commit`
    // must never leave `commits` updated without `tips`/`principals`
    // following (or vice versa) -- matching `SqliteIndexer`'s single
    // transaction and `MemoryIndexer`'s single lock-guarded mutation, not
    // a weaker per-keyspace-independent write.
    let mut batch = db.batch();

    batch.insert(commits, key, ser(&commit_ref)?);

    batch.insert(
        tips,
        pid_key,
        ser(&TipState {
            principal_id: commit.principal_id.clone(),
            pr: primary_pr.clone(),
            sr: primary_sr.clone(),
            ar: primary_ar.clone(),
            cr: primary_cr.clone(),
            commit_id: primary_cid.clone(),
            commit_count,
            last_updated: commit.timestamp,
        })?,
    );

    batch.insert(
        principals,
        pid_key,
        ser(&PrincipalSummary {
            principal_id: commit.principal_id.clone(),
            pr: primary_pr,
            commit_count,
            created,
            last_updated: commit.timestamp,
        })?,
    );

    for coz in &commit.cozies {
        let entity_type = if coz.typ.starts_with("cyphr/action") || coz.typ.contains("/action") {
            EntityType::Action
        } else {
            EntityType::Transaction
        };

        for digest_key in [coz.blob_hash.to_string(), coz.czd.clone()] {
            batch.insert(
                digests,
                digest_key.as_bytes(),
                ser(&EntityRef {
                    digest: digest_key.clone(),
                    blob_hash: coz.blob_hash,
                    entity_type,
                })?,
            );
        }
    }

    for variant in commit
        .commit_ids
        .iter()
        .chain(commit.prs.iter())
        .chain(commit.srs.iter())
        .chain(commit.ars.iter())
        .chain(commit.crs.iter())
    {
        batch.insert(
            digests,
            variant.as_bytes(),
            ser(&EntityRef {
                digest: variant.clone(),
                blob_hash: first_blob_hash,
                entity_type: EntityType::Commit,
            })?,
        );
    }

    for key_info in &commit.keys {
        batch.insert(public_keys, key_info.thumbprint.as_bytes(), ser(key_info)?);
    }

    batch.commit().map_err(to_backend_err)
}

#[cfg(test)]
mod tests;
