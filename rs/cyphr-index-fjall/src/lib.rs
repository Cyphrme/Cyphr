//! fjall-backed [`Indexer`] implementation.
//!
//! Per the settled KV-not-SQL design (forge #18/#23; root `AGENTS.md` I3):
//! the production index is arbitrary KV tables plus a meta-table tracking
//! them, over the durable fjall store — never a relational database. The
//! earlier relational-backed indexer this replaced was always
//! transitional.
//!
//! ## Layout
//!
//! One dedicated fjall keyspace ("partition") per logical index, plus a
//! `meta` partition recording the deriver's own claim of which partitions
//! it has produced (S3a, c-registry-generated — see [`FjallIndexer::registry`]):
//!
//! - `tips` — `principal_id` bytes → [`TipState`] (point lookup only)
//! - `principals` — `principal_id` bytes → [`PrincipalSummary`] (point lookup only,
//!   `list_principals` does a full scan)
//! - `commits` — [`commit_key`] (length-prefixed `principal_id` + big-endian sequence) →
//!   [`CommitRef`] (ordered range scan by sequence)
//! - `digests` — tagged-digest or blob-hash string → [`EntityRef`] (point lookup; also backs
//!   `is_blob_indexed` — one shared partition covers both blob hashes and czds, mirroring
//!   [`MemoryIndexer`]'s single `digest_index` map, since no `Indexer` method exposes per-coz
//!   metadata directly and a separate per-coz table would serve nothing)
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

use std::collections::BTreeSet;

use cyphr::state::TaggedDigest;
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{
    CommitRef, DeriveToken, EntityRef, EntityType, IndexableCommit, Indexer, IndexerError,
    IndexerWrite, PrincipalSummary, PublicKeyInfo, TipState,
};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};

/// Current schema version recorded in the `meta` partition.
const SCHEMA_VERSION: u32 = 1;

/// Fixed key under which the `meta` partition stores its single tracking
/// record.
const META_KEY: &[u8] = b"index-meta";

/// The set of index partitions this schema version's derivation produces.
/// Not a claim about what physically exists on disk (a raw, out-of-band
/// writer could create an extra keyspace, or a corrupted store could be
/// missing one) — see [`FjallIndexer::registry`] for the durable claim
/// the deriver itself records.
const PARTITION_NAMES: &[&str] = &[
    "index_tips",
    "index_principals",
    "index_commits",
    "index_digests",
    "index_public_keys",
];

/// The `meta` partition's single tracking record — the "meta-table
/// tracking [the] arbitrary KV index tables" the settled design calls for
/// (c5). Written atomically, as part of the SAME batch, by every
/// derivation write (S3a, c-registry-generated) — never a one-time
/// bootstrap literal independent of whether any derivation has actually
/// run. See [`FjallIndexer::registry`].
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
    (commit_key(principal_id, from), commit_key(principal_id, to))
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
/// writer for the *same* principal — the same per-principal serialization
/// guarantee `MemoryIndexer` gets from one global `RwLock`, kept here
/// without an actor thread fjall doesn't need for anything else.
pub struct FjallIndexer {
    db: Database,
    /// The registry claim (S3a, c-registry-generated) — see [`Self::registry`].
    meta: Keyspace,
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
        let dir =
            tempfile::tempdir().map_err(|e| IndexerError::Backend(format!("tempdir: {e}")))?;
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

        // No bootstrap write here: the registry claim (`index_meta`'s
        // record) is written only as derivation OUTPUT, atomically
        // alongside the rows each `index_commit` batch produces (see
        // `db_index_commit`) -- never as a literal issued unconditionally
        // at open time, regardless of whether any derivation has run.
        // `registry()` reports an empty set until the first commit is
        // indexed, which is the honest answer: nothing has been derived
        // yet.

        Ok(Self {
            db,
            meta,
            tips,
            principals,
            commits,
            digests,
            public_keys,
            write_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Report the set of index partitions this store's OWN derivation has
    /// durably produced.
    ///
    /// Reads back the `index_meta` claim written atomically -- as part of
    /// the SAME fjall batch as the actual rows -- inside every
    /// [`IndexerWrite::index_commit`] call (see `db_index_commit`).
    /// Deliberately NOT a live rescan of which fjall keyspaces physically
    /// exist: a rescan-based implementation would make a registry entry
    /// present-but-never-produced-by-any-derivation physically
    /// indistinguishable from an extra keyspace planted directly on disk
    /// out-of-band, collapsing two of
    /// `rs/cyphr-storage/tests/rebuild_compare.rs`'s three named
    /// mutations into one undetectable case. An index with no commits
    /// derived into it yet reports an empty set, not an error.
    pub fn registry(&self) -> Result<BTreeSet<String>, IndexerError> {
        match self.meta.get(META_KEY).map_err(to_backend_err)? {
            Some(bytes) => {
                let record: IndexMeta = de(&bytes)?;
                Ok(record.partitions.into_iter().collect())
            },
            None => Ok(BTreeSet::new()),
        }
    }
}

impl Indexer for FjallIndexer {
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

/// The fjall keyspace handles a write needs, bundled so a write function
/// takes one argument per logical concern (db, keyspaces, commit) instead
/// of one per partition.
#[derive(Clone)]
struct Keyspaces {
    meta: Keyspace,
    tips: Keyspace,
    principals: Keyspace,
    commits: Keyspace,
    digests: Keyspace,
    public_keys: Keyspace,
}

impl FjallIndexer {
    fn keyspaces(&self) -> Keyspaces {
        Keyspaces {
            meta: self.meta.clone(),
            tips: self.tips.clone(),
            principals: self.principals.clone(),
            commits: self.commits.clone(),
            digests: self.digests.clone(),
            public_keys: self.public_keys.clone(),
        }
    }
}

impl IndexerWrite for FjallIndexer {
    fn index_commit(
        &self,
        commit: &IndexableCommit,
        _token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        let db = self.db.clone();
        let ks = self.keyspaces();
        async move {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || db_index_commit(&db, &ks, &commit))
                .await
                .map_err(join_err)?
        }
    }

    fn clear(
        &self,
        _token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let ks = self.keyspaces();
        async move {
            let _guard = self.write_lock.lock().await;
            tokio::task::spawn_blocking(move || {
                ks.tips.clear().map_err(to_backend_err)?;
                ks.principals.clear().map_err(to_backend_err)?;
                ks.commits.clear().map_err(to_backend_err)?;
                ks.digests.clear().map_err(to_backend_err)?;
                ks.public_keys.clear().map_err(to_backend_err)?;
                // The registry claim is derivation output too: clearing
                // the derived rows without also retracting what the
                // deriver claims to have produced would leave a stale
                // registry asserting partitions no commit has populated
                // since the clear.
                ks.meta.remove(META_KEY).map_err(to_backend_err)?;
                Ok(())
            })
            .await
            .map_err(join_err)?
        }
    }
}

/// Synchronous body of `index_commit`, run inside `spawn_blocking`.
///
/// Mirrors `MemoryIndexer`'s reference semantics (the behavioral baseline
/// the KV-index migration established): idempotent on an already-indexed
/// `(principal_id, sequence)` (an idempotent re-index by primary key,
/// which the shared conformance suite's `index_commit_idempotent` test
/// holds every backend to); tracks each principal's genesis timestamp as
/// `created`, and folds every digest variant (commit IDs, PR/SR/AR/CR,
/// per-coz blob hashes and czds) into one `digests` partition exactly as
/// `MemoryIndexer`'s single `digest_index` map does, rather than a
/// separate per-coz table, since no `Indexer` method reads per-coz
/// metadata directly.
///
/// Also writes the `meta` partition's registry claim (S3a,
/// c-registry-generated) in the SAME atomic batch as the rows below, so
/// that claim is produced by, and only by, this write-sealed derivation
/// path -- never a value written independently of it. A write that
/// bypasses this function entirely (raw fjall access, exactly the class
/// `IndexerWrite`'s [`DeriveToken`] seals off) can still edit
/// `index_meta` directly, but doing so no longer matches what
/// [`FjallIndexer::registry`] reports for a store this function actually
/// produced, which is the divergence
/// `rs/cyphr-storage/tests/rebuild_compare.rs`'s m3 mutation asserts.
fn db_index_commit(
    db: &Database,
    ks: &Keyspaces,
    commit: &IndexableCommit,
) -> Result<(), IndexerError> {
    let key = commit_key(&commit.principal_id, commit.sequence);
    if ks.commits.contains_key(&key).map_err(to_backend_err)? {
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
    let existing_summary: Option<PrincipalSummary> = ks
        .principals
        .get(pid_key)
        .map_err(to_backend_err)?
        .map(|b| de(&b))
        .transpose()?;

    let commit_count = existing_summary.as_ref().map_or(0, |p| p.commit_count) + 1;
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
    // following (or vice versa), landing all writes in one all-or-nothing
    // transaction -- the same guarantee `MemoryIndexer`'s single
    // lock-guarded mutation gives, not a weaker per-keyspace-independent
    // write. The registry claim below (`meta`) rides in the same batch
    // for the identical reason.
    let mut batch = db.batch();

    batch.insert(&ks.commits, key, ser(&commit_ref)?);

    // The registry claim (S3a, c-registry-generated): re-asserted on
    // every commit, in the same atomic batch as the rows it describes,
    // so it is durably produced BY this derivation, not merely present
    // in the store from some earlier or out-of-band write.
    batch.insert(
        &ks.meta,
        META_KEY,
        ser(&IndexMeta {
            version: SCHEMA_VERSION,
            partitions: PARTITION_NAMES.iter().map(|s| s.to_string()).collect(),
        })?,
    );

    batch.insert(
        &ks.tips,
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
        &ks.principals,
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
                &ks.digests,
                digest_key.as_bytes(),
                ser(&EntityRef {
                    digest: digest_key.clone(),
                    blob_hash: coz.blob_hash,
                    entity_type,
                    sequence: Some(commit.sequence),
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
            &ks.digests,
            variant.as_bytes(),
            ser(&EntityRef {
                digest: variant.clone(),
                blob_hash: first_blob_hash,
                entity_type: EntityType::Commit,
                sequence: Some(commit.sequence),
            })?,
        );
    }

    for key_info in &commit.keys {
        batch.insert(
            &ks.public_keys,
            key_info.thumbprint.as_bytes(),
            ser(key_info)?,
        );
    }

    batch.commit().map_err(to_backend_err)
}

#[cfg(test)]
mod tests;
