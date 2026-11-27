//! The server's write order (root `AGENTS.md` I1: the blob store is the
//! source of truth; the commit log and the index are rebuildable caches):
//! a pushed commit is verified and staged, then its blobs and manifest are
//! stored, then the principal's commit log (EML) is written, then the
//! index. The EML is never ahead of the blob store.
//!
//! Each test drives the server's own storage stack (one fjall database for
//! blobs and every principal's EML, a fjall index, laid out as the server's
//! data directory lays them out) through the engine's push path with one
//! write made to fail, then reopens the same data directory as a real
//! server and pushes through HTTP. The fault is injected below the server
//! because the server builds its engine over concrete backends with no
//! fault seam.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use cyphr::eml::{AlgorithmMetas, Storage, WriteOp};
use cyphr::replay::WireBundle;
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_index_fjall::FjallIndexer;
use cyphr_server::config::ServerConfig;
use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use cyphr_storage::engine::{COMMIT_MANIFEST_PREFIX, LogFactory, StorageEngine};

const GENESIS_NOW: i64 = 1_700_000_000;

// ============================================================================
// Fault-injecting backends
// ============================================================================

/// The server's blob store, with commit-manifest writes failing on demand.
struct Blobs {
    inner: FjallBlobStore,
    fail_manifests: Arc<AtomicBool>,
}

impl BlobStore for Blobs {
    async fn persist(&self) -> Result<(), BlobStoreError> {
        self.inner.persist().await
    }

    async fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        if data.starts_with(COMMIT_MANIFEST_PREFIX) && self.fail_manifests.load(Ordering::SeqCst) {
            return Err(BlobStoreError::Backend(
                "injected manifest write failure".into(),
            ));
        }
        self.inner.put(data).await
    }

    async fn get(&self, hash: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        self.inner.get(hash).await
    }

    async fn exists(&self, hash: &Blake3Hash) -> Result<bool, BlobStoreError> {
        self.inner.exists(hash).await
    }

    async fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>, BlobStoreError>
    {
        self.inner.iter().await
    }
}

#[derive(Debug)]
struct Injected;

impl std::fmt::Display for Injected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected EML write failure")
    }
}

impl std::error::Error for Injected {}

/// A principal's durable EML, with writes failing on demand.
struct Eml {
    inner: FjallStorage,
    fail_writes: Arc<AtomicBool>,
}

fn lift<T>(r: Result<T, <FjallStorage as Storage>::Error>) -> Result<T, Injected> {
    r.map_err(|_| Injected)
}

impl Storage for Eml {
    type Error = Injected;

    async fn get_leaf(&self, index: u64) -> Result<Vec<u8>, Injected> {
        lift(self.inner.get_leaf(index).await)
    }

    async fn len(&self) -> Result<u64, Injected> {
        lift(self.inner.len().await)
    }

    async fn get_node(
        &self,
        alg_id: u64,
        left: u64,
        height: u32,
    ) -> Result<Option<Vec<u8>>, Injected> {
        lift(self.inner.get_node(alg_id, left, height).await)
    }

    async fn load_algorithm_metas(&self) -> Result<AlgorithmMetas, Injected> {
        lift(self.inner.load_algorithm_metas().await)
    }

    async fn append_count(&self) -> Result<u64, Injected> {
        lift(self.inner.append_count().await)
    }

    async fn apply(&mut self, ops: &[WriteOp<'_>]) -> Result<(), Injected> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(Injected);
        }
        lift(self.inner.apply(ops).await)
    }
}

/// The durable logs, each opened behind the EML write-fault switch.
struct Logs {
    inner: cyphr_blob_fjall::EmlLogs,
    fail_writes: Arc<AtomicBool>,
}

impl LogFactory<Eml> for Logs {
    fn generation(&self, principal_id: &cyphr::PrincipalGenesis) -> Result<u64, String> {
        self.inner.generation(principal_id)
    }

    fn open(&self, principal_id: &cyphr::PrincipalGenesis, generation: u64) -> Result<Eml, String> {
        Ok(Eml {
            inner: self.inner.open(principal_id, generation)?,
            fail_writes: self.fail_writes.clone(),
        })
    }

    fn retire_below(
        &self,
        principal_id: &cyphr::PrincipalGenesis,
        generation: u64,
    ) -> Result<(), String> {
        self.inner.retire_below(principal_id, generation)
    }
}

/// The server's storage stack over `config`'s data directory, with both
/// fault switches.
struct Stack {
    engine: StorageEngine<Blobs, FjallIndexer, Eml>,
    db: fjall::Database,
    fail_manifests: Arc<AtomicBool>,
    fail_eml: Arc<AtomicBool>,
}

fn stack(config: &ServerConfig) -> Stack {
    let db = fjall::Database::builder(config.blobs_dir())
        .open()
        .expect("open blob database");
    let fail_manifests = Arc::new(AtomicBool::new(false));
    let fail_eml = Arc::new(AtomicBool::new(false));
    let blobs = Blobs {
        inner: FjallBlobStore::from_database(db.clone()).expect("blob store"),
        fail_manifests: fail_manifests.clone(),
    };
    let indexer = FjallIndexer::open(&config.index_dir()).expect("index");
    let logs = Logs {
        inner: cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
        fail_writes: fail_eml.clone(),
    };
    let engine = StorageEngine::with_log_factory(blobs, indexer, logs);
    Stack {
        engine,
        db,
        fail_manifests,
        fail_eml,
    }
}

/// How many leaves the principal's durable EML holds.
async fn eml_leaves(db: &fjall::Database, principal_id: &cyphr::PrincipalGenesis) -> u64 {
    let logs = cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs");
    let generation = logs.generation(principal_id).expect("generation");
    let storage = logs.open(principal_id, generation).expect("open EML");
    cyphr::CommitTrees::open(storage)
        .await
        .expect("reopen EML")
        .global_size()
}

// ============================================================================
// Commits
// ============================================================================

/// The standard principal (`golden` with `key_a`) and the blobs of its
/// genesis commit and of two further commits (golden creates `key_b`,
/// then `alice`), each wire-ready.
async fn chain(pool: &test_fixtures::Pool) -> (cyphr::PrincipalGenesis, [WireBundle; 3]) {
    let id = common::golden_principal_id(pool).await;
    let mut p = cyphr::Principal::implicit(pool.get("golden").expect("golden").key().expect("key"))
        .await
        .expect("genesis");
    let genesis = test_fixtures::bundle::genesis_bundle(
        &mut p,
        pool.get("golden").expect("golden"),
        &[pool.get("key_a").expect("key_a").key().expect("key")],
        GENESIS_NOW,
    )
    .await
    .expect("genesis commit");
    let second = common::sign_key_create_commit(
        p.fork().await.expect("fork"),
        pool,
        "golden",
        "key_b",
        GENESIS_NOW + 100,
    )
    .await;
    cyphr::replay::replay_bundle(&mut p, &second.decode().expect("wire bundle"))
        .await
        .expect("second commit replays");
    let third = common::sign_key_create_commit(p, pool, "golden", "alice", GENESIS_NOW + 200).await;
    (id, [genesis, second, third])
}

fn push_body(id: &cyphr::PrincipalGenesis, bundle: &WireBundle) -> String {
    common::push_body(id, bundle)
}

/// Reopen the data directory as a real server and push `blobs` over HTTP.
async fn push_through_server(
    config: &ServerConfig,
    id: &cyphr::PrincipalGenesis,
    blobs: &WireBundle,
) -> StatusCode {
    let state = Arc::new(cyphr_server::AppState::new(config.clone()).expect("server opens"));
    let app = cyphr_server::build_router(state);
    let (status, body) = common::post_json(app, "/push", push_body(id, blobs)).await;
    assert!(
        status.is_success(),
        "push through the server: {status} {body:?}"
    );
    status
}

// ============================================================================
// Tests
// ============================================================================

/// Claim: the EML is never ahead of the blob store (I1). Scenario: a push
/// whose manifest write fails after the commit is staged is refused, and
/// leaves no EML leaf and no index entry for it; the server reopened over
/// the same data directory then accepts the same push. Turns red if: the
/// commit's EML leaf is written before its manifest. End-to-end scenario:
/// yes (signed commits, the server's stack, then the server over HTTP).
#[tokio::test]
async fn manifest_failure_leaves_no_eml_leaf_or_index_entry() {
    let pool = common::load_pool();
    let (id, [genesis, second, _]) = chain(&pool).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    {
        let s = stack(&config);
        s.engine
            .submit_commit(&id, None, &genesis)
            .await
            .expect("genesis push");
        s.fail_manifests.store(true, Ordering::SeqCst);
        let refused = s.engine.submit_commit(&id, None, &second).await;
        assert!(
            refused.is_err(),
            "a push whose manifest failed must be refused"
        );

        assert_eq!(
            eml_leaves(&s.db, &id).await,
            1,
            "the refused commit has an EML leaf"
        );
        let tip = s
            .engine
            .get_tip(&id)
            .await
            .expect("tip")
            .expect("known principal");
        assert_eq!(tip.commit_count, 1, "the refused commit is indexed");
    }
    push_through_server(&config, &id, &second).await;
}

/// Claim: a commit whose EML write fails after its manifest is still the
/// committed record; the EML is behind, never ahead, and the next load
/// repairs it. Scenario: the push is accepted with the manifest stored and
/// indexed and the EML one leaf behind; the server reopened over the same
/// data directory accepts the next push, whose load replays the stored
/// commit onto the log with no `DurableLeafMismatch`, leaving the EML whole.
/// Turns red if: the core writes the EML before the manifest (the failed
/// write then refuses the push and stores no manifest), or the failed
/// append is not counted (the `cyphr_eml_append_failures_total` metric
/// reads that count). End-to-end scenario: yes.
#[tokio::test]
async fn eml_failure_after_manifest_is_repaired_by_the_next_load() {
    let pool = common::load_pool();
    let (id, [genesis, second, third]) = chain(&pool).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    {
        let s = stack(&config);
        s.engine
            .submit_commit(&id, None, &genesis)
            .await
            .expect("genesis push");
        s.fail_eml.store(true, Ordering::SeqCst);
        let accepted = s.engine.submit_commit(&id, None, &second).await;
        let accepted = accepted.expect("the commit is recorded once its manifest is stored");
        assert!(accepted.manifest_hash.is_some(), "the manifest is stored");

        let tip = s
            .engine
            .get_tip(&id)
            .await
            .expect("tip")
            .expect("known principal");
        assert_eq!(tip.commit_count, 2, "the recorded commit is indexed");
        assert_eq!(
            eml_leaves(&s.db, &id).await,
            1,
            "the EML is behind by the failed write"
        );
        assert_eq!(
            s.engine.log_append_failures(),
            1,
            "the failed append is counted, so `/metrics` shows a log that keeps failing"
        );
    }
    push_through_server(&config, &id, &third).await;
    let db = fjall::Database::builder(config.blobs_dir())
        .open()
        .expect("reopen blob database");
    assert_eq!(
        eml_leaves(&db, &id).await,
        3,
        "the next load repaired the EML"
    );
}

/// Claim: a read that derives roots (the one behind signed `/tip` roots and
/// portable proofs) answered after an EML append failed, and before any
/// further push, is correct and leaves the log whole. The log is a cache of
/// the stored record (I1), so the read repairs it by replaying the manifest
/// rather than serving the stale log or refusing. Scenario: after the
/// failed append the engine derives the roots; they equal those of a twin
/// store that never failed, and the EML then holds every commit.
/// Turns red if: the read serves roots from the log that is a leaf behind,
/// refuses with a leaf mismatch, or leaves the EML short. End-to-end
/// scenario: yes (signed commits through the server's own stack).
#[tokio::test]
async fn proof_read_after_an_eml_failure_repairs_the_log() {
    let pool = common::load_pool();
    let (id, [genesis, second, _]) = chain(&pool).await;

    let healthy_dir = tempfile::tempdir().expect("tempdir");
    let healthy = stack(&ServerConfig {
        data_dir: healthy_dir.path().to_path_buf(),
        ..Default::default()
    });
    for bundle in [&genesis, &second] {
        healthy
            .engine
            .submit_commit(&id, None, bundle)
            .await
            .expect("healthy push");
    }
    let expected = healthy.engine.rederive_roots(&id).await.expect("roots");

    let dir = tempfile::tempdir().expect("tempdir");
    let s = stack(&ServerConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    });
    s.engine
        .submit_commit(&id, None, &genesis)
        .await
        .expect("genesis push");
    s.fail_eml.store(true, Ordering::SeqCst);
    s.engine
        .submit_commit(&id, None, &second)
        .await
        .expect("the commit is recorded once its manifest is stored");
    assert_eq!(eml_leaves(&s.db, &id).await, 1, "the EML is behind");
    s.fail_eml.store(false, Ordering::SeqCst);

    let derived = s
        .engine
        .rederive_roots(&id)
        .await
        .expect("a roots read after the failed append");
    assert_eq!(
        (&derived.pr, &derived.sr, &derived.ar, &derived.cr),
        (&expected.pr, &expected.sr, &expected.ar, &expected.cr),
        "the read served roots that differ from a store whose log never failed"
    );
    assert_eq!(
        eml_leaves(&s.db, &id).await,
        2,
        "the read left the EML short of the stored commits"
    );
}
