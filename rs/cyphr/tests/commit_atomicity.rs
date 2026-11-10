//! Commit atomicity: no commit-log (EML) leaf exists for a commit the
//! principal has not committed. A commit is two-phase: staging verifies it
//! and computes every root with nothing written, and the commit performs
//! the one durable write and adopts the staged state. Each test drives a
//! principal over a recording storage that sees every write.
//!
//! - `refused_bundle_*` (red first): a bundle whose trailing data action fails verification leaves
//!   the log and the principal untouched.
//! - `guard_*` (guard, not red first): a commit/create whose signature does not verify writes
//!   nothing.
//! - `apply_fails_*` (red first): an algorithm activation and the leaf it covers are written
//!   together or not at all.
//! - `cancel_*` (unit): dropping the finalize future at any await point before the write leaves
//!   nothing written, and the write is never separated from the adoption.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::eml::{AlgorithmMetas, MemoryStorage, Storage, WriteOp};
use cyphr::replay::{StoredCoz, replay_bundle};
use cyphr::{Error, Key, Principal};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

// ============================================================================
// Recording storage
// ============================================================================

/// What the test sees of the store a principal writes: the writes that
/// landed, a copy of the store after each, and the switches that make the
/// next write fail or suspend.
#[derive(Default)]
struct Probe {
    /// Writes (`Storage::apply` calls) that landed.
    writes: AtomicUsize,
    /// Fail every write that carries a leaf append.
    fail_appends: AtomicBool,
    /// Polls each write suspends for before it lands.
    pend: AtomicUsize,
    /// The store as of the last landed write.
    landed: Mutex<MemoryStorage>,
}

impl Probe {
    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn landed(&self) -> MemoryStorage {
        self.landed.lock().expect("probe lock").clone()
    }
}

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected write failure")
    }
}

impl std::error::Error for Refused {}

/// A [`MemoryStorage`] whose writes the [`Probe`] records, fails or
/// suspends. A failed or suspended write leaves the store as it was.
struct Recording {
    inner: MemoryStorage,
    probe: Arc<Probe>,
}

fn recording() -> (Recording, Arc<Probe>) {
    let probe = Arc::new(Probe::default());
    let storage = Recording {
        inner: MemoryStorage::new(),
        probe: probe.clone(),
    };
    (storage, probe)
}

/// Suspend once, waking at once: one await point.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn err<T>(e: <MemoryStorage as Storage>::Error) -> Result<T, Refused> {
    let _ = e;
    Err(Refused)
}

impl Storage for Recording {
    type Error = Refused;

    async fn get_leaf(&self, index: u64) -> Result<Vec<u8>, Refused> {
        self.inner.get_leaf(index).await.or_else(err)
    }

    async fn len(&self) -> Result<u64, Refused> {
        self.inner.len().await.or_else(err)
    }

    async fn get_node(
        &self,
        alg_id: u64,
        left: u64,
        height: u32,
    ) -> Result<Option<Vec<u8>>, Refused> {
        self.inner.get_node(alg_id, left, height).await.or_else(err)
    }

    async fn load_algorithm_metas(&self) -> Result<AlgorithmMetas, Refused> {
        self.inner.load_algorithm_metas().await.or_else(err)
    }

    async fn append_count(&self) -> Result<u64, Refused> {
        self.inner.append_count().await.or_else(err)
    }

    async fn apply(&mut self, ops: &[WriteOp<'_>]) -> Result<(), Refused> {
        for _ in 0..self.probe.pend.load(Ordering::SeqCst) {
            YieldOnce(false).await;
        }
        let appends = ops
            .iter()
            .any(|op| matches!(op, WriteOp::AppendLeaf { .. }));
        if appends && self.probe.fail_appends.load(Ordering::SeqCst) {
            return Err(Refused);
        }
        self.inner.apply(ops).await.or_else(err)?;
        self.probe.writes.fetch_add(1, Ordering::SeqCst);
        *self.probe.landed.lock().expect("probe lock") = self.inner.clone();
        Ok(())
    }
}

// ============================================================================
// Signed cozies
// ============================================================================

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// Sign `pay` (sorted, the form the signature covers) with pool key `k`.
fn sign(k: &test_fixtures::PoolKey, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay is an object").sort_keys();
    let bytes = serde_json::to_vec(&pay).expect("pay serializes");
    let prv =
        Base64UrlUnpadded::decode_vec(k.prv.as_deref().expect("pool key has prv")).expect("prv");
    let pubk = Base64UrlUnpadded::decode_vec(&k.pub_key).expect("pub");
    let (sig, cad) = coz::sign_json(&bytes, &k.alg, &prv, &pubk).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (bytes, sig, czd)
}

fn key_create(
    by: &test_fixtures::PoolKey,
    new: &test_fixtures::PoolKey,
    now: i64,
) -> serde_json::Value {
    serde_json::json!({
        "alg": by.alg,
        "id": new.compute_tmb_b64().expect("tmb"),
        "now": now,
        "tmb": by.compute_tmb_b64().expect("tmb"),
        "typ": format!("{AUTHORITY}/cyphr/key/create"),
    })
}

fn action(by: &test_fixtures::PoolKey, now: i64) -> serde_json::Value {
    serde_json::json!({
        "alg": by.alg,
        "msg": "hello",
        "now": now,
        "tmb": by.compute_tmb_b64().expect("tmb"),
        "typ": format!("{AUTHORITY}/comment/create"),
    })
}

/// A principal of pool key `golden` over a recording store, its genesis
/// committed (golden creates itself, then `others`).
async fn genesis(
    pool: &test_fixtures::Pool,
    others: &[&str],
) -> (Principal<Recording>, Arc<Probe>) {
    let golden = pool.get("golden").expect("golden");
    let (storage, probe) = recording();
    let mut p = Principal::open(golden.key().expect("key"), storage)
        .await
        .expect("open");
    let others: Vec<Key> = others
        .iter()
        .map(|n| pool.get(n).expect("pool key").key().expect("key"))
        .collect();
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &others,
        T,
        AUTHORITY,
    )
    .await
    .expect("genesis commits");
    (p, probe)
}

/// What a refused commit must leave unchanged.
fn observed(p: &Principal<Recording>) -> (String, usize, u64) {
    (
        p.pr_tagged().expect("pr"),
        p.commits().count(),
        p.commit_trees().global_size(),
    )
}

// ============================================================================
// Refusal after staging
// ============================================================================

/// Claim: no EML leaf exists for a commit the principal has not committed.
/// Scenario: a stored bundle carries a valid commit (golden creates
/// `key_a`) followed by a data action whose signature does not verify;
/// replaying it is refused, and the store sees no write and the principal
/// keeps its PR, commits and log size. Turns red if: a bundle's trailing
/// actions are checked after the commit's leaf is written (as when replay
/// finalized the commit before recording them). End-to-end scenario: yes
/// (sign, bundle, replay, observe the store).
#[tokio::test]
async fn refused_bundle_writes_nothing() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let (mut p, probe) = genesis(&pool, &[]).await;

    // The commit's cozies, signed on a copy so the principal itself is
    // reached only by the replay under test.
    let mut author = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("author");
    author
        .commit_genesis(
            &golden.software_signer().expect("signer"),
            &[],
            T,
            AUTHORITY,
        )
        .await
        .expect("author genesis");
    let (pay, sig, czd) = sign(golden, key_create(golden, key_a, T + 1));
    let mut scope = author.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_a.key().expect("key")))
        .expect("key/create applies");
    let commit = scope
        .finalize_with_software(&golden.software_signer().expect("signer"), T + 2, AUTHORITY)
        .await
        .expect("commit finalizes");
    let mut bundle: Vec<StoredCoz> = commit
        .iter_all_cozies()
        // The sidecar key is kept only on the key-introducing coz.
        .map(|vc| {
            StoredCoz::new(&vc.raw().pay, vc.raw().sig.clone(), key_a.key().ok())
                .expect("stored coz")
        })
        .collect();
    // Control: the commit alone replays on a fresh principal.
    let (mut control, _) = genesis(&pool, &[]).await;
    replay_bundle(&mut control, &bundle)
        .await
        .expect("control: the commit replays");

    let (apay, mut asig, _) = sign(golden, action(golden, T + 3));
    asig[0] ^= 0x01;
    let apay: serde_json::Value = serde_json::from_slice(&apay).expect("pay json");
    bundle.push(StoredCoz::new(&apay, asig, None).expect("stored coz"));

    let before = observed(&p);
    let writes = probe.writes();
    let r = replay_bundle(&mut p, &bundle).await;
    assert!(
        matches!(&r, Err(e) if matches!(e.source, Error::InvalidSignature)),
        "the bundle must be refused on its trailing action: {r:?}"
    );
    assert_eq!(probe.writes(), writes, "a refused bundle wrote to the log");
    assert_eq!(
        observed(&p),
        before,
        "a refused bundle changed the principal"
    );
}

/// Claim: the last verification of a commit, its `commit/create`
/// signature, still refuses before any write. Scenario: a commit whose
/// `commit/create` signature is corrupted, finished through `finish_commit`:
/// refused with `InvalidSignature`, no write, principal unchanged. A guard,
/// not red first: the signature has always been checked before the write.
/// Turns red if: a signature failure writes. End-to-end scenario: yes.
#[tokio::test]
async fn guard_bad_commit_signature_writes_nothing() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let (mut p, probe) = genesis(&pool, &[]).await;
    let before = observed(&p);
    let writes = probe.writes();

    let signer = golden.software_signer().expect("signer");
    let (pay, sig, czd) = sign(golden, key_create(golden, key_a, T + 1));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_a.key().expect("key")))
        .expect("key/create applies");
    let prepared = scope
        .prepare_commit(&signer, T + 2, AUTHORITY)
        .expect("prepare");
    let mut bad = signer.sign_now(prepared.cad()).expect("sign");
    bad[0] ^= 0x01;
    let r = scope.finish_commit(prepared, bad).await.map(|_| ());
    assert!(matches!(r, Err(Error::InvalidSignature)), "got {r:?}");
    assert_eq!(
        probe.writes(),
        writes,
        "a refused signature wrote to the log"
    );
    assert_eq!(
        observed(&p),
        before,
        "a refused signature changed the principal"
    );
}

// ============================================================================
// One write per commit
// ============================================================================

/// Claim: an algorithm activation and the append it covers commit together
/// or not at all. Scenario: a genesis commit, which registers the genesis
/// key's algorithm and appends its leaf, over a store whose write of the
/// append fails: the commit is refused with `Storage`, the store holds no
/// algorithm and no leaf, and the principal is still nascent. A unit test:
/// it needs a write-failure injection no scenario reaches. Turns red if:
/// the algorithm metadata or the leaf persists after the failed write (as
/// when registration and append were two writes).
#[tokio::test]
async fn apply_fails_leaves_no_algorithm_or_leaf() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let (storage, probe) = recording();
    let mut p = Principal::open(golden.key().expect("key"), storage)
        .await
        .expect("open");
    probe.fail_appends.store(true, Ordering::SeqCst);

    let r = p
        .commit_genesis(
            &golden.software_signer().expect("signer"),
            &[],
            T,
            AUTHORITY,
        )
        .await
        .map(|_| ());
    assert!(matches!(r, Err(Error::Storage(_))), "got {r:?}");
    let landed = probe.landed();
    assert!(
        landed.algorithm_metas.is_empty(),
        "a failed commit left an algorithm registered: {:?}",
        landed.algorithm_metas
    );
    assert!(landed.leaves.is_empty(), "a failed commit left a leaf");
    assert_eq!(probe.writes(), 0, "a failed commit wrote");
    assert!(
        p.pg().is_none(),
        "a failed genesis established the principal"
    );
    assert!(p.commit_trees().is_empty(), "the in-memory log moved");
}

// ============================================================================
// Cancellation
// ============================================================================

/// Claim: cancelling a commit leaves nothing; the one write is never
/// separated from the adoption. Scenario: a commit over a store whose write
/// suspends for `PEND` polls; the finalize future is dropped after each
/// number of polls in turn. Before the write lands the store and the
/// principal are untouched; once the future completes both moved together.
/// At no drop point is a write landed without the principal adopting it.
/// A unit test: only a hand-polled future reaches each await point, which
/// no scenario can. Turns red if: a write happens before the final step,
/// or an await separates the write from the adoption.
#[tokio::test]
async fn cancel_at_every_await_point_leaves_nothing() {
    const PEND: usize = 3;
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let signer = golden.software_signer().expect("signer");

    let mut completed_at = None;
    for polls in 0..=PEND + 2 {
        let (mut p, probe) = genesis(&pool, &[]).await;
        probe.pend.store(PEND, Ordering::SeqCst);
        let before = observed(&p);
        let writes = probe.writes();
        let (pay, sig, czd) = sign(golden, key_create(golden, key_a, T + 1));

        let done = {
            let mut scope = p.begin_commit();
            scope
                .verify_and_apply(&pay, &sig, czd, Some(key_a.key().expect("key")))
                .expect("key/create applies");
            let mut fut = std::pin::pin!(scope.finalize_with_software(&signer, T + 2, AUTHORITY));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut done = false;
            for _ in 0..polls {
                if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
                    r.expect("commit completes");
                    done = true;
                    break;
                }
            }
            done
            // The future is dropped here, mid-flight unless `done`.
        };

        let after = observed(&p);
        if done {
            completed_at.get_or_insert(polls);
            assert_eq!(
                probe.writes(),
                writes + 1,
                "a completed commit is one write"
            );
            assert_eq!(after.1, before.1 + 1, "a completed commit was not adopted");
            assert_eq!(after.2, before.2 + 1, "a completed commit has its leaf");
        } else {
            assert_eq!(
                probe.writes(),
                writes,
                "dropped after {polls} polls: a write landed"
            );
            assert_eq!(
                after, before,
                "dropped after {polls} polls: the principal moved"
            );
        }
    }
    assert_eq!(
        completed_at,
        Some(PEND + 1),
        "the commit must suspend exactly at the store's await points"
    );
}
