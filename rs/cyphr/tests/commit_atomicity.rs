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
use cyphr::replay::{Bundle, StoredCoz, replay_bundle};
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
/// Scenario: a stored bundle carries a valid transaction (golden creates
/// `key_a`), then a transaction whose signature does not verify, then the
/// `commit/create`; replaying it is refused, and the store sees no write and
/// the principal keeps its PR, commits and log size. Turns red if: a
/// commit's leaf is written before every transaction of the bundle is
/// verified (as when a transaction already verified was appended on its
/// own). A push carries no actions after its transactions (SPEC 4.6.2
/// `actions` are recorded first), so the refused coz here is a
/// transaction. End-to-end scenario: yes (sign, bundle, replay, observe the
/// store).
#[tokio::test]
async fn refused_bundle_writes_nothing() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let key_b = pool.get("key_b").expect("key_b");
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
    let stored = |vc: &cyphr::parsed_coz::VerifiedCoz| {
        StoredCoz::new(&vc.raw().pay, vc.raw().sig.clone()).expect("stored coz")
    };
    let mut txs: Vec<Vec<StoredCoz>> = commit
        .transactions()
        .map(|tx| tx.0.iter().map(stored).collect())
        .collect();
    let keys = vec![key_a.key().expect("key")];
    // Control: the commit alone replays on a fresh principal.
    let (mut control, _) = genesis(&pool, &[]).await;
    let whole = Bundle::new(Vec::new(), txs.clone(), keys.clone()).expect("bundle");
    replay_bundle(&mut control, &whole)
        .await
        .expect("control: the commit replays");

    let (bpay, mut bsig, _) = sign(golden, key_create(golden, key_b, T + 1));
    bsig[0] ^= 0x01;
    let bpay: serde_json::Value = serde_json::from_slice(&bpay).expect("pay json");
    let closing = txs.pop().expect("commit/create");
    txs.push(vec![StoredCoz::new(&bpay, bsig).expect("stored coz")]);
    txs.push(closing);
    let bundle = Bundle::new(Vec::new(), txs, keys).expect("bundle");

    let before = observed(&p);
    let writes = probe.writes();
    let r = replay_bundle(&mut p, &bundle).await;
    assert!(
        matches!(&r, Err(e) if matches!(e.source, Error::InvalidSignature)),
        "the bundle must be refused on its bad transaction: {r:?}"
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

// ============================================================================
// A hash algorithm leaves and returns
// ============================================================================
//
// An Ed25519 principal (SHA-512) adds an ES256 key (SHA-256) and deletes
// it, SPEC 6.2: SHA-256 leaves the active set, so no later commit-log leaf
// carries a SHA-256 variant. Every signer is Ed25519, whose signatures are
// deterministic, so two runs over the same keys agree on every root.

mod algorithm_set {
    use cyphr::commit_root::{CommitTrees, commit_root_from_trees};
    use cyphr::signer::SoftwareSigner;
    use cyphr::{HashAlg, Key, Principal};
    use serde_json::json;

    use super::*;

    struct Kp {
        alg: String,
        pubb: Vec<u8>,
        prv: Vec<u8>,
        tmb: coz::Thumbprint,
    }

    fn kp(alg: coz::Alg) -> Kp {
        let k = alg.generate_keypair();
        let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
        Kp {
            alg: k.alg.name().to_string(),
            pubb: k.pub_bytes,
            prv: k.prv_bytes,
            tmb,
        }
    }

    struct Keys {
        owner: Kp,
        es256: Kp,
        es256_again: Kp,
        spare: [Kp; 4],
    }

    fn keys() -> Keys {
        Keys {
            owner: kp(coz::Alg::Ed25519),
            es256: kp(coz::Alg::ES256),
            es256_again: kp(coz::Alg::ES256),
            spare: std::array::from_fn(|_| kp(coz::Alg::Ed25519)),
        }
    }

    fn key_of(k: &Kp) -> Key {
        Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
    }

    fn signer(k: &Kp) -> SoftwareSigner {
        SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
    }

    /// One commit by `by`: `typ` (`create`/`delete`) of `id`.
    async fn commit_key<S: cyphr::eml::Storage>(
        p: &mut Principal<S>,
        by: &Kp,
        typ: &str,
        id: &Kp,
        now: i64,
    ) -> cyphr::error::Result<()> {
        let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());
        let mut pay = json!({"alg": by.alg, "id": b64(&id.tmb), "now": now,
                             "tmb": b64(&by.tmb), "typ": format!("{AUTHORITY}/cyphr/key/{typ}")});
        pay.as_object_mut().expect("pay object").sort_keys();
        let v = serde_json::to_vec(&pay).expect("serialize pay");
        let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
        let sidecar = (typ == "create").then(|| key_of(id));
        let mut scope = p.begin_commit();
        scope.verify_and_apply(&v, &sig, czd, sidecar)?;
        scope
            .finalize_with_software(&signer(by), now + 1, AUTHORITY)
            .await
            .map(|_| ())
    }

    async fn principal(k: &Keys) -> (Principal<Recording>, Arc<Probe>) {
        let (storage, probe) = recording();
        let mut p = Principal::open(key_of(&k.owner), storage)
            .await
            .expect("open");
        p.commit_genesis(&signer(&k.owner), &[], T, AUTHORITY)
            .await
            .expect("genesis commits");
        (p, probe)
    }

    /// Reopen the store as the log a restarted process finds, and read its
    /// commit root over `algs`.
    async fn reopened_cr(probe: &Probe, algs: &[HashAlg]) -> cyphr::CommitRoot {
        let trees = CommitTrees::open(probe.landed())
            .await
            .expect("the commit log reopens");
        commit_root_from_trees(&trees, algs).expect("commit root from the reopened log")
    }

    /// Three commits after the delete, none carrying a SHA-256 variant.
    async fn after(p: &mut Principal<Recording>, k: &Keys) {
        for (i, s) in k.spare.iter().take(3).enumerate() {
            let now = T + 5 + 2 * i as i64;
            commit_key(p, &k.owner, "create", s, now)
                .await
                .expect("commit after the delete");
        }
    }

    /// Claim: a principal keeps committing, and its commit log keeps
    /// reopening, after the only key of one hash algorithm is deleted.
    /// Scenario: genesis, `key/create` ES256, `key/delete` it, then three
    /// commits that carry no SHA-256 variant: six leaves. The log reopens
    /// from the store and its commit root equals the live principal's.
    /// Turns red if: the log keeps SHA-256 active while its leaves carry no
    /// SHA-256 variant, so a Merkle node over only such leaves is null,
    /// never stored, and the reopen fails on the missing frontier node.
    #[tokio::test]
    async fn log_reopens_after_the_only_key_of_an_algorithm_is_deleted() {
        let k = keys();
        let (mut p, probe) = principal(&k).await;
        commit_key(&mut p, &k.owner, "create", &k.es256, T + 1)
            .await
            .expect("create es256");
        commit_key(&mut p, &k.owner, "delete", &k.es256, T + 3)
            .await
            .expect("delete es256");
        for (i, s) in k.spare.iter().take(3).enumerate() {
            let now = T + 5 + 2 * i as i64;
            commit_key(&mut p, &k.owner, "create", s, now)
                .await
                .expect("commit after the delete");
        }
        assert_eq!(p.commit_trees().global_size(), 6);
        let algs = p.active_algs();
        assert_eq!(algs, vec![HashAlg::Sha512], "premise: SHA-256 left");
        assert_eq!(
            reopened_cr(&probe, &algs).await,
            *p.cr().expect("cr"),
            "the reopened log disagrees with the live principal"
        );
    }

    /// Claim: an algorithm that returns after its last key was deleted is
    /// the same algorithm resumed, not a second registration. Scenario: as
    /// above, then a second ES256 key is added and a further commit made.
    /// The store holds exactly two algorithms, SHA-256 with two epochs
    /// (closed at the delete, reopened at the re-add), the log reopens and
    /// its commit root over both algorithms equals the live principal's.
    /// Turns red if: a returning algorithm is left frozen or registered
    /// again, or its history across the gap is not kept.
    #[tokio::test]
    async fn a_returning_algorithm_resumes_the_one_registration() {
        let k = keys();
        let (mut p, probe) = principal(&k).await;
        commit_key(&mut p, &k.owner, "create", &k.es256, T + 1)
            .await
            .expect("create es256");
        commit_key(&mut p, &k.owner, "delete", &k.es256, T + 3)
            .await
            .expect("delete es256");
        commit_key(&mut p, &k.owner, "create", &k.spare[0], T + 5)
            .await
            .expect("commit without SHA-256");
        commit_key(&mut p, &k.owner, "create", &k.es256_again, T + 7)
            .await
            .expect("a second ES256 key");
        commit_key(&mut p, &k.owner, "create", &k.spare[1], T + 9)
            .await
            .expect("commit with SHA-256 again");

        let landed = probe.landed();
        let mut ids: Vec<u64> = landed.algorithm_metas.keys().copied().collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 3], "one registration per algorithm");
        let sha256 = landed.algorithm_metas.get(&1).expect("SHA-256 registered");
        assert_eq!(
            sha256.as_slice(),
            [(1, 2), (4, u64::MAX)],
            "SHA-256: active over leaves 1, closed at the delete's leaf 2, resumed at the \
             re-add's leaf 4"
        );
        let algs = p.active_algs();
        assert_eq!(algs.len(), 2, "premise: SHA-256 is back");
        assert_eq!(reopened_cr(&probe, &algs).await, *p.cr().expect("cr"));
    }

    /// Claim: a crash between the algorithm leaving the log and the commit's
    /// leaf landing recovers to the same roots. Scenario: the deleting
    /// commit's leaf write fails, as a crash after the algorithm's close
    /// lands and before the leaf does: the store reopens. The commit is then
    /// made again, with the same keys and times, and the commits after it;
    /// the log reopens at the same commit root as a run that never failed.
    /// Turns red if: the interrupted close strands the log (it does not
    /// reopen, or the retried commit lands a different root).
    #[tokio::test]
    async fn a_crash_between_the_algorithm_leaving_and_the_leaf_recovers() {
        let k = keys();
        // Control: no failure.
        let (mut control, control_probe) = principal(&k).await;
        commit_key(&mut control, &k.owner, "create", &k.es256, T + 1)
            .await
            .expect("create es256");
        commit_key(&mut control, &k.owner, "delete", &k.es256, T + 3)
            .await
            .expect("delete es256");
        after(&mut control, &k).await;
        let algs = control.active_algs();
        let expected = reopened_cr(&control_probe, &algs).await;

        // The run that fails once.
        let (mut p, probe) = principal(&k).await;
        commit_key(&mut p, &k.owner, "create", &k.es256, T + 1)
            .await
            .expect("create es256");
        probe.fail_appends.store(true, Ordering::SeqCst);
        let failed = commit_key(&mut p, &k.owner, "delete", &k.es256, T + 3).await;
        assert!(matches!(failed, Err(Error::Storage(_))), "got {failed:?}");
        probe.fail_appends.store(false, Ordering::SeqCst);
        CommitTrees::open(probe.landed())
            .await
            .expect("the store reopens after the interrupted commit");
        commit_key(&mut p, &k.owner, "delete", &k.es256, T + 3)
            .await
            .expect("the commit retried");
        after(&mut p, &k).await;
        assert_eq!(reopened_cr(&probe, &algs).await, expected);
        assert_eq!(*p.cr().expect("cr"), expected);
    }
}
