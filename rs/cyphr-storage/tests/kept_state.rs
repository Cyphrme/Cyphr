//! U3: a write checks the extension, not the history (keep what was
//! verified, apply only what arrives).
//!
//! The engine keeps each principal's verified state between its uses,
//! used only while the index names the tip it stands at. These tests hold
//! that to the replay of the stored chain, which is the truth (root
//! `AGENTS.md` I1): the cost of a write does not grow with the history, and
//! the kept path answers exactly as a replay does, over refused bundles and
//! revokes too.
//!
//! Every engine here keeps its commit logs in fjall, as the server does:
//! over the in-memory logs a log never outlives its principal's replay,
//! so there is nothing for a kept state to resume.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;
use proptest::prelude::*;

const NOW: i64 = 1_700_300_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer, FjallStorage>;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn load_pool() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

fn kp(name: &str) -> Kp {
    let pool = load_pool();
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        // Keys that are only ever created (never sign) may be public-only.
        prv: pk
            .prv
            .as_ref()
            .map(|p| Base64UrlUnpadded::decode_vec(p).expect("prv b64"))
            .unwrap_or_default(),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// `signer` applies `pay` (optionally introducing `sidecar`) as a commit of
/// its own at `now`. False if the principal refuses it, leaving `p` as it
/// was.
async fn try_apply(
    p: &mut cyphr::Principal,
    signer: &Kp,
    pay: serde_json::Value,
    sidecar: Option<cyphr::Key>,
    now: i64,
) -> bool {
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    if scope.verify_and_apply(&pay, &sig, czd, sidecar).is_err() {
        return false;
    }
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .is_ok()
}

fn pay(typ: &str, signer: &Kp, id: Option<&Kp>, now: i64) -> serde_json::Value {
    let mut pay = serde_json::json!({
        "alg": signer.alg, "now": now, "tmb": signer.tmb.to_b64(),
        "typ": format!("cyphr.me/cyphr/{typ}"),
    });
    if let Some(id) = id {
        pay["id"] = serde_json::json!(id.tmb.to_b64());
    }
    // The signature covers the sorted form (the map keeps insertion order).
    pay.as_object_mut().expect("pay is an object").sort_keys();
    pay
}

fn bundle_at(p: &cyphr::Principal, i: usize) -> WireBundle {
    WireBundle::of_commit(p.commits().nth(i).expect("commit")).expect("bundle")
}

/// `k`'s self-signed naked revoke (SPEC 6.4).
fn naked_revoke(k: &Kp, rvk: i64) -> serde_json::Value {
    let pay = serde_json::json!({
        "alg": k.alg, "now": rvk, "rvk": rvk, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &k.alg, &k.prv, &k.pubb).expect("sign");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": k.alg, "pub": Base64UrlUnpadded::encode_string(&k.pubb)},
    })
}

/// An engine over fjall commit logs: `kept` principals' states kept
/// (0 = none, every write replays), and every use of one checked against a
/// cold replay when `shadow` (which replays, so it is off where replays
/// are counted). The second handle opens the same logs the engine does.
fn engine_with_logs(
    kept: usize,
    shadow: bool,
) -> (Engine, cyphr_blob_fjall::EmlLogs, tempfile::TempDir) {
    let stores = Stores::new();
    let logs = cyphr_blob_fjall::EmlLogs::new(stores.db.clone()).expect("logs");
    (stores.engine(kept, shadow), logs, stores.dir)
}

fn engine(kept: usize, shadow: bool) -> (Engine, tempfile::TempDir) {
    let (e, _logs, dir) = engine_with_logs(kept, shadow);
    (e, dir)
}

/// What outlives an engine: the blobs and the commit logs. An engine opened
/// over them again is the process restarted: it holds no kept state and
/// rebuilds its index from the blobs.
struct Stores {
    blobs: MemoryBlobStore,
    db: fjall::Database,
    dir: tempfile::TempDir,
}

impl Stores {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fjall::Database::builder(dir.path().join("db"))
            .open()
            .expect("open db");
        Self {
            blobs: MemoryBlobStore::new(),
            db,
            dir,
        }
    }

    fn engine(&self, kept: usize, shadow: bool) -> Engine {
        StorageEngine::with_log_factory(
            self.blobs.clone(),
            MemoryIndexer::new(),
            cyphr_blob_fjall::EmlLogs::new(self.db.clone()).expect("logs"),
        )
        .with_kept_states(kept)
        .with_kept_shadow(shadow)
    }
}

/// A principal of genesis keys `golden`, `key_a` after its genesis commit,
/// with the id and genesis the engine stores it under.
struct World {
    id: String,
    genesis: Genesis,
    shadow: cyphr::Principal,
    golden: Kp,
}

impl World {
    async fn new() -> Self {
        let (golden, key_a) = (kp("golden"), kp("key_a"));
        let mut shadow = cyphr::Principal::implicit(key_of(&golden))
            .await
            .expect("genesis");
        shadow
            .commit_genesis(&signer_of(&golden), &[key_of(&key_a)], NOW, "cyphr.me")
            .await
            .expect("genesis commit");
        let id = test_fixtures::bundle::genesis_id(&bundle_at(&shadow, 0)).expect("id");
        Self {
            id,
            genesis: Genesis::Disclosed(vec![key_of(&golden), key_of(&key_a)]),
            shadow,
            golden,
        }
    }

    async fn submit(&self, e: &Engine, bundle: &WireBundle) -> Result<(), String> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), bundle)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    /// The next commit creating or deleting pool key `name` (whichever it
    /// is not), on a copy of the shadow chain; adopt it with
    /// [`Self::adopt`] once an engine accepted it.
    async fn toggle(&self, name: &str, now: i64) -> Option<(cyphr::Principal, WireBundle)> {
        let k = kp(name);
        let mut next = self.shadow.fork().await.expect("fork");
        let created = if self.shadow.is_key_active(&k.tmb) {
            try_apply(
                &mut next,
                &self.golden,
                pay("key/delete", &self.golden, Some(&k), now),
                None,
                now,
            )
            .await
        } else {
            try_apply(
                &mut next,
                &self.golden,
                pay("key/create", &self.golden, Some(&k), now),
                Some(key_of(&k)),
                now,
            )
            .await
        };
        let at = next.commits().count() - 1;
        created.then(|| {
            let bundle = bundle_at(&next, at);
            (next, bundle)
        })
    }

    fn adopt(&mut self, next: cyphr::Principal) {
        self.shadow = next;
    }

    fn last(&self) -> WireBundle {
        bundle_at(&self.shadow, self.shadow.commits().count() - 1)
    }
}

/// The state of the stored chain, replayed cold, as the pretty-printed
/// `Debug` the states are compared by (every field is in it).
async fn replayed(e: &Engine, w: &World) -> String {
    let p = e
        .load_principal(&w.id, w.genesis.clone())
        .await
        .expect("replay");
    format!("{:#?}", *p)
}

/// Fail naming the first line where two printed states differ: the whole
/// state is too long to read.
fn assert_same_state(kept: &str, replayed: &str, what: &str) {
    if kept == replayed {
        return;
    }
    let at = kept
        .lines()
        .zip(replayed.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| kept.lines().count().min(replayed.lines().count()));
    let window = |s: &str| {
        s.lines()
            .skip(at.saturating_sub(3))
            .take(8)
            .collect::<Vec<_>>()
            .join("\n")
    };
    panic!(
        "{what}: first difference at line {at}\n--- kept\n{}\n--- replayed\n{}",
        window(kept),
        window(replayed)
    );
}

/// A principal of `n` commits: the genesis commit, then `n - 1` that toggle
/// `key_b` in and out.
async fn history(e: &Engine, n: usize) -> World {
    let mut w = World::new().await;
    w.submit(e, &w.last()).await.expect("genesis commit");
    for i in 1..n {
        let (next, bundle) = w
            .toggle("key_b", NOW + 10 * i as i64)
            .await
            .expect("a toggle of key_b applies");
        w.submit(e, &bundle)
            .await
            .unwrap_or_else(|err| panic!("toggle {i}: {err}"));
        w.adopt(next);
    }
    w
}

/// The commits replayed by one more write on a principal of `n` commits.
async fn replayed_by_next_write(e: &Engine, n: usize) -> u64 {
    let mut w = history(e, n).await;
    let before = e.commits_replayed();
    let (next, bundle) = w
        .toggle("key_b", NOW + 10 * n as i64)
        .await
        .expect("a toggle of key_b applies");
    w.submit(e, &bundle).await.expect("the write");
    w.adopt(next);
    e.commits_replayed() - before
}

/// U3, the cost: the commits one write replays do not depend on how many
/// the principal already has. Today a write replays them all (O(n)
/// signature checks per write, so O(n^2) to build a history), where the
/// kept state checks only the extension. Red with `with_kept_states(0)`
/// (every write replays: 8 and 40), green with the default.
#[tokio::test]
async fn u3_a_write_replays_a_bounded_number_of_commits() {
    let (e, _dir) = engine(128, false);
    let short = replayed_by_next_write(&e, 8).await;
    let (e, _dir) = engine(128, false);
    let long = replayed_by_next_write(&e, 40).await;
    assert_eq!(
        (short, long),
        (0, 0),
        "a write after a history of 8 commits replayed {short}, after 40 replayed {long}"
    );

    // The control the claim is red against: no kept state, every write
    // replays the principal's whole history.
    let (cold, _dir) = engine(0, false);
    assert_eq!(replayed_by_next_write(&cold, 8).await, 8);
}

/// One step of a generated history.
#[derive(Debug, Clone)]
enum Op {
    Toggle(usize),
    ReplayLast,
    Damage,
    Revoke(usize),
    /// A data action by `ACTORS[k]` dated `offset` seconds after this op's
    /// time: ahead of the chain, so a later commit can void it.
    Act(usize, i64),
    /// A rival of the chain's second commit: a fork that puts the
    /// principal in Error (SPEC 15.5) until a commit extends the head.
    Rival,
    /// The keeping engine restarted over its blobs and logs: nothing kept,
    /// the index rebuilt.
    Restart,
}

const TOGGLED: [&str; 3] = ["key_b", "alice", "bob"];
// Keys that can sign their own revoke; `alice` and `bob` are also toggled.
const REVOKED: [&str; 3] = ["key_a", "alice", "bob"];
const ACTORS: [&str; 2] = ["key_a", "golden"];

/// A history of generated steps behind the two that reach the fork path:
/// a toggle (so the chain has a second commit) and a rival of it. Left to
/// chance the rival came up in too few of 16 cases to catch a defect that
/// only a rival exposes (the merge gate found one at 128 cases and not at
/// 16), so every case reaches it and the steps after it are free.
fn ops() -> impl Strategy<Value = Vec<Op>> {
    steps().prop_map(|rest| {
        let mut ops = vec![Op::Toggle(0), Op::Rival];
        ops.extend(rest);
        ops
    })
}

fn steps() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(
        prop_oneof![
            4 => (0..TOGGLED.len()).prop_map(Op::Toggle),
            1 => Just(Op::ReplayLast),
            1 => Just(Op::Damage),
            1 => (0..REVOKED.len()).prop_map(Op::Revoke),
            3 => (0..ACTORS.len(), 1..80i64).prop_map(|(k, off)| Op::Act(k, off)),
            1 => Just(Op::Rival),
            1 => Just(Op::Restart),
        ],
        0..7,
    )
}

fn damaged(mut bundle: WireBundle) -> WireBundle {
    let last = bundle.txs.last_mut().and_then(|tx| tx.last_mut());
    let coz = last.expect("a coz");
    let mut v: serde_json::Value = serde_json::from_slice(coz).expect("coz json");
    let sig = v["sig"].as_str().expect("sig").to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    v["sig"] = serde_json::json!(format!("{flipped}{}", &sig[1..]));
    *coz = serde_json::to_vec(&v).expect("coz bytes");
    bundle
}

async fn run(ops: Vec<Op>) {
    let stores = Stores::new();
    let mut kept = stores.engine(8, true);
    let (cold, _d2) = engine(0, false);
    let mut w = World::new().await;
    for e in [&kept, &cold] {
        w.submit(e, &w.last()).await.expect("genesis commit");
    }
    let mut rival = w.shadow.fork().await.expect("fork");
    let key = kp("alice");
    assert!(
        try_apply(
            &mut rival,
            &w.golden,
            pay("key/create", &w.golden, Some(&key), NOW + 1),
            Some(key_of(&key)),
            NOW + 1
        )
        .await
    );
    for (i, op) in ops.into_iter().enumerate() {
        let now = NOW + 10 * (i as i64 + 1);
        let (bundle, next) = match op {
            Op::Toggle(k) => match w.toggle(TOGGLED[k], now).await {
                Some((next, bundle)) => (bundle, Some(next)),
                None => continue,
            },
            Op::ReplayLast => (w.last(), None),
            Op::Rival if w.shadow.commits().count() < 2 => continue,
            Op::Rival => (bundle_at(&rival, 1), None),
            Op::Act(k, off) => (
                WireBundle::actions(vec![action_blob(&kp(ACTORS[k]), now + off)]),
                None,
            ),
            Op::Damage => (damaged(w.last()), None),
            Op::Restart => {
                kept = stores.engine(8, true);
                continue;
            },
            Op::Revoke(k) => {
                // Received between this op's time and the next's.
                let evidence = naked_revoke(&kp(REVOKED[k]), now);
                for e in [&kept, &cold] {
                    e.record_revoke(&evidence, now + 5).await.expect("revoke");
                }
                continue;
            },
        };
        let (a, b) = (
            w.submit(&kept, &bundle).await,
            w.submit(&cold, &bundle).await,
        );
        assert_eq!(
            a, b,
            "op {i}: the kept path and the replay disagree on a bundle"
        );
        if let (Ok(()), Some(next)) = (a, next) {
            w.adopt(next);
        }
        let tips = [
            kept.get_tip(&w.id).await.expect("tip"),
            cold.get_tip(&w.id).await.expect("tip"),
        ];
        assert_eq!(tips[0], tips[1], "op {i}: tips differ");
        let cold_replay = replayed(&kept, &w).await;
        if let Some(state) = kept.kept_state(&w.id).await {
            assert_same_state(
                &format!("{state:#?}"),
                &cold_replay,
                &format!("op {i}: the kept state is not the replay of the stored chain"),
            );
        }
        // A reader gets the same state, kept or replayed, and leaves it
        // kept for the next write.
        let read = kept.at_tip(&w.id).await.expect("read").expect("stored");
        assert_same_state(
            &format!("{:#?}", **read),
            &cold_replay,
            &format!("op {i}: a reader's state is not the replay of the stored chain"),
        );
    }
    assert_eq!(
        kept.kept_divergences(),
        0,
        "a shadow check found a divergence"
    );
}

proptest! {
    // Each case builds two engines over a fresh fjall database.
    #![proptest_config(ProptestConfig::with_cases(16))]
    /// U3, I1: a state the engine keeps is a cache of the replay of the stored
    /// chain, never another answer. Over arbitrary histories of key toggles,
    /// refused bundles (a reused commit, a damaged signature), naked
    /// revokes, restarts and reads, an engine that keeps states and one that
    /// replays every write
    /// give the same verdict on every bundle and hold the same tip, and the
    /// state the first keeps is the state the replay of its blobs builds
    /// (the engine's shadow check, on, replays cold at every use and fails the
    /// write on a difference).
    #[test]
    fn u3_the_kept_path_equals_the_replay(ops in ops()) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(run(ops));
    }
}

/// U3, refusal leaves no trace: bad bundles must not be a way to make the
/// next write replay. A reused commit and a damaged signature are refused
/// and the next honest write is still served from the kept state.
#[tokio::test]
async fn u3_a_refusal_costs_the_kept_state_nothing() {
    let (e, _dir) = engine(8, false);
    let mut w = history(&e, 3).await;
    let (hits, misses) = (e.kept_hits(), e.kept_misses());

    for refused in [w.last(), damaged(w.last())] {
        assert!(w.submit(&e, &refused).await.is_err(), "refused");
    }
    let (next, bundle) = w.toggle("alice", NOW + 100).await.expect("toggle");
    w.submit(&e, &bundle).await.expect("honest write");
    w.adopt(next);
    assert_eq!(
        (e.kept_hits() - hits, e.kept_misses() - misses),
        (3, 0),
        "a refused bundle, or the write after two, was not served from the kept state"
    );

    assert_eq!(e.kept_divergences(), 0);
}

/// A naked revoke gates what arrives after it and judges nothing held
/// (SPEC 6.4, 14.12), so it is no part of what a kept state was folded
/// from: a revoke of a key the principal never held, and one of its own
/// key, each leave the state kept and the next write replaying nothing.
/// One revoke of any key otherwise makes every principal of the server
/// replay its history, and anyone can sign one. The gate itself holds: an
/// action the revoked key signs at or after the cutoff is refused, one
/// dated before it admitted.
#[tokio::test]
async fn a_naked_revoke_leaves_every_kept_state_kept() {
    let (e, _dir) = engine(8, false);
    let mut w = history(&e, 3).await;
    for (i, name) in ["bob", "key_a"].into_iter().enumerate() {
        e.record_revoke(&naked_revoke(&kp(name), NOW + 110), NOW + 115)
            .await
            .expect("revoke");
        assert!(
            e.kept_state(&w.id).await.is_some(),
            "a revoke of {name} dropped the kept state"
        );
        let at = e.commits_replayed();
        let (next, bundle) = w
            .toggle("alice", NOW + 200 + 10 * i as i64)
            .await
            .expect("toggle");
        w.submit(&e, &bundle).await.expect("write");
        w.adopt(next);
        assert_eq!(
            e.commits_replayed() - at,
            0,
            "the write after a revoke of {name} replayed the chain"
        );
    }
    let by_key_a = |now| WireBundle::actions(vec![action_blob(&kp("key_a"), now)]);
    assert!(
        w.submit(&e, &by_key_a(NOW + 115)).await.is_err(),
        "an action dated at the cutoff is refused"
    );
    w.submit(&e, &by_key_a(NOW + 114))
        .await
        .expect("an action dated before the cutoff is admitted");
    assert_eq!(e.kept_divergences(), 0);
}

/// A refused write leaves the principal's verified state kept, whether the
/// write resumed it or replayed it: after a restart nothing is kept, and a
/// refused bundle is free to send, so a refusal that dropped the replayed
/// state would cost a whole replay per bundle, for every principal. The
/// first refusal after the restart replays the chain once; the second
/// replays nothing.
///
/// The replay count is the engine's own: both refusals answer alike, so no
/// response can tell them apart.
#[tokio::test]
async fn a_refused_write_to_an_unkept_principal_replays_once() {
    let stores = Stores::new();
    let mut w = history(&stores.engine(8, false), 5).await;
    let e = stores.engine(8, false);
    assert!(e.get_tip(&w.id).await.expect("tip").is_some(), "rebuilt");
    assert!(e.kept_state(&w.id).await.is_none(), "nothing kept yet");
    let mut replayed = Vec::new();
    for _ in 0..2 {
        let at = e.commits_replayed();
        assert!(w.submit(&e, &damaged(w.last())).await.is_err(), "refused");
        replayed.push(e.commits_replayed() - at);
    }
    assert_eq!(replayed, [5, 0], "commits replayed by each refusal");
    assert!(e.kept_state(&w.id).await.is_some(), "kept by the refusal");

    // The replayed state is kept as any other: the writes after it are
    // served from it, each leaving its own state kept.
    let at = e.commits_replayed();
    for i in 0..2 {
        let (next, bundle) = w.toggle("alice", NOW + 500 + i).await.expect("toggle");
        w.submit(&e, &bundle).await.expect("honest write");
        w.adopt(next);
    }
    assert_eq!(e.commits_replayed() - at, 0, "writes after the refusals");
}

/// A refused bundle that is no rival costs index reads bounded by the
/// bundle, whatever the principal's history: a commit whose signature does
/// not verify, and a commit the chain already holds pushed again. Both are
/// free to send (the second is served by `/patch` to anyone), so a refusal
/// that read the chain to decide would let anyone make the store read a
/// principal's whole history per request.
///
/// Counted at the engine's one chain read, over histories of 4 and of 24
/// commits: the refusals are the same either way, and no signature is
/// replayed, so only the count shows the read.
#[tokio::test]
async fn a_refused_bundle_that_is_no_rival_reads_no_more_as_history_grows() {
    let mut rows = Vec::new();
    for n in [4, 24] {
        let (e, _dir) = engine(8, false);
        let w = history(&e, n).await;
        let before = e.chain_rows_read();
        for refused in [damaged(w.last()), bundle_at(&w.shadow, 1)] {
            assert!(w.submit(&e, &refused).await.is_err(), "refused");
        }
        rows.push(e.chain_rows_read() - before);
    }
    assert_eq!(
        rows[0], rows[1],
        "index commit records read by two refusals, over 4 commits and over 24"
    );
}

/// U3: a state resumes only over the commit log it was folded from, so a
/// kept state that fell behind its log (a regenerated or newer log) is
/// refused rather than extended: the log holds a different number of
/// commits than the state. `Principal::resume` is the core's one check of
/// it; the engine falls back to the replay on the refusal.
#[tokio::test]
async fn u3_resume_refuses_a_log_that_is_not_the_states() {
    use cyphr_storage::engine::LogFactory;

    let (e, logs, _dir) = engine_with_logs(8, false);
    let mut w = history(&e, 3).await;
    let behind = e.kept_state(&w.id).await.expect("kept after 3 commits");
    let (next, bundle) = w.toggle("alice", NOW + 100).await.expect("toggle");
    w.submit(&e, &bundle).await.expect("fourth commit");
    w.adopt(next);
    let current = e.kept_state(&w.id).await.expect("kept after 4 commits");

    let open = || logs.open(&w.id, 0).expect("the principal's log");
    let stale = cyphr::Principal::resume(behind, open()).await;
    assert!(
        stale.is_err(),
        "a state of 3 commits resumed over a log of 4"
    );
    let fresh = cyphr::Principal::resume(current, open()).await;
    assert!(fresh.is_ok(), "the control: the state of the log resumes");
}

/// U3: over logs that do not outlive a replay (the default in-memory
/// logs) a kept state could never resume, so the engine keeps none rather
/// than copy every principal's state at every write for nothing.
#[tokio::test]
async fn u3_an_engine_over_in_memory_logs_keeps_nothing() {
    let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let mut w = World::new().await;
    for bundle in [w.last(), {
        let (next, bundle) = w.toggle("key_b", NOW + 10).await.expect("toggle");
        w.adopt(next);
        bundle
    }] {
        e.submit_commit(&w.id, Some(w.genesis.clone()), &bundle)
            .await
            .expect("write");
    }
    assert!(e.kept_state(&w.id).await.is_none());
    assert_eq!(e.kept_hits(), 0);
}

/// A data action signed by `k` at `now`, as the wire blob a push carries.
fn action_blob(k: &Kp, now: i64) -> Vec<u8> {
    let pay = serde_json::json!({
        "alg": k.alg, "now": now, "tmb": k.tmb.to_b64(), "typ": "cyphr.me/app/post/create",
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &k.alg, &k.prv, &k.pubb).expect("sign");
    serde_json::to_vec(&serde_json::json!({
        "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("blob")
}

/// U3 merge-gate case, SPEC 6.2/6.5: a held action signed by `key_a` at
/// T+100, then a commit dated T+50 that deletes `key_a`. A replay judges
/// the action against the whole key timeline and leaves it out of DT; a
/// state kept after the action must not answer otherwise. Until the core
/// holds actions as an order-independent set with a read-time view, a
/// principal with held actions is replayed, not kept. Red at 1a9338c1: the
/// shadow check fails the second write.
#[tokio::test]
async fn u3_a_held_action_then_a_commit_that_removes_its_signer_before_it() {
    let (e, _dir) = engine(8, true);
    let mut w = history(&e, 2).await;
    let action = WireBundle::actions(vec![action_blob(&kp("key_a"), NOW + 100)]);
    w.submit(&e, &action).await.expect("the action is held");
    let (next, bundle) = w.toggle("key_a", NOW + 50).await.expect("delete key_a");
    w.submit(&e, &bundle).await.expect("the removing commit");
    w.adopt(next);
    let (next, bundle) = w.toggle("alice", NOW + 60).await.expect("toggle");
    w.submit(&e, &bundle).await.expect("a later write");
    w.adopt(next);
    assert_eq!(e.kept_divergences(), 0);
    let kept = e
        .kept_state(&w.id)
        .await
        .expect("a principal holding actions is kept");
    assert_eq!(
        kept.action_count(),
        0,
        "the removed signer's action is out of DT"
    );
}

/// U3, the cost of an action: an action-only write steps the kept state
/// instead of invalidating it, so the writes around it replay nothing.
#[tokio::test]
async fn u3_an_action_only_write_is_served_from_the_kept_state() {
    let (e, _dir) = engine(8, false);
    let mut w = history(&e, 3).await;
    let (hits, misses, replayed) = (e.kept_hits(), e.kept_misses(), e.commits_replayed());
    let action = WireBundle::actions(vec![action_blob(&kp("key_a"), NOW + 100)]);
    w.submit(&e, &action).await.expect("the action is held");
    let (next, bundle) = w.toggle("alice", NOW + 110).await.expect("toggle");
    w.submit(&e, &bundle).await.expect("a commit after it");
    w.adopt(next);
    assert_eq!(
        (
            e.kept_hits() - hits,
            e.kept_misses() - misses,
            e.commits_replayed() - replayed
        ),
        (2, 0, 0),
        "the action write, or the commit after it, replayed the chain"
    );
    let kept = e.kept_state(&w.id).await.expect("kept");
    assert_eq!(kept.action_count(), 1);
}

/// U3, the cost of an action: an action-only write verifies each of its
/// signatures once, not once to stage it and again to hold it. A count of
/// checks: the verdicts are the same either way, so no scenario can tell.
#[tokio::test]
async fn u3_an_action_only_write_verifies_each_signature_once() {
    let (e, _dir) = engine(8, false);
    let w = history(&e, 2).await;
    let actions = WireBundle::actions(vec![
        action_blob(&kp("key_a"), NOW + 100),
        action_blob(&kp("key_a"), NOW + 101),
        action_blob(&kp("golden"), NOW + 102),
    ]);
    let before = cyphr::probe::signatures_checked();
    w.submit(&e, &actions).await.expect("the actions are held");
    assert_eq!(cyphr::probe::signatures_checked() - before, 3);
}

/// U3, refusal leaves no trace, with actions: a commit bundle that carries
/// an action and is refused (a damaged signature) leaves the kept state
/// as it was, and the next honest write is served from it.
#[tokio::test]
async fn u3_a_refused_bundle_carrying_an_action_costs_no_replay() {
    let (e, _dir) = engine(8, false);
    let mut w = history(&e, 3).await;
    let (next, mut bundle) = w.toggle("alice", NOW + 100).await.expect("toggle");
    bundle.actions = vec![action_blob(&kp("key_a"), NOW + 90)];
    let (misses, replayed) = (e.kept_misses(), e.commits_replayed());
    assert!(w.submit(&e, &damaged(bundle.clone())).await.is_err());
    w.submit(&e, &bundle).await.expect("the honest write");
    w.adopt(next);
    assert_eq!(
        (e.kept_misses() - misses, e.commits_replayed() - replayed),
        (0, 0),
        "a refused bundle made the next write replay"
    );
    assert_eq!(e.kept_state(&w.id).await.expect("kept").action_count(), 1);
}

/// SPEC 6.2, 6.5: an action gets one verdict whatever envelope carries it.
/// Carried in the commit that removes its signer (dated before it), or
/// held alone ahead of that commit, it is out of DT, in a replay of the
/// store as in the state the engine kept. Red before the fix: the bundle
/// path judged it at the tip before the commit and kept it.
#[tokio::test]
async fn an_action_in_a_commit_bundle_gets_the_verdict_it_would_alone() {
    let (e, _dir) = engine(8, true);
    let mut w = history(&e, 2).await;
    let (next, mut bundle) = w.toggle("key_a", NOW + 50).await.expect("delete key_a");
    bundle.actions = vec![action_blob(&kp("key_a"), NOW + 100)];
    w.submit(&e, &bundle).await.expect("the carrying commit");
    w.adopt(next);
    let cold = e
        .load_principal(&w.id, w.genesis.clone())
        .await
        .expect("replay");
    assert_eq!(cold.action_count(), 0, "the replay of the store");
    if let Some(kept) = e.kept_state(&w.id).await {
        assert_eq!(kept.action_count(), 0, "the kept state");
    }
    assert_eq!(e.kept_divergences(), 0);
}

/// I1: a bundle refused while the principal is in Error (SPEC 15.5) stores
/// nothing and leaves the kept state as it was, its actions included. Red
/// when the refused actions stayed held on the kept state: once the
/// principal left Error, a re-push of them read as already held, stored
/// nothing, and the engine answered Ok with the action lost.
#[tokio::test]
async fn an_errored_refusal_of_actions_leaves_the_kept_state_unchanged() {
    let (e, _dir) = engine(8, false);
    let mut w = World::new().await;
    w.submit(&e, &w.last()).await.expect("genesis commit");
    let base = w.shadow.fork().await.expect("fork");
    let (next, bundle) = w.toggle("key_b", NOW + 10).await.expect("toggle");
    w.submit(&e, &bundle).await.expect("commit 1");
    w.adopt(next);
    let mut rival = base;
    assert!(
        try_apply(
            &mut rival,
            &w.golden,
            pay("key/create", &w.golden, Some(&kp("alice")), NOW + 11),
            Some(key_of(&kp("alice"))),
            NOW + 11
        )
        .await
    );
    assert!(w.submit(&e, &bundle_at(&rival, 1)).await.is_err());
    let action = WireBundle::actions(vec![action_blob(&kp("key_a"), NOW + 100)]);
    assert!(
        w.submit(&e, &action).await.is_err(),
        "refused while in Error"
    );
    let (next, bundle) = w.toggle("bob", NOW + 20).await.expect("toggle");
    w.submit(&e, &bundle)
        .await
        .expect("extends the canonical head");
    w.adopt(next);
    w.submit(&e, &action).await.expect("accepted");
    let cold = e
        .load_principal(&w.id, w.genesis.clone())
        .await
        .expect("replay");
    assert_eq!(
        cold.action_count(),
        1,
        "the accepted action is in the store"
    );
}

/// A holder that verifies against the engine's kept state (a gossip pull)
/// gets the principal as the next write would start from, checks the next
/// commit on it, and leaves the engine's store untouched until the engine
/// itself admits the commit; both then hold the same state.
///
/// Turns red if: the detached principal differs from the kept state, refuses
/// the commit the engine accepts, writes to the engine's log or tip, or
/// ends in a state the engine's own write does not.
/// End to end through the public engine API over fjall logs: yes.
#[tokio::test]
async fn a_detached_kept_principal_verifies_the_next_commit_without_storing_it() {
    let (e, _dir) = engine(128, false);
    let w = history(&e, 6).await;
    let at_tip = e.at_tip(&w.id).await.expect("read").expect("stored");
    let mut detached = at_tip.detach().await.expect("detaches");
    let kept = e.kept_state(&w.id).await.expect("kept state");
    assert_eq!(detached.projection(), kept.projection());
    let tip = e.get_tip(&w.id).await.expect("tip").expect("held");

    let (next, bundle) = w.toggle("key_b", NOW + 100).await.expect("toggle applies");
    let decoded = bundle.decode().expect("decodes");
    cyphr::replay::replay_held(&mut detached, &decoded)
        .await
        .expect("the detached principal verifies the commit");
    let after = e.get_tip(&w.id).await.expect("tip").expect("held");
    assert_eq!(after.commit_id, tip.commit_id, "the engine stored nothing");
    assert!(
        e.kept_state(&w.id).await.is_some(),
        "its state is still kept"
    );

    w.submit(&e, &bundle).await.expect("the engine admits it");
    let admitted = e.kept_state(&w.id).await.expect("kept state");
    assert_eq!(detached.projection(), admitted.projection());
    drop(next);

    // An engine that keeps nothing serves the same principal, by a replay.
    let (cold, _dir) = engine(0, false);
    let w = history(&cold, 3).await;
    let before = cold.commits_replayed();
    let read = cold.at_tip(&w.id).await.expect("read").expect("stored");
    assert_eq!(cold.commits_replayed() - before, 3);
    assert_eq!(format!("{:#?}", **read), replayed(&cold, &w).await);
}
