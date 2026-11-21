//! The engine's durability order (FS-DURABLE).
//!
//! SPEC 19.5 (atomic commits) needs the record durable before the index
//! that points into it; an attestor must be durable before it signs over a
//! commit, and a client before it releases one. So the engine syncs the
//! record store once per accepted commit, after the record is written and
//! before the first index write, for every role.
//!
//! A [`BlobStore`] that models a disk (a write is volatile until synced,
//! a power cut drops what is volatile, a sync can fail) and a recording
//! [`Indexer`] share one event log; the properties are read off that log
//! and off a simulated restart, over random sequences of every public
//! engine write: commits, retained rivals, fork resolution (promotion),
//! replays.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{
    CommitRef, DeriveToken, EntityRef, IndexableCommit, Indexer, IndexerError, IndexerWrite,
    MemoryIndexer, PrincipalSummary, PublicKeyInfo, TipState,
};
use proptest::prelude::*;

const T0: i64 = 1_700_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    /// A record write: a blob or manifest stored.
    Put,
    /// The record store was made durable.
    Persist,
    /// A write to the index.
    Index,
}

type Events = Arc<Mutex<Vec<Ev>>>;

fn note(events: &Events, ev: Ev) {
    events.lock().expect("event log").push(ev);
}

/// A blob store modelling a disk. A `put` lands in a volatile set (the
/// page cache); `persist` makes it durable; `power_cut` drops what is still
/// volatile. A `persist` armed to fail drops the volatile set too and
/// returns an error, and later syncs succeed (fsyncgate: the pages are gone
/// and nothing says so).
#[derive(Clone)]
struct RecBlobs {
    disk: Arc<Mutex<Disk>>,
    fail_next_persist: Arc<AtomicBool>,
    persist_failures: Arc<AtomicUsize>,
    events: Events,
}

#[derive(Default)]
struct Disk {
    durable: HashMap<[u8; 32], Vec<u8>>,
    volatile: HashMap<[u8; 32], Vec<u8>>,
}

impl RecBlobs {
    fn new(events: Events) -> Self {
        Self {
            disk: Arc::default(),
            fail_next_persist: Arc::default(),
            persist_failures: Arc::default(),
            events,
        }
    }

    /// What a restart finds: a store over the durable set only.
    fn power_cut(&self) -> Self {
        let mut disk = self.disk.lock().expect("disk");
        disk.volatile.clear();
        Self {
            disk: Arc::new(Mutex::new(Disk {
                durable: disk.durable.clone(),
                volatile: HashMap::new(),
            })),
            fail_next_persist: Arc::default(),
            persist_failures: Arc::default(),
            events: Events::default(),
        }
    }

    fn volatile(&self) -> usize {
        self.disk.lock().expect("disk").volatile.len()
    }
}

impl BlobStore for RecBlobs {
    async fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        let hash = *blake3::hash(data).as_bytes();
        let mut disk = self.disk.lock().expect("disk");
        if !disk.durable.contains_key(&hash) {
            disk.volatile.insert(hash, data.to_vec());
        }
        drop(disk);
        note(&self.events, Ev::Put);
        Ok(Blake3Hash::from_bytes(hash))
    }

    async fn get(&self, hash: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        let disk = self.disk.lock().expect("disk");
        let key = *hash.as_bytes();
        Ok(disk
            .volatile
            .get(&key)
            .or_else(|| disk.durable.get(&key))
            .cloned())
    }

    async fn exists(&self, hash: &Blake3Hash) -> Result<bool, BlobStoreError> {
        Ok(self.get(hash).await?.is_some())
    }

    async fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>, BlobStoreError>
    {
        let disk = self.disk.lock().expect("disk");
        let mut all: Vec<[u8; 32]> = disk
            .durable
            .keys()
            .chain(disk.volatile.keys())
            .copied()
            .collect();
        all.sort();
        all.dedup();
        Ok(Box::new(
            all.into_iter().map(|h| Ok(Blake3Hash::from_bytes(h))),
        ))
    }

    async fn persist(&self) -> Result<(), BlobStoreError> {
        // A real sync blocks; yielding lets another write's sync queue
        // behind this one, as it does behind fjall's journal lock.
        tokio::task::yield_now().await;
        note(&self.events, Ev::Persist);
        let mut disk = self.disk.lock().expect("disk");
        if self.fail_next_persist.swap(false, Ordering::SeqCst) {
            disk.volatile.clear();
            self.persist_failures.fetch_add(1, Ordering::SeqCst);
            return Err(BlobStoreError::Backend("injected sync failure".into()));
        }
        let moved: Vec<_> = disk.volatile.drain().collect();
        disk.durable.extend(moved);
        Ok(())
    }
}

type R<T> = Result<T, IndexerError>;

/// A [`MemoryIndexer`] that logs each write to the index (the dry-run
/// `check_commit` is not one).
struct RecIndex {
    inner: MemoryIndexer,
    events: Events,
}

impl Indexer for RecIndex {
    async fn get_tip(&self, id: &str) -> R<Option<TipState>> {
        self.inner.get_tip(id).await
    }

    async fn is_pg_established(&self, id: &str) -> R<bool> {
        self.inner.is_pg_established(id).await
    }

    async fn get_commit_chain(
        &self,
        id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> R<Vec<CommitRef>> {
        self.inner.get_commit_chain(id, from, to).await
    }

    async fn resolve_digest(&self, d: &cyphr::state::TaggedDigest) -> R<Option<EntityRef>> {
        self.inner.resolve_digest(d).await
    }

    async fn resolve_digest_holders(&self, d: &cyphr::state::TaggedDigest) -> R<Vec<EntityRef>> {
        self.inner.resolve_digest_holders(d).await
    }

    async fn list_principals(&self) -> R<Vec<PrincipalSummary>> {
        self.inner.list_principals().await
    }

    async fn is_blob_indexed(&self, h: &Blake3Hash) -> R<bool> {
        self.inner.is_blob_indexed(h).await
    }

    async fn get_key(&self, thumbprint: &str) -> R<Option<PublicKeyInfo>> {
        self.inner.get_key(thumbprint).await
    }
}

impl IndexerWrite for RecIndex {
    async fn check_commit(&self, c: &IndexableCommit, t: &DeriveToken) -> R<()> {
        self.inner.check_commit(c, t).await
    }

    async fn index_commit(&self, c: &IndexableCommit, t: &DeriveToken) -> R<()> {
        note(&self.events, Ev::Index);
        self.inner.index_commit(c, t).await
    }

    async fn replace_chain_from(
        &self,
        id: &str,
        sequence: u64,
        commits: &[IndexableCommit],
        t: &DeriveToken,
    ) -> R<()> {
        note(&self.events, Ev::Index);
        self.inner
            .replace_chain_from(id, sequence, commits, t)
            .await
    }

    async fn clear(&self, t: &DeriveToken) -> R<()> {
        note(&self.events, Ev::Index);
        self.inner.clear(t).await
    }

    async fn set_quarantined(&self, m: &[(Blake3Hash, String)], t: &DeriveToken) -> R<()> {
        note(&self.events, Ev::Index);
        self.inner.set_quarantined(m, t).await
    }

    async fn quarantined(&self) -> R<Vec<(Blake3Hash, String)>> {
        self.inner.quarantined().await
    }
}

type Engine = StorageEngine<RecBlobs, RecIndex>;

fn engine() -> (Engine, RecBlobs, Events) {
    let events = Events::default();
    let blobs = RecBlobs::new(events.clone());
    let e = StorageEngine::new(
        blobs.clone(),
        RecIndex {
            inner: MemoryIndexer::new(),
            events: events.clone(),
        },
    );
    (e, blobs, events)
}

/// The first index write that follows a record write no sync has covered,
/// as its position in the log; `None` when the order holds.
fn order_violation(log: &[Ev]) -> Option<usize> {
    let mut unsynced = false;
    for (i, ev) in log.iter().enumerate() {
        match ev {
            Ev::Put => unsynced = true,
            Ev::Persist => unsynced = false,
            Ev::Index if unsynced => return Some(i),
            Ev::Index => {},
        }
    }
    None
}

fn count(log: &[Ev], of: Ev) -> usize {
    log.iter().filter(|e| **e == of).count()
}

struct Kp {
    kp: coz::KeyPair,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("ed25519 thumbprint");
    Kp { kp, tmb }
}

impl Kp {
    fn signer(&self) -> cyphr::signer::SoftwareSigner {
        cyphr::signer::SoftwareSigner::new(
            self.kp.alg.name(),
            &self.kp.prv_bytes,
            &self.kp.pub_bytes,
            &self.tmb,
        )
    }

    fn key(&self, first_seen: i64) -> cyphr::Key {
        cyphr::Key::new(
            self.kp.alg.name().to_string(),
            self.tmb.clone(),
            self.kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(first_seen)
    }
}

/// `signer` creates `new` and finalizes a commit on `state`.
async fn create_on(state: &mut Principal, signer: &Kp, new: &Kp, now: i64) -> WireBundle {
    let alg = signer.kp.alg.name();
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create",
    }))
    .expect("pay");
    let (sig, cad) =
        coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
    let mut scope = state.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(new.key(now)))
        .expect("apply");
    scope
        .finalize_with_software(&signer.signer(), now, "cyphr.me")
        .await
        .expect("finalize");
    test_fixtures::bundle::last_commit_bundle(state).expect("bundle")
}

/// One principal, driven through the engine: the commits the engine holds
/// as canonical, and the local state after each, from which a rival or a
/// longer line can be built.
struct Line {
    signer: Kp,
    genesis: Genesis,
    id: String,
    chain: Vec<WireBundle>,
    /// `snaps[i]` is the state after commit `i`.
    snaps: Vec<Principal>,
    clock: i64,
}

impl Line {
    async fn new() -> Self {
        let signer = kp();
        let key = signer.key(T0);
        let mut state = Principal::implicit(key.clone()).await.expect("genesis");
        state
            .commit_genesis(&signer.signer(), &[], T0, "cyphr.me")
            .await
            .expect("genesis commit");
        let g = test_fixtures::bundle::last_commit_bundle(&state).expect("bundle");
        Self {
            id: test_fixtures::bundle::genesis_id(&g).expect("pg"),
            genesis: Genesis::Implicit(key),
            chain: vec![g],
            snaps: vec![state.fork().await.expect("fork")],
            signer,
            clock: T0,
        }
    }

    fn tick(&mut self) -> i64 {
        self.clock += 1;
        self.clock
    }

    /// `n` commits on the state after commit `base`, none submitted.
    async fn line_from(&mut self, base: usize, n: usize) -> Vec<(WireBundle, Principal)> {
        let mut state = self.snaps[base].fork().await.expect("fork");
        let mut out = Vec::new();
        for _ in 0..n {
            let now = self.tick();
            let bundle = create_on(&mut state, &self.signer, &kp(), now).await;
            out.push((bundle, state.fork().await.expect("fork")));
        }
        out
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    /// The next canonical commit.
    Extend,
    /// A commit at an already-taken position: a fork, refused as the tip.
    Rival(usize),
    /// A line from position `p` longer than the chain it displaces; its
    /// last commit resolves the fork.
    Promote(usize),
    /// Push an earlier canonical commit again.
    Replay(usize),
    /// An action-only bundle (no commit), answered 201 with its blob hashes.
    Action(u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Extend),
        2 => any::<usize>().prop_map(Op::Rival),
        2 => any::<usize>().prop_map(Op::Promote),
        1 => any::<usize>().prop_map(Op::Replay),
        1 => any::<u8>().prop_map(Op::Action),
    ]
}

#[derive(Default, Debug)]
struct Outcome {
    accepted: usize,
    promotions: usize,
    kept: usize,
    failed: bool,
}

/// The engine under test, its disk, and what the run has seen so far.
struct Rig {
    e: Engine,
    blobs: RecBlobs,
    events: Events,
    out: Outcome,
}

impl Rig {
    /// Submit `bundle` for `line`, checking what this one write did to the
    /// record, the index and the disk. Returns whether it was accepted.
    async fn push(&mut self, line: &Line, bundle: &WireBundle) -> bool {
        let before = self.events.lock().expect("log").len();
        let failures = self.blobs.persist_failures.load(Ordering::SeqCst);
        let ok = self
            .e
            .submit_commit(&line.id, Some(line.genesis.clone()), bundle)
            .await
            .is_ok();
        let wrote: Vec<Ev> = self.events.lock().expect("log")[before..].to_vec();
        let (puts, persists, indexed) = (
            count(&wrote, Ev::Put),
            count(&wrote, Ev::Persist),
            count(&wrote, Ev::Index),
        );
        let failed_now = self.blobs.persist_failures.load(Ordering::SeqCst) > failures;
        if self.out.failed {
            assert!(
                !ok && wrote.is_empty(),
                "after a failed sync the engine writes nothing: ok={ok} {wrote:?}"
            );
        } else if failed_now {
            assert!(!ok, "a commit whose sync failed is not accepted");
            assert_eq!(
                indexed, 0,
                "an index write followed a failed sync: {wrote:?}"
            );
            self.out.failed = true;
        } else if ok {
            assert_eq!(persists, 1, "one persist per accepted commit: {wrote:?}");
            self.out.accepted += 1;
        } else {
            assert_eq!(indexed, 0, "a refused commit wrote to the index: {wrote:?}");
            assert_eq!(
                persists,
                usize::from(puts > 0),
                "a retained rival is one persist, a refusal that stored nothing none: {wrote:?}"
            );
            self.out.kept += usize::from(puts > 0);
        }
        if !self.out.failed {
            assert_eq!(
                self.blobs.volatile(),
                0,
                "a record write no sync covered is left behind: {wrote:?}"
            );
        }
        ok
    }
}

/// Run `ops`; the sync of the write at `fail_at` (or the first after it
/// that syncs) fails. Checks every write as it happens ([`Rig::push`]),
/// the order over the whole log, that a failed engine stays failed, and,
/// for a run that never failed, that a power cut changes nothing the
/// engine would sign over.
async fn run(ops: &[Op], fail_at: Option<usize>) -> Outcome {
    let (e, blobs, events) = engine();
    let mut rig = Rig {
        e,
        blobs,
        events,
        out: Outcome::default(),
    };
    let mut line = Line::new().await;
    let g = line.chain[0].clone();
    assert!(rig.push(&line, &g).await, "genesis is accepted");

    for (n, op) in ops.iter().enumerate() {
        if fail_at == Some(n) {
            rig.blobs.fail_next_persist.store(true, Ordering::SeqCst);
        }
        match *op {
            Op::Extend => {
                let len = line.chain.len();
                let (bundle, state) = line.line_from(len - 1, 1).await.remove(0);
                if rig.push(&line, &bundle).await {
                    line.chain.push(bundle);
                    line.snaps.push(state);
                }
            },
            Op::Rival(p) => {
                let len = line.chain.len();
                if len < 2 {
                    continue;
                }
                let at = 1 + p % (len - 1);
                let (bundle, _) = line.line_from(at - 1, 1).await.remove(0);
                rig.push(&line, &bundle).await;
            },
            Op::Promote(p) => {
                let len = line.chain.len();
                if len < 2 {
                    continue;
                }
                let at = 1 + p % (len - 1);
                let rival = line.line_from(at - 1, len - at + 1).await;
                for (i, (bundle, _)) in rival.iter().enumerate() {
                    let ok = rig.push(&line, bundle).await;
                    if ok && i + 1 == rival.len() {
                        line.chain.truncate(at);
                        line.snaps.truncate(at);
                        for (b, s) in rival {
                            line.chain.push(b);
                            line.snaps.push(s);
                        }
                        rig.out.promotions += 1;
                        break;
                    }
                }
            },
            Op::Replay(i) => {
                let bundle = line.chain[i % line.chain.len()].clone();
                rig.push(&line, &bundle).await;
            },
            Op::Action(m) => {
                // Each distinct, so none is a repeat the engine stores nothing for.
                let now = line.tick();
                let bundle = WireBundle::actions(vec![action_blob(&line.signer, n, m, now)]);
                rig.push(&line, &bundle).await;
            },
        }
    }

    let log = rig.events.lock().expect("log").clone();
    assert_eq!(
        order_violation(&log),
        None,
        "an index write followed a record write no persist covered: {log:?}"
    );

    assert_eq!(
        rig.e.durability_lost(),
        rig.out.failed,
        "the engine reports a lost record exactly when a sync failed"
    );
    if rig.out.failed {
        // A revoke is a write too: refused, and it stores nothing.
        let before = rig.events.lock().expect("log").len();
        assert!(
            matches!(
                rig.e.record_revoke(&revoke_evidence(), T0).await,
                Err(cyphr_storage::engine::EngineError::DurabilityLost(_))
            ),
            "a failed engine refuses a revoke"
        );
        assert_eq!(rig.events.lock().expect("log").len(), before);
    } else {
        // Power cut: what the engine would sign over (the principal's tip
        // and, in Error, the held heads with their first-seen times) is the
        // same when it restarts over what reached the disk.
        let before = signed(&rig.e, &line.id).await;
        let restarted = StorageEngine::new(
            rig.blobs.power_cut(),
            RecIndex {
                inner: MemoryIndexer::new(),
                events: Events::default(),
            },
        );
        assert_eq!(
            signed(&restarted, &line.id).await,
            before,
            "a power cut changed what the engine signs over"
        );
    }
    rig.out
}

/// What the engine would sign over for `id`: its tip and, in Error, the
/// held heads with their first-seen times.
async fn signed(e: &Engine, id: &str) -> (Option<(String, u64)>, String) {
    let tip = e
        .get_tip(id)
        .await
        .expect("tip")
        .map(|t| (t.commit_id, t.commit_count));
    let held = format!("{:?}", e.error_state(id).await.expect("error state"));
    (tip, held)
}

/// A signed action coz (`{pay, sig}`) by `signer`.
fn action_blob(signer: &Kp, n: usize, m: u8, now: i64) -> Vec<u8> {
    let alg = signer.kp.alg.name();
    let pay = serde_json::json!({
        "alg": alg, "msg": format!("{n}-{m}"), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/comment/create",
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) =
        coz::sign_json(&bytes, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
    serde_json::to_vec(&serde_json::json!({
        "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("wire")
}

fn revoke_evidence() -> serde_json::Value {
    let k = kp();
    let alg = k.kp.alg.name();
    let pay = serde_json::json!({
        "alg": alg, "now": T0, "rvk": T0, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, alg, &k.kp.prv_bytes, &k.kp.pub_bytes).expect("sign");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": alg, "pub": Base64UrlUnpadded::encode_string(&k.kp.pub_bytes)},
    })
}

fn drive<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Over any sequence of public engine writes, with a sync that may
    /// fail anywhere: each accepted commit is one persist; a retained
    /// rival is one persist before it is visible; no index write follows
    /// an unsynced record write; a refusal writes nothing to the index; a
    /// failed sync refuses every later write; and a power cut leaves the
    /// tip and the held statement exactly as they were. Turns red if the
    /// engine syncs nothing, syncs after the index write or after a rival
    /// is listed, syncs per blob, lets a refusal reach the index, or
    /// carries on after a failed sync.
    #[test]
    fn the_record_is_durable_before_anything_is_visible(
        ops in prop::collection::vec(op_strategy(), 0..10),
        fail_at in prop::option::of(0usize..10),
    ) {
        drive(run(&ops, fail_at));
    }
}

/// The property must reach the paths it claims to cover: a promotion
/// (fork resolution, with its own index write), a retained rival (the
/// held statement), and a failed sync. Turns red if a scenario stops
/// reaching its path, which would leave the property above passing
/// vacuously over it.
#[test]
fn the_scenarios_reach_promotion_rivals_and_failure() {
    let ops = [Op::Extend, Op::Extend, Op::Promote(0)];
    let out = drive(run(&ops, None));
    assert_eq!(out.promotions, 1, "the line displaced the chain: {out:?}");
    assert!(out.kept >= 1, "a rival of the line was retained: {out:?}");

    let out = drive(run(&[Op::Extend, Op::Extend], Some(1)));
    assert!(out.failed, "the armed sync failed: {out:?}");

    let out = drive(run(&[Op::Action(1), Op::Action(2)], None));
    assert_eq!(
        out.accepted, 3,
        "genesis and two action-only bundles: {out:?}"
    );
}

/// Two writes to different principals are in flight when a sync fails
/// (fsyncgate: the kernel drops the dirty pages of every write, and the
/// next sync reports success over them). The write whose sync queued
/// behind the failure must be refused, not accepted and attested over
/// pages that are gone. This is a concurrency edge the sequential property
/// above cannot reach: it runs one write at a time, so no sync is ever
/// queued behind a failing one. Turns red if a sync that follows a failure
/// is trusted.
#[test]
fn a_sync_queued_behind_a_failed_one_is_refused() {
    drive(async {
        let (e, blobs, events) = engine();
        let (a, b) = (Line::new().await, Line::new().await);
        blobs.fail_next_persist.store(true, Ordering::SeqCst);
        let (ra, rb) = tokio::join!(
            e.submit_commit(&a.id, Some(a.genesis.clone()), &a.chain[0]),
            e.submit_commit(&b.id, Some(b.genesis.clone()), &b.chain[0]),
        );
        assert!(
            ra.is_err() && rb.is_err(),
            "neither write is accepted: {ra:?} {rb:?}"
        );
        assert!(
            matches!(
                rb,
                Err(cyphr_storage::engine::EngineError::DurabilityLost(_))
            ),
            "the queued write is refused as a durability loss: {rb:?}"
        );
        let log = events.lock().expect("log");
        assert_eq!(count(&log, Ev::Index), 0, "nothing was indexed: {log:?}");
    });
}

/// The hacker seat's attack, as one scenario: a rival is pushed, the
/// server would sign a held statement over it, power is cut. The held
/// statement survives (the property checks this over random sequences;
/// this pins the case that was demonstrated). Turns red if a rival is
/// listed before its record is synced.
#[test]
fn a_held_statement_survives_a_power_cut() {
    let out = drive(run(&[Op::Extend, Op::Rival(0)], None));
    assert_eq!(out.kept, 1, "the rival was retained: {out:?}");
}

/// A revoke record is durable before it is visible: the /revoke response
/// tells the caller the key was durably recorded dead. Turns red if
/// `record_revoke` leaves its record to a later commit's sync.
#[test]
fn a_revoke_record_is_durable_before_it_is_visible() {
    drive(async {
        let (e, blobs, events) = engine();
        e.record_revoke(&revoke_evidence(), T0)
            .await
            .expect("revoke");
        let log = events.lock().expect("log");
        assert_eq!(
            *log,
            vec![Ev::Put, Ev::Persist],
            "one record write, then one persist"
        );
        assert_eq!(blobs.volatile(), 0);
    });
}
