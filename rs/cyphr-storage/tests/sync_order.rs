//! The engine's durability order (FS-DURABLE).
//!
//! SPEC 19.5 (atomic commits) needs the record durable before the index
//! that points into it; an attestor must be durable before it signs over a
//! commit, and a client before it releases one. So the engine syncs the
//! record store once per accepted commit, after the record is written and
//! before the first index write, for every role.
//!
//! A counting [`BlobStore`] and a recording [`Indexer`] share one event
//! log; the properties are read off that log, over random sequences of
//! every public engine write: commits, refused forks, fork resolution
//! (promotion), replays.

use std::sync::{Arc, Mutex};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError, MemoryBlobStore};
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

/// A [`MemoryBlobStore`] that logs its writes and its syncs.
struct RecBlobs {
    inner: MemoryBlobStore,
    events: Events,
}

impl BlobStore for RecBlobs {
    async fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        let hash = self.inner.put(data).await?;
        note(&self.events, Ev::Put);
        Ok(hash)
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

    async fn persist(&self) -> Result<(), BlobStoreError> {
        self.inner.persist().await?;
        note(&self.events, Ev::Persist);
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

fn engine() -> (Engine, Events) {
    let events = Events::default();
    let e = StorageEngine::new(
        RecBlobs {
            inner: MemoryBlobStore::new(),
            events: events.clone(),
        },
        RecIndex {
            inner: MemoryIndexer::new(),
            events: events.clone(),
        },
    );
    (e, events)
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

    async fn submit(&self, e: &Engine, bundle: &WireBundle) -> bool {
        e.submit_commit(&self.id, Some(self.genesis.clone()), bundle)
            .await
            .is_ok()
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
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Extend),
        2 => any::<usize>().prop_map(Op::Rival),
        2 => any::<usize>().prop_map(Op::Promote),
        1 => any::<usize>().prop_map(Op::Replay),
    ]
}

#[derive(Default, Debug)]
struct Outcome {
    accepted: usize,
    promotions: usize,
}

/// Run `ops`, checking after every submit that a refused commit wrote
/// nothing to the index, and at the end the two durability properties.
async fn run(ops: &[Op]) -> Outcome {
    let (e, events) = engine();
    let mut line = Line::new().await;
    let mut out = Outcome::default();
    let g = line.chain[0].clone();
    assert!(line.submit(&e, &g).await, "genesis is accepted");
    out.accepted += 1;

    for op in ops {
        let before = events.lock().expect("log").len();
        let accepted = match *op {
            Op::Extend => {
                let len = line.chain.len();
                let (bundle, state) = line.line_from(len - 1, 1).await.remove(0);
                let ok = line.submit(&e, &bundle).await;
                assert!(ok, "extending the tip is accepted");
                line.chain.push(bundle);
                line.snaps.push(state);
                1
            },
            Op::Rival(p) => {
                let len = line.chain.len();
                if len < 2 {
                    continue;
                }
                let at = 1 + p % (len - 1);
                let (bundle, _) = line.line_from(at - 1, 1).await.remove(0);
                usize::from(line.submit(&e, &bundle).await)
            },
            Op::Promote(p) => {
                let len = line.chain.len();
                if len < 2 {
                    continue;
                }
                let at = 1 + p % (len - 1);
                let rival = line.line_from(at - 1, len - at + 1).await;
                let mut accepted = 0;
                for (i, (bundle, _)) in rival.iter().enumerate() {
                    let ok = line.submit(&e, bundle).await;
                    accepted += usize::from(ok);
                    if ok && i + 1 == rival.len() {
                        line.chain.truncate(at);
                        line.snaps.truncate(at);
                        for (b, s) in rival {
                            line.chain.push(b);
                            line.snaps.push(s);
                        }
                        out.promotions += 1;
                        break;
                    }
                }
                accepted
            },
            Op::Replay(i) => {
                let bundle = line.chain[i % line.chain.len()].clone();
                usize::from(line.submit(&e, &bundle).await)
            },
        };
        out.accepted += accepted;

        let log = events.lock().expect("log");
        let wrote = &log[before..];
        if accepted == 0 {
            assert_eq!(
                count(wrote, Ev::Index),
                0,
                "{op:?}: a refused commit wrote to the index: {wrote:?}"
            );
        }
        assert_eq!(
            count(wrote, Ev::Persist),
            accepted,
            "{op:?}: one persist per accepted commit: {wrote:?}"
        );
    }

    let log = events.lock().expect("log");
    assert_eq!(
        order_violation(&log),
        None,
        "an index write followed a record write no persist covered: {log:?}"
    );
    assert_eq!(
        count(&log, Ev::Persist),
        out.accepted,
        "persists over the whole run equal the accepted commits"
    );
    out
}

fn drive<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Over any sequence of public engine writes: each accepted commit is
    /// one persist, no index write follows an unsynced record write, and
    /// a refused commit writes nothing to the index. Turns red if the
    /// engine syncs nothing, syncs after the index write, syncs per blob,
    /// or lets a refusal reach the index.
    #[test]
    fn one_persist_per_accepted_commit_before_the_index(
        ops in prop::collection::vec(op_strategy(), 0..10)
    ) {
        drive(run(&ops));
    }
}

/// The property test must reach the path it claims to cover: a promotion
/// (fork resolution) is an accepted commit with its own index write
/// (`replace_chain_from`) and must be one persist as well. Turns red if
/// the scenario stops promoting (the property above would then pass
/// vacuously over that path) or the promotion path skips the sync.
#[test]
fn a_promotion_is_one_persist_before_its_index_write() {
    let out = drive(run(&[Op::Extend, Op::Extend, Op::Promote(0)]));
    assert_eq!(out.promotions, 1, "the line displaced the chain: {out:?}");
}

/// A revoke record is attested (a tip report names the revoked keys), so
/// it must be durable before it is visible to a signer. Turns red if
/// `record_revoke` leaves its record to a later commit's sync.
#[test]
fn a_revoke_record_is_durable_before_it_is_visible() {
    drive(async {
        let (e, events) = engine();
        let k = kp();
        let alg = k.kp.alg.name();
        let pay = serde_json::json!({
            "alg": alg, "now": T0, "rvk": T0, "tmb": k.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/revoke"
        });
        let bytes = serde_json::to_vec(&pay).expect("pay");
        let (sig, _) = coz::sign_json(&bytes, alg, &k.kp.prv_bytes, &k.kp.pub_bytes).expect("sign");
        let evidence = serde_json::json!({
            "pay": pay,
            "sig": Base64UrlUnpadded::encode_string(&sig),
            "key": {"alg": alg, "pub": Base64UrlUnpadded::encode_string(&k.kp.pub_bytes)},
        });
        e.record_revoke(&evidence, T0).await.expect("revoke");
        let log = events.lock().expect("log");
        assert_eq!(
            *log,
            vec![Ev::Put, Ev::Persist],
            "one record write, then one persist"
        );
    });
}
