//! Adversarial sweep (AS1) of the storage engine: attacks reproduced end to
//! end over the engine seam, each a red test owned by the node that fixes it.
//! Helpers mirror `embedded_principals.rs`.

use cyphr::replay::WireBundle;
use cyphr::{Principal, Tip, Tracking};
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{EngineError, StorageEngine};
use cyphr_storage::index::MemoryIndexer;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

const T0: i64 = 1_700_000_000;

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

/// A principal's chain as pushed: its genesis, its id, and the local core
/// state the next commit is built on.
struct Line {
    genesis: Genesis,
    id: String,
    state: Principal,
    bundles: Vec<WireBundle>,
}

impl Line {
    async fn new(first: &Kp) -> Self {
        let key = first.key(T0);
        let mut state = Principal::implicit(key.clone()).await.expect("genesis");
        state
            .commit_genesis(&first.signer(), &[], T0, "cyphr.me")
            .await
            .expect("genesis commit");
        let g = test_fixtures::bundle::last_commit_bundle(&state).expect("bundle");
        Self {
            genesis: Genesis::Implicit(key),
            id: test_fixtures::bundle::genesis_id(&g).expect("pg"),
            state,
            bundles: vec![g],
        }
    }

    /// [`commit_on`] this line's state, the commit kept to push.
    async fn commit(
        &mut self,
        signer: &Kp,
        typ: &str,
        id: &str,
        new: Option<&Kp>,
        now: i64,
    ) -> Result<WireBundle, cyphr::Error> {
        let bundle = commit_on(&mut self.state, signer, typ, id, new, now).await?;
        self.bundles.push(bundle.clone());
        Ok(bundle)
    }

    async fn push(&self, engine: &Engine, bundle: &WireBundle) -> Result<(), EngineError> {
        engine
            .submit_commit(&self.id, Some(self.genesis.clone()), bundle)
            .await
            .map(|_| ())
    }

    async fn push_all(&self, engine: &Engine) {
        for (i, bundle) in self.bundles.iter().enumerate() {
            self.push(engine, bundle)
                .await
                .unwrap_or_else(|e| panic!("commit {i} of {}: {e}", self.id));
        }
    }
}

/// `signer` signs `typ` naming `id` (introducing `new`) and finalizes a
/// commit on `state`; the commit is returned, not yet pushed.
async fn commit_on(
    state: &mut Principal,
    signer: &Kp,
    typ: &str,
    id: &str,
    new: Option<&Kp>,
    now: i64,
) -> Result<WireBundle, cyphr::Error> {
    let alg = signer.kp.alg.name();
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": alg, "id": id, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": format!("cyphr.me/cyphr/{typ}"),
    }))
    .expect("pay");
    let (sig, cad) =
        coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
    let mut scope = state.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, new.map(|k| k.key(now)))?;
    scope
        .finalize_with_software(&signer.signer(), now, "cyphr.me")
        .await?;
    Ok(test_fixtures::bundle::last_commit_bundle(state).expect("bundle"))
}

/// A line `a` that embeds `b_pr` (in its Key Tree), and whose local state
/// follows `b` so a key of `b` can sign for it.
async fn a_embedding(alice: &Kp, b_pr: &str, b: &Principal) -> Line {
    let mut a = Line::new(alice).await;
    a.commit(alice, "AT/KT/nonce/create", b_pr, None, T0 + 1)
        .await
        .expect("A embeds B");
    a.state
        .reveal_embedded(b_pr, Tracking::Pin(Box::new(Tip::new(b, T0 + 100))))
        .expect("reveal B");
    a
}

/// B: `bob`'s genesis, then a commit creating `carol`. Returns the PR B
/// held after its genesis, the form A embeds.
async fn b_with_carol(bob: &Kp, carol: &Kp) -> (Line, String) {
    let mut b = Line::new(bob).await;
    let pr = b.state.pr_tagged().expect("pr");
    b.commit(bob, "key/create", &carol.tmb.to_b64(), Some(carol), T0 + 10)
        .await
        .expect("B creates carol");
    (b, pr)
}

/// Claim (SPEC 10.5, 10.7): a commit of A signed by a key of the embedded
/// principal B is admitted when B's PR is held and the key is active at the
/// tip held for B, and A then loads with it.
///
/// Turns red if the engine refuses the commit as an embedded limitation or
/// as an unknown key, or loads A without the commit.
/// Delegates to a [`MemoryBlobStore`], counting `get`s: replaying a chain
/// reads its blobs, so the count observes a pass over it.
struct CountingBlobs {
    inner: MemoryBlobStore,
    gets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl cyphr_storage::blob::BlobStore for CountingBlobs {
    async fn put(
        &self,
        data: &[u8],
    ) -> Result<cyphr_storage::blob::Blake3Hash, cyphr_storage::blob::BlobStoreError> {
        self.inner.put(data).await
    }

    async fn get(
        &self,
        hash: &cyphr_storage::blob::Blake3Hash,
    ) -> Result<Option<Vec<u8>>, cyphr_storage::blob::BlobStoreError> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(hash).await
    }

    async fn exists(
        &self,
        hash: &cyphr_storage::blob::Blake3Hash,
    ) -> Result<bool, cyphr_storage::blob::BlobStoreError> {
        self.inner.exists(hash).await
    }

    async fn iter(
        &self,
    ) -> Result<
        Box<
            dyn Iterator<
                    Item = Result<
                        cyphr_storage::blob::Blake3Hash,
                        cyphr_storage::blob::BlobStoreError,
                    >,
                > + Send,
        >,
        cyphr_storage::blob::BlobStoreError,
    > {
        self.inner.iter().await
    }
}

type Counted = StorageEngine<CountingBlobs, MemoryIndexer>;

async fn push_counted(e: &Counted, line: &Line, bundle: &WireBundle) -> Result<(), EngineError> {
    e.submit_commit(&line.id, Some(line.genesis.clone()), bundle)
        .await
        .map(|_| ())
}

/// Blob reads of a stranger's refused push to A, and of one load of A,
/// with A carrying `tail` commits by its own key after embedding B.
async fn stranger_cost(tail: usize) -> (usize, usize, String) {
    let (alice, bob, carol, mallory) = (kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    for i in 0..6 {
        let k = kp();
        b.commit(&bob, "key/create", &k.tmb.to_b64(), Some(&k), T0 + 11 + i)
            .await
            .expect("B grows");
    }
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    for i in 0..tail {
        let k = kp();
        a.commit(
            &alice,
            "key/create",
            &k.tmb.to_b64(),
            Some(&k),
            T0 + 100 + i as i64,
        )
        .await
        .expect("A grows by its own key");
    }
    let mut m = Line::new(&mallory).await;
    let k = kp();
    let strangers = m
        .commit(&mallory, "key/create", &k.tmb.to_b64(), Some(&k), T0 + 50)
        .await
        .expect("mallory's own commit");
    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let e: Counted = StorageEngine::new(
        CountingBlobs {
            inner: MemoryBlobStore::new(),
            gets: gets.clone(),
        },
        MemoryIndexer::new(),
    );
    for (line, n) in [(&b, b.bundles.len()), (&a, a.bundles.len())] {
        for bundle in &line.bundles[..n] {
            push_counted(&e, line, bundle).await.expect("honest push");
        }
    }
    push_counted(&e, &m, &m.bundles[0])
        .await
        .expect("M genesis: mallory's key is indexed");
    use std::sync::atomic::Ordering::SeqCst;
    gets.store(0, SeqCst);
    let answer = push_counted(&e, &a, &strangers).await;
    let push = gets.swap(0, SeqCst);
    e.load_principal(&a.id, a.genesis.clone())
        .await
        .expect("A loads");
    let load = gets.load(SeqCst);
    (push, load, format!("{answer:?}"))
}

/// Claim (resource bound): a push to A signed by a key A never held, which
/// nobody authorized and which A refuses, costs the engine no more than
/// reading A and the principals A embeds once. Anyone may push to any
/// principal (no bearer token is required) with a signature by any key the
/// index holds, so the refusal path's cost is the attacker's lever.
///
/// Today the rival retention tries the stranger's bundle at every position
/// of A after the embedding and, at each one, follows every principal A's
/// Key Tree names: a replay of B per position. A stranger's single push to
/// an A with 24 commits after its embedding reads many times what loading A
/// reads, and the cost grows with A's length times B's.
///
/// Turns red while a refused stranger's push costs more than two loads of A.
/// End to end: yes (real chains, blob reads counted at the store).
#[tokio::test]
#[ignore = "RED(DEBT3)"]
async fn strangers_refused_push_costs_at_most_a_load_of_a() {
    let (short_push, short_load, short_answer) = stranger_cost(4).await;
    let (long_push, long_load, long_answer) = stranger_cost(24).await;
    println!("tail 4: push {short_push} load {short_load} ({short_answer})");
    println!("tail 24: push {long_push} load {long_load} ({long_answer})");
    assert!(long_answer.starts_with("Err"), "the stranger is refused");
    assert!(
        long_push <= 2 * long_load,
        "a stranger's refused push read {long_push} blobs; one load of A reads {long_load}"
    );
}

/// Claim (SPEC 10.7, R5; I1): two principals that embed each other, each
/// signing for the other in turn, every pin naming a state the engine held
/// before the commit that records it, stay loadable. Mutual embedding is
/// no self-embedding (SPEC 10.6) and no pin depends on a later admission.
///
/// The interleaving: A embeds B, B embeds A; carol (B) signs A2, pinned to
/// B at B2; alice (A) signs B3, pinned to A at A2; carol signs A3, pinned
/// to B at B3. Loading A replays A3's pin, B to B3, whose pin replays A to
/// A2, whose pin asks for B at B2 while B's chain is being replayed in the
/// same call: today that is refused as a cycle ("pins itself"), so A, whose
/// every commit was admitted, no longer loads, and a rebuild quarantines it.
///
/// Turns red while any of the honest pushes is refused, A does not load
/// after them, or a rebuild from blobs quarantines anything.
/// End to end: yes (two real chains, interleaved pushes, a restart).
#[tokio::test]
async fn mutually_embedding_principals_stay_loadable() {
    let (alice, bob, carol, x, y, z) = (kp(), kp(), kp(), kp(), kp(), kp());
    let (mut b, _) = b_with_carol(&bob, &carol).await;
    let b_pr = b.state.pr_tagged().expect("pr");
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let a_pr = a.state.pr_tagged().expect("pr");
    b.commit(&bob, "AT/KT/nonce/create", &a_pr, None, T0 + 12)
        .await
        .expect("B embeds A");
    let b2 = b.state.pr_tagged().expect("pr");
    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;

    // A2: carol signs for A through B at B2.
    a.state
        .reveal_embedded(&b_pr, Tracking::Pin(Box::new(Tip::new(&b.state, T0 + 100))))
        .expect("reveal B");
    let a2 = a
        .commit(&carol, "key/create", &x.tmb.to_b64(), Some(&x), T0 + 20)
        .await
        .expect("carol signs A2");
    a.push(&engine, &a2).await.expect("A2 admitted through B");
    // B3: alice signs for B through A at A2.
    b.state
        .reveal_embedded(&a_pr, Tracking::Pin(Box::new(Tip::new(&a.state, T0 + 100))))
        .expect("reveal A");
    let b3 = b
        .commit(&alice, "key/create", &y.tmb.to_b64(), Some(&y), T0 + 30)
        .await
        .expect("alice signs B3");
    b.push(&engine, &b3).await.expect("B3 admitted through A");
    // A3: carol signs for A through B at B3.
    a.state
        .reveal_embedded(&b_pr, Tracking::Pin(Box::new(Tip::new(&b.state, T0 + 100))))
        .expect("reveal B");
    let a3 = a
        .commit(&carol, "key/create", &z.tmb.to_b64(), Some(&z), T0 + 40)
        .await
        .expect("carol signs A3");
    let pushed = a.push(&engine, &a3).await;
    println!("A3: {pushed:?}; b2 = {b2}");
    pushed.expect("A3 admitted through B");
    let loaded = engine.load_principal(&a.id, a.genesis.clone()).await;
    println!("load A: {:?}", loaded.as_ref().map(|p| p.pr_tagged()));
    let report = StorageEngine::new(blobs.clone(), MemoryIndexer::new())
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    println!("rebuild quarantined: {:?}", report.quarantined);
    loaded.expect("A loads after its every commit was admitted");
    assert!(report.quarantined.is_empty(), "{:?}", report.quarantined);
}
