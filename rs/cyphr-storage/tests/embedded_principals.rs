//! Embedded principals through the storage engine (SPEC be0663f 10.3, 10.5,
//! 10.7, 6.2). Principal A embeds principal B by B's PR in its Key Tree and
//! a key `carol` of B signs for A.
//!
//! The engine judges a commit through B against the tip it holds of B at
//! admission and records B's PR there in the commit's manifest; replay judges
//! the admitted commit against that state, never a later one, so a restart
//! or a rebuild from blobs alone reaches what admission reached (I1).
//! Every scenario pushes real signed chains over the engine seam.

use cyphr::replay::WireBundle;
use cyphr::{Principal, Tip, Tracking};
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{DerivedRoots, EngineError, StorageEngine};
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

    async fn roots(&self, engine: &Engine) -> DerivedRoots {
        engine
            .rederive_roots_with_genesis(&self.id, self.genesis.clone())
            .await
            .expect("roots")
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
/// End to end: yes (two real chains pushed to one engine).
#[tokio::test]
async fn push_through_embedded_principal_is_accepted_and_loaded() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 20,
    )
    .await
    .expect("carol signs for A");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;

    let loaded = engine
        .load_principal(&a.id, a.genesis.clone())
        .await
        .expect("A loads");
    assert!(loaded.is_key_active(&dave.tmb), "the B-signed commit is in");
    assert_eq!(
        loaded.pr_tagged().expect("pr"),
        a.state.pr_tagged().expect("pr"),
        "the engine's A is the local A"
    );
}

/// Claim (SPEC 6.2, 14.12): a commit once admitted is never judged against a
/// later state of B. After B removes `carol`, the engine still loads A with
/// carol's commit, and a restart that rebuilds the index from blobs alone
/// replays it to the same roots, with nothing quarantined (I1: rebuild equals
/// live).
///
/// Turns red if replay judges A's commit against B's tip (A then fails to
/// load, or the rebuild quarantines it), or if the rebuild does not find B at
/// the state the manifest recorded.
/// End to end: yes (B advances, A reloaded live and rebuilt from blobs).
#[tokio::test]
async fn admitted_commit_survives_b_removing_the_key_and_a_rebuild() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 20,
    )
    .await
    .expect("carol signs for A");

    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;
    let before = a.roots(&engine).await;

    let removal = b
        .commit(&bob, "key/delete", &carol.tmb.to_b64(), None, T0 + 30)
        .await
        .expect("B removes carol");
    b.push(&engine, &removal).await.expect("B takes it");
    assert_eq!(a.roots(&engine).await, before, "live: A loads unchanged");

    let restarted = StorageEngine::new(blobs, MemoryIndexer::new());
    let report = restarted
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild from blobs");
    assert!(
        report.quarantined.is_empty(),
        "an honest store rebuilds whole: {:?}",
        report.quarantined
    );
    assert_eq!(
        a.roots(&restarted).await,
        before,
        "restart: A loads byte-identical"
    );
    let loaded = restarted
        .load_principal(&a.id, a.genesis.clone())
        .await
        .expect("A loads");
    assert!(loaded.is_key_active(&dave.tmb));
}

/// Claim (SPEC 10.5, 10.7 "at the time of authentication"): a key B removed
/// first is refused whatever `now` the commit claims. B creates `carol` and
/// removes her; a commit of A signed by carol and dated before the removal
/// is refused, and A's chain is as it was.
///
/// Turns red if the engine admits the backdated commit.
/// End to end: yes (real chains, HTTP-free engine push).
#[tokio::test]
async fn backdated_commit_by_a_removed_key_is_refused() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    // A is built against B while carol is active, then B removes her.
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let backdated = a
        .commit(
            &carol,
            "key/create",
            &dave.tmb.to_b64(),
            Some(&dave),
            T0 + 15,
        )
        .await
        .expect("built while carol is active in B");
    b.commit(&bob, "key/delete", &carol.tmb.to_b64(), None, T0 + 20)
        .await
        .expect("B removes carol");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    b.push_all(&engine).await;
    for bundle in &a.bundles[..2] {
        a.push(&engine, bundle).await.expect("A's own commits");
    }
    let before = a.roots(&engine).await;

    let refused = a.push(&engine, &backdated).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(
                cyphr::Error::UnknownKey | cyphr::Error::KeyRevoked
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(a.roots(&engine).await, before, "nothing of it is stored");
}

/// Claim (SPEC 10.5, 6.2): a signer is judged through B's current view
/// unless a key of A's own authorizes it. A key that signs a coz BEFORE the
/// same bundle introduces it is not yet a key of A, so a commit of that shape
/// signed by a `carol` that B has since removed is refused, as it is when
/// the bundle introduces her nowhere, and A's chain is as it was.
///
/// Turns red if the engine counts a signer as A's own because the bundle
/// introduces it somewhere, skips following B, and admits carol through a
/// stale pinned view of B.
/// End to end: yes (real chains, HTTP-free engine push).
#[tokio::test]
async fn key_used_before_its_introduction_is_judged_through_b() {
    let (alice, bob, carol, dave, erin) = (kp(), kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    // A has admitted a commit by carol, so replaying A pins B with carol in
    // it: the stale view a skipped follow would leave.
    a.commit(
        &carol,
        "key/create",
        &erin.tmb.to_b64(),
        Some(&erin),
        T0 + 12,
    )
    .await
    .expect("carol signs through B while active there");
    // Built while carol is active in B: carol signs, then alice introduces
    // carol, in one commit.
    let signed = |signer: &Kp, typ: &str, id: &str, now: i64| {
        let alg = signer.kp.alg.name();
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": alg, "id": id, "now": now,
            "tmb": signer.tmb.to_b64(), "typ": format!("cyphr.me/cyphr/{typ}"),
        }))
        .expect("pay");
        let (sig, cad) =
            coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
        (pay, sig, czd)
    };
    let now = T0 + 15;
    let (p1, s1, c1) = signed(&carol, "key/create", &dave.tmb.to_b64(), now);
    let (p2, s2, c2) = signed(&alice, "key/create", &carol.tmb.to_b64(), now);
    let mut scope = a.state.begin_commit();
    scope
        .verify_and_apply(&p1, &s1, c1, Some(dave.key(now)))
        .expect("carol signs through B while active there");
    scope
        .verify_and_apply(&p2, &s2, c2, Some(carol.key(now)))
        .expect("alice then introduces carol");
    scope
        .finalize_with_software(&alice.signer(), now, "cyphr.me")
        .await
        .expect("finalize");
    let bundle = test_fixtures::bundle::last_commit_bundle(&a.state).expect("bundle");
    let removal = b
        .commit(&bob, "key/delete", &carol.tmb.to_b64(), None, T0 + 20)
        .await
        .expect("B removes carol");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for held in &b.bundles[..2] {
        b.push(&engine, held).await.expect("B before the removal");
    }
    a.push_all(&engine).await;
    b.push(&engine, &removal).await.expect("B removes carol");
    let before = a.roots(&engine).await;

    let refused = a.push(&engine, &bundle).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(
                cyphr::Error::UnknownKey | cyphr::Error::KeyRevoked
            ))
        ),
        "{refused:?}"
    );
    assert_eq!(a.roots(&engine).await, before, "nothing of it is stored");
}

/// Claim (SPEC 11.1, 6.2): with B in Error a push through B is refused, and
/// the history A already holds through B still loads. A admits a commit by
/// `carol`, B then forks, and a second commit by carol is refused while the
/// first stays in A.
///
/// Turns red if the engine admits through an errored B, or if the fork of B
/// makes A's held commit fail to replay.
/// End to end: yes (real chains, a real fork of B).
#[tokio::test]
async fn forked_b_refuses_a_push_and_a_still_loads() {
    let (alice, bob, carol, dave, erin) = (kp(), kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 20,
    )
    .await
    .expect("carol signs for A");
    let second = a
        .commit(
            &carol,
            "key/create",
            &erin.tmb.to_b64(),
            Some(&erin),
            T0 + 21,
        )
        .await
        .expect("carol signs again");
    a.bundles.pop();

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;
    let before = a.roots(&engine).await;

    // Two rivals at B's position 2: B forks.
    let (x, y) = (kp(), kp());
    let mut one = b.state.fork().await.expect("fork");
    let first = commit_on(
        &mut one,
        &bob,
        "key/create",
        &x.tmb.to_b64(),
        Some(&x),
        T0 + 40,
    )
    .await
    .expect("rival one");
    let mut two = b.state.fork().await.expect("fork");
    let second_rival = commit_on(
        &mut two,
        &bob,
        "key/create",
        &y.tmb.to_b64(),
        Some(&y),
        T0 + 41,
    )
    .await
    .expect("rival two");
    b.push(&engine, &first).await.expect("one rival extends B");
    let _ = b.push(&engine, &second_rival).await;
    assert!(
        engine
            .assess(&b.id)
            .await
            .expect("assess")
            .fork_point
            .is_some(),
        "B is in Error"
    );

    let refused = a.push(&engine, &second).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::EmbeddedErrored))
        ),
        "a push through an errored B: {refused:?}"
    );
    assert_eq!(
        a.roots(&engine).await,
        before,
        "A's held history still loads"
    );
}

/// Claim (SPEC 10.3 "opaque nodes do not trigger state synchronization"): a
/// digest of A's Key Tree that names no principal this engine holds is
/// opaque and authorizes nothing, so a commit signed by a key of that
/// unheld principal is an unknown key.
///
/// Turns red if the engine admits it, or reports it as anything but the
/// plain unknown key.
/// End to end: yes (A pushed without B).
#[tokio::test]
async fn embedded_principal_not_held_is_an_unknown_key() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 20,
    )
    .await
    .expect("carol signs for A");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for bundle in &a.bundles[..2] {
        a.push(&engine, bundle).await.expect("A's own commits");
    }
    let refused = a.push(&engine, &a.bundles[2]).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::UnknownKey))
        ),
        "{refused:?}"
    );
}

/// A data action of `typ` signed by `signer`, as the wire carries it.
fn action_by(signer: &Kp, typ: &str, now: i64) -> WireBundle {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let alg = signer.kp.alg.name();
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": alg, "now": now, "tmb": signer.tmb.to_b64(), "typ": typ,
    }))
    .expect("pay");
    let (sig, _) =
        coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
    let coz = serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    });
    WireBundle::actions(vec![serde_json::to_vec(&coz).expect("coz")])
}

/// The engine restarted over the same blobs: a rebuild from them alone.
async fn restart(blobs: &MemoryBlobStore) -> Engine {
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild from blobs");
    assert!(
        report.quarantined.is_empty(),
        "an honest store rebuilds whole: {:?}",
        report.quarantined
    );
    engine
}

async fn in_error(engine: &Engine, id: &str) -> bool {
    engine
        .assess(id)
        .await
        .expect("assess")
        .fork_point
        .is_some()
}

/// A admitted through B up to a commit by `carol`, with a rival to that
/// commit also signed by `carol` (a holder of one of B's keys forking A),
/// and a resolving commit extending the rival.
struct Forked {
    engine: Engine,
    blobs: MemoryBlobStore,
    a: Line,
    rival: WireBundle,
    resolving: WireBundle,
    resolved: Principal,
}

async fn forked() -> Forked {
    let (alice, bob, carol, dave, erin, frank) = (kp(), kp(), kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let mut other = a.state.fork().await.expect("fork");
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 20,
    )
    .await
    .expect("carol signs for A");
    let rival = commit_on(
        &mut other,
        &carol,
        "key/create",
        &erin.tmb.to_b64(),
        Some(&erin),
        T0 + 21,
    )
    .await
    .expect("a rival, also through B");
    let resolving = commit_on(
        &mut other,
        &carol,
        "key/create",
        &frank.tmb.to_b64(),
        Some(&frank),
        T0 + 22,
    )
    .await
    .expect("a resolving commit through B");

    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;
    Forked {
        engine,
        blobs,
        a,
        rival,
        resolving,
        resolved: other,
    }
}

/// Claim (SPEC 15.7.1, R4/R5): a rival signed through B is a fork
/// participant. It is refused as the tip, kept as evidence, and A is in
/// Error, on the live engine and after a rebuild from blobs alone.
///
/// Turns red if the rival is dropped unseen (A stays Active) or does not
/// survive the restart.
/// End to end: yes.
#[tokio::test]
async fn rival_signed_through_b_is_retained_and_a_is_in_error() {
    let f = forked().await;
    assert!(f.a.push(&f.engine, &f.rival).await.is_err(), "a rival");
    assert!(in_error(&f.engine, &f.a.id).await, "live: A is in Error");
    let restarted = restart(&f.blobs).await;
    assert!(in_error(&restarted, &f.a.id).await, "restart: in Error");
}

/// Claim (SPEC 15.8 item 1): the owner's resolving commit through B,
/// extending the retained rival, promotes it; A leaves Error with the
/// resolved history, and so does a rebuild from blobs alone.
///
/// Turns red if the resolution is refused, or the rebuild does not replay
/// the promoted commits against B as admitted.
/// End to end: yes.
#[tokio::test]
async fn resolving_commit_through_b_promotes_the_rival() {
    let f = forked().await;
    let _ = f.a.push(&f.engine, &f.rival).await;
    f.a.push(&f.engine, &f.resolving)
        .await
        .expect("the resolution through B is admitted");
    assert!(!in_error(&f.engine, &f.a.id).await, "live: resolved");
    let want = f.resolved.pr_tagged().expect("pr");
    let live = f.a.roots(&f.engine).await;
    assert_eq!(live.pr, want, "live: the resolved chain");
    let restarted = restart(&f.blobs).await;
    assert!(!in_error(&restarted, &f.a.id).await, "restart: resolved");
    assert_eq!(f.a.roots(&restarted).await, live, "restart: same roots");
}

/// Claim (SPEC 10.5 "to sign/act as a primary principal", 6.5): a data
/// action signed by a key of B is admitted, judged by B's key timeline at
/// its `now`; it stays in A's Data Tree after B removes the key and after a
/// rebuild from blobs alone.
///
/// Turns red if the action is refused, or replay judges it against a later
/// B and drops it.
/// End to end: yes.
#[tokio::test]
async fn action_signed_through_b_is_admitted_and_survives_rebuild() {
    let (alice, bob, carol) = (kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    let a = a_embedding(&alice, &b_pr, &b.state).await;
    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;
    a.push(&engine, &action_by(&carol, "cyphr.me/test/note", T0 + 20))
        .await
        .expect("carol acts for A through B");
    let acts = |p: &Principal| p.actions().count();
    let live = engine
        .load_principal(&a.id, a.genesis.clone())
        .await
        .expect("load");
    assert_eq!(acts(&live), 1, "the action is in DT");

    let removal = b
        .commit(&bob, "key/delete", &carol.tmb.to_b64(), None, T0 + 30)
        .await
        .expect("B removes carol");
    b.push(&engine, &removal).await.expect("B takes it");
    let restarted = restart(&blobs).await;
    for e in [&engine, &restarted] {
        let p = e
            .load_principal(&a.id, a.genesis.clone())
            .await
            .expect("load");
        assert_eq!(acts(&p), 1, "the action is judged against B as admitted");
    }
}

/// Stated limit: an embedding created and used in the same bundle is
/// refused, typed and closed (`UnknownKey`): the digest is not in the Key
/// Tree the engine follows until the bundle that creates it is admitted.
/// Turns red if it is admitted, or fails any other way.
#[tokio::test]
async fn embedding_created_and_used_in_one_bundle_is_an_unknown_key() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = Line::new(&alice).await;
    a.state
        .reveal_embedded(&b_pr, Tracking::Pin(Box::new(Tip::new(&b.state, T0 + 100))))
        .expect("reveal");
    let pay = |signer: &Kp, typ: &str, id: &str, now: i64| {
        let alg = signer.kp.alg.name();
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": alg, "id": id, "now": now,
            "tmb": signer.tmb.to_b64(), "typ": format!("cyphr.me/cyphr/{typ}"),
        }))
        .expect("pay");
        let (sig, cad) =
            coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
        (pay, sig, czd)
    };
    let mut scope = a.state.begin_commit();
    let (p, s, c) = pay(&alice, "AT/KT/nonce/create", &b_pr, T0 + 1);
    scope.verify_and_apply(&p, &s, c, None).expect("embed");
    let (p, s, c) = pay(&carol, "key/create", &dave.tmb.to_b64(), T0 + 1);
    scope
        .verify_and_apply(&p, &s, c, Some(dave.key(T0 + 1)))
        .expect("carol signs in the same commit");
    scope
        .finalize_with_software(&alice.signer(), T0 + 1, "cyphr.me")
        .await
        .expect("finalize");
    let bundle = test_fixtures::bundle::last_commit_bundle(&a.state).expect("bundle");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push(&engine, &a.bundles[0]).await.expect("A genesis");
    let refused = a.push(&engine, &bundle).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::UnknownKey))
        ),
        "{refused:?}"
    );
}

/// Stated limit: B with no commits is opaque unless its genesis state is
/// held. A names the PR of a principal that was never pushed (so none is
/// held); its genesis key's commit is an unknown key.
/// Turns red if the engine admits it or fails any other way.
#[tokio::test]
async fn embedded_principal_with_no_commits_is_opaque() {
    let (alice, bob, dave) = (kp(), kp(), kp());
    let bare = Principal::implicit(bob.key(T0)).await.expect("genesis");
    let bare_pr = bare.pr_tagged().expect("pr");
    let mut a = a_embedding(&alice, &bare_pr, &bare).await;
    a.commit(&bob, "key/create", &dave.tmb.to_b64(), Some(&dave), T0 + 20)
        .await
        .expect("built against the bare B");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for bundle in &a.bundles[..2] {
        a.push(&engine, bundle).await.expect("A's own commits");
    }
    let refused = a.push(&engine, &a.bundles[2]).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::UnknownKey))
        ),
        "{refused:?}"
    );
}

/// Stated limit (SPEC 10.6): a principal embedding its own PR follows
/// nothing and authorizes nothing. A creates `carol`, embeds its own PR
/// from that state, then removes carol; a commit by carol built against the
/// earlier state is refused (`UnknownKey`), not authorized by A's past.
/// Turns red if the engine follows A as its own embedded principal.
#[tokio::test]
async fn self_embedding_authorizes_nothing() {
    let (alice, carol, dave) = (kp(), kp(), kp());
    let mut a = Line::new(&alice).await;
    a.commit(
        &alice,
        "key/create",
        &carol.tmb.to_b64(),
        Some(&carol),
        T0 + 1,
    )
    .await
    .expect("A creates carol");
    let past = a.state.fork().await.expect("fork");
    let own_pr = a.state.pr_tagged().expect("pr");
    a.commit(&alice, "AT/KT/nonce/create", &own_pr, None, T0 + 2)
        .await
        .expect("A embeds its own PR");
    a.commit(&alice, "key/delete", &carol.tmb.to_b64(), None, T0 + 3)
        .await
        .expect("A removes carol");
    let mut built = a.state.fork().await.expect("fork");
    built
        .reveal_embedded(&own_pr, Tracking::Pin(Box::new(Tip::new(&past, T0 + 100))))
        .expect("reveal");
    let by_carol = commit_on(
        &mut built,
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 4,
    )
    .await
    .expect("built against A's own past");

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    a.push_all(&engine).await;
    let refused = a.push(&engine, &by_carol).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::UnknownKey))
        ),
        "{refused:?}"
    );
}

/// Delegates to a [`MemoryBlobStore`], counting `get`s: replaying a chain
/// reads its blobs, so the count observes a pass over it.
struct CountingBlobs {
    inner: MemoryBlobStore,
    gets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl cyphr_storage::blob::BlobStore for CountingBlobs {
    async fn persist(&self) -> Result<(), cyphr_storage::blob::BlobStoreError> {
        self.inner.persist().await
    }

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

/// Claim: loading A reads B's held chain once, however many distinct states
/// of B its commits were admitted against (one forward pass per call, the
/// state at each needed PR taken on the way; dropped with the call). A
/// carries three commits through B at three different PRs of B.
///
/// Turns red if each pin replays B from its genesis again (the reads grow
/// with the pins), or if a state is taken from the wrong prefix (A fails to
/// load).
/// End to end: yes (interleaved pushes, blob reads counted).
#[tokio::test]
async fn load_reads_b_once_for_every_pinned_state() {
    let (alice, bob, carol) = (kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = StorageEngine::new(
        CountingBlobs {
            inner: MemoryBlobStore::new(),
            gets: gets.clone(),
        },
        MemoryIndexer::new(),
    );
    type Counted = StorageEngine<CountingBlobs, MemoryIndexer>;
    async fn push(engine: &Counted, line: &Line, bundle: &WireBundle) -> Result<(), EngineError> {
        engine
            .submit_commit(&line.id, Some(line.genesis.clone()), bundle)
            .await
            .map(|_| ())
    }
    for bundle in &b.bundles {
        push(&engine, &b, bundle).await.expect("B");
    }
    for bundle in &a.bundles {
        push(&engine, &a, bundle).await.expect("A");
    }
    for i in 0..3_i64 {
        let key = kp();
        let bundle = a
            .commit(
                &carol,
                "key/create",
                &key.tmb.to_b64(),
                Some(&key),
                T0 + 20 + i,
            )
            .await
            .expect("carol signs for A");
        push(&engine, &a, &bundle).await.expect("A through B");
        // B moves on, so the next commit of A is admitted against a later PR.
        let spare = kp();
        let moved = b
            .commit(
                &bob,
                "key/create",
                &spare.tmb.to_b64(),
                Some(&spare),
                T0 + 50 + i,
            )
            .await
            .expect("B moves");
        push(&engine, &b, &moved).await.expect("B takes it");
        a.state
            .reveal_embedded(&b_pr, Tracking::Pin(Box::new(Tip::new(&b.state, T0 + 100))))
            .expect("reveal B");
    }
    let blobs_of =
        |bundles: &[WireBundle]| bundles.iter().map(|x| x.cozies().count()).sum::<usize>();
    let a_blobs = blobs_of(&a.bundles[..a.bundles.len()]);

    gets.store(0, std::sync::atomic::Ordering::SeqCst);
    let loaded = engine
        .load_principal(&a.id, a.genesis.clone())
        .await
        .expect("A loads");
    assert_eq!(
        loaded.pr_tagged().expect("pr"),
        a.state.pr_tagged().expect("pr")
    );
    let read = gets.load(std::sync::atomic::Ordering::SeqCst);
    let b_blobs = blobs_of(&b.bundles);
    // A commit's frame is read from its manifest when a load needs it (one
    // read per commit of A, and per commit of B's pass), so a load costs
    // the blobs once, plus one manifest per commit: linear, and B is not
    // re-read for each of A's pinned states.
    let manifests = a.bundles.len() + b.bundles.len();
    assert!(
        read <= a_blobs + b_blobs + manifests,
        "{read} reads for A's {a_blobs} blobs and one pass over B's {b_blobs}, plus {manifests} \
         manifests"
    );
}

/// B reorganizes by fork promotion after A was admitted through B at the
/// tip of B's line X: one commit X past `below` commits that follow the one
/// that creates carol (a fork line is displaced only while its first
/// commit is unextended, so depth lives below the fork). A rival line Y
/// (signed by `signer`, two commits) is pushed to B, kept as evidence and
/// then promoted by its second commit, so B's canonical chain is Y and A's
/// pin names a displaced state of B. Returns the engine and A's roots
/// before.
async fn b_reorganizes(below: i64, thief: bool) -> (Engine, MemoryBlobStore, Line, DerivedRoots) {
    let depth = 1;
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    for i in 0..below {
        let k = kp();
        b.commit(&bob, "key/create", &k.tmb.to_b64(), Some(&k), T0 + 20 + i)
            .await
            .expect("B's chain below the fork");
    }
    let base = b.state.fork().await.expect("fork");
    for i in 0..depth {
        let k = kp();
        b.commit(
            &bob,
            "key/create",
            &k.tmb.to_b64(),
            Some(&k),
            T0 + 20 + below + i,
        )
        .await
        .expect("B's line X");
    }
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    a.commit(
        &carol,
        "key/create",
        &dave.tmb.to_b64(),
        Some(&dave),
        T0 + 60,
    )
    .await
    .expect("carol signs for A at the tip of X");

    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    b.push_all(&engine).await;
    a.push_all(&engine).await;
    let before = a.roots(&engine).await;

    let signer = if thief { &carol } else { &bob };
    let mut y = base;
    for i in 0..=depth {
        let k = kp();
        let rival = commit_on(
            &mut y,
            signer,
            "key/create",
            &k.tmb.to_b64(),
            Some(&k),
            T0 + 70 + i,
        )
        .await
        .expect("B's rival line Y");
        let pushed = b.push(&engine, &rival).await;
        assert_eq!(
            pushed.is_ok(),
            i == depth,
            "only the last of Y promotes: {pushed:?}"
        );
    }
    assert!(!in_error(&engine, &b.id).await, "B resolved onto Y");
    (engine, blobs, a, before)
}

/// Claim (SPEC 14.12 "Cyphr does not use reversion", 2.3.2): B choosing
/// another branch undoes nothing A did through B. A, admitted through B at
/// the tip of line X, loads with the same roots after B's fork promotes line
/// Y, live and after a rebuild from blobs alone.
///
/// Turns red if a pin is resolved only along B's canonical chain: the
/// displaced state is then never found and A fails to load.
/// End to end: yes.
#[tokio::test]
async fn pin_survives_b_promoting_a_rival_line() {
    let (engine, blobs, a, before) = b_reorganizes(0, false).await;
    assert_eq!(a.roots(&engine).await, before, "live");
    assert_eq!(a.roots(&restart(&blobs).await).await, before, "rebuilt");
}

/// As above with the rival line signed by `carol`, a thief holding one key
/// of B, whose branch is the one promoted.
#[tokio::test]
async fn pin_survives_a_thiefs_branch_of_b_being_promoted() {
    let (engine, blobs, a, before) = b_reorganizes(0, true).await;
    assert_eq!(a.roots(&engine).await, before, "live");
    assert_eq!(a.roots(&restart(&blobs).await).await, before, "rebuilt");
}

/// As above with the pin two commits deep in B's chain, below the fork, so
/// the walk by `pre` crosses commits that precede the displaced one. (A
/// displaced line is a single commit: a line extended past its first
/// commit is extended, and the fork rule does not let a rival displace it.)
#[tokio::test]
async fn pin_deep_on_a_displaced_line_survives() {
    let (engine, blobs, a, before) = b_reorganizes(2, false).await;
    assert_eq!(a.roots(&engine).await, before, "live");
    assert_eq!(a.roots(&restart(&blobs).await).await, before, "rebuilt");
}

/// An engine over durable (fjall) commit logs, as the server runs: the only
/// kind that keeps a principal's verified state between uses.
type DurableEngine =
    StorageEngine<MemoryBlobStore, MemoryIndexer, cyphr_blob_fjall::storage_fjall::FjallStorage>;

fn durable(blobs: &MemoryBlobStore, db: &fjall::Database) -> DurableEngine {
    StorageEngine::with_log_factory(
        blobs.clone(),
        MemoryIndexer::new(),
        cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
    )
    .with_kept_states(8)
}

async fn push(engine: &DurableEngine, line: &Line, bundle: &WireBundle) -> Result<(), EngineError> {
    engine
        .submit_commit(&line.id, Some(line.genesis.clone()), bundle)
        .await
        .map(|_| ())
}

/// A's state as a cold replay of the store builds it, printed: every field,
/// the view of each embedded principal included.
async fn replayed(engine: &DurableEngine, a: &Line) -> String {
    // From the genesis the store holds, as the engine reads it: the
    // line's own carries a first-seen time no stored coz states.
    let genesis = engine.resolve_genesis(&a.id, &[]).await.expect("genesis");
    let cold = engine
        .load_principal(&a.id, genesis)
        .await
        .expect("A replays");
    format!("{:#?}", **cold)
}

/// What a reader is handed for A, and what the engine keeps for it when it
/// keeps anything, are the cold replay.
async fn assert_kept_is_the_replay(engine: &DurableEngine, a: &Line, when: &str) {
    let cold = replayed(engine, a).await;
    if let Some(kept) = engine.kept_state(&a.id).await {
        let k = format!("{kept:#?}");
        if let Some((a, b)) = k.lines().zip(cold.lines()).find(|(a, b)| a != b) {
            panic!("{when}: the kept state\n kept: {a}\n cold: {b}");
        }
        assert!(k == cold, "{when}: the kept state");
    }
    let read = engine.at_tip(&a.id).await.expect("read").expect("stored");
    assert!(format!("{:#?}", **read) == cold, "{when}: a reader's state");
}

/// Claim (I1): the state the engine keeps for a principal that embeds
/// another is the one a replay of the store builds, the view of the
/// embedded principal included. A replay pins B at the state each commit
/// was admitted against; a write follows B to the tip held now. So a state
/// a write has followed B through is never the one kept, whether the write
/// was admitted or refused, and after a restart too, where the engine must
/// learn again from the store that A embeds.
///
/// Turns red if the engine keeps a state that followed B's tip: the kept
/// view of B then names B's later state where the replay names the pinned
/// one. Over durable commit logs, since no state is kept over any other.
/// End to end: yes (two real chains through the engine, and a restart over
/// the same blobs and logs).
#[tokio::test]
async fn an_embedding_principals_kept_state_is_its_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("db"))
        .open()
        .expect("open db");
    let blobs = MemoryBlobStore::new();
    let (alice, bob, carol, dave, erin, frank) = (kp(), kp(), kp(), kp(), kp(), kp());
    let (mut b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let through_b = a
        .commit(
            &carol,
            "key/create",
            &dave.tmb.to_b64(),
            Some(&dave),
            T0 + 20,
        )
        .await
        .expect("carol signs for A");

    let engine = durable(&blobs, &db);
    for bundle in &b.bundles {
        push(&engine, &b, bundle).await.expect("B's commit");
    }
    for (i, bundle) in a.bundles.iter().take(2).enumerate() {
        push(&engine, &a, bundle).await.expect("A's commit");
        assert_kept_is_the_replay(&engine, &a, &format!("after A's commit {i}")).await;
    }

    // Restarted while A names B and no commit of A has yet been admitted
    // through it: a refused write signed by B's key follows B all the same.
    drop(engine);
    let engine = durable(&blobs, &db);
    assert_kept_is_the_replay(&engine, &a, "after a restart, B not yet used").await;
    let mut forged = through_b.clone();
    let mut coz: serde_json::Value = serde_json::from_slice(&forged.txs[0][0]).expect("coz");
    let sig = coz["sig"].as_str().expect("sig").to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    coz["sig"] = format!("{flipped}{}", &sig[1..]).into();
    forged.txs[0][0] = serde_json::to_vec(&coz).expect("coz bytes");
    assert!(push(&engine, &a, &forged).await.is_err(), "refused");
    assert_kept_is_the_replay(&engine, &a, "after a refused write, B not yet used").await;

    push(&engine, &a, &through_b)
        .await
        .expect("A's commit through B");
    assert_kept_is_the_replay(&engine, &a, "after A's commit through B").await;

    // Restarted: nothing kept, and B moves on, so the tip a write follows
    // is no longer the state A's commits were admitted against.
    drop(engine);
    let engine = durable(&blobs, &db);
    assert_kept_is_the_replay(&engine, &a, "after a restart").await;
    let moved = b
        .commit(&bob, "key/create", &erin.tmb.to_b64(), Some(&erin), T0 + 30)
        .await
        .expect("B creates erin");
    push(&engine, &b, &moved).await.expect("B's new commit");

    // A refused write that followed B's tip: carol's commit pushed again.
    assert!(push(&engine, &a, &through_b).await.is_err(), "refused");
    assert!(
        engine.kept_state(&a.id).await.is_some(),
        "a refusal leaves A's state kept"
    );
    assert_kept_is_the_replay(&engine, &a, "after a refused write through B").await;

    // An admitted write that followed B's tip, then one by A's own key.
    let second = a
        .commit(
            &carol,
            "key/create",
            &frank.tmb.to_b64(),
            Some(&frank),
            T0 + 40,
        )
        .await
        .expect("carol signs for A again");
    push(&engine, &a, &second)
        .await
        .expect("admitted through B");
    assert_kept_is_the_replay(&engine, &a, "after an admitted write through B").await;
    let own = a
        .commit(&alice, "key/delete", &dave.tmb.to_b64(), None, T0 + 50)
        .await
        .expect("alice deletes dave");
    push(&engine, &a, &own).await.expect("A's own commit");
    assert_kept_is_the_replay(&engine, &a, "after A's own write").await;
}

/// Claim: a push nobody of the principal signed costs an embedding
/// principal no replay of the principals it embeds. A bundle that names a
/// signer A does not hold is judged through the principals A embeds, at
/// the tips held for them, before any signature is checked, and anyone can
/// name any signer. Those tips are read from the states the engine keeps:
/// the first such push may replay B once, and every one after it replays
/// nothing.
///
/// Turns red if each such push replays B (three pushes, three replays of
/// B's chain). The replay count is the engine's own: each push is refused
/// alike. Over durable logs, the only kind states are kept over.
#[tokio::test]
async fn an_unsigned_push_to_an_embedding_principal_replays_nothing_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("db"))
        .open()
        .expect("open db");
    let blobs = MemoryBlobStore::new();
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (b, b_pr) = b_with_carol(&bob, &carol).await;
    let mut a = a_embedding(&alice, &b_pr, &b.state).await;
    let mut forged = a
        .commit(
            &carol,
            "key/create",
            &dave.tmb.to_b64(),
            Some(&dave),
            T0 + 20,
        )
        .await
        .expect("carol signs for A");
    a.bundles.pop();
    let mut coz: serde_json::Value = serde_json::from_slice(&forged.txs[0][0]).expect("coz");
    let sig = coz["sig"].as_str().expect("sig").to_owned();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    coz["sig"] = format!("{flipped}{}", &sig[1..]).into();
    forged.txs[0][0] = serde_json::to_vec(&coz).expect("coz bytes");

    // The kept-state shadow check replays cold on every use, and those
    // replays are counted too: with it on (`CYPHR_KEPT_SHADOW`) this count
    // would measure the check, not the engine.
    let engine = durable(&blobs, &db).with_kept_shadow(false);
    for bundle in &b.bundles {
        push(&engine, &b, bundle).await.expect("B's commit");
    }
    for bundle in &a.bundles {
        push(&engine, &a, bundle).await.expect("A's commit");
    }
    let mut replayed = Vec::new();
    for _ in 0..3 {
        let at = engine.commits_replayed();
        assert!(push(&engine, &a, &forged).await.is_err(), "refused");
        replayed.push(engine.commits_replayed() - at);
    }
    assert_eq!(
        replayed[1..],
        [0, 0],
        "commits replayed by the second and third push: {replayed:?}"
    );
}
