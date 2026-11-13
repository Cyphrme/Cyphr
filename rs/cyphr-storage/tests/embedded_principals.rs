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
