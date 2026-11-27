//! The fork rule at the engine seam (SPEC 15.7-15.8): what a holder admits
//! and what verdict it reads are functions of the commits it holds.
//!
//! A contest's child is *extended* when a held commit names its PR as
//! `pre`; the walk from genesis follows the only extended child, and none
//! or several is Error. Two extended branches are Error at any heights and
//! no further commit leaves it.
//!
//! The properties run over generated trees of real signed commits, pushed
//! in a random order that keeps parents first: the live verdict must be the
//! rule applied to what the engine ended up holding, whatever the order,
//! and a rebuild from the blobs must answer as the live engine does.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::PrincipalGenesis;
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{Consensus, StorageEngine};
use cyphr_storage::index::MemoryIndexer;
use proptest::prelude::*;

const NOW: i64 = 1_700_400_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(name: &str) -> Kp {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool.toml");
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
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

/// `signer` creates `new` at `now` and finalizes the commit itself.
async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    });
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .expect("finalize");
}

/// The genesis keys, any of which may sign a commit anywhere in a tree.
const SIGNERS: [&str; 3] = ["golden", "diana_es384", "eve_ed25519"];
/// The key a commit creates, by depth: no line creates one twice.
const CREATED: [&str; 5] = ["key_a", "key_b", "alice", "bob", "carol"];

/// A tree of commits over one genesis, built once: node `i + 1` is the
/// child of node `parents[i]` (0 is the shared genesis commit), signed by
/// `SIGNERS[signers[i]]`.
struct World {
    id: PrincipalGenesis,
    genesis: Genesis,
    /// Each node's principal after its commit, and its commit id.
    nodes: Vec<cyphr::Principal>,
    ids: Vec<String>,
    parents: Vec<usize>,
}

async fn world(parents: &[usize], signers: &[usize]) -> World {
    let keys: Vec<Kp> = SIGNERS.iter().map(|n| kp(n)).collect();
    let genesis = Genesis::Disclosed(keys.iter().map(key_of).collect());
    let mut p = cyphr::Principal::implicit(key_of(&keys[0]))
        .await
        .expect("genesis");
    let others: Vec<cyphr::Key> = keys[1..].iter().map(key_of).collect();
    p.commit_genesis(&signer_of(&keys[0]), &others, NOW, "cyphr.me")
        .await
        .expect("genesis commit");
    let mut nodes = vec![p];
    let mut depth = vec![0usize];
    for (i, &parent) in parents.iter().enumerate() {
        let mut p = nodes[parent].fork().await.expect("fork");
        let at = depth[parent];
        // Distinct `now` per node keeps siblings distinct commits.
        create_key(
            &mut p,
            &keys[signers[i]],
            &kp(CREATED[at]),
            NOW + 10 + i as i64,
        )
        .await;
        depth.push(at + 1);
        nodes.push(p);
    }
    let bundle = |n: usize| {
        let p = &nodes[n];
        WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
    };
    let first = bundle(0);
    let id = test_fixtures::bundle::genesis_id(&first).expect("genesis id");
    let ids = (0..nodes.len())
        .map(|n| {
            nodes[n]
                .commits()
                .last()
                .expect("commit")
                .tr()
                .0
                .tagged_first()
                .expect("commit id")
                .to_string()
        })
        .collect();
    World {
        id,
        genesis,
        nodes,
        ids,
        parents: parents.to_vec(),
    }
}

impl World {
    fn bundle(&self, n: usize) -> WireBundle {
        WireBundle::of_commit(self.nodes[n].commits().last().expect("commit")).expect("bundle")
    }

    async fn push(&self, e: &Engine, n: usize) -> Result<(), String> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), &self.bundle(n))
            .await
            .map(|_| ())
            .map_err(|why| format!("{why:?}"))
    }

    /// The nodes the engine holds, genesis included.
    async fn held(&self, e: &Engine) -> Vec<usize> {
        let mut held = Vec::new();
        for n in 0..self.nodes.len() {
            if e.holds_commit(&self.id, &self.ids[n]).await.expect("holds") {
                held.push(n);
            }
        }
        held
    }

    /// Rule E over the held nodes, written the plain way: `Err(())` is
    /// Error, `Ok(n)` the leaf the walk ends at.
    fn reference(&self, held: &[usize]) -> Result<usize, ()> {
        let kids = |n: usize| -> Vec<usize> {
            held.iter()
                .copied()
                .filter(|&k| k > 0 && self.parents[k - 1] == n)
                .collect()
        };
        let mut at = 0;
        loop {
            let children = kids(at);
            match children.len() {
                0 => return Ok(at),
                1 => at = children[0],
                _ => {
                    let extended: Vec<usize> = children
                        .iter()
                        .copied()
                        .filter(|&c| !kids(c).is_empty())
                        .collect();
                    match extended.as_slice() {
                        [only] => at = *only,
                        _ => return Err(()),
                    }
                },
            }
        }
    }
}

fn engine() -> Engine {
    StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
}

/// What an engine answers about the verdict: Error, or the one head.
async fn verdict(e: &Engine, id: &PrincipalGenesis) -> Result<String, ()> {
    let a = e.assess(id).await.expect("assess");
    match a.consensus {
        Consensus::Error => Err(()),
        Consensus::Active => {
            assert_eq!(a.heads.len(), 1, "Active has one head: {:?}", a.heads);
            Ok(a.heads[0].clone())
        },
    }
}

/// A tree of up to 5 commits (`parents[i] <= i`), a signer for each, and a
/// push order as choices among the nodes whose parent is already pushed.
fn shape() -> impl Strategy<Value = (Vec<usize>, Vec<usize>, Vec<usize>)> {
    (1usize..=5).prop_flat_map(|n| {
        (
            // Biased to long lines off the genesis, where contests form.
            (0..n)
                .map(|i| prop_oneof![Just(0), Just(i), 0..=i])
                .collect::<Vec<_>>(),
            proptest::collection::vec(0..SIGNERS.len(), n),
            proptest::collection::vec(0usize..8, n),
        )
    })
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Catches path dependence and rebuild drift: whatever order a tree is
    /// pushed in, the live verdict is rule E over what the engine holds,
    /// and an engine rebuilt from the blobs reads the same (tallest-wins
    /// reads a taller both-extended branch Active).
    #[test]
    fn live_and_rebuilt_engines_read_the_rule((parents, signers, picks) in shape()) {
        run(async {
            let w = world(&parents, &signers).await;
            let e = engine();
            w.push(&e, 0).await.expect("genesis commit");
            let mut pushed = vec![0usize];
            let mut left: Vec<usize> = (1..w.nodes.len()).collect();
            for pick in picks {
                let ready: Vec<usize> = left
                    .iter()
                    .copied()
                    .filter(|&n| pushed.contains(&w.parents[n - 1]))
                    .collect();
                if ready.is_empty() { break; }
                let n = ready[pick % ready.len()];
                left.retain(|&m| m != n);
                // A refusal is allowed (caps, timestamps); what is held
                // afterwards is what the verdict must follow.
                let _ = w.push(&e, n).await;
                pushed.push(n);
            }
            let held = w.held(&e).await;
            let want = w.reference(&held).map(|n| w.ids[n].clone());
            prop_assert_eq!(verdict(&e, &w.id).await, want.clone(), "live, held {:?}", held);
            e.rebuild_index_from_scratch().await.expect("rebuild");
            prop_assert_eq!(verdict(&e, &w.id).await, want, "rebuilt, held {:?}", held);
            Ok(())
        })?;
    }
}

/// Two branches over one position, each extended once: pushed in any
/// order the engine ends in Error with every commit held, and a further
/// commit on either branch, taller than the other, is refused.
#[tokio::test]
async fn a_taller_extension_of_a_both_extended_fork_is_refused() {
    // 1, 2 over genesis; 3 over 1; 4 over 2; 5 over 3 (the taller branch).
    let w = world(&[0, 0, 1, 2, 3], &[0, 1, 0, 1, 0]).await;
    for order in [[1, 2, 3, 4], [2, 1, 4, 3], [1, 3, 2, 4]] {
        let e = engine();
        w.push(&e, 0).await.expect("genesis commit");
        for n in order {
            let _ = w.push(&e, n).await;
        }
        assert_eq!(verdict(&e, &w.id).await, Err(()), "order {order:?}");
        let refused = w.push(&e, 5).await;
        assert!(
            refused.is_err(),
            "the taller branch is no exit: {refused:?}"
        );
        assert_eq!(verdict(&e, &w.id).await, Err(()), "order {order:?}, after");
    }
}

/// With neither branch extended a single commit on either resolves, and
/// the other branch stays held as evidence; one extension of the abandoned
/// branch afterwards re-opens the fork, though the chosen branch is taller.
/// Catches a rule that never lets a commit resolve, one that closes a fork
/// for good, and tallest-wins, which keeps the taller branch Active.
// @docket: sc-l2814 :: scripts/docket-run sc-l2814
#[tokio::test]
async fn one_extension_resolves_and_the_abandoned_branch_reopens_it() {
    // 1, 2 over genesis; 3 over 1 and 4 over 3 (the chosen branch); 5 over 2.
    let w = world(&[0, 0, 1, 3, 2], &[0, 1, 0, 1, 0]).await;
    let e = engine();
    w.push(&e, 0).await.expect("genesis commit");
    w.push(&e, 1).await.expect("the first branch");
    let _ = w.push(&e, 2).await;
    assert_eq!(verdict(&e, &w.id).await, Err(()), "an unextended fork");
    w.push(&e, 3).await.expect("one commit resolves");
    assert_eq!(verdict(&e, &w.id).await, Ok(w.ids[3].clone()));
    w.push(&e, 4).await.expect("the chosen branch grows");
    assert!(
        w.held(&e).await.contains(&2),
        "the abandoned branch is held"
    );
    let _ = w.push(&e, 5).await;
    assert_eq!(
        verdict(&e, &w.id).await,
        Err(()),
        "re-opened by its extension"
    );
    e.rebuild_index_from_scratch().await.expect("rebuild");
    assert_eq!(verdict(&e, &w.id).await, Err(()), "a rebuild agrees");
}

/// A genesis commit of the shared keys, signed by `first` (the others
/// follow in key order), at `now`.
async fn genesis_commit(first: usize, now: i64) -> cyphr::Principal {
    let keys: Vec<Kp> = SIGNERS.iter().map(|n| kp(n)).collect();
    let mut p = cyphr::Principal::implicit(key_of(&keys[first]))
        .await
        .expect("genesis");
    let others: Vec<cyphr::Key> = (0..keys.len())
        .filter(|&i| i != first)
        .map(|i| key_of(&keys[i]))
        .collect();
    p.commit_genesis(&signer_of(&keys[first]), &others, now, "cyphr.me")
        .await
        .expect("genesis commit");
    p
}

fn commit_id(p: &cyphr::Principal) -> String {
    p.commits()
        .last()
        .expect("commit")
        .tr()
        .0
        .tagged_first()
        .expect("commit id")
        .to_string()
}

/// Whether two distinct genesis commits of one principal can share a
/// Principal Root, which would make a sequence-1 commit extend both. Not
/// constructible from honest signing: the same keys, signer and time give
/// the one commit (no fork), and changing the time or the signer changes
/// the commit and its PR. A shared PR is then a hash collision, and the
/// rule's answer to one (both extended: Error) is pinned over held
/// commits in the core tests.
#[tokio::test]
async fn distinct_genesis_commits_have_distinct_principal_roots() {
    let same = (genesis_commit(0, NOW).await, genesis_commit(0, NOW).await);
    assert_eq!(commit_id(&same.0), commit_id(&same.1), "one commit");
    assert_eq!(
        same.0.pr_tagged().expect("pr"),
        same.1.pr_tagged().expect("pr")
    );
    let others = [
        genesis_commit(0, NOW + 7).await,
        genesis_commit(1, NOW).await,
    ];
    for o in &others {
        assert_ne!(commit_id(o), commit_id(&same.0), "a distinct commit");
        assert_ne!(
            o.pr_tagged().expect("pr"),
            same.0.pr_tagged().expect("pr"),
            "with a distinct PR"
        );
    }
}

/// Rule E at position 0: two genesis commits of one principal are a
/// contest like any other. Neither extended is Error; a commit over one
/// selects it; a commit over the other too is Error again. Catches a rule
/// that skips position 0, and tallest-wins (the second extension below is
/// the taller branch's rival).
#[tokio::test]
async fn two_genesis_commits_are_a_contest_like_any_other() {
    let a = genesis_commit(0, NOW).await;
    let b = genesis_commit(0, NOW + 7).await;
    let keys: Vec<Kp> = SIGNERS.iter().map(|n| kp(n)).collect();
    let mut a1 = a.fork().await.expect("fork");
    create_key(&mut a1, &keys[0], &kp(CREATED[0]), NOW + 20).await;
    let mut b1 = b.fork().await.expect("fork");
    create_key(&mut b1, &keys[0], &kp(CREATED[1]), NOW + 21).await;
    let mut b2 = b1.fork().await.expect("fork");
    create_key(&mut b2, &keys[0], &kp(CREATED[2]), NOW + 22).await;

    let bundle = |p: &cyphr::Principal| {
        WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
    };
    let id = test_fixtures::bundle::genesis_id(&bundle(&a)).expect("genesis id");
    let genesis = Genesis::Disclosed(keys.iter().map(key_of).collect());
    let e = engine();
    let push = |p: &cyphr::Principal| {
        let (e, id, genesis, b) = (&e, id.clone(), genesis.clone(), bundle(p));
        async move { e.submit_commit(&id, Some(genesis), &b).await.map(|_| ()) }
    };
    push(&a).await.expect("the first genesis");
    let _ = push(&b).await;
    assert_eq!(
        verdict(&e, &id).await,
        Err(()),
        "two unextended genesis commits"
    );
    let fp = e.assess(&id).await.expect("assess").fork_point;
    assert_eq!(
        fp.map(|f| (f.height, f.pre)),
        Some((0, None)),
        "the fork point"
    );

    push(&a1)
        .await
        .expect("one commit over one genesis selects it");
    assert_eq!(verdict(&e, &id).await, Ok(commit_id(&a1)));
    let _ = push(&b1).await;
    assert_eq!(
        verdict(&e, &id).await,
        Err(()),
        "both genesis commits extended"
    );
    let refused = push(&b2).await;
    assert!(
        refused.is_err(),
        "a taller extension is no exit: {refused:?}"
    );
    assert_eq!(verdict(&e, &id).await, Err(()));
    e.rebuild_index_from_scratch().await.expect("rebuild");
    assert_eq!(verdict(&e, &id).await, Err(()), "a rebuild agrees");
}
