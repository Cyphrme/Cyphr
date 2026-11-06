//! A fork of a stored principal is kept as a branch, never merged (G1).
//!
//! Single-writer-per-principal (AGENTS.md I2) forbids merging, not
//! knowing: a commit that takes an already-taken position is refused as
//! the principal's tip, but a commit that verifies at its `pre` is
//! evidence of a fork and the store retains it, indexed by `pre`, beside
//! the canonical chain. Every scenario here runs over the engine seam on
//! real signed commits.
//!
//! The tests that touch the retention API (`StorageEngine::list_branches`,
//! `EngineError::BranchLimit`) were written red against a base that lacked
//! it; the others characterise behaviour that must survive retention.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;

const NOW: i64 = 1_700_100_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rs dir")
        .parent()
        .expect("repo root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
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

/// Apply `pay` signed by `signer` (optionally introducing `sidecar`) and
/// finalize the commit with `finalizer`.
fn apply(
    p: &mut cyphr::Principal,
    signer: &Kp,
    finalizer: &Kp,
    pay: serde_json::Value,
    sidecar: Option<cyphr::Key>,
    now: i64,
) {
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &finalizer.alg,
                &finalizer.prv,
                &finalizer.pubb,
                &finalizer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

fn create_pay(signer: &Kp, new: &Kp, now: i64) -> serde_json::Value {
    serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    })
}

/// `signer` creates `new` at time `now` and finalizes the commit itself.
/// Distinct `now` values give distinct commits at one position.
fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    apply(
        p,
        signer,
        signer,
        create_pay(signer, new, now),
        Some(key_of(new)),
        now,
    );
}

/// Wire blobs of commit `i` of `p`: key-introducing cozies carry their key,
/// and commit 0's last blob carries the genesis key so the principal's
/// genesis is recoverable from its first commit.
fn blobs(p: &cyphr::Principal, genesis: &Kp, i: usize) -> Vec<Vec<u8>> {
    let entry = &cyphr_storage::export_commits(p).expect("export")[i];
    let mut key_idx = 0;
    let last = entry.cozies.len() - 1;
    entry
        .cozies
        .iter()
        .enumerate()
        .map(|(n, c)| {
            let mut c = c.clone();
            let typ = c["pay"]["typ"].as_str().unwrap_or("").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) && key_idx < entry.keys.len() {
                let k = &entry.keys[key_idx];
                c["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                key_idx += 1;
            }
            if i == 0 && n == last {
                c["key"] = serde_json::json!({
                    "alg": genesis.alg,
                    "pub": Base64UrlUnpadded::encode_string(&genesis.pubb),
                    "tmb": genesis.tmb.to_b64(),
                });
            }
            serde_json::to_vec(&c).expect("blob")
        })
        .collect()
}

/// A principal with one shared commit (position 0) and any number of
/// rival commits at position 1, every one signed by `golden`, a key active
/// at their common `pre` (the Principal Root after commit 0).
struct Fork {
    genesis: Genesis,
    id: String,
    pre: String,
    /// Commit 0, shared by every branch.
    first: Vec<Vec<u8>>,
    /// Rival commits at position 1; each is valid on its own.
    rivals: Vec<Vec<Vec<u8>>>,
    /// Commit 0's principal state, for building more rivals.
    base: cyphr::Principal,
    golden: Kp,
}

impl Fork {
    fn new(rivals: usize) -> Self {
        let pool = load_pool();
        let golden = kp(&pool, "golden");
        let genesis = Genesis::Implicit(key_of(&golden));
        let mut base = cyphr::Principal::implicit(key_of(&golden)).expect("genesis");
        let id = base.pr_tagged().expect("genesis id");
        create_key(&mut base, &golden, &kp(&pool, "key_a"), NOW);
        let pre = base.pr_tagged().expect("pr after commit 0");
        let first = blobs(&base, &golden, 0);
        let mut fork = Self {
            genesis,
            id,
            pre,
            first,
            rivals: Vec::new(),
            base,
            golden,
        };
        for n in 0..rivals {
            fork.add_rival(n as i64);
        }
        fork
    }

    /// The principal after the rival commit `salt` at position 1.
    fn rival_state(&self, salt: i64) -> cyphr::Principal {
        let pool = load_pool();
        let mut p = self.base.clone();
        let new = kp(&pool, if salt % 2 == 0 { "key_b" } else { "alice" });
        create_key(&mut p, &self.golden, &new, NOW + 1 + salt);
        p
    }

    /// One more valid commit at position 1; `salt` makes it distinct.
    fn add_rival(&mut self, salt: i64) {
        let p = self.rival_state(salt);
        self.rivals.push(blobs(&p, &self.golden, 1));
    }

    /// A second, divergent commit 0 from the same genesis key.
    fn second_genesis(&self) -> Vec<Vec<u8>> {
        let pool = load_pool();
        let mut p = cyphr::Principal::implicit(key_of(&self.golden)).expect("genesis");
        create_key(&mut p, &self.golden, &kp(&pool, "key_b"), NOW + 7);
        blobs(&p, &self.golden, 0)
    }

    async fn submit(
        &self,
        e: &Engine,
        bundle: &[Vec<u8>],
    ) -> Result<(), cyphr_storage::engine::EngineError> {
        let refs: Vec<&[u8]> = bundle.iter().map(Vec::as_slice).collect();
        e.submit_commit(&self.id, Some(self.genesis.clone()), &refs)
            .await
            .map(|_| ())
    }

    /// A fresh engine holding commit 0 and then `order` of the rivals.
    async fn engine_with(
        &self,
        order: &[usize],
    ) -> (Engine, Vec<Result<(), cyphr_storage::engine::EngineError>>) {
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        self.submit(&e, &self.first).await.expect("commit 0");
        let mut outcomes = Vec::new();
        for &i in order {
            outcomes.push(self.submit(&e, &self.rivals[i]).await);
        }
        (e, outcomes)
    }
}

/// Every durable branch manifest in the engine's blob store, as JSON.
async fn branch_manifests(e: &Engine) -> Vec<serde_json::Value> {
    let store = e.blob_store();
    let mut found = Vec::new();
    for hash in store.iter().await.expect("iter") {
        let data = store
            .get(&hash.expect("hash"))
            .await
            .expect("get")
            .expect("stored");
        if let Some(json) = data.strip_prefix(cyphr_storage::engine::BRANCH_MANIFEST_PREFIX) {
            found.push(serde_json::from_slice(json).expect("manifest json"));
        }
    }
    found
}

async fn blob_count(e: &Engine) -> usize {
    e.blob_store()
        .iter()
        .await
        .expect("iter")
        .collect::<Result<Vec<_>, _>>()
        .expect("hashes")
        .len()
}

/// Backs the survival half of G1: a commit at a taken position is refused
/// as the tip and the principal's tip and commit count do not move. Turns
/// red if retention lets the rival become, or move, the tip. A green
/// characterization test at the engine seam; the end-to-end 409 is
/// `principal_id_canonical.rs`.
#[tokio::test]
async fn fork_commit_is_refused_as_the_tip() {
    let f = Fork::new(2);
    let (e, outcomes) = f.engine_with(&[0]).await;
    assert!(
        outcomes[0].is_ok(),
        "the first rival is the canonical commit"
    );
    let before = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert_eq!(before.commit_count, 2);

    let refused = f.submit(&e, &f.rivals[1]).await;
    assert!(
        refused.is_err(),
        "a commit at a taken position must be refused"
    );

    let after = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert_eq!(
        (&after.commit_id, &after.pr, after.commit_count),
        (&before.commit_id, &before.pr, before.commit_count),
        "the refused fork moved the tip"
    );
}

/// Backs a-verify: a bundle that does not verify at its `pre` retains
/// nothing -- the engine's blob count and tip are unchanged. Turns red if
/// retention stores a rival before (or without) verifying it, e.g. keeps
/// the blobs of a bad signature. Here the signature is corrupted. Green
/// today; must stay green. Unit-level: the invalid bundle is cheaper to
/// build by corrupting a valid one than as a scenario.
#[tokio::test]
async fn unverifiable_rival_is_refused_and_stores_nothing() {
    let f = Fork::new(2);
    let (e, _) = f.engine_with(&[0]).await;
    let blobs_before = blob_count(&e).await;
    let tip_before = e.get_tip(&f.id).await.expect("tip").expect("stored");

    let mut bad = f.rivals[1].clone();
    let mut coz: serde_json::Value = serde_json::from_slice(&bad[0]).expect("coz");
    let sig = coz["sig"].as_str().expect("sig").to_string();
    let mut raw = Base64UrlUnpadded::decode_vec(&sig).expect("sig b64");
    raw[0] ^= 0xff;
    coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&raw));
    bad[0] = serde_json::to_vec(&coz).expect("coz bytes");

    assert!(f.submit(&e, &bad).await.is_err(), "bad signature accepted");
    assert_eq!(
        blob_count(&e).await,
        blobs_before,
        "a refused bundle left blobs"
    );
    let tip_after = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert_eq!(tip_after.commit_id, tip_before.commit_id);
}

/// Backs the survival half of G1 at sequence 0: a second genesis commit
/// from the same key is refused as the tip and the tip does not move.
/// Turns red if retention lets the second genesis replace the first.
/// Green today. End to end at the engine seam: yes.
#[tokio::test]
async fn second_genesis_is_refused_as_the_tip() {
    let f = Fork::new(0);
    let (e, _) = f.engine_with(&[]).await;
    let before = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert!(
        f.submit(&e, &f.second_genesis()).await.is_err(),
        "a second commit 0 must be refused"
    );
    let after = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert_eq!(
        (&after.commit_id, after.commit_count),
        (&before.commit_id, before.commit_count)
    );
}

/// A principal whose `golden` key is revoked at position 1 (`golden`
/// self-revokes, `key_a` finalizes), so `golden` is active at the `pre` of
/// position 1 and revoked at the `pre` of position 2.
struct Revoked {
    f: Fork,
    key_a: Kp,
    /// The principal after the revocation, position 1.
    canonical: cyphr::Principal,
    /// A rival AT the revocation position, signed while golden was active.
    theft: Vec<Vec<u8>>,
}

fn revoked() -> Revoked {
    let f = Fork::new(0);
    let pool = load_pool();
    let key_a = kp(&pool, "key_a");
    let mut canonical = f.base.clone();
    apply(
        &mut canonical,
        &f.golden,
        &key_a,
        serde_json::json!({"alg": f.golden.alg, "now": NOW + 10, "rvk": NOW + 10,
                           "tmb": f.golden.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"}),
        None,
        NOW + 10,
    );
    let mut rival = f.base.clone();
    create_key(&mut rival, &f.golden, &kp(&pool, "key_b"), NOW + 11);
    let theft = blobs(&rival, &f.golden, 1);
    Revoked {
        f,
        key_a,
        canonical,
        theft,
    }
}

/// Position 2 on the revoked chain, hand-built because the `Principal` API
/// will not apply a revoked key: `key_a` (active) builds a valid commit
/// creating `key_c`, then its transaction coz is re-signed by the revoked
/// `golden` through `coz` directly. Its arrow cannot match (the state
/// root after a revoked-key transaction cannot be computed), so the
/// closing coz is not self-consistent with the swapped transaction.
fn after_revocation(r: &Revoked) -> Vec<Vec<u8>> {
    let pool = load_pool();
    let mut q = r.canonical.clone();
    create_key(&mut q, &r.key_a, &kp(&pool, "bob"), NOW + 12);
    let mut bundle = blobs(&q, &r.f.golden, 2);
    let mut coz_v: serde_json::Value = serde_json::from_slice(&bundle[0]).expect("tx coz");
    coz_v["pay"]["tmb"] = serde_json::json!(r.f.golden.tmb.to_b64());
    coz_v["pay"]["alg"] = serde_json::json!(r.f.golden.alg);
    let pay = serde_json::to_vec(&coz_v["pay"]).expect("pay");
    let (sig, _) =
        coz::sign_json(&pay, &r.f.golden.alg, &r.f.golden.prv, &r.f.golden.pubb).expect("sign");
    coz_v["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&sig));
    let obj = coz_v.as_object_mut().expect("coz object");
    obj.remove("cad");
    obj.remove("czd");
    bundle[0] = serde_json::to_vec(&coz_v).expect("coz bytes");
    bundle
}

/// Backs a-verify: a bundle at a position after a key was revoked, signed
/// by that revoked key, is refused and stores nothing. The control builds
/// the same position-2 commit with the active `key_a` and it is accepted,
/// so the refusal is about the swapped signer and not the position. Green
/// today; must stay green. The refusal is `KeyRevoked` (observed), not an
/// arrow mismatch, so it is attributable to the revocation.
#[tokio::test]
async fn revoked_key_bundle_is_refused_and_stores_nothing() {
    let r = revoked();
    let (e, _) = {
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, &r.f.golden, 1))
            .await
            .expect("revocation");
        (e, ())
    };
    let blobs_before = blob_count(&e).await;
    let tip_before = e.get_tip(&r.f.id).await.expect("tip").expect("stored");

    // Control: the same commit signed by the active key_a is accepted.
    let pool = load_pool();
    let mut ok = r.canonical.clone();
    create_key(&mut ok, &r.key_a, &kp(&pool, "bob"), NOW + 12);
    let ok_blobs = blobs(&ok, &r.f.golden, 2);
    let control = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    r.f.submit(&control, &r.f.first)
        .await
        .expect("control commit 0");
    r.f.submit(&control, &blobs(&r.canonical, &r.f.golden, 1))
        .await
        .expect("control revocation");
    r.f.submit(&control, &ok_blobs)
        .await
        .expect("control: an active key commits at position 2");

    let refused = r.f.submit(&e, &after_revocation(&r)).await;
    assert!(
        matches!(
            refused,
            Err(cyphr_storage::engine::EngineError::Protocol(
                cyphr::Error::KeyRevoked
            ))
        ),
        "a bundle signed by a revoked key must be refused as KeyRevoked: {refused:?}"
    );
    assert_eq!(
        blob_count(&e).await,
        blobs_before,
        "a refused bundle left blobs"
    );
    let tip_after = e.get_tip(&r.f.id).await.expect("tip").expect("stored");
    assert_eq!(tip_after.commit_id, tip_before.commit_id);
}

mod retained {
    use cyphr_storage::engine::EngineError;

    use super::*;

    /// Order-independent view of a principal's branches.
    async fn branches(e: &Engine, id: &str) -> Vec<(String, Option<String>, u64, bool)> {
        let mut v: Vec<_> = e
            .list_branches(id)
            .await
            .expect("list_branches")
            .into_iter()
            .map(|b| (b.tip, b.pre, b.sequence, b.canonical))
            .collect();
        v.sort();
        v
    }

    /// Backs a-red-retain: after one commit is stored at a position, a
    /// rival there is refused as the tip yet retained: `list_branches`
    /// returns both tips at that sequence, with the shared `pre`, exactly
    /// one canonical, and the canonical one is the stored chain's tip.
    /// Turns red if the rival is dropped (one branch listed), if both or
    /// neither is canonical, or if `pre` is not the rivals' common parent.
    /// End to end at the engine seam: yes.
    #[tokio::test]
    async fn refused_fork_is_retained_as_a_non_tip_branch() {
        let f = Fork::new(2);
        let (e, outcomes) = f.engine_with(&[0, 1]).await;
        assert!(
            outcomes[0].is_ok() && outcomes[1].is_err(),
            "premise: second is refused"
        );
        let tip = e.get_tip(&f.id).await.expect("tip").expect("stored");

        let got = e.list_branches(&f.id).await.expect("list_branches");
        let at_fork: Vec<_> = got.iter().filter(|b| b.sequence == 1).collect();
        assert_eq!(
            at_fork.len(),
            2,
            "both rivals at position 1 must be listed: {got:?}"
        );
        assert!(
            at_fork
                .iter()
                .all(|b| b.pre.as_deref() == Some(f.pre.as_str())),
            "pre is the shared parent: {got:?}"
        );
        assert_ne!(at_fork[0].tip, at_fork[1].tip, "two distinct tips");
        assert_eq!(
            at_fork.iter().filter(|b| b.canonical).count(),
            1,
            "exactly one canonical: {got:?}"
        );
        // The canonical branch's tip is the commit id `get_tip` reports.
        let after = e.get_tip(&f.id).await.expect("tip").expect("stored");
        let canonical = at_fork.iter().find(|b| b.canonical).expect("one canonical");
        assert_eq!(
            canonical.tip, after.commit_id,
            "canonical tip is get_tip().commit_id"
        );
        assert_eq!(after.commit_id, tip.commit_id, "retention moved the tip");
        assert_eq!(after.commit_count, 2);
    }

    /// Backs a-red-rebuild: the attack is a key holder forking a principal
    /// so that the tip flips after a restart. `rebuild_index_from_scratch`
    /// over the same blobs must give the same canonical tip and branch set
    /// whichever rival the engine saw first. The same two commits are
    /// stored in both orders, so the blob set (and so the manifest hash
    /// order) is identical and exactly one order has the canonical
    /// manifest sorting after the fork's. Turns red if the rebuild picks
    /// the canonical by manifest hash order (the tip then flips in one
    /// order) or drops the retained branch. End to end at the engine seam:
    /// yes.
    #[tokio::test]
    async fn rebuild_keeps_tip_and_branches_in_both_manifest_orders() {
        let f = Fork::new(2);
        for order in [[0, 1], [1, 0]] {
            let (e, _) = f.engine_with(&order).await;
            let tip = e.get_tip(&f.id).await.expect("tip").expect("stored");
            let listed = branches(&e, &f.id).await;
            assert_eq!(
                listed.iter().filter(|b| b.3).count(),
                1,
                "premise: one canonical"
            );

            e.rebuild_index_from_scratch().await.expect("rebuild");

            let rebuilt = e.get_tip(&f.id).await.expect("tip").expect("stored");
            assert_eq!(
                rebuilt.commit_id, tip.commit_id,
                "the tip flipped on rebuild (insertion order {order:?})"
            );
            assert_eq!(
                branches(&e, &f.id).await,
                listed,
                "the branch set changed on rebuild (insertion order {order:?})"
            );
        }
    }

    /// Backs a-replay: a retained branch is derivable from blobs alone and
    /// equals the branch as ingested. The rival's tip and roots, derived
    /// independently by applying it to the `Principal` at its `pre`, are
    /// what the durable branch manifest records and what the listing
    /// reports, before and after a rebuild from scratch. Turns red if the
    /// branch is kept only in memory (the manifest is absent or the listing
    /// is lost on rebuild), or the manifest records a state the rival does
    /// not produce. End to end at the engine seam: yes.
    #[tokio::test]
    async fn branch_replay_from_blobs_equals_the_branch_as_ingested() {
        let f = Fork::new(2);
        let (e, _) = f.engine_with(&[0, 1]).await;
        // `rivals[1]` was refused; the independent derivation of its state.
        let entry = cyphr_storage::export_commits(&f.rival_state(1))
            .expect("export")
            .remove(1);

        let first_digest = |v: &serde_json::Value, field: &str| {
            v["commit"][field][0].as_str().expect("digest").to_string()
        };

        let ingested = branches(&e, &f.id).await;
        for round in ["as ingested", "after rebuild"] {
            if round == "after rebuild" {
                e.rebuild_index_from_scratch().await.expect("rebuild");
                assert_eq!(branches(&e, &f.id).await, ingested, "{round}");
            }
            let found = branch_manifests(&e).await;
            assert_eq!(found.len(), 1, "{round}: one durable branch manifest");
            let m = &found[0];
            assert_eq!(first_digest(m, "commit_ids"), entry.commit_id, "{round}");
            assert_eq!(first_digest(m, "prs"), entry.pr, "{round}");
            assert_eq!(first_digest(m, "srs"), entry.sr, "{round}");
            assert_eq!(first_digest(m, "ars"), entry.auth_root, "{round}");
            assert_eq!(m["commit"]["pre"], f.pre, "{round}");
            assert!(
                ingested
                    .iter()
                    .any(|b| b.0 == entry.commit_id && !b.3 && b.1.as_deref() == Some(&f.pre)),
                "{round}: the listing reports the derived rival: {ingested:?}"
            );
        }
    }

    /// Backs a-verify: retention is bounded per principal. Rivals are
    /// pushed until the store answers the typed `EngineError::BranchLimit`;
    /// the refused one stores nothing and the listing stops growing.
    /// Turns red if retention is unbounded (no such error within
    /// `ATTEMPTS`), if it arrives at any count but the 17th rival (the
    /// canonical one plus `BRANCH_LIMIT` retained non-canonical), or the
    /// error is untyped. `ATTEMPTS` is a harness ceiling, not the bound.
    #[tokio::test]
    async fn retention_is_bounded_by_a_typed_error() {
        const ATTEMPTS: usize = 100;
        // Mirrors the brief's API note: `BRANCH_LIMIT = 16` retained
        // non-canonical branches.
        const BRANCH_LIMIT: usize = 16;
        let mut f = Fork::new(0);
        let (e, _) = f.engine_with(&[]).await;
        let mut limit_at = None;
        for n in 0..ATTEMPTS {
            f.add_rival(n as i64);
            let (blobs_before, listed_before) = (blob_count(&e).await, branches(&e, &f.id).await);
            // The first rival is canonical (Ok); the rest are refused as the
            // tip yet retained, which is not the bound.
            if let Err(EngineError::BranchLimit) =
                f.submit(&e, f.rivals.last().expect("rival")).await
            {
                assert_eq!(
                    blob_count(&e).await,
                    blobs_before,
                    "BranchLimit stored blobs"
                );
                assert_eq!(
                    branches(&e, &f.id).await,
                    listed_before,
                    "BranchLimit stored a branch"
                );
                let non_canonical = listed_before.iter().filter(|b| !b.3).count();
                assert_eq!(non_canonical, BRANCH_LIMIT, "bound reached off the limit");
                limit_at = Some(n);
                break;
            }
        }
        assert_eq!(
            limit_at,
            Some(BRANCH_LIMIT + 1),
            "BranchLimit must answer the rival after canonical + {BRANCH_LIMIT} retained"
        );
    }

    /// Backs a-red-formats at sequence 0: a second genesis from the same
    /// key is refused as the tip and listed beside the canonical genesis,
    /// both with `pre` None, exactly one canonical, and the canonical tip
    /// the commit id `get_tip` reports. Turns red if the second genesis is
    /// dropped, or `pre` is not None at sequence 0. End to end at the
    /// engine seam: yes.
    #[tokio::test]
    async fn second_genesis_is_retained_with_no_pre() {
        let f = Fork::new(0);
        let (e, _) = f.engine_with(&[]).await;
        assert!(
            f.submit(&e, &f.second_genesis()).await.is_err(),
            "premise: refused"
        );
        let tip = e.get_tip(&f.id).await.expect("tip").expect("stored");

        let got = e.list_branches(&f.id).await.expect("list_branches");
        let at_zero: Vec<_> = got.iter().filter(|b| b.sequence == 0).collect();
        assert_eq!(at_zero.len(), 2, "both genesis commits listed: {got:?}");
        assert!(
            at_zero.iter().all(|b| b.pre.is_none()),
            "pre is None at sequence 0: {got:?}"
        );
        assert_eq!(
            at_zero.iter().filter(|b| b.canonical).count(),
            1,
            "one canonical: {got:?}"
        );
        let canonical = at_zero.iter().find(|b| b.canonical).expect("canonical");
        assert_eq!(
            canonical.tip, tip.commit_id,
            "canonical tip is get_tip().commit_id"
        );
    }

    /// Backs a-verify (theft evidence): a rival AT the revocation position,
    /// signed by a key that was still active at its `pre`, is retained
    /// beside the revocation, while the revocation stays canonical and the
    /// tip does not move. Turns red if such a rival is dropped. End to end
    /// at the engine seam: yes.
    #[tokio::test]
    async fn rival_at_the_revocation_position_is_retained() {
        let r = revoked();
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, &r.f.golden, 1))
            .await
            .expect("revocation");
        let tip = e.get_tip(&r.f.id).await.expect("tip").expect("stored");

        assert!(
            r.f.submit(&e, &r.theft).await.is_err(),
            "premise: refused as the tip"
        );
        assert_eq!(
            e.get_tip(&r.f.id)
                .await
                .expect("tip")
                .expect("stored")
                .commit_id,
            tip.commit_id,
            "the rival moved the tip"
        );
        let got = e.list_branches(&r.f.id).await.expect("list_branches");
        let at_rev: Vec<_> = got.iter().filter(|b| b.sequence == 1).collect();
        assert_eq!(at_rev.len(), 2, "revocation and the rival listed: {got:?}");
        let canonical = at_rev.iter().find(|b| b.canonical).expect("one canonical");
        assert_eq!(
            canonical.tip, tip.commit_id,
            "the revocation stays canonical"
        );
    }

    /// Backs a-verify: the refused revoked-key bundle is not listed either.
    /// Turns red if a bundle that does not verify at its `pre` is retained
    /// as a branch. End to end at the engine seam: yes.
    #[tokio::test]
    async fn revoked_key_bundle_is_not_listed() {
        let r = revoked();
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, &r.f.golden, 1))
            .await
            .expect("revocation");
        let listed = branches(&e, &r.f.id).await;
        assert!(r.f.submit(&e, &after_revocation(&r)).await.is_err());
        assert_eq!(
            branches(&e, &r.f.id).await,
            listed,
            "an unverified bundle was listed"
        );
    }
}
