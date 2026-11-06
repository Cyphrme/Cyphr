//! A fork of a stored principal is kept as a branch, never merged (G1).
//!
//! Single-writer-per-principal (AGENTS.md I2) forbids merging, not
//! knowing: a commit that takes an already-taken position is refused as
//! the principal's tip, but a commit that verifies at its `pre` is
//! evidence of a fork and the store retains it, indexed by `pre`, beside
//! the canonical chain. Every scenario here runs over the engine seam on
//! real signed commits.
//!
//! The retention API these tests name (`StorageEngine::list_branches`,
//! `BranchTip`, `EngineError::BranchLimit`) does not exist at the base, so
//! every test that touches it is gated behind `cfg(red_g1)`; run those with
//! `RUSTFLAGS="--cfg red_g1"`, where they fail to compile on the base. The
//! ungated tests characterise behaviour that must survive retention.

// The `red_g1` cfg is a test-only gate, not a Cargo feature.
#![allow(unexpected_cfgs)]

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

/// `signer` creates `new` at time `now` and finalizes the commit itself.
/// Distinct `now` values give distinct commits at one position.
fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &signer.prv,
                &signer.pubb,
                &signer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
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
    #[cfg_attr(not(red_g1), allow(dead_code))]
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

    /// One more valid commit at position 1; `salt` makes it distinct.
    fn add_rival(&mut self, salt: i64) {
        let pool = load_pool();
        let mut p = self.base.clone();
        let new = kp(&pool, if salt % 2 == 0 { "key_b" } else { "alice" });
        create_key(&mut p, &self.golden, &new, NOW + 1 + salt);
        self.rivals.push(blobs(&p, &self.golden, 1));
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

#[cfg(red_g1)]
mod red {
    use cyphr_storage::engine::EngineError;

    use super::*;

    /// Order-independent view of a principal's branches.
    async fn branches(e: &Engine, id: &str) -> Vec<(String, String, u64, bool)> {
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
            at_fork.iter().all(|b| b.pre == f.pre),
            "pre is the shared parent: {got:?}"
        );
        assert_ne!(at_fork[0].tip, at_fork[1].tip, "two distinct tips");
        assert_eq!(
            at_fork.iter().filter(|b| b.canonical).count(),
            1,
            "exactly one canonical: {got:?}"
        );
        // The canonical branch is the chain `get_tip` reports.
        let after = e.get_tip(&f.id).await.expect("tip").expect("stored");
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

    /// Backs a-verify: retention is bounded per principal. Rivals are
    /// pushed until the store answers the typed `EngineError::BranchLimit`;
    /// the refused one stores nothing and the listing stops growing.
    /// Turns red if retention is unbounded (no such error within
    /// `ATTEMPTS`) or the error is untyped. `ATTEMPTS` is a harness
    /// ceiling, not the bound: the bound must be below it.
    #[tokio::test]
    async fn retention_is_bounded_by_a_typed_error() {
        const ATTEMPTS: usize = 100;
        let mut f = Fork::new(0);
        let (e, _) = f.engine_with(&[]).await;
        let mut limit_at = None;
        for n in 0..ATTEMPTS {
            f.add_rival(n as i64);
            let (blobs_before, listed_before) = (blob_count(&e).await, branches(&e, &f.id).await);
            match f.submit(&e, f.rivals.last().expect("rival")).await {
                Err(EngineError::BranchLimit) => {
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
                    limit_at = Some(n);
                    break;
                },
                // The first rival is canonical (Ok); the rest are refused as the
                // tip yet retained, which is not the bound.
                Ok(()) | Err(_) => {},
            }
        }
        assert!(
            limit_at.is_some(),
            "no BranchLimit after {ATTEMPTS} distinct rivals"
        );
    }
}
