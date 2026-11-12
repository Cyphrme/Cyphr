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
use cyphr::replay::WireBundle;
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
async fn apply(
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
        .await
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
async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    apply(
        p,
        signer,
        signer,
        create_pay(signer, new, now),
        Some(key_of(new)),
        now,
    )
    .await;
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// The wire bundle of commit `i` of `p` (SPEC 4.6.2): its keys travel in
/// `keys`, so the principal's genesis is recoverable from its genesis
/// commit's `key/create`s (SPEC 5.1).
fn blobs(p: &cyphr::Principal, i: usize) -> WireBundle {
    WireBundle::of_commit(p.commits().nth(i).expect("commit")).expect("bundle")
}

/// The principal with genesis keys `keys` (the first signs), after its
/// genesis commit at `now` (SPEC 5.1).
async fn genesis_of(keys: &[&Kp], now: i64) -> cyphr::Principal {
    let mut p = cyphr::Principal::implicit(key_of(keys[0]))
        .await
        .expect("genesis");
    let others: Vec<cyphr::Key> = keys[1..].iter().map(|k| key_of(k)).collect();
    p.commit_genesis(&signer_of(keys[0]), &others, now, "cyphr.me")
        .await
        .expect("genesis commit");
    p
}

/// A principal with one shared commit (position 0, its genesis commit, in
/// which `golden` creates itself and `key_a`) and any number of rival
/// commits at position 1, every one signed by `golden`, a key active at
/// their common `pre` (the Principal Root after commit 0).
struct Fork {
    genesis: Genesis,
    id: String,
    pre: String,
    /// Commit 0, shared by every branch.
    first: WireBundle,
    /// Rival commits at position 1; each is valid on its own.
    rivals: Vec<WireBundle>,
    /// Commit 0's principal state, for building more rivals.
    base: cyphr::Principal,
    golden: Kp,
}

impl Fork {
    async fn new(rivals: usize) -> Self {
        let pool = load_pool();
        let golden = kp(&pool, "golden");
        let key_a = kp(&pool, "key_a");
        let genesis = Genesis::Disclosed(vec![key_of(&golden), key_of(&key_a)]);
        let base = genesis_of(&[&golden, &key_a], NOW).await;
        let pre = base.pr_tagged().expect("pr after commit 0");
        let first = blobs(&base, 0);
        let id = test_fixtures::bundle::genesis_id(&first).expect("genesis id");
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
            fork.add_rival(n as i64).await;
        }
        fork
    }

    /// The principal after the rival commit `salt` at position 1.
    async fn rival_state(&self, salt: i64) -> cyphr::Principal {
        let pool = load_pool();
        let mut p = self.base.fork().await.expect("fork");
        let new = kp(&pool, if salt % 2 == 0 { "key_b" } else { "alice" });
        create_key(&mut p, &self.golden, &new, NOW + 1 + salt).await;
        p
    }

    /// One more valid commit at position 1; `salt` makes it distinct.
    async fn add_rival(&mut self, salt: i64) {
        let p = self.rival_state(salt).await;
        self.rivals.push(blobs(&p, 1));
    }

    /// A second, divergent genesis commit of the same principal (the same
    /// genesis keys, so the same PG, at another time).
    async fn second_genesis(&self) -> WireBundle {
        let key_a = kp(&load_pool(), "key_a");
        blobs(&genesis_of(&[&self.golden, &key_a], NOW + 7).await, 0)
    }

    async fn submit(
        &self,
        e: &Engine,
        bundle: &WireBundle,
    ) -> Result<(), cyphr_storage::engine::EngineError> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), bundle)
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
    let f = Fork::new(2).await;
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
    let f = Fork::new(2).await;
    let (e, _) = f.engine_with(&[0]).await;
    let blobs_before = blob_count(&e).await;
    let tip_before = e.get_tip(&f.id).await.expect("tip").expect("stored");

    let mut bad = f.rivals[1].clone();
    let mut coz: serde_json::Value = serde_json::from_slice(&bad.txs[0][0]).expect("coz");
    let sig = coz["sig"].as_str().expect("sig").to_string();
    let mut raw = Base64UrlUnpadded::decode_vec(&sig).expect("sig b64");
    raw[0] ^= 0xff;
    coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&raw));
    bad.txs[0][0] = serde_json::to_vec(&coz).expect("coz bytes");

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
    let f = Fork::new(0).await;
    let (e, _) = f.engine_with(&[]).await;
    let before = e.get_tip(&f.id).await.expect("tip").expect("stored");
    assert!(
        f.submit(&e, &f.second_genesis().await).await.is_err(),
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
    theft: WireBundle,
}

async fn revoked() -> Revoked {
    let f = Fork::new(0).await;
    let pool = load_pool();
    let key_a = kp(&pool, "key_a");
    let mut canonical = f.base.fork().await.expect("fork");
    apply(
        &mut canonical,
        &f.golden,
        &key_a,
        serde_json::json!({"alg": f.golden.alg, "now": NOW + 10, "rvk": NOW + 10,
                           "tmb": f.golden.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"}),
        None,
        NOW + 10,
    )
    .await;
    let mut rival = f.base.fork().await.expect("fork");
    create_key(&mut rival, &f.golden, &kp(&pool, "key_b"), NOW + 11).await;
    let theft = blobs(&rival, 1);
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
async fn after_revocation(r: &Revoked) -> WireBundle {
    let pool = load_pool();
    let mut q = r.canonical.fork().await.expect("fork");
    create_key(&mut q, &r.key_a, &kp(&pool, "bob"), NOW + 12).await;
    let mut bundle = blobs(&q, 2);
    let mut coz_v: serde_json::Value = serde_json::from_slice(&bundle.txs[0][0]).expect("tx coz");
    coz_v["pay"]["tmb"] = serde_json::json!(r.f.golden.tmb.to_b64());
    coz_v["pay"]["alg"] = serde_json::json!(r.f.golden.alg);
    let pay = serde_json::to_vec(&coz_v["pay"]).expect("pay");
    let (sig, _) =
        coz::sign_json(&pay, &r.f.golden.alg, &r.f.golden.prv, &r.f.golden.pubb).expect("sign");
    coz_v["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&sig));
    let obj = coz_v.as_object_mut().expect("coz object");
    obj.remove("cad");
    obj.remove("czd");
    bundle.txs[0][0] = serde_json::to_vec(&coz_v).expect("coz bytes");
    bundle
}

/// Backs the participation gate on promotion (SPEC 6.4, 15.8) at the
/// engine seam every holder ingests through, a verifier's store included:
/// the canonical commit at 1 revokes `golden`, a `golden`-signed rival R
/// is retained at 1, and B over R (also `golden`'s) would promote R's
/// line. R is signed by a key the chain revoked, so it is evidence only:
/// B is refused, the revocation stays the tip and the principal Active.
/// Turns red if B is admitted or moves the tip.
#[tokio::test]
async fn revoked_keys_rival_is_never_promoted() {
    let r = revoked().await;
    let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    r.f.submit(&e, &r.f.first).await.expect("commit 0");
    r.f.submit(&e, &blobs(&r.canonical, 1))
        .await
        .expect("the revocation");
    let pool = load_pool();
    let mut rival = r.f.base.fork().await.expect("fork");
    create_key(&mut rival, &r.f.golden, &kp(&pool, "key_b"), NOW + 11).await;
    create_key(&mut rival, &r.f.golden, &kp(&pool, "bob"), NOW + 12).await;
    assert!(
        r.f.submit(&e, &blobs(&rival, 1)).await.is_err(),
        "R is a rival"
    );
    let tip = e.get_tip(&r.f.id).await.expect("tip").expect("held");
    assert!(
        r.f.submit(&e, &blobs(&rival, 2)).await.is_err(),
        "B promoted a revoked key's rival"
    );
    let after = e.get_tip(&r.f.id).await.expect("tip").expect("held");
    assert_eq!(after.commit_id, tip.commit_id, "the revocation is the tip");
    assert!(!e.is_errored(&r.f.id).await.expect("verdict"));
}

/// Backs the retention bound on promotion: `golden` already has its
/// [`BRANCH_PER_KEY`](cyphr_storage::engine::BRANCH_PER_KEY) rivals
/// retained at position 1 beside its canonical commit there, and
/// `key_a`'s rival R at 1 is extended by B. The promotion swaps R for the
/// displaced canonical commit one for one: it is admitted whatever
/// `golden`'s quota holds, B is the tip, and the retained set does not
/// grow. Turns red if a full quota refuses the promotion or the retained
/// set outgrows its size before it.
#[tokio::test]
async fn promotion_swaps_retained_commits_one_for_one() {
    let f = Fork::new(3).await;
    let (e, outcomes) = f.engine_with(&[0, 1, 2]).await;
    assert!(outcomes[0].is_ok(), "rival 0 is the canonical commit");
    let pool = load_pool();
    let key_a = kp(&pool, "key_a");
    let mut r = f.base.fork().await.expect("fork");
    create_key(&mut r, &key_a, &kp(&pool, "bob"), NOW + 20).await;
    create_key(&mut r, &key_a, &kp(&pool, "carol"), NOW + 21).await;
    assert!(f.submit(&e, &blobs(&r, 1)).await.is_err(), "R is a rival");
    let held = e.list_branches(&f.id).await.expect("branches").len();
    f.submit(&e, &blobs(&r, 2))
        .await
        .expect("B promotes R whatever golden's quota holds");
    assert_eq!(
        e.get_tip(&f.id).await.expect("tip").expect("held").pr,
        r.pr_tagged().expect("pr"),
        "B is the tip"
    );
    assert_eq!(e.list_branches(&f.id).await.expect("branches").len(), held);
}

/// `k`'s self-signed naked revoke (SPEC 6.4) as of `rvk`: `{pay, sig, key}`.
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

/// Backs key death at admission (SPEC 6.4), at the engine seam every path
/// ingests through (`/push`, gossip, witness sync, a verifier's store):
/// once the engine holds `key_a`'s naked revoke, a commit `key_a` signs at
/// the tip is refused whatever its `now`, even one dated before the
/// declared `rvk` (the holder chooses both); a revoke the thief recorded
/// first, dated far in the future, changes nothing. Turns red if the
/// engine admits a dead key's commit at the tip.
#[tokio::test]
async fn a_dead_keys_tip_commit_is_refused_whatever_its_dates() {
    let f = Fork::new(0).await;
    let pool = load_pool();
    let key_a = kp(&pool, "key_a");
    for thief_first in [false, true] {
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        f.submit(&e, &f.first).await.expect("commit 0");
        if thief_first {
            e.record_revoke(&naked_revoke(&key_a, (1 << 53) - 1))
                .await
                .expect("the thief's revoke");
        }
        e.record_revoke(&naked_revoke(&key_a, NOW + 5))
            .await
            .expect("the owner's revoke");
        for now in [NOW + 2, NOW + 6] {
            let mut p = f.base.fork().await.expect("fork");
            create_key(&mut p, &key_a, &kp(&pool, "bob"), now).await;
            assert!(
                f.submit(&e, &blobs(&p, 1)).await.is_err(),
                "thief_first={thief_first}: key_a's commit dated {now} admitted at the tip"
            );
        }
    }
}

/// Backs burial (SPEC 6.4, not retroactive): with `key_a` dead, its commit
/// is admitted when the same submission carries a later commit, signed by
/// `golden` alone, that extends it: the owner's later commit endorses it.
/// Alone it is refused. Turns red if a buried commit is refused or an
/// unburied one admitted.
#[tokio::test]
async fn a_dead_keys_commit_is_admitted_only_when_buried() {
    let f = Fork::new(0).await;
    let pool = load_pool();
    let key_a = kp(&pool, "key_a");
    let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    f.submit(&e, &f.first).await.expect("commit 0");
    e.record_revoke(&naked_revoke(&key_a, NOW + 5))
        .await
        .expect("revoke");
    let mut p = f.base.fork().await.expect("fork");
    create_key(&mut p, &key_a, &kp(&pool, "bob"), NOW + 2).await;
    create_key(&mut p, &f.golden, &kp(&pool, "carol"), NOW + 3).await;
    assert!(
        f.submit(&e, &blobs(&p, 1)).await.is_err(),
        "an unburied dead key's commit"
    );
    let outcomes = e
        .submit_commits(
            &f.id,
            Some(f.genesis.clone()),
            &[blobs(&p, 1), blobs(&p, 2)],
        )
        .await;
    assert!(
        outcomes.iter().all(Result::is_ok),
        "the buried commit and its live successor: {outcomes:?}"
    );
    assert_eq!(
        e.get_tip(&f.id).await.expect("tip").expect("held").pr,
        p.pr_tagged().expect("pr")
    );
}

/// Backs the owner's exit (SPEC 6.4): `golden` is already naked-revoked
/// here, and the owner commits `golden`'s chain-level self-revoke,
/// finalized by `key_a`. A dead key's coz that only revokes its own
/// signer can only end the key, so the commit is admitted. Turns red if a
/// known revoke blocks the key's own chain-level revocation.
#[tokio::test]
async fn a_dead_keys_self_revoke_lands() {
    let r = revoked().await;
    let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    r.f.submit(&e, &r.f.first).await.expect("commit 0");
    e.record_revoke(&naked_revoke(&r.f.golden, NOW + 5))
        .await
        .expect("revoke");
    r.f.submit(&e, &blobs(&r.canonical, 1))
        .await
        .expect("the chain-level self-revoke");
}

/// Backs a-verify: a bundle at a position after a key was revoked, signed
/// by that revoked key, is refused and stores nothing. The control builds
/// the same position-2 commit with the active `key_a` and it is accepted,
/// so the refusal is about the swapped signer and not the position. Green
/// today; must stay green. The refusal is `KeyRevoked` (observed), not an
/// arrow mismatch, so it is attributable to the revocation.
#[tokio::test]
async fn revoked_key_bundle_is_refused_and_stores_nothing() {
    let r = revoked().await;
    let (e, _) = {
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, 1))
            .await
            .expect("revocation");
        (e, ())
    };
    let blobs_before = blob_count(&e).await;
    let tip_before = e.get_tip(&r.f.id).await.expect("tip").expect("stored");

    // Control: the same commit signed by the active key_a is accepted.
    let pool = load_pool();
    let mut ok = r.canonical.fork().await.expect("fork");
    create_key(&mut ok, &r.key_a, &kp(&pool, "bob"), NOW + 12).await;
    let ok_blobs = blobs(&ok, 2);
    let control = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    r.f.submit(&control, &r.f.first)
        .await
        .expect("control commit 0");
    r.f.submit(&control, &blobs(&r.canonical, 1))
        .await
        .expect("control revocation");
    r.f.submit(&control, &ok_blobs)
        .await
        .expect("control: an active key commits at position 2");

    let refused = r.f.submit(&e, &after_revocation(&r).await).await;
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
        let f = Fork::new(2).await;
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
        let f = Fork::new(2).await;
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

    /// A principal of `n` commits (golden creates one pool key per commit)
    /// plus an authenticated rival at position 1, and the rival's blobs.
    async fn long_chain(n: usize) -> (Fork, Engine, WireBundle, Vec<cyphr::Principal>) {
        let f = Fork::new(0).await;
        let pool = load_pool();
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        f.submit(&e, &f.first).await.expect("commit 0");
        let mut p = f.base.fork().await.expect("fork");
        let mut states = vec![p.fork().await.expect("fork")];
        let names = ["key_b", "alice", "bob", "diana_es384", "eve_ed25519"];
        for (i, name) in names.iter().take(n - 1).enumerate() {
            create_key(&mut p, &f.golden, &kp(&pool, name), NOW + 100 + i as i64).await;
            f.submit(&e, &blobs(&p, i + 1))
                .await
                .expect("canonical commit");
            states.push(p.fork().await.expect("fork"));
        }
        let mut r = f.base.fork().await.expect("fork");
        create_key(&mut r, &f.golden, &kp(&pool, "eve_ed25519"), NOW + 900).await;
        let rival = blobs(&r, 1);
        (f, e, rival, states)
    }

    /// Backs the cost bound on retention: a refused bundle that is not
    /// signed by a key this principal has ever had, or whose signature
    /// does not verify, replays nothing, and an authenticated rival on a
    /// chain of n commits costs at most n + 1 replays. Turns red if
    /// retention replays before authenticating (anyone could then make the
    /// store replay history) or searches positions by replaying a prefix
    /// for each (quadratic). End to end at the engine seam: yes.
    #[tokio::test]
    async fn retention_cost_is_bounded_and_authenticated_first() {
        const N: usize = 5;
        let (f, e, rival, states) = long_chain(N).await;
        let listed = branches(&e, &f.id).await;

        // Unknown signer: carol never held a key of this principal.
        let pool = load_pool();
        let carol = kp(&pool, "carol");
        let stranger = genesis_of(&[&carol, &kp(&pool, "bob")], NOW + 5).await;
        let before = e.retention_replays();
        assert!(f.submit(&e, &blobs(&stranger, 0)).await.is_err());
        assert_eq!(e.retention_replays(), before, "unknown signer was replayed");

        // Failed signature by a real key.
        let mut bad = rival.clone();
        let mut coz: serde_json::Value = serde_json::from_slice(&bad.txs[0][0]).expect("coz");
        let mut raw =
            Base64UrlUnpadded::decode_vec(coz["sig"].as_str().expect("sig")).expect("b64");
        raw[0] ^= 0xff;
        coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&raw));
        bad.txs[0][0] = serde_json::to_vec(&coz).expect("coz bytes");
        assert!(f.submit(&e, &bad).await.is_err());
        assert_eq!(e.retention_replays(), before, "bad signature was replayed");
        assert_eq!(branches(&e, &f.id).await, listed, "refused bundles listed");

        // Authenticated rival: retained, within n + 1 replays.
        assert!(f.submit(&e, &rival).await.is_err(), "premise: refused");
        let spent = e.retention_replays() - before;
        assert!(spent <= N as u64 + 1, "{spent} replays for a chain of {N}");
        assert_eq!(
            branches(&e, &f.id).await.iter().filter(|b| !b.3).count(),
            1,
            "the authenticated rival is retained"
        );

        // Only positions where the signer was active are tried: alice
        // joined at commit 2, so a rival at the tip's position (4, after
        // commits 0..=3) is tried at positions 3 and 4 and no earlier.
        let alice = kp(&pool, "alice");
        let mut late = states[3].fork().await.expect("fork");
        create_key(&mut late, &alice, &kp(&pool, "carol"), NOW + 950).await;
        let trials = e.retention_trials();
        assert!(f.submit(&e, &blobs(&late, 4)).await.is_err());
        assert_eq!(
            e.retention_trials() - trials,
            2,
            "searched inactive positions"
        );
        assert_eq!(
            branches(&e, &f.id).await.iter().filter(|b| !b.3).count(),
            2,
            "the late rival is retained"
        );
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
        let f = Fork::new(2).await;
        let (e, _) = f.engine_with(&[0, 1]).await;
        // `rivals[1]` was refused; the independent derivation of its state.
        let entry = cyphr_storage::export_commits(&f.rival_state(1).await)
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
            assert_eq!(Some(first_digest(m, "srs")), entry.sr, "{round}");
            assert_eq!(Some(first_digest(m, "ars")), entry.auth_root, "{round}");
            assert_eq!(m["commit"]["pre"], f.pre, "{round}");
            assert!(
                ingested
                    .iter()
                    .any(|b| b.0 == entry.commit_id && !b.3 && b.1.as_deref() == Some(&f.pre)),
                "{round}: the listing reports the derived rival: {ingested:?}"
            );
        }
    }

    /// A signing key that is not in the pool.
    fn fresh_kp() -> Kp {
        let g = coz::Alg::Ed25519.generate_keypair();
        let tmb = g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb");
        Kp {
            alg: g.alg.name().to_owned(),
            prv: g.prv_bytes.clone(),
            pubb: g.pub_bytes.clone(),
            tmb,
        }
    }

    impl Fork {
        /// A valid commit at position 1, signed by `signer` (a key active
        /// at the fork's `pre`); `salt` makes it distinct.
        async fn rival_by(&self, signer: &Kp, salt: i64) -> WireBundle {
            let mut p = self.base.fork().await.expect("fork");
            create_key(&mut p, signer, &fresh_kp(), NOW + 1 + salt).await;
            blobs(&p, 1)
        }
    }

    /// Backs the slot policy (PLAN N18a, per-key quota): one key may retain
    /// at most `BRANCH_PER_KEY` = 2 rivals of a principal; the next is the
    /// typed `EngineError::BranchLimit` naming that key, and stores
    /// nothing. Turns red if the quota is absent (the third rival is
    /// kept), the refusal does not name the signing key, or a refusal
    /// stores blobs or a branch. End to end at the engine seam: yes.
    #[tokio::test]
    async fn a_key_past_its_quota_is_refused_naming_it() {
        const BRANCH_PER_KEY: usize = 2;
        let mut f = Fork::new(0).await;
        let (e, _) = f.engine_with(&[]).await;
        // The first rival takes the position; the quota counts rivals
        // refused as the tip.
        for n in 0..=BRANCH_PER_KEY {
            f.add_rival(n as i64).await;
            f.submit(&e, f.rivals.last().expect("rival"))
                .await
                .or_else(|err| match err {
                    EngineError::Protocol(_) => Ok(()),
                    other => Err(other),
                })
                .expect("within the quota the rival is retained");
        }
        let (blobs_before, listed_before) = (blob_count(&e).await, branches(&e, &f.id).await);
        f.add_rival(BRANCH_PER_KEY as i64 + 1).await;
        let refused = f.submit(&e, f.rivals.last().expect("rival")).await;
        match refused {
            Err(EngineError::BranchLimit { key }) => {
                assert_eq!(key, f.golden.tmb.to_b64(), "the refusal names the key")
            },
            other => panic!("expected BranchLimit naming the key, got {other:?}"),
        }
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
        assert_eq!(
            listed_before.iter().filter(|b| !b.3).count(),
            BRANCH_PER_KEY,
            "exactly the quota is retained"
        );
    }

    /// Backs the slot policy: a key that has used up its quota does not
    /// stop a rival signed by another key of the same principal from being
    /// retained. Turns red if slots are first-come across keys. End to end
    /// at the engine seam: yes.
    #[tokio::test]
    async fn one_keys_flood_leaves_a_slot_for_another_key() {
        let mut f = Fork::new(0).await;
        let (e, _) = f.engine_with(&[]).await;
        for n in 0..6 {
            f.add_rival(n).await;
            let _ = f.submit(&e, f.rivals.last().expect("rival")).await;
        }
        let key_a = kp(&load_pool(), "key_a");
        let other = f.rival_by(&key_a, 50).await;
        f.submit(&e, &other).await.expect_err("refused as the tip");
        let listed = e.list_branches(&f.id).await.expect("list_branches");
        let kept_other = listed.iter().filter(|b| !b.canonical).count();
        assert_eq!(
            kept_other, 3,
            "two of golden's and key_a's rival are retained: {listed:?}"
        );
    }

    /// Backs the slot policy: the total ceiling `BRANCH_LIMIT` = 16 holds
    /// across keys. Eight keys retain two rivals each; a ninth key (within
    /// its own quota) is refused as `BranchLimit` naming it. Turns red if
    /// the ceiling is absent or applied per key only. End to end at the
    /// engine seam: yes.
    #[tokio::test]
    async fn the_total_ceiling_holds_across_keys() {
        const SIGNERS: usize = 9;
        let golden = kp(&load_pool(), "golden");
        let signers: Vec<Kp> = (0..SIGNERS).map(|_| fresh_kp()).collect();
        let mut base = genesis_of(&[&golden], NOW).await;
        let genesis = Genesis::Implicit(key_of(&golden));
        let id = cyphr_storage::engine::genesis_principal_id(&genesis).expect("id");
        for (i, k) in signers.iter().enumerate() {
            create_key(&mut base, &golden, k, NOW + 1 + i as i64).await;
        }
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        let submit = |b: WireBundle| {
            let (e, id, genesis) = (&e, id.clone(), genesis.clone());
            async move { e.submit_commit(&id, Some(genesis), &b).await.map(|_| ()) }
        };
        // The genesis commit, then one commit per signer.
        for i in 0..=SIGNERS {
            submit(blobs(&base, i)).await.expect("shared prefix");
        }
        let rival = async |signer: &Kp, salt: i64| {
            let mut p = base.fork().await.expect("fork");
            create_key(&mut p, signer, &fresh_kp(), NOW + 1000 + salt).await;
            blobs(&p, SIGNERS + 1)
        };
        // Signer 0's first rival takes the position; signers 1..=8 then fill
        // all sixteen slots.
        submit(rival(&signers[0], 0).await)
            .await
            .expect("canonical");
        let mut salt = 1;
        for signer in &signers[1..] {
            for _ in 0..2 {
                assert!(matches!(
                    submit(rival(signer, salt).await).await,
                    Err(EngineError::Protocol(_))
                ));
                salt += 1;
            }
        }
        let kept = e
            .list_branches(&id)
            .await
            .expect("list")
            .iter()
            .filter(|b| !b.canonical)
            .count();
        assert_eq!(kept, 16, "every key within its quota is retained");
        match submit(rival(&signers[0], salt).await).await {
            Err(EngineError::BranchLimit { key }) => {
                assert_eq!(key, signers[0].tmb.to_b64(), "the refusal names the key")
            },
            other => panic!("expected BranchLimit at the ceiling, got {other:?}"),
        }
    }

    /// Backs the cheap check before any clone: a bundle that is, byte for
    /// byte, a commit the engine already holds (canonical or retained) is
    /// nobody's rival, so it is answered with no replay trial. Turns red
    /// if re-pushing a held commit costs retention work. End to end at the
    /// engine seam: yes (the counters are the engine's cost surface).
    #[tokio::test]
    async fn a_held_commit_costs_retention_no_trial() {
        let f = Fork::new(2).await;
        let (e, _) = f.engine_with(&[0, 1]).await;
        let before = e.retention_trials();
        f.submit(&e, &f.rivals[0])
            .await
            .expect_err("canonical re-push refused");
        f.submit(&e, &f.rivals[1])
            .await
            .expect_err("retained re-push refused");
        assert_eq!(e.retention_trials(), before, "a held commit was tried");
    }

    /// A blob store that can be told to fail writes.
    struct Flaky {
        inner: MemoryBlobStore,
        fail_puts: std::sync::atomic::AtomicBool,
    }

    impl BlobStore for Flaky {
        async fn put(
            &self,
            data: &[u8],
        ) -> Result<cyphr_storage::blob::Blake3Hash, cyphr_storage::blob::BlobStoreError> {
            if self.fail_puts.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(cyphr_storage::blob::BlobStoreError::Backend(
                    "injected write failure".into(),
                ));
            }
            self.inner.put(data).await
        }

        async fn get(
            &self,
            hash: &cyphr_storage::blob::Blake3Hash,
        ) -> Result<Option<Vec<u8>>, cyphr_storage::blob::BlobStoreError> {
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

    /// Backs best-effort retention (PLAN N18a): when keeping a rival hits a
    /// storage error, the push still answers the fork's own refusal (a
    /// protocol error, 409/422 at the server), never a storage error (500).
    /// Turns red if the storage fault replaces the refusal. Engine seam,
    /// not the server: the server's stores are concrete, so a failing blob
    /// store can only be injected here.
    #[tokio::test]
    async fn a_storage_fault_while_retaining_keeps_the_original_refusal() {
        let f = Fork::new(2).await;
        let e = StorageEngine::new(
            Flaky {
                inner: MemoryBlobStore::new(),
                fail_puts: false.into(),
            },
            MemoryIndexer::new(),
        );
        let go = |b: &WireBundle| {
            let b = b.clone();
            let e = &e;
            let (id, g) = (f.id.clone(), f.genesis.clone());
            async move { e.submit_commit(&id, Some(g), &b).await.map(|_| ()) }
        };
        go(&f.first).await.expect("commit 0");
        go(&f.rivals[0]).await.expect("canonical");
        e.blob_store()
            .fail_puts
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let refused = go(&f.rivals[1]).await;
        assert!(
            matches!(refused, Err(EngineError::Protocol(_))),
            "the original refusal must survive a retention fault: {refused:?}"
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
        let f = Fork::new(0).await;
        let (e, _) = f.engine_with(&[]).await;
        assert!(
            f.submit(&e, &f.second_genesis().await).await.is_err(),
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
        let r = revoked().await;
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, 1))
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
        let r = revoked().await;
        let e = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        r.f.submit(&e, &r.f.first).await.expect("commit 0");
        r.f.submit(&e, &blobs(&r.canonical, 1))
            .await
            .expect("revocation");
        let listed = branches(&e, &r.f.id).await;
        assert!(r.f.submit(&e, &after_revocation(&r).await).await.is_err());
        assert_eq!(
            branches(&e, &r.f.id).await,
            listed,
            "an unverified bundle was listed"
        );
    }
}
