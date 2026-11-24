//! A revoked key is stopped from the moment this node received the revoke
//! (SPEC 6.4: "a self-signed declaration that a key is compromised and
//! should never be trusted again"; the spec author on #203: "A revoked
//! stops the key at the time the revoke was received", "honor it from the
//! witness's own receipt time"). A message the key signs is judged by its
//! own `now` against that receipt, on every branch, whether the revoke
//! came naked or inside a commit. What the key signed before the cutoff
//! stands, whenever it reaches the node (SPEC 14.12: "Cyphr does not use
//! reversion"). Backdating is the documented limit, answered by witness
//! timestamps (#203: "Back dating should be obvious to a durable network
//! of witnesses").
//!
//! The attacks are the review's reproductions: a key its owner revoked
//! forks below the revoke and takes the principal over by a resync proof.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::engine::EngineError;

mod common;
use common::*;

/// The wall clock, which is what a node stamps a revoke's receipt with.
fn wall() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("secs")
}

fn pop_over(signer: &Kp, id: &str, now: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": id, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/resync/create"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay json"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    })
}

/// `signer` deletes `gone` in a commit of its own.
async fn delete_key(p: &mut cyphr::Principal, signer: &Kp, gone: &Kp, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": gone.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("applies");
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .expect("finalizes");
}

/// `k` revokes itself inside a commit that `finalizer` closes.
async fn revoke_in_chain(p: &mut cyphr::Principal, k: &Kp, finalizer: &Kp, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": k.alg, "now": now, "rvk": now, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("applies");
    scope
        .finalize_with_software(&signer_of(finalizer), now, "cyphr.me")
        .await
        .expect("finalizes");
}

fn naked_revoke(k: &Kp, rvk: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": k.alg, "now": rvk, "rvk": rvk, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &k.alg, &k.prv, &k.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay json"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": k.alg, "pub": Base64UrlUnpadded::encode_string(&k.pubb)},
    })
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

async fn offer_action(
    rig: &Rig,
    e: &Engine,
    k: &Kp,
    now: i64,
) -> Result<cyphr_storage::engine::IngestResult, EngineError> {
    e.submit_commit(
        &rig.id,
        Some(rig.genesis.clone()),
        &WireBundle::actions(vec![action_blob(k, now)]),
    )
    .await
}

/// c0 genesis(G), c1 G creates K, c2 K revokes itself (closed by G), c3 G
/// creates L, all received now. K is dead from the receipt of c2.
async fn setup() -> (Rig, Engine, cyphr::Principal) {
    let rig = Rig::new(2).await;
    let e = rig.fed(1).await;
    let k = &rig.keys[0];
    let mut legit = rig.states[1].fork().await.expect("fork");
    revoke_in_chain(&mut legit, k, &rig.golden, NOW + 10).await;
    rig.submit(&e, &last(&legit)).await.expect("c2 revokes K");
    create_key(&mut legit, &rig.golden, &fresh_kp(), NOW + 20).await;
    rig.submit(&e, &last(&legit)).await.expect("c3");
    assert!(!legit.is_key_active(&k.tmb), "premise: K revoked in chain");
    (rig, e, legit)
}

/// The takeover: K forks below its own revoke, deletes G, and has a resync
/// proof of the line signed.
async fn takeover(rig: &Rig, e: &Engine, now: i64) -> Result<(), EngineError> {
    let k = &rig.keys[0];
    let mut evil = rig.states[1].fork().await.expect("fork");
    delete_key(&mut evil, k, &rig.golden, now).await;
    let pop = pop_over(k, &evil.pr_tagged().expect("pr"), now + 1);
    e.submit_resync(&rig.id, &pop, &[last(&evil)])
        .await
        .map(|_| ())
}

fn is_dead_key(r: &Result<(), EngineError>) -> bool {
    matches!(r, Err(EngineError::DeadKey { .. }))
}

/// SPEC 6.4 (a revoked key is never trusted again), the review's HACKER-1
/// with an in-chain revoke: dated after the node received the revoke, the
/// revoked key's proof does not count, and the chain is not displaced.
#[tokio::test]
async fn an_in_chain_revoked_key_cannot_resync_a_takeover() {
    let (rig, e, _legit) = setup().await;
    let before = e.get_tip(&rig.id).await.expect("tip").expect("held");

    let r = takeover(&rig, &e, wall() + 10).await;

    assert!(is_dead_key(&r), "the dead key's proof is refused: {r:?}");
    let after = e.get_tip(&rig.id).await.expect("tip").expect("held");
    assert_eq!(
        after.commit_id, before.commit_id,
        "the chain is not displaced"
    );
}

/// A naked revoke cuts the key off at the node's receipt: dated at or after
/// it the key's proof is refused. Dated below it the proof passes the gate:
/// backdating is the documented limit (`known-limits.md`), answered by
/// witness timestamps, not prevented here.
#[tokio::test]
async fn a_naked_revoked_key_is_cut_off_at_the_receipt() {
    let rig = Rig::new(2).await;
    let e = rig.fed(1).await;
    let k = &rig.keys[0];
    let wrt = NOW + 500;
    e.record_revoke(&naked_revoke(k, wrt), wrt)
        .await
        .expect("naked revoke recorded");

    let r = takeover(&rig, &e, NOW + 1_000).await;
    assert!(is_dead_key(&r), "dated after the receipt: {r:?}");

    let r = takeover(&rig, &e, NOW + 5).await;
    assert!(r.is_ok(), "the documented limit: backdated below it: {r:?}");
}

/// A dead key's commit offered as a rival branch, dated after the receipt,
/// is refused too: the revoke is the node's, not one branch's.
#[tokio::test]
async fn an_in_chain_revoked_key_cannot_extend_another_branch() {
    let (rig, e, _legit) = setup().await;
    let k = &rig.keys[0];
    let mut evil = rig.states[1].fork().await.expect("fork");
    create_key(&mut evil, k, &fresh_kp(), wall() + 10).await;

    let r = rig.submit(&e, &last(&evil)).await;

    assert!(is_dead_key(&r), "refused: {r:?}");
    assert!(!rig.verdict(&e).await.0, "no fork was kept");
}

/// A data action of a self-revoked key follows the same cutoff (the spec
/// author: "it does make sense to reject any new data actions from revoked
/// keys"): dated after the receipt it is refused, dated before it, when K
/// was still active, it stands.
#[tokio::test]
async fn a_data_action_of_an_in_chain_revoked_key_follows_the_cutoff() {
    let (rig, e, _legit) = setup().await;
    let k = &rig.keys[0];
    let after = offer_action(&rig, &e, k, wall() + 10).await;
    assert!(
        matches!(after, Err(EngineError::Protocol(cyphr::Error::KeyRevoked))),
        "dated after the receipt: {after:?}"
    );
    let before = offer_action(&rig, &e, k, NOW + 5).await;
    assert!(before.is_ok(), "dated before it: {before:?}");
}

/// What a node learns about a key's revoke before the key's earlier
/// commits, it still applies those commits: the cutoff is the receipt, and
/// what the key signed before it is history whenever it arrives (SPEC
/// 14.12). Arrival-time gating would refuse this.
#[tokio::test]
async fn a_node_that_learns_the_revoke_first_still_applies_the_keys_earlier_commits() {
    let rig = Rig::new(2).await;
    let e = rig.fed(1).await;
    let k = &rig.keys[0];
    e.record_revoke(&naked_revoke(k, wall()), wall())
        .await
        .expect("the revoke arrives first");
    let mut earlier = rig.states[1].fork().await.expect("fork");
    create_key(&mut earlier, k, &fresh_kp(), NOW + 5).await;

    let r = rig.submit(&e, &last(&earlier)).await;

    assert!(r.is_ok(), "dated before the receipt, it is history: {r:?}");
    assert_eq!(
        e.get_tip(&rig.id)
            .await
            .expect("tip")
            .expect("held")
            .commit_count,
        3
    );
}

/// What was held before the revoke arrived stays held, a rebuild from the
/// blobs included, and the key stays dead through it (I1: the death is
/// derived from the record).
#[tokio::test]
async fn a_rebuild_keeps_what_was_held_and_keeps_the_key_dead() {
    let rig = Rig::new(2).await;
    let e = rig.fed(1).await;
    let k = &rig.keys[0];
    let held = WireBundle::actions(vec![action_blob(k, NOW + 5)]);
    e.submit_commit(&rig.id, Some(rig.genesis.clone()), &held)
        .await
        .expect("held before the revoke arrives");
    let mut legit = rig.states[1].fork().await.expect("fork");
    revoke_in_chain(&mut legit, k, &rig.golden, NOW + 10).await;
    rig.submit(&e, &last(&legit)).await.expect("c2 revokes K");

    let report = e.rebuild_index_with_report().await.expect("rebuild");

    assert!(report.quarantined.is_empty(), "{:?}", report.quarantined);
    let patch = e.get_patch(&rig.id, None, None).await.expect("patch");
    assert_eq!(patch.actions.len(), 1, "the held action is still held");
    assert_eq!(patch.entries.len(), 3, "every commit is still held");
    let again = WireBundle::actions(vec![action_blob(k, wall() + 10)]);
    let r = e
        .submit_commit(&rig.id, Some(rig.genesis.clone()), &again)
        .await;
    assert!(
        matches!(r, Err(EngineError::Protocol(cyphr::Error::KeyRevoked))),
        "still dead after the rebuild: {r:?}"
    );
}
