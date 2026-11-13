//! A key in the server's death set cannot be introduced anywhere (SPEC §6.4,
//! be0663f): a `key/create` or `key/replace` whose target thumbprint is dead
//! is refused in ANY principal, as a genesis commit or a later one.
//!
//! The existing gate (`naked_revoke.rs`) refuses a dead key as a SIGNER, at
//! push and login. It does not look at the key a coz introduces, so a revoked
//! key can be re-added to a fresh principal and used from there. Every test
//! drives the live `/revoke` and `/push` routes, so the red baseline is a
//! behavioral accept, never a missing symbol.
//!
//! The tests are end-to-end scenarios. The `live_key_*` control is green on
//! the base: it shows the refusals below are about the dead key, not about
//! `key/create`/`key/replace` of a second key in a fresh principal at all (a
//! gate that refuses every introduction would pass the red tests).

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::{AppState, build_router};
use test_fixtures::{Pool, PoolKey};

mod common;

/// Every commit here is dated a minute ahead of the wall clock (inside the
/// push window, SPEC 15.9), so the revoke this server receives now, whose
/// receipt time is the key's cutoff (#203), comes before them.
static NOW: std::sync::LazyLock<i64> = std::sync::LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        + 60
});
const CREATE: &str = "cyphr.me/cyphr/key/create";
const REPLACE: &str = "cyphr.me/cyphr/key/replace";

/// A keyed server whose index already knows `key_a` (held by the golden
/// principal) and in which `key_a` has been naked-revoked: it is now in the
/// death set. Returns the state and its tempdir guard.
async fn server_with_key_a_dead(pool: &Pool) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = common::write_signing_key(dir.path());
    let state = Arc::new(common::keyed_appstate(&dir.path().join("data"), &key));

    let pid = common::golden_principal_id(pool).await;
    let body = common::build_genesis_push_body(pool, &pid, *NOW).await;
    let (status, json) = common::post_json(build_router(state.clone()), "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap golden+key_a: {json:?}"
    );

    let k = pool.get("key_a").expect("key_a");
    let tmb = k.compute_tmb_b64().expect("tmb");
    let pay = serde_json::json!({
        "alg": k.alg, "now": *NOW, "rvk": *NOW, "tmb": tmb,
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let (sig, _) = coz::sign_json(
        &serde_json::to_vec(&pay).unwrap(),
        &k.alg,
        &prv(k),
        &pubk(k),
    )
    .expect("sign revoke");
    let revoke = serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": k.alg, "pub": k.pub_key},
    });
    let (status, json) =
        common::post_json(build_router(state.clone()), "/revoke", revoke.to_string()).await;
    assert!(
        status.is_success(),
        "naked revoke of key_a: {status} {json:?}"
    );
    (state, dir)
}

fn prv(k: &PoolKey) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(k.prv.as_ref().expect("prv")).expect("prv b64")
}

fn pubk(k: &PoolKey) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(&k.pub_key).expect("pub b64")
}

fn key_of(k: &PoolKey) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.compute_tmb().expect("tmb"), pubk(k))
        .expect("key binds its tmb")
}

/// A commit on `principal`, signed by `signer`, whose one coz is of `typ`
/// (`key/create` or `key/replace`) and introduces `target`. Returns the wire
/// blobs (the introduced key embedded on its coz).
async fn intro_commit(
    mut principal: cyphr::Principal,
    signer: &PoolKey,
    target: &PoolKey,
    typ: &str,
) -> Vec<Vec<u8>> {
    let signer_tmb = signer.compute_tmb_b64().expect("signer tmb");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg,
        "id": target.compute_tmb_b64().expect("target tmb"),
        "now": *NOW,
        "tmb": signer_tmb,
        "typ": typ,
    }))
    .unwrap();
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &prv(signer), &pubk(signer)).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(target).with_first_seen(*NOW)))
        .expect("the introduction is valid against the starting principal");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &prv(signer),
                &pubk(signer),
                &signer.compute_tmb().expect("tmb"),
            ),
            *NOW,
            "cyphr.me",
        )
        .await
        .expect("finalize");

    let entry = cyphr_storage::export_commits(&principal)
        .expect("export")
        .pop()
        .expect("a commit");
    let mut keys = entry.keys.iter();
    entry
        .txs
        .iter()
        .flatten()
        .map(|v| {
            let mut coz = v.clone();
            if cyphr::parsed_coz::typ::is_key_introducing(coz["pay"]["typ"].as_str().unwrap_or(""))
            {
                let k = keys.next().expect("a key per introducing coz");
                coz["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
            }
            serde_json::to_vec(&coz).unwrap()
        })
        .collect()
}

fn body(pid: &str, blobs: &[Vec<u8>]) -> String {
    common::push_blobs(pid, blobs)
}

fn signer_of(k: &PoolKey) -> cyphr::signer::SoftwareSigner {
    k.software_signer().expect("pool key signs")
}

/// The pool key that, in a `key/replace` genesis, is created and then
/// replaces itself with the target.
const REPLACER: &str = "carol";

/// The genesis push of a new principal on `genesis` (SPEC 5.1) whose
/// genesis commit introduces `target` by `typ`: a `key/create` of it by
/// `genesis`, or, for `key/replace`, the creation of [`REPLACER`], which
/// then replaces itself with `target`, before the `principal/create`.
/// Returns the push body, the principal's id (its PG) and the principal
/// after that genesis commit.
async fn genesis_push(
    pool: &Pool,
    genesis: &str,
    target: &str,
    typ: &str,
) -> (String, String, cyphr::Principal) {
    let g = pool.get(genesis).expect("genesis key");
    let t = pool.get(target).expect("target key");
    let wire = |cozies: Vec<serde_json::Value>| -> Vec<Vec<u8>> {
        cozies
            .iter()
            .map(|c| serde_json::to_vec(c).expect("coz"))
            .collect()
    };
    if typ == CREATE {
        let mut p = cyphr::Principal::implicit(key_of(g))
            .await
            .expect("genesis");
        p.commit_genesis(&signer_of(g), &[key_of(t)], *NOW, "cyphr.me")
            .await
            .expect("genesis commit");
        let bundle = cyphr::replay::WireBundle::of_commit(p.commits().last().expect("genesis"))
            .expect("bundle");
        let pid = test_fixtures::bundle::genesis_id(&bundle).expect("PG");
        return (common::push_body(&pid, &bundle), pid, p);
    }

    let r = pool.get(REPLACER).expect("replacer key");
    let mut p = cyphr::Principal::implicit(key_of(g))
        .await
        .expect("genesis");
    let mut scope = p.begin_commit();
    let mut cozies = scope
        .create_genesis_keys(&signer_of(g), &[key_of(r)], *NOW, "cyphr.me")
        .await
        .expect("genesis key/creates");
    // Each key/create carries the key it creates for `push_blobs` to move
    // into the bundle's `keys`.
    for (coz, key) in cozies.iter_mut().zip([key_of(g), key_of(r)]) {
        coz["key"] = serde_json::to_value(cyphr_storage::KeyEntry::of(&key)).unwrap();
    }
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": r.alg,
        "id": t.compute_tmb_b64().expect("target tmb"),
        "now": *NOW,
        "tmb": r.compute_tmb_b64().expect("replacer tmb"),
        "typ": typ,
    }))
    .unwrap();
    let (sig, cad) = coz::sign_json(&pay, &r.alg, &prv(r), &pubk(r)).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &r.alg).expect("czd");
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(t).with_first_seen(*NOW)))
        .expect("the replace is valid in the genesis commit");
    cozies.push(serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).unwrap(),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": t.alg, "pub": t.pub_key, "tmb": t.compute_tmb_b64().unwrap()},
    }));
    let pid = scope.genesis_id().expect("PG");
    cozies.push(
        scope
            .create_principal(&signer_of(g), *NOW, "cyphr.me")
            .await
            .expect("principal/create"),
    );
    let commit = scope
        .finalize_with_software(&signer_of(g), *NOW, "cyphr.me")
        .await
        .expect("finalize");
    cozies.push(
        serde_json::to_value(commit.commit_tx().0.first().expect("commit/create").raw())
            .expect("commit/create json"),
    );
    (body(&pid, &wire(cozies)), pid, p)
}

async fn push(state: &Arc<AppState>, body: String) -> StatusCode {
    common::post_json(build_router(state.clone()), "/push", body)
        .await
        .0
}

async fn assert_refused_and_unwritten(state: &Arc<AppState>, status: StatusCode, pid: &str) {
    assert!(
        status.is_client_error(),
        "a dead key must be refused with a 4xx, got {status}"
    );
    assert!(
        state.engine.get_tip(pid).await.expect("tip").is_none(),
        "a refused introduction left the principal behind"
    );
}

/// Claim: a globally revoked key cannot be re-added anywhere: a new
/// principal's genesis commit that `key/create`s it is refused, and nothing
/// of that principal is written. Turns red if the death set is consulted only
/// for signers (a dead tmb in `pay.id` accepted).
#[tokio::test]
async fn dead_key_refused_as_key_create_in_a_new_principal() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    let (body, pid, _) = genesis_push(&pool, "bob", "key_a", CREATE).await;
    let status = push(&state, body).await;
    assert_refused_and_unwritten(&state, status, &pid).await;
}

/// Claim: as above for `key/replace`: a principal cannot swap onto a dead
/// key. Turns red if only `key/create` is gated.
#[tokio::test]
async fn dead_key_refused_as_key_replace_in_a_new_principal() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    let (body, pid, _) = genesis_push(&pool, "alice", "key_a", REPLACE).await;
    let status = push(&state, body).await;
    assert_refused_and_unwritten(&state, status, &pid).await;
}

/// Claim: the refusal holds for an established principal's LATER commit, not
/// only for a first one, and leaves that principal at its prior tip. Turns
/// red if the gate runs only on the genesis push.
#[tokio::test]
async fn dead_key_refused_as_key_create_in_an_existing_principal() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    let (first, pid, bob) = genesis_push(&pool, "bob", "key_b", CREATE).await;
    assert_eq!(
        push(&state, first).await,
        StatusCode::CREATED,
        "bootstrap bob+key_b"
    );
    let before = state.engine.get_tip(&pid).await.unwrap().expect("tip");

    let blobs = intro_commit(
        bob,
        pool.get("bob").unwrap(),
        pool.get("key_a").unwrap(),
        CREATE,
    )
    .await;
    let status = push(&state, body(&pid, &blobs)).await;

    assert!(
        status.is_client_error(),
        "a dead key was added to bob: {status}"
    );
    let after = state.engine.get_tip(&pid).await.unwrap().expect("tip");
    assert_eq!(after.commit_count, before.commit_count, "bob's chain moved");
}

/// Control (green on the base): a key that is NOT dead is introduced by
/// `key/create` and by `key/replace` in a fresh principal. Without it the
/// refusals above could be a gate that refuses every introduction.
#[tokio::test]
async fn live_key_is_still_introducible_by_create_and_replace() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    for (genesis, typ) in [("bob", CREATE), ("alice", REPLACE)] {
        let (body, ..) = genesis_push(&pool, genesis, "key_b", typ).await;
        assert_eq!(
            push(&state, body).await,
            StatusCode::CREATED,
            "{genesis} {typ} key_b"
        );
    }
}
