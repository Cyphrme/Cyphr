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

const NOW: i64 = 1_700_000_000;
const CREATE: &str = "cyphr.me/cyphr/key/create";
const REPLACE: &str = "cyphr.me/cyphr/key/replace";

/// A keyed server whose index already knows `key_a` (held by the golden
/// principal) and in which `key_a` has been naked-revoked: it is now in the
/// death set. Returns the state and its tempdir guard.
async fn server_with_key_a_dead(pool: &Pool) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = common::write_signing_key(dir.path());
    let state = Arc::new(common::keyed_appstate(&dir.path().join("data"), &key));

    let pid = common::golden_principal_id(pool);
    let body = common::build_genesis_push_body(pool, &pid, NOW);
    let (status, json) = common::post_json(build_router(state.clone()), "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap golden+key_a: {json:?}"
    );

    let k = pool.get("key_a").expect("key_a");
    let tmb = k.compute_tmb_b64().expect("tmb");
    let pay = serde_json::json!({
        "alg": k.alg, "now": NOW, "rvk": NOW, "tmb": tmb,
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
/// blobs (the introduced key embedded on its coz) and the commit entry.
fn intro_commit(
    mut principal: cyphr::Principal,
    signer: &PoolKey,
    target: &PoolKey,
    typ: &str,
) -> (Vec<Vec<u8>>, cyphr_storage::CommitEntry) {
    let signer_tmb = signer.compute_tmb_b64().expect("signer tmb");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg,
        "id": target.compute_tmb_b64().expect("target tmb"),
        "now": NOW,
        "tmb": signer_tmb,
        "typ": typ,
    }))
    .unwrap();
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &prv(signer), &pubk(signer)).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(target).with_first_seen(NOW)))
        .expect("the introduction is valid against the starting principal");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &prv(signer),
                &pubk(signer),
                &signer.compute_tmb().expect("tmb"),
            ),
            NOW,
            "cyphr.me",
        )
        .expect("finalize");

    let entry = cyphr_storage::export_commits(&principal)
        .expect("export")
        .pop()
        .expect("a commit");
    let mut keys = entry.keys.iter();
    let blobs = entry
        .cozies
        .iter()
        .map(|v| {
            let mut coz = v.clone();
            if cyphr::parsed_coz::typ::is_key_introducing(coz["pay"]["typ"].as_str().unwrap_or(""))
            {
                let k = keys.next().expect("a key per introducing coz");
                coz["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
            }
            serde_json::to_vec(&coz).unwrap()
        })
        .collect();
    (blobs, entry)
}

fn body(pid: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": pid,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// The genesis push of a new implicit principal on `genesis`, introducing
/// `target` by `typ`, with the genesis key embedded on the closing coz.
fn genesis_push(
    pool: &Pool,
    genesis: &str,
    target: &str,
    typ: &str,
) -> (String, cyphr::Key, cyphr_storage::CommitEntry) {
    let g = pool.get(genesis).expect("genesis key");
    let gkey = key_of(g);
    let (mut blobs, entry) = intro_commit(
        cyphr::Principal::implicit(gkey.clone()).expect("implicit"),
        g,
        pool.get(target).expect("target key"),
        typ,
    );
    let last = blobs.len() - 1;
    let mut closing: serde_json::Value = serde_json::from_slice(&blobs[last]).unwrap();
    closing["key"] = serde_json::json!({
        "alg": g.alg, "pub": g.pub_key, "tmb": g.compute_tmb_b64().unwrap(),
    });
    blobs[last] = serde_json::to_vec(&closing).unwrap();
    (body(&g.compute_tmb_b64().unwrap(), &blobs), gkey, entry)
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
    let (body, ..) = genesis_push(&pool, "bob", "key_a", CREATE);
    let status = push(&state, body).await;
    assert_refused_and_unwritten(&state, status, &common::implicit_principal_id(&pool, "bob"))
        .await;
}

/// Claim: as above for `key/replace`: a principal cannot swap onto a dead
/// key. Turns red if only `key/create` is gated.
#[tokio::test]
async fn dead_key_refused_as_key_replace_in_a_new_principal() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    let (body, ..) = genesis_push(&pool, "alice", "key_a", REPLACE);
    let status = push(&state, body).await;
    assert_refused_and_unwritten(
        &state,
        status,
        &common::implicit_principal_id(&pool, "alice"),
    )
    .await;
}

/// Claim: the refusal holds for an established principal's LATER commit, not
/// only for a first one, and leaves that principal at its prior tip. Turns
/// red if the gate runs only on the genesis push.
#[tokio::test]
async fn dead_key_refused_as_key_create_in_an_existing_principal() {
    let pool = common::load_pool();
    let (state, _dir) = server_with_key_a_dead(&pool).await;
    let (first, gkey, entry) = genesis_push(&pool, "bob", "key_b", CREATE);
    assert_eq!(
        push(&state, first).await,
        StatusCode::CREATED,
        "bootstrap bob+key_b"
    );
    let pid = common::implicit_principal_id(&pool, "bob");
    let before = state.engine.get_tip(&pid).await.unwrap().expect("tip");

    let replayed = cyphr_storage::load_principal_from_commits(
        cyphr_storage::Genesis::Implicit(gkey),
        std::slice::from_ref(&entry),
    )
    .expect("replay genesis");
    let (blobs, _) = intro_commit(
        replayed,
        pool.get("bob").unwrap(),
        pool.get("key_a").unwrap(),
        CREATE,
    );
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
        let (body, ..) = genesis_push(&pool, genesis, "key_b", typ);
        assert_eq!(
            push(&state, body).await,
            StatusCode::CREATED,
            "{genesis} {typ} key_b"
        );
    }
}
