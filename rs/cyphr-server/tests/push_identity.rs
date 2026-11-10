//! `POST /push` identity binding (security sweep D1 storage path, D2).
//!
//! A principal's identifier is derived from its genesis (SPEC 3.1: for a
//! single-key genesis, `tmb` is promoted to PR; SPEC.md:323). The server must
//! not store a genesis under any other `principal_id`, and must not
//! accept a key whose unsigned `pub` sidecar was swapped out from under
//! its signed `tmb`.
//!
//! Every refusal is checked end to end: the HTTP status, and that the
//! refused write did not land (`/tip` is 404).

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;
use cyphr_storage::{Genesis, load_principal_from_commits};

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, golden_principal_id, keyless_server,
    load_pool, post_json,
};

const NOW: i64 = 1_700_100_000;

/// The genesis-derived id for `build_genesis_push_body`'s principal
/// (a genesis commit on the pool's `golden` key that also creates `key_a`):
/// its PG.
async fn derived_id(pool: &test_fixtures::Pool) -> String {
    golden_principal_id(pool).await
}

async fn tip_status(app: axum::Router, id: &str) -> StatusCode {
    get_json(app, &format!("/tip?pr={id}")).await.0
}

// ============================================================================
// D2 -- principal_id must be the genesis-derived id
// ============================================================================

/// Control: the same bundle under the genesis-derived id is accepted.
/// Without it, the refusals below could be satisfied by refusing every
/// push.
#[tokio::test]
async fn d2_control_push_under_derived_id_is_accepted() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    let id = derived_id(&pool).await;

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, NOW).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    assert_eq!(tip_status(app, &id).await, StatusCode::OK);
}

/// Backs: `/push` refuses a genesis stored under a `principal_id` that is
/// not the genesis-derived id (keyless server, so the attestor-only
/// canonical-form gate does not mask the defect). Red now because the
/// handler stores the genesis under any client-chosen string: here `"bob"`.
#[tokio::test]
async fn d2_push_refuses_genesis_under_arbitrary_id_keyless() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    let squat = "bob";

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, squat, NOW).await,
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST,
        "genesis stored under unrelated principal_id {squat:?}: {status} {body:?}"
    );
    assert_eq!(
        tip_status(app, squat).await,
        StatusCode::NOT_FOUND,
        "a refused push must not land"
    );
}

/// Backs: same refusal for a well-formed-looking but wrong 32-byte id on
/// an attestor server, where `parse_genesis_id_str` passes (right length)
/// yet the id is not this genesis's. This is the in-tree
/// `routes.rs` `push_test_genesis` shape (`[0x61; 32]`). Red now because
/// only the id's byte length is checked.
#[tokio::test]
async fn d2_push_refuses_genesis_under_wellformed_wrong_id_attestor() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let squat = Base64UrlUnpadded::encode_string(&[0x61u8; 32]);
    assert_ne!(squat, derived_id(&pool).await, "premise");

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &squat, NOW).await,
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST,
        "genesis stored under a well-formed but unrelated principal_id: {status} {body:?}"
    );
    assert_eq!(
        tip_status(app, &squat).await,
        StatusCode::NOT_FOUND,
        "a refused push must not land"
    );
}

// ============================================================================
// D1 -- storage paths must reject a substituted key sidecar
// ============================================================================

/// Rewrites the `pub` of the bundle's `keys` entry that transaction 0
/// (the `key/create`) names to `new_pub_b64`, leaving the signed pay, `sig`
/// and the entry's `tmb` untouched.
fn substitute_sidecar_pub(body: &str, new_pub_b64: &str) -> String {
    let mut req: serde_json::Value = serde_json::from_str(body).expect("push body json");
    let raw =
        Base64UrlUnpadded::decode_vec(req["txs"][0][0].as_str().expect("blob str")).expect("b64");
    let coz: serde_json::Value = serde_json::from_slice(&raw).expect("blob json");
    assert_eq!(
        coz["pay"]["typ"], "cyphr.me/cyphr/key/create",
        "premise: transaction 0 is the key/create"
    );
    let id = coz["pay"]["id"].as_str().expect("id").to_owned();
    let entry = req["keys"]
        .as_array_mut()
        .expect("keys")
        .iter_mut()
        .find(|k| k["tmb"] == id.as_str())
        .expect("the key/create's key entry");
    entry["pub"] = serde_json::json!(new_pub_b64);
    req.to_string()
}

/// Backs (D1, push path): a `key/create` whose sidecar `pub` is swapped
/// for another key's keeps the same signed pay and the same PR, so it
/// must be refused. Red now because `/push` replays the bundle without
/// checking the sidecar's `tmb == H(pub)`, accepting it under the correct
/// derived id.
#[tokio::test]
async fn d1_push_refuses_substituted_key_sidecar() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    let id = derived_id(&pool).await;
    let attacker_pub = pool.get("key_b").expect("key_b in pool").pub_key.clone();

    let honest = build_genesis_push_body(&pool, &id, NOW).await;
    let forged = substitute_sidecar_pub(&honest, &attacker_pub);
    assert_ne!(honest, forged, "premise: the body was altered");

    let (status, body) = post_json(app.clone(), "/push", forged).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "push accepted a key/create whose sidecar pub does not hash to its tmb: {body:?}"
    );
    // The refusal names the binding failure itself, not a generic malformed
    // payload that would also fit a dropped sidecar.
    assert!(
        body.to_string().contains("does not match its public key"),
        "the refusal must report the tmb/pub mismatch: {body:?}"
    );
    assert_eq!(
        tip_status(app, &id).await,
        StatusCode::NOT_FOUND,
        "a refused push must not land"
    );
}

/// Honest history: the genesis commit of `golden` (SPEC 5.1), then golden
/// `key/create` key_a.
async fn honest_history(pool: &test_fixtures::Pool) -> cyphr::Principal {
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let dom = |pk: &test_fixtures::PoolKey| {
        cyphr::Key::new(
            pk.alg.clone(),
            pk.compute_tmb().expect("tmb"),
            Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        )
        .expect("key binds its tmb")
    };
    let b64d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    let mut p = cyphr::Principal::implicit(dom(golden))
        .await
        .expect("genesis");
    p.commit_genesis(
        &golden.software_signer().expect("golden signer"),
        &[],
        NOW,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    let g_prv = b64d(golden.prv.as_ref().expect("golden prv"));
    let g_pub = b64d(&golden.pub_key);
    let pay = serde_json::json!({
        "alg": golden.alg,
        "id": key_a.compute_tmb_b64().expect("tmb"),
        "now": NOW,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_vec = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay_vec, &golden.alg, &g_prv, &g_pub).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig, czd, Some(dom(key_a)))
        .expect("honest key/create");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &golden.alg,
                &g_prv,
                &g_pub,
                &golden.compute_tmb().expect("tmb"),
            ),
            NOW + 1,
            "cyphr.me",
        )
        .await
        .expect("finalize");

    p
}

/// Backs (D1, storage replay path): replaying stored commits whose
/// `key/create` sidecar `pub` was swapped must fail even though the
/// recorded `pr`/`ar`/`sr` still match (they do not cover `pub`). Red now
/// because `load_principal_from_commits` rebuilds the key from the stored
/// sidecar without checking `tmb == H(pub)`.
#[tokio::test]
async fn d1_replay_refuses_substituted_key_sidecar() {
    let pool = load_pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let attacker_pub = pool.get("key_b").expect("key_b").pub_key.clone();

    let dom = |pk: &test_fixtures::PoolKey| {
        cyphr::Key::new(
            pk.alg.clone(),
            pk.compute_tmb().expect("tmb"),
            Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        )
        .expect("key binds its tmb")
    };

    let p = honest_history(&pool).await;
    let honest = cyphr_storage::export_commits(&p).expect("export");
    load_principal_from_commits(Genesis::Implicit(dom(golden)), &honest)
        .await
        .expect("control: honest history replays");

    // Commit 0 is the genesis commit; commit 1 is the key_a `key/create`.
    let mut forged = honest.clone();
    assert_eq!(forged[1].keys[0].tmb, key_a.compute_tmb_b64().expect("tmb"));
    forged[1].keys[0].pub_key = attacker_pub;
    assert!(
        load_principal_from_commits(Genesis::Implicit(dom(golden)), &forged)
            .await
            .is_err(),
        "replay accepted a stored key whose pub does not hash to its tmb"
    );
}
