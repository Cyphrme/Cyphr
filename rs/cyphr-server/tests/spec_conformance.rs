//! SPEC conformance (SC1), server tier. The map is
//! `docs/architecture/spec-conformance.md`; the core-tier scenarios live in
//! `rs/cyphr/tests/spec_conformance.rs`. This file holds the one row whose
//! requirement is only observable through the HTTP write path.
//!
//! Frozen- and deleted-principal pushes, and out-of-range `rvk` pushes, have
//! no server-tier test here on purpose: the only way to author such a commit
//! is the core builder, which will refuse to build it once the requirement is
//! enforced, so the scenario would silently stop exercising the server. The
//! core tier owns them (a hand-signed wire vector would go stale on every
//! corpus regeneration and pass for the wrong reason).

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    build_second_commit_push_body, envelope_payload, get_json, keyless_server, load_pool, post_json,
};

const NOW: i64 = 1_700_100_000;

/// A genesis push for the pool's `golden` principal whose single commit adds
/// `key_b`. Same shape as `common::build_genesis_push_body` (which adds
/// `key_a`): the genesis key rides on the closing `commit/create`.
fn genesis_push_adding_key_b(pool: &test_fixtures::Pool, principal_id: &str) -> String {
    let golden = pool.get("golden").expect("golden in pool");
    let mut body: serde_json::Value =
        serde_json::from_str(&build_second_commit_push_body(pool, principal_id, NOW))
            .expect("push body is JSON");
    let blobs = body["blobs"].as_array_mut().expect("blobs array");
    let last = blobs.len() - 1;
    let raw = Base64UrlUnpadded::decode_vec(blobs[last].as_str().expect("blob is a string"))
        .expect("blob base64");
    let mut closing: serde_json::Value = serde_json::from_slice(&raw).expect("blob is JSON");
    closing.as_object_mut().expect("coz object").insert(
        "key".to_string(),
        serde_json::json!({
            "alg": golden.alg,
            "pub": golden.pub_key,
            "tmb": golden.compute_tmb_b64().expect("golden tmb"),
        }),
    );
    blobs[last] = serde_json::Value::String(Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&closing).expect("serialize"),
    ));
    body.to_string()
}

async fn commit_count(app: &axum::Router, id: &str) -> u64 {
    let (status, env) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    assert_eq!(status, StatusCode::OK, "tip of {id}: {env:?}");
    envelope_payload(&env)["commit_count"]
        .as_u64()
        .expect("commit_count")
}

/// Backs SPEC 2.3.2: "Commits are never removed from the chain and implicit
/// forks are prohibited by the protocol." Scenario over HTTP: one principal
/// has its first commit (adds `key_a`) accepted; a competing first commit
/// (adds `key_b`, signed by the same genesis key, so it is fully authorized)
/// is pushed on the same `pre` and must be refused, leaving the chain at one
/// commit. Control: on a fresh server the competing commit alone is accepted,
/// so the refusal is the stale `pre`, not a malformed body. Turns red if the
/// server appends a second commit on a `pre` the chain has moved past, or
/// reports success for it. End to end: yes (HTTP, store, replay).
// @docket: sc-l237 :: scripts/docket-run sc-l237
#[tokio::test]
async fn s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put() {
    let pool = load_pool();
    let id = pool
        .get("golden")
        .expect("golden in pool")
        .compute_tmb_b64()
        .expect("golden tmb");
    let competing = genesis_push_adding_key_b(&pool, &id);

    let (control_state, _control_dir) = keyless_server();
    let control = build_router(control_state);
    let (status, body) = post_json(control, "/push", competing.clone()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "control: the competing commit is valid on its own: {body:?}"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, body) = post_json(
        app.clone(),
        "/push",
        common::build_genesis_push_body(&pool, &id, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "first commit: {body:?}");
    assert_eq!(commit_count(&app, &id).await, 1);

    let (status, body) = post_json(app.clone(), "/push", competing).await;
    assert!(
        status.is_client_error(),
        "a commit on a stale pre was not refused: {status}: {body:?}"
    );
    assert_eq!(
        commit_count(&app, &id).await,
        1,
        "the refused fork commit landed in the chain"
    );
}
