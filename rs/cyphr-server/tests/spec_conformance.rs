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
/// is pushed on the same `pre` and must be refused with 409, leaving the chain at one
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
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a commit on a stale pre was not refused as a conflict: {body:?}"
    );
    assert_eq!(
        commit_count(&app, &id).await,
        1,
        "the refused fork commit landed in the chain"
    );
}

/// Backs SPEC 6 (line 944): the private component is "never transmitted".
/// Scenario over HTTP: a genesis push (the pool's `golden` adds `key_a`),
/// then every read surface (`/tip`, `/patch` with its decoded blobs) and the
/// push response itself, none of which may contain either key's private
/// component in base64url. The server holds only public material, so this
/// pins that no response type gains a private field. Turns red if any
/// response carries a private component. End to end: yes.
// @docket: sc-l944 :: scripts/docket-run sc-l944
#[tokio::test]
async fn s6_no_http_response_carries_private_key_material() {
    let pool = load_pool();
    let id = pool
        .get("golden")
        .expect("golden in pool")
        .compute_tmb_b64()
        .expect("golden tmb");
    let needles: Vec<String> = ["golden", "key_a"]
        .iter()
        .map(|n| {
            pool.get(n)
                .expect("key in pool")
                .prv
                .clone()
                .expect("pool key has prv")
        })
        .collect();

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, push) = post_json(
        app.clone(),
        "/push",
        common::build_genesis_push_body(&pool, &id, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{push:?}");
    let (_, tip) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    let (status, patch) = get_json(app, &format!("/patch?pr={id}")).await;
    assert_eq!(status, StatusCode::OK);

    let mut surfaces = vec![push.to_string(), tip.to_string(), patch.to_string()];
    for entry in envelope_payload(&patch)["entries"]
        .as_array()
        .expect("entries")
    {
        for blob in entry["blobs"].as_array().expect("blobs") {
            let raw = Base64UrlUnpadded::decode_vec(blob.as_str().expect("blob string"))
                .expect("blob base64url");
            surfaces.push(String::from_utf8_lossy(&raw).into_owned());
        }
    }
    assert!(surfaces.len() > 3, "premise: the patch carried blobs");
    for s in &surfaces {
        for n in &needles {
            assert!(
                !s.contains(n.as_str()),
                "a response carries a private component"
            );
        }
    }
}

/// Backs SPEC 17.2 Option A step 1: "Service generates a 256-bit
/// cryptographic challenge (nonce)". Scenario: ten `/auth/challenge`
/// requests; every challenge decodes to 32 bytes and no two are equal.
/// Turns red if a challenge is shorter, longer, or repeats. Uniqueness over
/// ten draws is a smoke bound for a CSPRNG (a repeat has probability
/// 2^-250), not a randomness proof. End to end: yes.
// @docket: sc-l3054 :: scripts/docket-run sc-l3054
#[tokio::test]
async fn s17_2_challenge_is_256_bits_and_unique() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let config = cyphr_server::config::ServerConfig {
        data_dir: dir.path().to_path_buf(),
        signing_key_path: Some(key_path),
        audience: Some("cyphr.me".to_string()),
        ..Default::default()
    };
    let app = build_router(std::sync::Arc::new(
        cyphr_server::AppState::new(config).expect("open AppState"),
    ));
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..10 {
        let (status, env) = post_json(app.clone(), "/auth/challenge", String::new()).await;
        assert_eq!(status, StatusCode::OK, "{env:?}");
        let c = envelope_payload(&env)["challenge"]
            .as_str()
            .expect("challenge string");
        let bytes = Base64UrlUnpadded::decode_vec(c).expect("challenge is b64ut");
        assert_eq!(bytes.len(), 32, "challenge is not 256 bits");
        assert!(seen.insert(bytes), "a challenge repeated");
    }
}
