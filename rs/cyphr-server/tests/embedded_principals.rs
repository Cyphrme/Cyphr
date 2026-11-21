//! A push whose commit is signed by a key of an embedded principal (SPEC
//! be0663f 10.3, 10.5) is judged against the tip the server holds of that
//! principal: accepted when it is held and the key is active there, an
//! unknown key when the principal is not held.

use axum::http::StatusCode;
use cyphr_server::build_router;

mod common;

use common::{
    build_bundle, envelope_payload, fixture_principal_id, get_json, keyless_server, load_golden,
    load_pool, post_json, push_body,
};

/// The tip payload minus the response's own clock.
async fn tip(app: &axum::Router, id: &str) -> serde_json::Value {
    let (status, body) =
        get_json(app.clone(), &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let mut payload = envelope_payload(&body).clone();
    payload.as_object_mut().expect("object").remove("now");
    payload
}

/// The embedded principal B of the golden vector: its id (the PG its genesis
/// commit names) and its commit lines, which a client pushes first.
fn peer_of(fixture: &serde_json::Value) -> (String, Vec<serde_json::Value>) {
    let lines = fixture["peer"]["commits"].as_array().expect("peer").clone();
    let id = test_fixtures::bundle::genesis_id(&build_bundle(&lines[0])).expect("peer pg");
    (id, lines)
}

/// Backs SPEC 10.3/10.5/10.7 over HTTP (golden vector
/// `embedding/embedded_member_signs_for_principal`): principal A embeds B's
/// PR in its Key Tree and a key of B signs A's next commit. With B's chain
/// pushed first, A's genesis, its embedding commit and the B-signed commit
/// are all stored (201) and A's tip advances to the vector's PR. Turns red
/// if the server refuses the B-signed commit (as unsupported or as an
/// unknown key) though B is held, or stores a different chain.
/// End to end: yes (HTTP pushes of real signed chains).
#[tokio::test]
async fn embedded_signed_commit_is_accepted_when_b_is_held() {
    let fixture = load_golden("embedding", "embedded_member_signs_for_principal");
    let id = fixture_principal_id(&fixture);
    let (peer_id, peer_lines) = peer_of(&fixture);
    let commits = fixture["commits"].as_array().expect("commits");
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    for line in &peer_lines {
        let (status, body) = post_json(
            app.clone(),
            "/push",
            push_body(&peer_id, &build_bundle(line)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "peer: {body:?}");
    }
    for (i, commit) in commits.iter().enumerate() {
        let (status, body) =
            post_json(app.clone(), "/push", push_body(&id, &build_bundle(commit))).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }
    let tip = tip(&app, &id).await;
    assert_eq!(tip["pr"], fixture["expected"]["pr"], "{tip}");
}

/// Backs SPEC 10.3 "opaque nodes do not trigger state synchronization": the
/// same pushes without B's chain leave the digest in A's Key Tree opaque, so
/// the B-signed commit is the plain protocol refusal (422 `unknown key`)
/// and A's chain is as it was. Turns red if the server stores the commit or
/// reports a limitation instead of the unknown key.
/// End to end: yes (HTTP pushes of a real signed chain).
#[tokio::test]
async fn embedded_signed_commit_is_unknown_key_when_b_is_not_held() {
    let fixture = load_golden("embedding", "embedded_member_signs_for_principal");
    let id = fixture_principal_id(&fixture);
    let commits = fixture["commits"].as_array().expect("commits");
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    for (i, commit) in commits[..2].iter().enumerate() {
        let (status, body) =
            post_json(app.clone(), "/push", push_body(&id, &build_bundle(commit))).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }
    let before = tip(&app, &id).await;

    let (status, body) = post_json(
        app.clone(),
        "/push",
        push_body(&id, &build_bundle(&commits[2])),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    let message = envelope_payload(&body)["error"]
        .as_str()
        .expect("error message");
    assert!(message.contains("unknown key"), "{message}");

    assert_eq!(
        tip(&app, &id).await,
        before,
        "nothing of the refused commit is stored"
    );
}

/// Backs the plain unknown-key refusal on a principal whose KT holds a
/// digest: a `key/delete` of a key it does not hold, signed by its own
/// active key, is 422 `unknown key`, as it is on any principal, though an
/// embedded digest is in play (the signer resolves, so nothing is followed).
/// Turns red if such a refusal is reported as anything else. End to end: yes
/// (HTTP push of a signed coz).
#[tokio::test]
async fn unknown_key_delete_by_a_known_signer_stays_unknown_key() {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let fixture = load_golden("embedding", "embedded_member_signs_for_principal");
    let id = fixture_principal_id(&fixture);
    let commits = fixture["commits"].as_array().expect("commits");
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for commit in &commits[..2] {
        let (status, body) =
            post_json(app.clone(), "/push", push_body(&id, &build_bundle(commit))).await;
        assert_eq!(status, StatusCode::CREATED, "{body:?}");
    }

    let pool = load_pool();
    let alice = pool.get("alice").expect("alice");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    let (prv, pubb) = (d(alice.prv.as_ref().expect("prv")), d(&alice.pub_key));
    let absent = pool
        .get("key_a")
        .expect("key_a")
        .compute_tmb()
        .expect("tmb");
    let pay = serde_json::json!({
        "alg": alice.alg, "id": absent.to_b64(), "now": 1_700_000_003,
        "tmb": alice.compute_tmb().expect("tmb").to_b64(),
        "typ": "cyphr.me/cyphr/key/delete",
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &alice.alg, &prv, &pubb).expect("sign");
    let coz = serde_json::json!({ "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) });
    let blob = serde_json::to_vec(&coz).expect("coz");

    let (status, body) = post_json(app, "/push", common::push_blobs(&id, &[blob])).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    let message = envelope_payload(&body)["error"].as_str().expect("error");
    assert!(message.contains("unknown key"), "{message}");
}
