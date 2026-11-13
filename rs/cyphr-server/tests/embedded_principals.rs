//! A push whose commit is signed by a key of an embedded principal (SPEC
//! be0663f 10.3, 10.5) is refused as unsupported: the server resolves no
//! embedded principal's tip, so it cannot judge such a coz, and says so
//! rather than calling the key unknown.

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

/// Backs the server's typed refusal of embedded authorization (the
/// architect's ruling for EP1): principal A embeds B's PR in its KT and a
/// key of B signs A's next commit (golden vector
/// `embedding/embedded_member_signs_for_principal`). A's genesis and its
/// embedding commit are stored (201); the B-signed commit is refused with
/// 501 and a message naming the embedded limitation and the signer, and
/// A's chain is left as it was. Turns red if the server stores the commit,
/// or refuses it as a plain unknown key (422) instead of the limitation.
/// End to end: yes (HTTP pushes of a real signed chain).
#[tokio::test]
async fn embedded_signed_commit_is_refused_as_unsupported() {
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
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body:?}");
    let message = envelope_payload(&body)["error"]
        .as_str()
        .expect("error message");
    assert!(message.contains("embedded unsupported"), "{message}");
    let carol = load_pool()
        .get("carol")
        .expect("carol")
        .compute_tmb()
        .expect("tmb")
        .to_b64();
    assert!(message.contains(&carol), "names the signer: {message}");

    assert_eq!(
        tip(&app, &id).await,
        before,
        "nothing of the refused commit is stored"
    );
}

/// Backs the narrowness of that refusal: on a principal whose KT holds a
/// digest, a `key/delete` of a key it does not hold, signed by its own
/// active key, is the plain protocol refusal (422 `unknown key`), not the
/// embedded limitation, because the signer resolves. Turns red if every
/// core `UnknownKey` on such a principal is reported as an unresolved
/// embedded signer. End to end: yes (HTTP push of a signed coz).
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
