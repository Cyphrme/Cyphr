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
