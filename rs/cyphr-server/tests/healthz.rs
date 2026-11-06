//! `GET /healthz` -- can this peer serve? (G6, a-healthz)
//!
//! Both tests are end-to-end scenarios over the production router
//! (`build_app_router`): real fjall storage in a tempdir, a real push, a real
//! HTTP request. They are RED until `/healthz` exists; run the reds with
//! `cargo test -p cyphr-server --test healthz -- --ignored`.
//!
//! ## Why the fault is "the record directory vanishes"
//!
//! Probed on the base tip: after `remove_dir_all(record_dir)` every *read*
//! (`get_tip`) still answers `Ok(None)` from open file descriptors, and only
//! a write (`POST /push`) fails (`500 internal storage error`). So a probe
//! that merely reads (e.g. `get_tip("healthz")`) reports a peer that cannot
//! accept writes as healthy; the contract pinned here is that `/healthz`
//! exercises the write path. The index directory is deliberately NOT a
//! fault: removing it left pushes succeeding (201) on the base tip, so no
//! observable "index down" exists to pin without a production hook.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use cyphr_server::build_app_router;
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{build_genesis_push_body, golden_principal_id, keyless_server, load_pool, post_json};

async fn get_raw(app: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Claim: an operator can tell a peer that serves from one that does not --
/// and a peer that has served traffic still answers, without credentials.
/// Defect that turns it red: no `/healthz` route (404 today), a route behind
/// auth, or a handler that fails once the peer holds data.
/// End-to-end: yes (push a principal, then probe).
#[tokio::test]
async fn healthz_answers_200_on_a_healthy_peer_that_holds_data() {
    let (state, _dir) = keyless_server();
    let app = build_app_router(state).expect("router");

    let pool = load_pool();
    let id = golden_principal_id(&pool);
    let (push, _) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, 1_700_100_000),
    )
    .await;
    assert_eq!(push, StatusCode::CREATED, "fixture push must land");

    let (status, _, body) = get_raw(&app, "/healthz").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "healthy peer must answer 200: {body}"
    );
    assert!(
        !body.contains(&id),
        "health body must not name a principal: {body}"
    );
}

/// Claim: `/healthz` tracks the peer's live ability to store, not a startup
/// snapshot, and says so with a typed 503. Same app, same process: 200,
/// then the storage vanishes, then 503.
/// Defects that turn it red: a constant-200 handler (never reaches the 503
/// assertion's status), a handler that caches its first answer or probes
/// only reads (stays 200 after the fault), a non-JSON/untyped failure body,
/// and a failure body that leaks the data directory path.
/// End-to-end: yes.
#[tokio::test]
async fn healthz_turns_503_when_storage_is_destroyed() {
    let (state, _dir) = keyless_server();
    let record_dir = state.config.record_dir();
    let data_dir = state.config.data_dir.to_string_lossy().into_owned();
    let app = build_app_router(state).expect("router");

    let (before, _, body) = get_raw(&app, "/healthz").await;
    assert_eq!(before, StatusCode::OK, "healthy before the fault: {body}");

    std::fs::remove_dir_all(&record_dir).expect("destroy the record store");

    let (after, headers, body) = get_raw(&app, "/healthz").await;
    assert_eq!(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "a peer that cannot store must answer 503: {body}"
    );
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.contains("json"),
        "the failure must be typed (JSON), got content-type {content_type:?}"
    );
    serde_json::from_str::<serde_json::Value>(&body).expect("failure body parses as JSON");
    assert!(
        !body.contains(&data_dir),
        "failure body must not reveal the data directory: {body}"
    );
}
