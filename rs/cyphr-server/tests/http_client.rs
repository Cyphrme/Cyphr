//! The shared upstream HTTP client never follows a redirect: a gossip peer
//! or witness upstream answering 3xx must not carry the server's request to
//! a host the operator did not name.

use axum::Router;
use axum::http::{StatusCode, header};
use axum::routing::get;
use cyphr_server::AppState;
use cyphr_server::config::ServerConfig;

/// Claim: an upstream's redirect is returned as it is, not followed.
///
/// Turns red if the client's redirect policy is the default (follow): the
/// request then lands on `/elsewhere` and the status is 200.
/// End-to-end scenario: yes (a real listener and the state's own client).
#[tokio::test]
async fn the_upstream_client_does_not_follow_a_redirect() {
    let app = Router::new()
        .route(
            "/start",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/elsewhere")]) }),
        )
        .route("/elsewhere", get(|| async { "reached" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });

    let dir = tempfile::tempdir().expect("tempdir");
    let state = AppState::new(ServerConfig {
        data_dir: dir.path().join("data"),
        ..Default::default()
    })
    .expect("state");
    let response = state
        .http_client
        .get(format!("http://{addr}/start"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::FOUND);
}
