//! `GET /server` — the identity/capability discovery endpoint
//! (`docs/specs/server-identity.md`).
//!
//! Exercises the tier declaration's honesty contract: `attestor` requires
//! BOTH a bootstrapped principal AND a live signing identity, publishing
//! the PG and the CURRENT key material read only from `AppState.identity`;
//! any other combination — keyless, or keyed-but-not-yet-bootstrapped
//! (only reachable when the router is built without `serve()`, i.e. here)
//! — declares `repository` with no identity-shaped fields a client could
//! mistake for attestation.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ========================================================================
// Fixture helpers (mirrored from tests/server_principal.rs and
// tests/keyless_matrix.rs, which are separate integration-test crates and
// cannot be imported here)
// ========================================================================

/// Write a fresh Ed25519 signing key file and return its path.
fn write_signing_key(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    let file = serde_json::json!({
        "alg": kp.alg.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    path
}

/// A keyed `AppState` whose signing key is `key_path`. Mirrors what
/// `serve` constructs before it bootstraps the principal (which callers
/// drive directly, exactly like `tests/server_principal.rs`'s
/// `keyed_appstate`).
fn keyed_appstate(data_dir: &std::path::Path, key_path: &std::path::Path) -> AppState {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    AppState::new(config).expect("keyed AppState opens")
}

/// An `AppState` with a temporary database and NO signing identity.
fn keyless_state() -> Arc<AppState> {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("failed to open keyless AppState"))
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

/// Assert `body` is a well-formed unsigned envelope
/// (`docs/specs/http-envelope.md`) and return its `payload`.
fn assert_unsigned_envelope(body: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(body["v"], serde_json::json!(1), "envelope v=1: {body:?}");
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("unsigned"),
        "the discovery response is never signed today: {body:?}"
    );
    &body["payload"]
}

// ========================================================================
// Keyed + bootstrapped: attestor
// ========================================================================

/// A keyed, bootstrapped server publishes the attestor payload: tier,
/// stable PG, and current key material read from `AppState.identity`.
#[tokio::test]
async fn keyed_bootstrapped_server_publishes_attestor_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity.clone(), &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap the server principal");
    let pg = sp.pg().to_string();
    state.principal = Some(Arc::new(sp));

    let app = build_router(Arc::new(state));
    let (status, envelope) = get_json(app, "/server").await;
    assert_eq!(status, StatusCode::OK, "discovery must succeed: {envelope:?}");

    let payload = assert_unsigned_envelope(&envelope);
    assert_eq!(payload["tier"], serde_json::json!("attestor"));
    assert_eq!(
        payload["pg"], serde_json::json!(pg),
        "published pg must equal the bootstrap PG"
    );
    assert_eq!(payload["alg"], serde_json::json!(identity.alg().name()));
    assert_eq!(
        payload["pub"],
        serde_json::json!(Base64UrlUnpadded::encode_string(identity.pub_key()))
    );
    let tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("thumbprint");
    assert_eq!(
        payload["tmb"],
        serde_json::json!(Base64UrlUnpadded::encode_string(tmb.as_bytes()))
    );
}

/// The published PG is stable across a reboot: a second bootstrap against
/// the same key and data directory reports the same PG the discovery
/// endpoint published on the first.
#[tokio::test]
async fn published_pg_is_stable_across_a_reboot() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let data_dir = dir.path().join("data");

    let mut state1 = keyed_appstate(&data_dir, &key_path);
    let identity1 = state1.identity.clone().expect("identity");
    let sp1 = ServerPrincipal::bootstrap(&state1.engine, identity1, &key_path, &state1.config.data_dir)
        .await
        .expect("first boot bootstraps");
    state1.principal = Some(Arc::new(sp1));
    let app1 = build_router(Arc::new(state1));
    let (_, envelope1) = get_json(app1, "/server").await;
    let pg1 = assert_unsigned_envelope(&envelope1)["pg"].clone();

    let mut state2 = keyed_appstate(&data_dir, &key_path);
    let identity2 = state2.identity.clone().expect("identity");
    let sp2 = ServerPrincipal::bootstrap(&state2.engine, identity2, &key_path, &state2.config.data_dir)
        .await
        .expect("second boot loads the existing principal");
    state2.principal = Some(Arc::new(sp2));
    let app2 = build_router(Arc::new(state2));
    let (_, envelope2) = get_json(app2, "/server").await;
    let pg2 = assert_unsigned_envelope(&envelope2)["pg"].clone();

    assert_eq!(pg1, pg2, "the published PG must survive a reboot");
}

// ========================================================================
// Keyless: repository, honestly absent identity fields
// ========================================================================

/// A keyless server declares `repository` with no identity-shaped fields
/// a client could mistake for attestation.
#[tokio::test]
async fn keyless_server_declares_repository_with_no_identity_fields() {
    let app = build_router(keyless_state());
    let (status, envelope) = get_json(app, "/server").await;
    assert_eq!(status, StatusCode::OK, "discovery must succeed: {envelope:?}");

    let payload = assert_unsigned_envelope(&envelope);
    assert_eq!(payload["tier"], serde_json::json!("repository"));
    assert!(payload.get("pg").is_none(), "repository carries no pg: {payload:?}");
    assert!(payload.get("alg").is_none(), "repository carries no alg: {payload:?}");
    assert!(payload.get("pub").is_none(), "repository carries no pub: {payload:?}");
    assert!(payload.get("tmb").is_none(), "repository carries no tmb: {payload:?}");
}

// ========================================================================
// Keyed but not yet bootstrapped: repository (delegated ruling)
// ========================================================================

/// A keyed `AppState` whose principal was never bootstrapped (only
/// reachable when the router is built without `serve()`, e.g. this test
/// or an embedder) declares `repository`, not `attestor`: no established,
/// servable chain means nothing to pin, so the tier tracks the PRINCIPAL,
/// not the key file.
#[tokio::test]
async fn keyed_but_unbootstrapped_principal_declares_repository() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let state = keyed_appstate(&dir.path().join("data"), &key_path);
    assert!(state.identity.is_some(), "state is keyed");
    assert!(state.principal.is_none(), "principal was never bootstrapped");

    let app = build_router(Arc::new(state));
    let (status, envelope) = get_json(app, "/server").await;
    assert_eq!(status, StatusCode::OK, "discovery must succeed: {envelope:?}");

    let payload = assert_unsigned_envelope(&envelope);
    assert_eq!(payload["tier"], serde_json::json!("repository"));
    assert!(payload.get("pg").is_none(), "repository carries no pg: {payload:?}");
}
