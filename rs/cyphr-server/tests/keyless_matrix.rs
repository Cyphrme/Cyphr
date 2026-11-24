//! The keyless full-surface matrix: coverage of every route when the
//! server has no signing identity configured.
//!
//! A server with no configured signing identity (`config.signing_key_path
//! = None`, the compiled default -- see `docs/specs/http-envelope.md`)
//! still MUST serve its repository-tier surface honestly:
//! every JSON success response is an explicitly-unsigned envelope, never a
//! bare body a client could misread as attested, and the identity-gated
//! auth surface (`/auth/login`, `/auth/challenge`) fails loudly and
//! explicitly rather than masquerading a declared capability absence as a
//! transient server fault.
//!
//! Other test suites cite this module by name as the keyless conformance
//! evaluator; it is not itself the origin of the enveloping or
//! degradation behavior it tests (that is `src/routes.rs` and
//! `src/auth/login.rs`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

// ========================================================================
// Shared fixture helpers (mirrored from tests/e2e.rs, which is a separate
// integration-test crate and cannot be imported here)
// ========================================================================

/// Load the shared cryptographic key pool backing the golden fixtures.
fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

/// An `AppState` with a temporary database and NO signing identity -- the
/// keyless deployment shape this matrix exercises throughout.
fn keyless_state() -> Arc<AppState> {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("failed to open keyless AppState"))
}

/// Assert `body` is a well-formed unsigned envelope
/// (`docs/specs/http-envelope.md`) and return its `payload`. This is the
/// matrix's core honesty check: a keyless server must never emit a
/// response a client could misread as attested.
fn assert_unsigned_envelope(body: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(
        body["v"],
        serde_json::json!(1),
        "response must carry envelope v=1: {body:?}"
    );
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("unsigned"),
        "a keyless server's response must be explicitly unsigned, never merely missing a \
         signature: {body:?}"
    );
    assert!(
        body["statement"]["coz"].is_null(),
        "an unsigned statement must carry no coz slot: {body:?}"
    );
    &body["payload"]
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

async fn post_json(app: axum::Router, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
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

// ========================================================================
// Repository-tier surface: push / tip / patch / entity, all honestly
// unsigned on a keyless server
// ========================================================================

/// A brand-new principal's push, tip read, patch read, and entity fetch
/// all succeed on a keyless server, and every JSON body is an explicitly
/// unsigned envelope -- the repository surface works with no signing
/// identity configured, and never claims an attestation it cannot make.
#[tokio::test]
async fn keyless_push_tip_patch_entity_round_trip_is_honestly_unsigned() {
    let pool = load_pool();
    // The id the genesis commit derives: its PG (SPEC 5.1).
    let principal_id_derived = common::golden_principal_id(&pool).await;
    let principal_id = principal_id_derived.as_str();
    let now = 1_700_000_000;
    let push_body = common::build_genesis_push_body(&pool, principal_id, now).await;
    let pushed_blobs =
        common::wire_cozies(&serde_json::from_str(&push_body).expect("push body")).len();

    let state = keyless_state();
    let app = build_router(state);

    // --- push ---
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "push must succeed on a keyless server: {push_envelope:?}"
    );
    let push_payload = assert_unsigned_envelope(&push_envelope);
    assert_eq!(
        push_payload["blob_hashes"].as_array().unwrap().len(),
        pushed_blobs,
        "push response should report a hash per submitted blob: {push_payload:?}"
    );

    // --- tip ---
    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pg={principal_id}")).await;
    assert_eq!(
        tip_status,
        StatusCode::OK,
        "tip must succeed on a keyless server: {tip_envelope:?}"
    );
    let tip_payload = assert_unsigned_envelope(&tip_envelope);
    // `/tip` names the principal by its bare canonical digest.
    assert_eq!(
        tip_payload["principal_id"],
        principal_id.split_once(':').expect("labelled PG").1
    );
    assert_eq!(tip_payload["commit_count"].as_u64().unwrap(), 1);
    let pr_digest = tip_payload["pr"]
        .as_str()
        .expect("tip payload carries pr")
        .to_string();
    assert!(
        !tip_payload["cr"]
            .as_str()
            .expect("tip payload carries cr")
            .is_empty(),
        "cr must be populated once a commit has landed: {tip_payload:?}"
    );

    // --- patch ---
    let (patch_status, patch_envelope) =
        get_json(app.clone(), &format!("/patch?pg={principal_id}")).await;
    assert_eq!(
        patch_status,
        StatusCode::OK,
        "patch must succeed on a keyless server: {patch_envelope:?}"
    );
    let patch_payload = assert_unsigned_envelope(&patch_envelope);
    assert_eq!(patch_payload["entries"].as_array().unwrap().len(), 1);

    // --- entity ---
    // `pr` is itself a `TaggedDigest` that resolves through the index
    // (mirrors `rs/cyphr-storage/tests/properties.rs`'s reindex-recovery
    // assertion). Entity responses are EXCLUDED from the envelope
    // (`[envelope-r-entity]`): raw content-addressed bytes, not JSON.
    let entity_req = Request::builder()
        .uri(format!("/e/{pr_digest}"))
        .body(Body::empty())
        .unwrap();
    let entity_resp = app.oneshot(entity_req).await.unwrap();
    assert_eq!(
        entity_resp.status(),
        StatusCode::OK,
        "the tip's own pr digest must resolve via GET /e/{{digest}} on a keyless server"
    );
    let entity_bytes = entity_resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!entity_bytes.is_empty(), "entity content must be non-empty");
}

// ========================================================================
// Auth surface: honest capability-absence degradation
// ========================================================================

/// A minimal, syntactically valid (but unsigned-for-this-purpose) coz JSON
/// body -- sufficient to pass axum's `Json<CozJson>` extraction. The
/// keyless identity check in `login()` fires before any payload parsing,
/// so this body's content is otherwise irrelevant to these tests.
fn empty_coz_body() -> String {
    serde_json::json!({ "pay": {}, "sig": "" }).to_string()
}

/// `POST /auth/challenge` on a keyless server returns the explicit
/// capability-absence error -- never a 500: issuing a nonce that can
/// never be redeemed (no identity to issue the resulting token) would be
/// a silent trap, not a service worth offering.
#[tokio::test]
async fn keyless_challenge_returns_capability_absence_not_internal_error() {
    let state = keyless_state();
    let app = build_router(state);

    let (status, json) = post_json(app, "/auth/challenge", String::new()).await;
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a keyless server's declared capability absence must never surface as 500: {json:?}"
    );
    assert!(
        status.is_client_error() || status == StatusCode::NOT_IMPLEMENTED,
        "a keyless capability absence must not read as a transient server fault, got {status}: \
         {json:?}"
    );
    let payload = assert_unsigned_envelope(&json);
    let message = payload["error"]
        .as_str()
        .expect("error body names the condition");
    assert!(
        message.contains("signing identity"),
        "the rejection must name the keyless condition, got: {message:?}"
    );
    assert!(
        message.contains("/server"),
        "the rejection must point a rejected client at the discovery route, got: {message:?}"
    );
}

/// Login and challenge return the SAME explicit capability-absence error
/// on a keyless server (delegated design lean): one honest condition, one
/// treatment, not two differently-worded rejections a client would have
/// to reconcile.
// @docket: signon-honest-refusal :: scripts/docket-run signon-honest-refusal
#[tokio::test]
async fn keyless_login_and_challenge_share_the_same_rejection() {
    let state = keyless_state();

    let (login_status, login_json) =
        post_json(build_router(state.clone()), "/auth/login", empty_coz_body()).await;
    let (challenge_status, challenge_json) =
        post_json(build_router(state), "/auth/challenge", String::new()).await;

    assert_eq!(
        login_status, challenge_status,
        "login and challenge must reject a keyless server with the same status"
    );
    assert_eq!(
        login_json, challenge_json,
        "login and challenge must reject a keyless server with the same body"
    );
}
