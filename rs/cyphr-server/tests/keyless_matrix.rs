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
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

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

/// Sign a fresh "add `new_key_name`" commit onto `principal`, signed by
/// `signer_name`. Returns the new commit's raw coz blob bytes, wire-ready
/// for `submit_commit`. Mirrors the helper of the same name in
/// `tests/e2e.rs`.
fn sign_key_create_commit(
    mut principal: cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key_name: &str,
    now: i64,
) -> Vec<Vec<u8>> {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let new_key = pool.get(new_key_name).expect("new key in pool");

    let signer_tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");
    let new_tmb_b64 = new_key.compute_tmb_b64().expect("new key tmb");

    let pay_value = serde_json::json!({
        "alg": signer.alg,
        "id": new_tmb_b64,
        "now": now,
        "tmb": signer_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_vec = serde_json::to_vec(&pay_value).unwrap();

    let signer_prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("valid signer prv base64");
    let signer_pub =
        Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub base64");
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &signer.alg, &signer_prv, &signer_pub)
        .expect("signing supported for this algorithm");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).expect("czd for this algorithm");

    let new_cyphr_key = cyphr::Key {
        alg: new_key.alg.clone(),
        tmb: coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(&new_tmb_b64).expect("valid new key tmb base64"),
        ),
        pub_key: Base64UrlUnpadded::decode_vec(&new_key.pub_key).expect("valid new key pub base64"),
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_cyphr_key))
        .expect("key/create should verify against the starting principal state");

    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_arrow(
            &signer.alg,
            &signer_prv,
            &signer_pub,
            &signer_tmb,
            now,
            "cyphr.me",
        )
        .expect("commit should finalize");

    let entries = cyphr_storage::export_commits(&principal).expect("export the new commit");
    let new_commit = entries.last().expect("at least one commit after finalize");

    let mut key_idx = 0;
    new_commit
        .cozies
        .iter()
        .map(|v| {
            let mut coz = v.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < new_commit.keys.len() {
                let key = &new_commit.keys[key_idx];
                coz.as_object_mut().unwrap().insert(
                    "key".to_string(),
                    serde_json::json!({
                        "alg": key.alg,
                        "pub": key.pub_key,
                        "tmb": key.tmb,
                    }),
                );
                key_idx += 1;
            }
            serde_json::to_vec(&coz).expect("cozy serializes")
        })
        .collect()
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

/// Build a brand-new principal's genesis push HTTP body: a `key/create`
/// closed by `commit/create`, the genesis key embedded on the closing
/// cozy (the wire contract `resolve_genesis` requires for a brand-new
/// principal). Mirrors `push_new_principal_happy_path` in `tests/e2e.rs`.
fn build_genesis_push_body(pool: &test_fixtures::Pool, principal_id: &str, now: i64) -> String {
    let golden = pool.get("golden").expect("golden key in pool");
    let golden_key = cyphr::Key {
        alg: golden.alg.clone(),
        tmb: golden.compute_tmb().expect("golden tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("golden pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    let principal = cyphr::Principal::implicit(golden_key.clone()).expect("implicit genesis");
    let mut blobs = sign_key_create_commit(principal, pool, "golden", "key_a", now);

    let closing_idx = blobs.len() - 1;
    let mut closing: serde_json::Value = serde_json::from_slice(&blobs[closing_idx]).unwrap();
    closing.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": golden_key.alg,
            "pub": golden.pub_key,
            "tmb": Base64UrlUnpadded::encode_string(golden_key.tmb.as_bytes()),
        }),
    );
    blobs[closing_idx] = serde_json::to_vec(&closing).unwrap();

    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
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
    let principal_id = "keyless-matrix-repo";
    let now = 1_700_000_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

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
        2,
        "push response should report a hash per submitted blob: {push_payload:?}"
    );

    // --- tip ---
    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(
        tip_status,
        StatusCode::OK,
        "tip must succeed on a keyless server: {tip_envelope:?}"
    );
    let tip_payload = assert_unsigned_envelope(&tip_envelope);
    assert_eq!(tip_payload["principal_id"], principal_id);
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
        get_json(app.clone(), &format!("/patch?pr={principal_id}")).await;
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

/// `GET /server` on a keyless server declares `repository` honestly
/// unsigned, as part of the repository-tier surface this matrix sweeps
/// (`docs/specs/server-identity.md`).
#[tokio::test]
async fn keyless_discovery_declares_repository_tier() {
    let state = keyless_state();
    let app = build_router(state);

    let (status, envelope) = get_json(app, "/server").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "discovery must succeed on a keyless server: {envelope:?}"
    );
    let payload = assert_unsigned_envelope(&envelope);
    assert_eq!(payload["tier"], serde_json::json!("repository"));
    assert!(
        payload.get("pg").is_none(),
        "a keyless server's discovery payload carries no pg: {payload:?}"
    );
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

/// `POST /auth/login` on a keyless server returns the explicit
/// capability-absence error -- never a 500.
#[tokio::test]
async fn keyless_login_returns_capability_absence_not_internal_error() {
    let state = keyless_state();
    let app = build_router(state);

    let (status, json) = post_json(app, "/auth/login", empty_coz_body()).await;
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
// docket: signon-honest-refusal :: cargo test --manifest-path rs/Cargo.toml --test keyless_matrix
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
