//! End-to-end integration tests for the cyphr-server MSS API.
//!
//! These tests exercise the full HTTP stack — request parsing, route dispatch,
//! engine orchestration, and response serialization — without binding a TCP
//! port.  Uses `tower::ServiceExt::oneshot` against `build_router`.
//!
//! ## Bootstrap strategy
//!
//! Golden fixtures use a pre-existing genesis key that signs commits but
//! isn't embedded in the commit blobs (the embedded `"key"` field is the
//! key being *added*, not the genesis key).  This means the HTTP `/push`
//! endpoint's genesis auto-detection cannot bootstrap from raw fixture
//! data alone.
//!
//! Tests therefore bootstrap principals via the engine API (which accepts
//! explicit genesis), then exercise the HTTP transport layer for reads and
//! error paths.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use http_body_util::BodyExt;
use tower::ServiceExt;

use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};

// ========================================================================
// Helpers
// ========================================================================

/// Load a golden fixture from the shared test vectors.
fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

/// Convert a golden fixture's key JSON to a domain `cyphr::Key`.
fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();

    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();

    cyphr::Key {
        alg: alg.to_string(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Build genesis from a golden fixture's `genesis_keys` array.
fn make_genesis(genesis_keys: &[serde_json::Value]) -> cyphr_storage::Genesis {
    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    if keys.len() == 1 {
        cyphr_storage::Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        cyphr_storage::Genesis::Explicit(keys)
    }
}

/// Build raw coz blobs from a golden fixture's commit, embedding key material.
fn build_raw_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    let mut blobs = Vec::new();

    for coz_value in cozies {
        let mut coz = coz_value.clone();

        let typ = coz["pay"]["typ"].as_str().unwrap_or("");
        let is_key_introducing = typ.contains("/key/create") || typ.contains("/key/replace");

        if is_key_introducing {
            if let Some(ks) = keys {
                if key_idx < ks.len() {
                    coz.as_object_mut()
                        .unwrap()
                        .insert("key".to_string(), ks[key_idx].clone());
                    key_idx += 1;
                }
            }
        }

        blobs.push(serde_json::to_vec(&coz).unwrap());
    }

    blobs
}

/// Build an `AppState` with in-memory backends and default config.
fn test_state() -> Arc<AppState> {
    Arc::new(AppState::new(ServerConfig::default()))
}

/// Bootstrap a principal into the engine via the validated write path.
fn bootstrap_principal(state: &AppState, principal_id: &str, fixture: &serde_json::Value) {
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        state
            .engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .expect("bootstrap submit_commit failed");
    }
}

// ========================================================================
// Tests — read path (bootstrapped via engine, queried via HTTP)
// ========================================================================

/// GET /tip for a bootstrapped principal → 200 with correct state.
#[tokio::test]
async fn tip_after_bootstrap() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = "e2e-tip";

    let state = test_state();
    bootstrap_principal(&state, principal_id, &fixture);

    let app = build_router(state);

    let req = Request::builder()
        .uri(format!("/tip?pr={principal_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let tip: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        tip["commit_count"].as_u64().unwrap(),
        commits.len() as u64,
        "tip commit_count should match number of submitted commits"
    );
    assert_eq!(tip["principal_id"], principal_id);
}

/// GET /patch for a bootstrapped principal → 200 with correct entries.
#[tokio::test]
async fn patch_after_bootstrap() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = "e2e-patch";

    let state = test_state();
    bootstrap_principal(&state, principal_id, &fixture);

    let app = build_router(state);

    let req = Request::builder()
        .uri(format!("/patch?pr={principal_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let patch: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(patch["principal_id"], principal_id);
    let entries = patch["entries"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        commits.len(),
        "patch should have one entry per commit"
    );

    // Each entry should have base64url-encoded blobs.
    for entry in entries {
        let blobs = entry["blobs"].as_array().unwrap();
        assert!(!blobs.is_empty(), "each commit entry should contain blobs");
        // Verify each blob is valid base64url.
        for blob_str in blobs {
            let s = blob_str.as_str().unwrap();
            Base64UrlUnpadded::decode_vec(s)
                .unwrap_or_else(|_| panic!("blob should be valid base64url: {s}"));
        }
    }
}

/// GET /patch with range parameters → returns subset of commits.
#[tokio::test]
async fn patch_with_range() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let principal_id = "e2e-patch-range";

    let state = test_state();
    bootstrap_principal(&state, principal_id, &fixture);

    let app = build_router(state);

    // Request only commit 0.
    let req = Request::builder()
        .uri(format!("/patch?pr={principal_id}&from=0&to=0"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let patch: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let entries = patch["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "range 0..0 should return exactly one commit"
    );
    assert_eq!(entries[0]["sequence"].as_u64().unwrap(), 0);
}

// ========================================================================
// Tests — error paths (no bootstrap needed)
// ========================================================================

/// GET /tip for unknown principal → 404.
#[tokio::test]
async fn tip_unknown_principal() {
    let app = build_router(test_state());

    let req = Request::builder()
        .uri("/tip?pr=nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// GET /e/{bad-digest} → 400 (malformed digest parse failure).
#[tokio::test]
async fn entity_bad_digest() {
    let app = build_router(test_state());

    let req = Request::builder()
        .uri("/e/not-a-valid-digest")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
        "bad digest should return 400 or 404, got {}",
        resp.status()
    );
}

/// POST /push with empty blob list → 400.
#[tokio::test]
async fn push_empty_blobs_rejected() {
    let app = build_router(test_state());
    let body = serde_json::json!({
        "principal_id": "test",
        "blobs": [],
    })
    .to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST /push with invalid base64url blob → 400.
#[tokio::test]
async fn push_bad_base64_rejected() {
    let app = build_router(test_state());
    let body = serde_json::json!({
        "principal_id": "test",
        "blobs": ["!!!not-base64!!!"],
    })
    .to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// POST /push with malformed JSON blob (valid base64, not JSON) → 422.
#[tokio::test]
async fn push_malformed_json_rejected() {
    let app = build_router(test_state());
    let garbage = Base64UrlUnpadded::encode_string(b"not json at all");
    let body = serde_json::json!({
        "principal_id": "test",
        "blobs": [garbage],
    })
    .to_string();

    let req = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Could be 400 (MalformedBlob) or 422 (Protocol) depending on parsing order.
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "malformed blob should return 400 or 422, got {status}"
    );
}
