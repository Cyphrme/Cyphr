//! Route-protection tests over real HTTP (ARCHITECT RULING R7).
//!
//! - `POST /push`: no bearer token is ever required -- a valid signed commit bundle is its own
//!   authorization, including a brand-new principal's genesis (`push_new_principal_happy_path` in
//!   `tests/e2e.rs` is the untouched empirical baseline for this). A bearer token is an OPTIONAL
//!   admission knob: absent or matching is always fine, present-but-mismatched is rejected.
//! - `GET /tip`, `GET /patch`, `GET /e/{digest}`: public reads with no bearer requirement at all
//!   (SPEC.md §13 -- witness registration via `GET /tip`, resync via `GET /patch`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ========================================================================
// Shared fixture helpers (mirrored from tests/e2e.rs and tests/login.rs,
// which are separate integration-test crates and cannot be imported here)
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
        tmb: coz::Thumbprint::from_bytes(tmb_bytes),
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
        let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(typ);

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
/// `signer_name` (must have a known private key in `pool`). Returns the new
/// commit's raw coz blob bytes (wire-ready for `submit_commit`) alongside
/// its `CommitEntry` -- the latter lets a caller replay this exact commit
/// onto a fresh `Principal` (via `cyphr_storage::load_principal_from_commits`)
/// to build a genuinely independent NEXT commit, since `Principal::clone()`
/// shares the same underlying durable commit log rather than deep-copying
/// it (two clones both trying to append "the next commit" collide on the
/// same leaf position instead of chaining).
fn sign_key_create_commit(
    mut principal: cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key_name: &str,
    now: i64,
) -> (Vec<Vec<u8>>, cyphr_storage::CommitEntry) {
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
    let blobs = new_commit
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
        .collect();

    (blobs, new_commit.clone())
}

/// Bootstrap a principal into the engine via the validated write path
/// (explicit genesis), submitting every commit in the fixture in order.
async fn bootstrap_principal(state: &AppState, principal_id: &str, fixture: &serde_json::Value) {
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        state
            .engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("bootstrap submit_commit failed");
    }
}

/// An `AppState` with a temporary database and no signing identity --
/// mirrors the no-auth-configured deployment shape.
fn test_state() -> Arc<AppState> {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config = ServerConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("failed to open AppState"))
}

/// An `AppState` with both a temp database and a configured signing
/// identity, for tests that mint bearer tokens for the `/push` admission
/// knob.
fn state_with_identity() -> Arc<AppState> {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let key_path = temp_dir.path().join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    let key_file = serde_json::json!({
        "alg": kp.alg.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
    });
    std::fs::write(&key_path, serde_json::to_vec(&key_file).unwrap()).unwrap();

    let config = ServerConfig {
        data_dir: temp_dir.path().join("data"),
        signing_key_path: Some(key_path),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("failed to open AppState with identity"))
}

/// Send a request and return its status plus parsed JSON body (empty body
/// parses as `Null`).
async fn send(req: Request<Body>, app: axum::Router) -> (StatusCode, serde_json::Value) {
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

/// Build a brand-new principal's genesis push HTTP body: the same wire
/// contract `push_new_principal_happy_path` (`tests/e2e.rs`) exercises --
/// a `key/create` closed by `commit/create` with the genesis key embedded
/// on the closing cozy. Shared by the admission-knob tests below, which
/// only differ in what (if any) bearer token they attach.
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
    let (mut blobs, _entry) = sign_key_create_commit(principal, pool, "golden", "key_a", now);

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

fn push_request(body: String, bearer: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body)).unwrap()
}

// ========================================================================
// /push admission knob (ARCHITECT RULING R7)
// ========================================================================

/// Current wall-clock Unix seconds -- matches `auth::server_now()`, which
/// `check_push_admission` uses to check token expiry. A token issued
/// against the fixture's fictional signing timestamps (e.g.
/// `1_700_000_000`) would already be expired by the time it is verified
/// against real server time, so admission-knob tests mint tokens against
/// this instead.
fn real_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A bearer token naming a DIFFERENT principal than the one being pushed
/// to is rejected -- the admission knob must not let a valid token for
/// one principal authorize a push under another's identity.
#[tokio::test]
async fn push_with_mismatched_token_pr_rejected() {
    let pool = load_pool();
    let principal_id = "push-admission-mismatch";
    let body = build_genesis_push_body(&pool, principal_id, 1_700_000_000);

    let state = state_with_identity();
    let token = state
        .identity
        .as_ref()
        .unwrap()
        .issue_token(
            "a-different-principal",
            vec!["write".to_string()],
            real_now(),
            300,
        )
        .expect("issue token");

    let app = build_router(state);
    let (status, json) = send(push_request(body, Some(&token)), app).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token naming a different principal must reject the push: {json:?}"
    );
}

/// A bearer token naming the SAME principal being pushed to is accepted:
/// the admission knob does not block a genuinely matching token.
#[tokio::test]
async fn push_with_matching_token_pr_succeeds() {
    let pool = load_pool();
    let principal_id = "push-admission-match";
    let body = build_genesis_push_body(&pool, principal_id, 1_700_000_000);

    let state = state_with_identity();
    let token = state
        .identity
        .as_ref()
        .unwrap()
        .issue_token(
            principal_id,
            vec!["read".to_string(), "write".to_string()],
            real_now(),
            300,
        )
        .expect("issue token");

    let app = build_router(state);
    let (status, json) = send(push_request(body, Some(&token)), app).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a token matching the target principal must not block the push: {json:?}"
    );
}

/// An already-existing principal (not a brand-new genesis) may push a
/// follow-up commit with NO bearer token at all -- the admission knob is
/// genuinely optional beyond the genesis-bootstrap case, not merely
/// untested by omission.
///
/// The principal is bootstrapped over real HTTP first (genesis
/// auto-detection, same wire contract as `push_new_principal_happy_path`
/// in `tests/e2e.rs`) rather than via the engine's explicit-genesis API:
/// `resolve_genesis`'s existing-principal branch re-derives genesis by
/// re-scanning the first STORED commit's own wire blobs for an embedded
/// key, which an explicit-genesis bootstrap never carries (that key is
/// supplied out-of-band instead) -- so only an HTTP-bootstrapped
/// principal is a valid target for a genesis-less follow-up push.
#[tokio::test]
async fn push_for_existing_principal_with_no_token_succeeds() {
    let pool = load_pool();
    let principal_id = "push-admission-existing-no-token";

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
    let (mut genesis_blobs, genesis_entry) =
        sign_key_create_commit(principal, &pool, "golden", "key_a", 1_700_000_000);
    let closing_idx = genesis_blobs.len() - 1;
    let mut closing: serde_json::Value =
        serde_json::from_slice(&genesis_blobs[closing_idx]).unwrap();
    closing.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": golden_key.alg,
            "pub": golden.pub_key,
            "tmb": Base64UrlUnpadded::encode_string(golden_key.tmb.as_bytes()),
        }),
    );
    genesis_blobs[closing_idx] = serde_json::to_vec(&closing).unwrap();
    let genesis_body = serde_json::json!({
        "principal_id": principal_id,
        "blobs": genesis_blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string();

    let state = test_state();
    let app = build_router(state);

    let (genesis_status, genesis_json) = send(push_request(genesis_body, None), app.clone()).await;
    assert_eq!(
        genesis_status,
        StatusCode::CREATED,
        "genesis bootstrap push must succeed: {genesis_json:?}"
    );

    // Follow-up commit for the now-existing principal: replay the
    // genesis commit onto a FRESH principal (a live clone of `principal`
    // would share the same durable commit log and collide on the same
    // leaf position rather than chain -- see `sign_key_create_commit`'s
    // doc comment). No embedded genesis key on this one (only a
    // genuinely new principal's wire blobs carry one), and no bearer
    // token.
    let replayed = cyphr_storage::load_principal_from_commits(
        cyphr_storage::Genesis::Implicit(golden_key),
        std::slice::from_ref(&genesis_entry),
    )
    .expect("replay the genesis commit onto a fresh principal");
    let (followup_blobs, _followup_entry) =
        sign_key_create_commit(replayed, &pool, "golden", "key_b", 1_700_000_100);
    let followup_body = serde_json::json!({
        "principal_id": principal_id,
        "blobs": followup_blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string();

    let (status, json) = send(push_request(followup_body, None), app).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a follow-up push for an existing principal must succeed with no token: {json:?}"
    );
}

// ========================================================================
// Public witness-read routes (SPEC.md §13): no bearer requirement at all
// ========================================================================

/// `GET /tip` succeeds with zero `Authorization` header -- SPEC's own
/// design for witness registration (`GET /tip?pr=...`), not an oversight.
#[tokio::test]
async fn tip_succeeds_with_no_bearer_token() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = "route-protection-tip-public";

    let state = test_state();
    bootstrap_principal(&state, principal_id, &fixture).await;
    let app = build_router(state);

    let req = Request::builder()
        .uri(format!("/tip?pr={principal_id}"))
        .body(Body::empty())
        .unwrap();
    assert!(
        !req.headers()
            .contains_key(axum::http::header::AUTHORIZATION),
        "test setup: this request must carry no Authorization header"
    );

    let (status, json) = send(req, app).await;
    assert_eq!(status, StatusCode::OK, "GET /tip must be public: {json:?}");
}

/// `GET /patch` succeeds with zero `Authorization` header -- SPEC's own
/// design for witness resync (`GET /patch`), not an oversight.
#[tokio::test]
async fn patch_succeeds_with_no_bearer_token() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = "route-protection-patch-public";

    let state = test_state();
    bootstrap_principal(&state, principal_id, &fixture).await;
    let app = build_router(state);

    let req = Request::builder()
        .uri(format!("/patch?pr={principal_id}"))
        .body(Body::empty())
        .unwrap();
    assert!(
        !req.headers()
            .contains_key(axum::http::header::AUTHORIZATION),
        "test setup: this request must carry no Authorization header"
    );

    let (status, json) = send(req, app).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /patch must be public: {json:?}"
    );
}

/// `GET /e/{digest}` is reachable with zero `Authorization` header: a
/// syntactically valid digest not present in the store returns the
/// route's normal not-found status, never a 401/403 auth rejection.
#[tokio::test]
async fn entity_succeeds_with_no_bearer_token() {
    let state = test_state();
    let app = build_router(state);

    let digest = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    let req = Request::builder()
        .uri(format!("/e/{digest}"))
        .body(Body::empty())
        .unwrap();
    assert!(
        !req.headers()
            .contains_key(axum::http::header::AUTHORIZATION),
        "test setup: this request must carry no Authorization header"
    );

    let (status, json) = send(req, app).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "GET /e/{{digest}} must be public: unknown digest is 404, never a 401/403 auth rejection: \
         {json:?}"
    );
}
