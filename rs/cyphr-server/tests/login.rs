//! End-to-end tests for the login flows (SPEC.md 17.2) over real HTTP.
//!
//! Both flows and the full rejection matrix are exercised against a running
//! axum router (via `tower::ServiceExt::oneshot`, no TCP bind). Principals
//! are built through the real write path so the login handler reconstructs
//! them exactly as in production (genesis auto-detected from the stored
//! commit's embedded key). The Frozen and Deleted cases drive real
//! `freeze/create` and `principal/delete` transactions through the full
//! storage path and assert the reconstructed lifecycle state before the
//! login attempt.

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
/// commit's raw coz blob bytes, wire-ready for `submit_commit`. Mirrors the
/// helper of the same name in tests/e2e.rs.
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
        .finalize_with_arrow(&signer.alg, &signer_prv, &signer_pub, &signer_tmb, now, "cyphr.me")
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

// ========================================================================
// Login-specific helpers
// ========================================================================

const AUDIENCE: &str = "cyphr.me";

/// An `AppState` configured for login: a fresh Ed25519 signing identity and
/// an audience, over a temporary database.
fn login_state() -> Arc<AppState> {
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
        data_dir: temp_dir.path().to_path_buf(),
        signing_key_path: Some(key_path),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("open login AppState"))
}

/// Current wall-clock Unix seconds, for signing timestamp-flow logins the
/// server will accept as in-window.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Sign a login envelope with a pool key, returning the JSON request body.
///
/// `audience` becomes the login `typ`'s authority segment (pass "" to name
/// no audience). `claimed_pr` is the principal the signer claims (`None`
/// omits it entirely). `challenge`, when present, selects the
/// challenge-response flow.
fn login_body(
    pool: &test_fixtures::Pool,
    signer_name: &str,
    audience: &str,
    claimed_pr: Option<&str>,
    challenge: Option<&str>,
    now: i64,
) -> String {
    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let tmb = signer.compute_tmb().expect("signer tmb");

    let mut pay = coz::Pay::new();
    pay.alg = Some(signer.alg.clone());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(format!("{audience}/cyphr/auth/login"));
    if let Some(pr) = claimed_pr {
        pay.extra
            .insert("pr".to_string(), serde_json::Value::String(pr.into()));
    }
    if let Some(c) = challenge {
        pay.extra
            .insert("challenge".to_string(), serde_json::Value::String(c.into()));
    }

    let pay_bytes = serde_json::to_vec(&pay).unwrap();
    let (sig, _cad) = coz::sign_json(&pay_bytes, &signer.alg, &prv, &pub_key).expect("sign login");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).unwrap(),
        sig,
    })
    .unwrap()
}

/// POST a JSON body and return the status plus parsed JSON response.
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

/// Bootstrap a brand-new Active principal (genesis `golden`, plus one added
/// key) through the real `/push` wire path, so `golden` and the added key
/// are both active and the principal is loadable by the login handler.
async fn bootstrap_active_with_key(
    app: axum::Router,
    pool: &test_fixtures::Pool,
    principal_id: &str,
    add_key: &str,
) {
    let golden = pool.get("golden").expect("golden in pool");
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
    let mut blobs = sign_key_create_commit(principal, pool, "golden", add_key, 1_700_000_000);

    // Embed genesis on the closing commit/create -- the wire contract for a
    // brand-new principal's genesis auto-detection.
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

    let body = serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string();
    let (status, _) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap active principal push must succeed");
}

/// Bootstrap a golden `lifecycle/` fixture so the login handler can load it:
/// the genesis key is embedded on the stored `commit/create` cozy (what
/// `resolve_genesis` recovers an existing principal's genesis from), and the
/// fixture's own pre-signed transactions drive the real lifecycle
/// transition. Only reachable once the storage layer recognizes the
/// lifecycle transactions (see the module-level note).
async fn bootstrap_lifecycle(state: &AppState, principal_id: &str, fixture_name: &str) {
    let fixture = load_golden("lifecycle", fixture_name);
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let gk = &genesis_keys[0];

    for commit in fixture["commits"].as_array().unwrap() {
        let mut blobs = build_raw_blobs(commit);
        for blob in blobs.iter_mut() {
            let mut value: serde_json::Value = serde_json::from_slice(blob).unwrap();
            let typ = value["pay"]["typ"].as_str().unwrap_or("");
            if typ.ends_with("/commit/create") {
                value.as_object_mut().unwrap().insert(
                    "key".to_string(),
                    serde_json::json!({ "alg": gk["alg"], "pub": gk["pub"], "tmb": gk["tmb"] }),
                );
                *blob = serde_json::to_vec(&value).unwrap();
            }
        }
        let slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        state
            .engine
            .submit_commit(principal_id, Some(make_genesis(genesis_keys)), &slices)
            .await
            .expect("bootstrap lifecycle commit");
    }
}

// ========================================================================
// Happy paths
// ========================================================================

/// Timestamp flow: a golden-signed login for an Active principal issues a
/// bearer token that verifies as a genuine token for that principal.
#[tokio::test]
async fn login_timestamp_flow_issues_valid_token() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-ts-active";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;

    let app = build_router(state.clone());
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;

    assert_eq!(status, StatusCode::OK, "valid timestamp login must succeed: {json:?}");
    let token = json["token"].as_str().expect("token in response");

    let claims = state
        .identity
        .as_ref()
        .unwrap()
        .verify_token(token, now_secs())
        .expect("issued token must verify as a genuine bearer token");
    assert_eq!(claims.pr, pid, "token must bind the logged-in principal");
}

/// Challenge flow: fetch a challenge, sign it, receive a valid token.
#[tokio::test]
async fn login_challenge_flow_issues_valid_token() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-chal-active";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state.clone());

    let (cs, cj) = post_json(app.clone(), "/auth/challenge", String::new()).await;
    assert_eq!(cs, StatusCode::OK);
    let challenge = cj["challenge"].as_str().expect("challenge issued").to_string();

    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), Some(&challenge), now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::OK, "valid challenge login must succeed: {json:?}");
    assert!(json["token"].as_str().is_some(), "a token must be issued");
}

// ========================================================================
// Replay defenses
// ========================================================================

/// A consumed challenge cannot be replayed.
#[tokio::test]
async fn login_rejects_replayed_challenge() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-replay";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state.clone());

    let (_, cj) = post_json(app.clone(), "/auth/challenge", String::new()).await;
    let challenge = cj["challenge"].as_str().unwrap().to_string();
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), Some(&challenge), now_secs());

    let (first, _) = post_json(app.clone(), "/auth/login", body.clone()).await;
    assert_eq!(first, StatusCode::OK, "first use of the challenge succeeds");

    let (second, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "a replayed challenge must be rejected");
}

/// A timestamp far outside the acceptance window is rejected.
#[tokio::test]
async fn login_rejects_out_of_window_timestamp() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-window";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state);

    let stale = now_secs() - 3600;
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, stale);
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an out-of-window timestamp must be rejected");
}

// ========================================================================
// Audience binding
// ========================================================================

/// A login for a different audience (the relay attack) is rejected.
#[tokio::test]
async fn login_rejects_mismatched_audience() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-aud-mismatch";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state);

    let body = login_body(&pool, "golden", "evil.example", Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a login for another audience must be rejected");
    assert!(
        json["error"].as_str().unwrap_or("").contains("audience"),
        "the rejection must be a distinct audience error, not a generic one: {json:?}"
    );
}

/// A login naming no audience at all is rejected distinctly.
#[tokio::test]
async fn login_rejects_missing_audience() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-aud-missing";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state);

    let body = login_body(&pool, "golden", "", Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a login naming no audience must be rejected");
    assert!(
        json["error"].as_str().unwrap_or("").contains("audience"),
        "the rejection must name the audience gap: {json:?}"
    );
}

// ========================================================================
// Principal binding
// ========================================================================

/// The claimed principal must be named.
#[tokio::test]
async fn login_rejects_missing_principal_claim() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-no-pr";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state);

    let body = login_body(&pool, "golden", AUDIENCE, None, None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "a login without a claimed principal must reject");
}

/// The key-sharing ambiguity: the same key+signature is accepted for the
/// principal it is active in, but rejected for a different claimed principal
/// that does not have it -- the server never infers the principal from the
/// thumbprint.
#[tokio::test]
async fn login_binds_key_to_claimed_principal_not_thumbprint() {
    let state = login_state();
    let pool = load_pool();

    // P_other genuinely has key_a active; P_claimed (golden + key_b) does not.
    let other = "login-share-other";
    let claimed = "login-share-claimed";
    bootstrap_active_with_key(build_router(state.clone()), &pool, other, "key_a").await;
    bootstrap_active_with_key(build_router(state.clone()), &pool, claimed, "key_b").await;

    // key_a claiming P_other: accepted (key_a is active there).
    let ok_body = login_body(&pool, "key_a", AUDIENCE, Some(other), None, now_secs());
    let (ok_status, _) = post_json(build_router(state.clone()), "/auth/login", ok_body).await;
    assert_eq!(ok_status, StatusCode::OK, "key_a is active in P_other, so login there succeeds");

    // The same key_a signature claiming P_claimed: rejected -- key_a is not
    // an active key of the claimed principal, even though it is a valid
    // active key of another principal.
    let bad_body = login_body(&pool, "key_a", AUDIENCE, Some(claimed), None, now_secs());
    let (bad_status, _) = post_json(build_router(state), "/auth/login", bad_body).await;
    assert_eq!(
        bad_status,
        StatusCode::UNAUTHORIZED,
        "key_a is not active in the claimed principal, so this login must reject"
    );
}

// ========================================================================
// Signature
// ========================================================================

/// A tampered signed payload (pr unchanged so the principal still loads, but
/// the signature no longer matches) is rejected.
#[tokio::test]
async fn login_rejects_invalid_signature() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-badsig";
    bootstrap_active_with_key(build_router(state.clone()), &pool, pid, "key_a").await;
    let app = build_router(state);

    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    // Corrupt the detached signature without touching the payload.
    let mut value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sig = value["sig"].as_str().unwrap();
    let mut sig_bytes = Base64UrlUnpadded::decode_vec(sig).unwrap();
    sig_bytes[0] ^= 0x01;
    value["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&sig_bytes));
    let tampered = serde_json::to_string(&value).unwrap();

    let (status, _) = post_json(app, "/auth/login", tampered).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an invalid signature must be rejected");
}

// ========================================================================
// Unknown principal
// ========================================================================

/// Login for a principal the server has never seen is rejected with the same
/// 401 status as any other auth failure. The response body's message text
/// does currently differ by cause (unknown vs. known-but-inactive key) --
/// this test only asserts on status code, not message equality, and does not
/// claim the message text is generic; see ledger finding F28 for whether
/// existence-disclosure across the public route surface needs closing.
#[tokio::test]
async fn login_rejects_unknown_principal() {
    let state = login_state();
    let pool = load_pool();
    let app = build_router(state);

    let body = login_body(&pool, "golden", AUDIENCE, Some("no-such-principal"), None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "login for an unknown principal must reject");
}

// ========================================================================
// Lifecycle gate (real states via real transactions)
// ========================================================================

/// Login against a genuinely Frozen principal is rejected.
///
/// The principal is frozen by submitting a real `freeze/create` transaction
/// through the full storage path, then reconstructed by the login handler
/// from durable state -- its lifecycle state is asserted Frozen before the
/// login attempt, so the 401 is the lifecycle gate firing, not an incidental
/// failure.
#[tokio::test]
async fn login_rejects_frozen_principal() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-frozen";
    bootstrap_lifecycle(&state, pid, "freeze_create_transitions_to_frozen").await;

    // The reconstructed principal is genuinely Frozen (real state, real path).
    let genesis = state.engine.resolve_genesis(pid, &[]).await.expect("resolve genesis");
    let principal = state.engine.load_principal(pid, genesis).await.expect("load principal");
    assert_eq!(
        principal.lifecycle_state(),
        cyphr::lifecycle::LifecycleState::Frozen,
        "the bootstrapped principal must be genuinely Frozen via the real transaction path"
    );

    let app = build_router(state);
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "login against a Frozen principal must reject");
}

/// Login against a genuinely Deleted principal is rejected.
///
/// Built the same way via a real `principal/delete` transaction, with the
/// reconstructed lifecycle state asserted Deleted before the login attempt.
#[tokio::test]
async fn login_rejects_deleted_principal() {
    let state = login_state();
    let pool = load_pool();
    let pid = "login-deleted";
    bootstrap_lifecycle(&state, pid, "principal_delete_transitions_to_deleted").await;

    let genesis = state.engine.resolve_genesis(pid, &[]).await.expect("resolve genesis");
    let principal = state.engine.load_principal(pid, genesis).await.expect("load principal");
    assert_eq!(
        principal.lifecycle_state(),
        cyphr::lifecycle::LifecycleState::Deleted,
        "the bootstrapped principal must be genuinely Deleted via the real transaction path"
    );

    let app = build_router(state);
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "login against a Deleted principal must reject");
}
