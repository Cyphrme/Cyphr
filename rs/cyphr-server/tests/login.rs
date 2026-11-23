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

/// A push body: `principal_id` and `bundle` in the wire form (SPEC 4.6.2).
fn push_body(principal_id: &str, bundle: &cyphr::replay::WireBundle) -> String {
    let mut body = serde_json::to_value(bundle).expect("bundle serializes");
    body["principal_id"] = principal_id.into();
    body.to_string()
}

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

    cyphr::Key::new(
        alg.to_string(),
        coz::Thumbprint::from_bytes(tmb_bytes),
        pub_bytes,
    )
    .expect("key binds its tmb")
}

/// Build genesis from a golden fixture's `genesis_keys` array.
fn make_genesis(genesis_keys: &[serde_json::Value]) -> cyphr_storage::Genesis {
    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    if keys.len() == 1 {
        cyphr_storage::Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        cyphr_storage::Genesis::Disclosed(keys)
    }
}

/// A golden fixture's commit line as the wire bundle a client would push
/// (SPEC 4.6.2: `txs` by transaction, the keys they introduce in `keys`).
fn build_bundle(commit: &serde_json::Value) -> cyphr::replay::WireBundle {
    serde_json::from_value::<cyphr_storage::CommitEntry>(commit.clone())
        .expect("fixture commit line")
        .bundle()
        .expect("fixture bundle")
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

/// Assert `body` is a well-formed unsigned envelope
/// (`docs/specs/http-envelope.md`) and return its `payload` for further
/// field assertions -- migrated suites read `payload.*`, never top-level
/// fields (`[envelope-r-migration]`). Error bodies (`{"error": ...}`) are
/// NOT enveloped (`[envelope-r-error]`) and must never be passed here.
fn envelope_payload(body: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(
        body["v"],
        serde_json::json!(1),
        "response must carry envelope v=1: {body:?}"
    );
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("unsigned"),
        "an unattested response must be explicitly unsigned, not merely missing a signature: \
         {body:?}"
    );
    &body["payload"]
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

/// Bootstrap a brand-new Active principal through the real `/push` wire
/// path: its genesis commit (SPEC 5.1), in which `genesis_name` creates
/// itself and `add_key`, so both keys are active and the principal is
/// loadable by the login handler. Returns the principal's id (its PG) in
/// the bare spelling.
async fn bootstrap_active_with_key(
    app: axum::Router,
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    add_key: &str,
) -> String {
    let key = |name: &str| {
        pool.get(name)
            .expect("key in pool")
            .key()
            .expect("pool key")
    };
    let mut principal = cyphr::Principal::implicit(key(genesis_name))
        .await
        .expect("genesis");
    let blobs = test_fixtures::bundle::genesis_bundle(
        &mut principal,
        pool.get(genesis_name).expect("genesis key in pool"),
        &[key(add_key)],
        1_700_000_000,
    )
    .await
    .expect("genesis commit");
    let principal_id = test_fixtures::bundle::genesis_id(&blobs).expect("PG");

    let body = push_body(&principal_id, &blobs);
    let (status, _) = post_json(app, "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap active principal push must succeed"
    );
    principal_id
        .split_once(':')
        .expect("an algorithm-labelled PG")
        .1
        .to_string()
}

/// Bootstrap a golden `lifecycle/` fixture so the login handler can load it:
/// its first commit is its genesis commit (what `resolve_genesis` recovers
/// an existing principal's genesis from), and the
/// fixture's own pre-signed transactions drive the real lifecycle
/// transition. Only reachable once the storage layer recognizes the
/// lifecycle transactions (see the module-level note).
async fn bootstrap_lifecycle(state: &AppState, fixture_name: &str) -> String {
    let fixture = load_golden("lifecycle", fixture_name);
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let principal_id = cyphr_storage::engine::genesis_principal_id(&make_genesis(genesis_keys))
        .expect("fixture genesis derives an id");

    for commit in fixture["commits"].as_array().unwrap() {
        state
            .engine
            .submit_commit(
                &principal_id,
                Some(make_genesis(genesis_keys)),
                &build_bundle(commit),
            )
            .await
            .expect("bootstrap lifecycle commit");
    }
    principal_id
}

/// Sign a fresh "self-revoke `signer_name`" commit onto `principal`. Mirrors
/// the common `sign_key_create_commit`'s shape (see that function for the
/// pattern), but for `key/revoke`: no new key is introduced, the signer revokes
/// itself (`rvk`, no `id` -- SPEC's self-revoke shape), so the mechanism
/// differs enough not to share a body with the create case.
async fn sign_key_revoke_commit<S: eml::Storage>(
    mut principal: cyphr::Principal<S>,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    rvk: i64,
) -> cyphr::replay::WireBundle {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let signer_tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");

    let pay_value = serde_json::json!({
        "alg": signer.alg,
        "now": rvk,
        "rvk": rvk,
        "tmb": signer_tmb_b64,
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let pay_vec = serde_json::to_vec(&pay_value).unwrap();

    let signer_prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("valid signer prv base64");
    let signer_pub =
        Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub base64");
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &signer.alg, &signer_prv, &signer_pub)
        .expect("signing supported for this algorithm");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).expect("czd for this algorithm");

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, None)
        .expect("key/revoke should verify against the starting principal state");

    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&signer.alg, &signer_prv, &signer_pub, &signer_tmb),
            rvk,
            "cyphr.me",
        )
        .await
        .expect("commit should finalize");

    let commit = principal.commits().last().expect("the new commit");
    cyphr::replay::WireBundle::of_commit(commit).expect("the new commit's bundle")
}

/// Bootstrap a principal with two active keys (`golden` + `revoked_key`)
/// through the real `/push` wire path, then genuinely revoke `revoked_key`
/// via a real, separately-signed `key/revoke` commit submitted through the
/// real storage path -- so the login attempt against it exercises a key
/// that really was active in this exact principal and really was revoked,
/// not a key that was merely never introduced.
async fn bootstrap_active_then_revoke(
    state: &Arc<AppState>,
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    revoked_key: &str,
) -> String {
    let principal_id =
        bootstrap_active_with_key(build_router(state.clone()), pool, genesis_name, revoked_key)
            .await;
    let principal_id = principal_id.as_str();

    let genesis = state
        .engine
        .resolve_genesis(principal_id, &[])
        .await
        .expect("resolve genesis");
    let principal = state
        .engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load principal")
        .detach()
        .await
        .expect("detach principal");
    let blobs = sign_key_revoke_commit(principal, pool, revoked_key, 1_700_000_100).await;
    state
        .engine
        .submit_commit(principal_id, None, &blobs)
        .await
        .expect("submit the revoke commit");
    principal_id.to_string()
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
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();

    let app = build_router(state.clone());
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid timestamp login must succeed: {json:?}"
    );
    let payload = envelope_payload(&json);
    let token = payload["token"].as_str().expect("token in response");

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
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
    let app = build_router(state.clone());

    let (cs, cj) = post_json(app.clone(), "/auth/challenge", String::new()).await;
    assert_eq!(cs, StatusCode::OK);
    let challenge_payload = envelope_payload(&cj);
    let challenge = challenge_payload["challenge"]
        .as_str()
        .expect("challenge issued")
        .to_string();

    let body = login_body(
        &pool,
        "golden",
        AUDIENCE,
        Some(pid),
        Some(&challenge),
        now_secs(),
    );
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid challenge login must succeed: {json:?}"
    );
    let payload = envelope_payload(&json);
    assert!(
        payload["token"].as_str().is_some(),
        "a token must be issued"
    );
}

// ========================================================================
// Replay defenses
// ========================================================================

/// A consumed challenge cannot be replayed.
// @docket: signon-replay-bound :: scripts/docket-run signon-replay-bound
#[tokio::test]
async fn login_rejects_replayed_challenge() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
    let app = build_router(state.clone());

    let (_, cj) = post_json(app.clone(), "/auth/challenge", String::new()).await;
    let challenge = envelope_payload(&cj)["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let body = login_body(
        &pool,
        "golden",
        AUDIENCE,
        Some(pid),
        Some(&challenge),
        now_secs(),
    );

    let (first, _) = post_json(app.clone(), "/auth/login", body.clone()).await;
    assert_eq!(first, StatusCode::OK, "first use of the challenge succeeds");

    let (second, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        second,
        StatusCode::UNAUTHORIZED,
        "a replayed challenge must be rejected"
    );
}

/// A timestamp far outside the acceptance window is rejected.
#[tokio::test]
async fn login_rejects_out_of_window_timestamp() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
    let app = build_router(state);

    let stale = now_secs() - 3600;
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, stale);
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an out-of-window timestamp must be rejected"
    );
}

// ========================================================================
// Audience binding
// ========================================================================

/// A login for a different audience (the relay attack) is rejected.
// @docket: signon-audience-binding :: scripts/docket-run signon-audience-binding
#[tokio::test]
async fn login_rejects_mismatched_audience() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
    let app = build_router(state);

    let body = login_body(&pool, "golden", "evil.example", Some(pid), None, now_secs());
    let (_status, json) = post_json(app, "/auth/login", body).await;
    let err = json["payload"]["error"]
        .as_str()
        .or_else(|| json["error"].as_str())
        .unwrap_or("");
    assert!(
        err.contains("audience"),
        "the rejection must be a distinct audience error, not a generic one: {json:?}"
    );
}

/// A login naming no audience at all is rejected distinctly.
#[tokio::test]
async fn login_rejects_missing_audience() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
    let app = build_router(state);

    let body = login_body(&pool, "golden", "", Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a login naming no audience must be rejected"
    );
    let err = json["payload"]["error"]
        .as_str()
        .or_else(|| json["error"].as_str())
        .unwrap_or("");
    assert!(
        err.contains("audience"),
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
    bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let app = build_router(state);

    let body = login_body(&pool, "golden", AUDIENCE, None, None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a login without a claimed principal must reject"
    );
}

/// The key-sharing ambiguity: the same key+signature is accepted for the
/// principal it is active in, but rejected for a different claimed principal
/// that does not have it -- the server never infers the principal from the
/// thumbprint.
// @docket: signon-claimed-principal :: scripts/docket-run signon-claimed-principal
#[tokio::test]
async fn login_binds_key_to_claimed_principal_not_thumbprint() {
    let state = login_state();
    let pool = load_pool();

    // P_other genuinely has key_a active; P_claimed (alice + key_b) does not.
    // Distinct genesis keys, because a principal's id is derived from its
    // genesis.
    let other =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let claimed =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "alice", "key_b").await;
    let (other, claimed) = (other.as_str(), claimed.as_str());

    // key_a claiming P_other: accepted (key_a is active there).
    let ok_body = login_body(&pool, "key_a", AUDIENCE, Some(other), None, now_secs());
    let (ok_status, _) = post_json(build_router(state.clone()), "/auth/login", ok_body).await;
    assert_eq!(
        ok_status,
        StatusCode::OK,
        "key_a is active in P_other, so login there succeeds"
    );

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
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let pid = pid.as_str();
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
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an invalid signature must be rejected"
    );
}

// ========================================================================
// Malformed bodies
// ========================================================================

/// A login (or push) body with a wrong-typed field is refused 400 and the
/// refusal does not echo the field's value: serde's and axum's own texts
/// quote it. Covers the handler's body parse, the payload schema parse and
/// the shared JSON extractor. Turns red if any of the three reflects it.
#[tokio::test]
async fn malformed_login_bodies_do_not_echo_values() {
    let app = build_router(login_state());
    for (path, body) in [
        ("/auth/login", r#"{"pay":{},"sig":424242424242}"#),
        (
            "/auth/login",
            r#"{"pay":{"tmb":424242424242},"sig":"AAAA"}"#,
        ),
        ("/push", r#"{"principal_id":424242424242}"#),
    ] {
        let (status, reply) = post_json(app.clone(), path, body.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {body}: {reply:?}");
        assert!(
            !reply.to_string().contains("424242424242"),
            "{path} echoed the value: {reply:?}"
        );
    }
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

    let body = login_body(
        &pool,
        "golden",
        AUDIENCE,
        Some("no-such-principal"),
        None,
        now_secs(),
    );
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login for an unknown principal must reject"
    );
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
    let pid = bootstrap_lifecycle(&state, "freeze_create_transitions_to_frozen").await;
    let pid = pid.as_str();

    // The reconstructed principal is genuinely Frozen (real state, real path).
    let genesis = state
        .engine
        .resolve_genesis(pid, &[])
        .await
        .expect("resolve genesis");
    let principal = state
        .engine
        .load_principal(pid, genesis)
        .await
        .expect("load principal");
    assert_eq!(
        principal.lifecycle_state(),
        cyphr::lifecycle::LifecycleState::Frozen,
        "the bootstrapped principal must be genuinely Frozen via the real transaction path"
    );

    let app = build_router(state);
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login against a Frozen principal must reject"
    );
}

/// Login against a genuinely Deleted principal is rejected.
///
/// Built the same way via a real `principal/delete` transaction, with the
/// reconstructed lifecycle state asserted Deleted before the login attempt.
#[tokio::test]
async fn login_rejects_deleted_principal() {
    let state = login_state();
    let pool = load_pool();
    let pid = bootstrap_lifecycle(&state, "principal_delete_transitions_to_deleted").await;
    let pid = pid.as_str();

    let genesis = state
        .engine
        .resolve_genesis(pid, &[])
        .await
        .expect("resolve genesis");
    let principal = state
        .engine
        .load_principal(pid, genesis)
        .await
        .expect("load principal");
    assert_eq!(
        principal.lifecycle_state(),
        cyphr::lifecycle::LifecycleState::Deleted,
        "the bootstrapped principal must be genuinely Deleted via the real transaction path"
    );

    let app = build_router(state);
    let body = login_body(&pool, "golden", AUDIENCE, Some(pid), None, now_secs());
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login against a Deleted principal must reject"
    );
}

// ========================================================================
// Revoked key (distinct from a key unknown to the claimed principal: this
// key WAS active in this exact principal and was genuinely revoked from it)
// ========================================================================

/// Login with a key that was genuinely revoked *from the claimed principal*
/// is rejected -- distinct from `login_binds_key_to_claimed_principal_not_thumbprint`,
/// which tests a key active in a *different* principal. The principal here
/// keeps one other active key (`golden`, so it stays Active, not Dead),
/// built via a real implicit genesis, a real `key/create` for `key_a`, and
/// a real, separately-signed `key/revoke` self-revoking `key_a` -- all
/// through the full storage path.
// @docket: signon-key-active-in-principal :: scripts/docket-run signon-key-active-in-principal
#[tokio::test]
async fn login_rejects_key_revoked_in_claimed_principal() {
    let state = login_state();
    let pool = load_pool();
    let pid = bootstrap_active_then_revoke(&state, &pool, "golden", "key_a").await;
    let pid = pid.as_str();

    let genesis = state
        .engine
        .resolve_genesis(pid, &[])
        .await
        .expect("resolve genesis");
    let principal = state
        .engine
        .load_principal(pid, genesis)
        .await
        .expect("load principal");
    assert!(
        !principal.is_key_active(&pool.get("key_a").unwrap().compute_tmb().unwrap()),
        "key_a must be genuinely revoked (not merely absent) in the bootstrapped principal"
    );

    let app = build_router(state);
    // key_a is the key that was revoked; golden remains active.
    let body = login_body(&pool, "key_a", AUDIENCE, Some(pid), None, now_secs());
    let (status, json) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a key genuinely revoked from the claimed principal must be rejected: {json:?}"
    );
}

/// `signer` creates `new_key` on `principal` and returns the commit's push
/// body under `id`.
async fn create_key_push(
    principal: &mut cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key: &str,
    now: i64,
    id: &str,
) -> String {
    let signer = pool.get(signer_name).expect("signer in pool");
    let new = pool.get(new_key).expect("new key in pool").key().expect("key");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg,
        "id": new.tmb().to_b64(),
        "now": now,
        "tmb": signer.compute_tmb_b64().expect("signer tmb"),
        "typ": "cyphr.me/cyphr/key/create",
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &prv, &pub_key).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(new))
        .expect("key/create applies");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &prv,
                &pub_key,
                &signer.compute_tmb().expect("signer tmb"),
            ),
            now,
            "cyphr.me",
        )
        .await
        .expect("finalize");
    let bundle = test_fixtures::bundle::last_commit_bundle(principal).expect("bundle");
    push_body(id, &bundle)
}

/// Backs SPEC 17.2 ("Principal lifecycle state is Active (reject Frozen,
/// Deleted, Errored, etc.)"): a principal in Error by a fork, two commits
/// on each branch, one branch per genesis key, refuses a login by either
/// key. Turns red if login consults only the lifecycle base state, which
/// stays Active under a fork. End to end: yes.
#[tokio::test]
async fn login_rejects_errored_principal() {
    let state = login_state();
    let pool = load_pool();
    let app = build_router(state.clone());
    let (golden, eve) = ("golden", "eve_ed25519");

    let key = |name: &str| pool.get(name).expect("key in pool").key().expect("key");
    let mut shared = cyphr::Principal::implicit(key(golden))
        .await
        .expect("genesis");
    let genesis = test_fixtures::bundle::genesis_bundle(
        &mut shared,
        pool.get(golden).expect("golden"),
        &[key(eve)],
        1_700_000_000,
    )
    .await
    .expect("genesis commit");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("PG");
    let (status, _) = post_json(app.clone(), "/push", push_body(&id, &genesis)).await;
    assert_eq!(status, StatusCode::CREATED, "genesis");

    // Branch A is golden's, branch B is eve's; each gets two commits.
    let mut a = shared.fork().await.expect("fork");
    let mut b = shared.fork().await.expect("fork");
    let a1 = create_key_push(&mut a, &pool, golden, "key_a", 1_700_000_003, &id).await;
    let b1 = create_key_push(&mut b, &pool, eve, "key_b", 1_700_000_004, &id).await;
    let b2 = create_key_push(&mut b, &pool, eve, "carol", 1_700_000_005, &id).await;
    let a2 = create_key_push(&mut a, &pool, golden, "bob", 1_700_000_006, &id).await;
    let mut statuses = Vec::new();
    for body in [a1, b1, b2, a2] {
        statuses.push(post_json(app.clone(), "/push", body).await.0);
    }
    assert_eq!(
        statuses,
        [
            StatusCode::CREATED,
            StatusCode::CONFLICT,
            StatusCode::CREATED,
            StatusCode::CONFLICT
        ],
        "A, B (rival), B2 (resolves for B), A2 (rival)"
    );
    let bare = id.split_once(':').expect("labelled PG").1;
    assert!(
        state.engine.is_errored(bare).await.expect("verdict"),
        "both branches extended: Error"
    );

    for signer in [golden, eve] {
        let body = login_body(&pool, signer, AUDIENCE, Some(bare), None, now_secs());
        let (status, json) = post_json(app.clone(), "/auth/login", body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{signer}: an Errored principal must refuse login: {json:?}"
        );
    }
}

// ========================================================================
// Sign-on hardening (SO1)
// ========================================================================

/// Backs: one principal has one token subject. A login claiming the bare
/// spelling and one claiming the algorithm-labelled spelling of the same
/// identity both succeed and mint tokens naming the same subject. Turns
/// red if: `parsed.pr` reaches `issue_login_token` as typed, giving a relying
/// party two account rows for one identity. A no-op that canonicalizes
/// only one flow (or lowercases) still fails the equality. End to end: yes.
#[tokio::test]
async fn token_subject_is_one_whatever_spelling_logged_in() {
    let state = login_state();
    let pool = load_pool();
    let bare =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let labelled = format!("SHA-256:{bare}");

    let mut subjects = Vec::new();
    for spelling in [bare.as_str(), labelled.as_str()] {
        let body = login_body(&pool, "golden", AUDIENCE, Some(spelling), None, now_secs());
        let (status, json) = post_json(build_router(state.clone()), "/auth/login", body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "login under {spelling} must succeed (same identity): {json:?}"
        );
        let token = envelope_payload(&json)["token"].as_str().expect("token");
        let claims = state
            .identity
            .as_ref()
            .unwrap()
            .verify_token(token, now_secs())
            .expect("issued token verifies");
        subjects.push(claims.pr);
    }
    assert_eq!(
        subjects[0], subjects[1],
        "two spellings of one principal produced two token subjects"
    );
}

/// Backs: signon-honest-refusal. A server that holds a signing key but no
/// audience cannot complete any login (login answers "not configured"), so
/// it must not hand out a challenge a login can never redeem, and must
/// refuse both steps alike. Turns red if: `challenge` checks the identity
/// only and issues a nonce (200) while `login` refuses. A no-op that makes
/// challenge fail with a different status/body than login still fails the
/// equality. End to end: yes.
#[tokio::test]
async fn login_and_challenge_refuse_alike_without_audience() {
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
        audience: None,
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    let state = Arc::new(AppState::new(config).expect("open audience-less AppState"));

    let pool = load_pool();
    let body = login_body(&pool, "golden", AUDIENCE, Some("any"), None, now_secs());
    let (login_status, login_json) =
        post_json(build_router(state.clone()), "/auth/login", body).await;
    let (challenge_status, challenge_json) =
        post_json(build_router(state), "/auth/challenge", String::new()).await;

    assert!(
        !login_status.is_success(),
        "premise: a server with no audience cannot log anyone in: {login_json:?}"
    );
    assert_eq!(
        challenge_status, login_status,
        "challenge must refuse with login's status: {challenge_json:?}"
    );
    assert_eq!(
        challenge_json, login_json,
        "challenge must refuse with login's body"
    );
}

/// Backs: signon-replay-bound (window arm), future side. A timestamp as far
/// ahead of server time as the stale one is behind is refused too: the
/// window is two-sided. Turns red if: the bound is one-sided (only
/// `server - client` is checked), letting a pre-dated signature live for
/// hours. Characterization (green today); the existing stale-timestamp test
/// covers only the past side. End to end: yes.
#[tokio::test]
async fn login_rejects_future_dated_timestamp() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let app = build_router(state);

    let future = now_secs() + 3600;
    let body = login_body(&pool, "golden", AUDIENCE, Some(&pid), None, future);
    let (status, _) = post_json(app, "/auth/login", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a future-dated timestamp outside the window must be rejected"
    );
}

// ========================================================================
// Sign-on typ and role separation (SPEC 17.2: both flows share one typ,
// `<audience>/cyphr/auth/login`; the challenge field tells them apart)
// ========================================================================

/// Sign a login-shaped payload under an arbitrary `typ`, so tests can vary
/// exactly the field the exact-match rule judges.
fn login_body_typ(
    pool: &test_fixtures::Pool,
    signer_name: &str,
    typ: &str,
    pr: &str,
    challenge: Option<&str>,
    now: i64,
) -> String {
    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv")).unwrap();
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).unwrap();

    let mut pay = coz::Pay::new();
    pay.alg = Some(signer.alg.clone());
    pay.now = Some(now);
    pay.tmb = Some(signer.compute_tmb().expect("signer tmb"));
    pay.typ = Some(typ.to_string());
    pay.extra
        .insert("pr".to_string(), serde_json::Value::String(pr.into()));
    if let Some(c) = challenge {
        pay.extra
            .insert("challenge".to_string(), serde_json::Value::String(c.into()));
    }
    let pay_bytes = serde_json::to_vec(&pay).unwrap();
    let (sig, _cad) = coz::sign_json(&pay_bytes, &signer.alg, &prv, &pub_key).expect("sign");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).unwrap(),
        sig,
    })
    .unwrap()
}

/// Backs: a sign-on statement is accepted only under exactly the typ it was
/// signed for, `<server audience>/cyphr/auth/login`. Turns red if the typ
/// match loosens to a prefix/suffix/contains test: a foreign audience, a
/// trailing segment, a leading segment, or no audience then yields a token.
/// The control (exact typ accepted) stops a reject-everything no-op.
/// Characterization (green). End to end: yes.
#[tokio::test]
async fn login_typ_is_matched_exactly() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;

    let exact = format!("{AUDIENCE}/cyphr/auth/login");
    let (status, json) = post_json(
        build_router(state.clone()),
        "/auth/login",
        login_body_typ(&pool, "golden", &exact, &pid, None, now_secs()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: exact typ accepted: {json:?}"
    );

    for typ in [
        "evil.example/cyphr/auth/login".to_string(),
        format!("{AUDIENCE}/cyphr/auth/login/extra"),
        format!("sub/{AUDIENCE}/cyphr/auth/login"),
        "/cyphr/auth/login".to_string(),
        format!("{AUDIENCE}/cyphr/auth/logout"),
    ] {
        let (status, json) = post_json(
            build_router(state.clone()),
            "/auth/login",
            login_body_typ(&pool, "golden", &typ, &pid, None, now_secs()),
        )
        .await;
        assert!(
            !status.is_success() && json["payload"]["token"].is_null(),
            "typ {typ:?} must not be accepted as this server's login: {status} {json:?}"
        );
    }
}

/// Backs: a statement carrying a challenge is accepted only through
/// challenge-response, once. Turns red if a challenge-bearing statement can
/// be re-presented (a consumed challenge, or one this server never issued)
/// and accepted as a timestamp login because its `now` is in the window.
/// Characterization (green; the flow is chosen by the challenge field's
/// presence). End to end: yes.
#[tokio::test]
async fn cross_flow_challenge_statement_never_passes_as_timestamp() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let typ = format!("{AUDIENCE}/cyphr/auth/login");

    let (_, cj) = post_json(
        build_router(state.clone()),
        "/auth/challenge",
        String::new(),
    )
    .await;
    let challenge = envelope_payload(&cj)["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let body = login_body_typ(&pool, "golden", &typ, &pid, Some(&challenge), now_secs());

    let (first, _) = post_json(build_router(state.clone()), "/auth/login", body.clone()).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "control: challenge flow succeeds once"
    );
    let (replay, json) = post_json(build_router(state.clone()), "/auth/login", body).await;
    assert_eq!(
        replay,
        StatusCode::UNAUTHORIZED,
        "a consumed challenge statement, in-window, must not pass as a timestamp login: {json:?}"
    );

    let forged = login_body_typ(
        &pool,
        "golden",
        &typ,
        &pid,
        Some("never-issued"),
        now_secs(),
    );
    let (status, json) = post_json(build_router(state), "/auth/login", forged).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a timestamp login carrying an unissued challenge must be refused: {json:?}"
    );
}

/// Backs: role separation for the roles that exist in code today (bearer
/// token, naked revoke; the transport binding and pairing have no code yet
/// and are not testable). A statement signed in another role is never a
/// login, and a login is never accepted in another role. Turns red if
/// `/auth/login` accepts a `key/revoke` statement or a server-minted bearer
/// token, or `/revoke` accepts a login (the key then dies). Characterization
/// (green). End to end: yes.
#[tokio::test]
async fn login_role_is_not_interchangeable_with_other_statements() {
    let state = login_state();
    let pool = load_pool();
    let pid =
        bootstrap_active_with_key(build_router(state.clone()), &pool, "golden", "key_a").await;
    let login_typ = format!("{AUDIENCE}/cyphr/auth/login");

    // Other roles presented as a login.
    let revoke_as_login = login_body_typ(
        &pool,
        "golden",
        "cyphr.me/cyphr/key/revoke",
        &pid,
        None,
        now_secs(),
    );
    let (status, json) =
        post_json(build_router(state.clone()), "/auth/login", revoke_as_login).await;
    assert!(
        !status.is_success() && json["payload"]["token"].is_null(),
        "a key/revoke statement must not be accepted as a login: {status} {json:?}"
    );
    let token = state
        .identity
        .as_ref()
        .unwrap()
        .issue_login_token(
            pid.as_str(),
            &pool.get("golden").unwrap().compute_tmb().unwrap(),
            vec!["read".into()],
            now_secs(),
            300,
            None,
        )
        .expect("issue token");
    let (status, json) = post_json(build_router(state.clone()), "/auth/login", token).await;
    assert!(
        !status.is_success() && json["payload"]["token"].is_null(),
        "a bearer token must not be accepted as a login: {status} {json:?}"
    );

    // A login presented as a naked revoke (with the key disclosed so only
    // the typ can stop it).
    let golden = pool.get("golden").unwrap();
    let mut login: serde_json::Value = serde_json::from_str(&login_body_typ(
        &pool,
        "golden",
        &login_typ,
        &pid,
        None,
        now_secs(),
    ))
    .unwrap();
    login["pay"]["rvk"] = serde_json::json!(now_secs());
    login.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({ "alg": golden.alg, "pub": golden.pub_key }),
    );
    let (status, json) = post_json(build_router(state.clone()), "/revoke", login.to_string()).await;
    assert!(
        !status.is_success(),
        "a login must not act as a naked revoke: {status} {json:?}"
    );

    // Control: the key is still alive and the login role still works.
    let (status, json) = post_json(
        build_router(state),
        "/auth/login",
        login_body_typ(&pool, "golden", &login_typ, &pid, None, now_secs()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the golden key must not be dead: {json:?}"
    );
}
