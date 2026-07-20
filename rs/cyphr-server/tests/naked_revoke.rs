//! Acceptance suite for the witness naked-revoke ingest path (SPEC.md §6.4).
//!
//! A **naked revoke** is a `key/revoke` coz signed *outside* a commit
//! (SPEC.md:1157-1179). A witness accepts one, verifies it against the named
//! principal's own keys, records a durable server-local observation *without
//! mutating PR*, and thereafter refuses the naked-revoked key at login. This
//! is the red acceptance surface for node N2; the implementation walk that
//! follows drives it green without weakening any assertion.
//!
//! ## Endpoint contract (this suite is the source of truth)
//!
//! The HTTP method/path and request body of the naked-revoke endpoint are
//! DELEGATED to the node (CAMPAIGN-IBC "Decision rights"), so this suite fixes
//! them and the implementation must match:
//!
//! - `POST /revoke`
//! - request body: `{ "principal_id": "<pr>", "coz": { "pay": {..}, "sig": "<b64url>", "key"?: {..}
//!   } }`. `principal_id` is the UNSIGNED target principal whose witness record is annotated
//!   (mirrors `PushRequest`, `routes.rs:42-49`); `coz` is the signed `key/revoke` envelope. The
//!   optional `key` slot carries a third party's own key so a signature made by a key the server
//!   does not otherwise hold can still be verified (the third-party path; see the third-party test
//!   below).
//! - on acceptance: a 2xx response (the envelope pattern -- signed if the server is an attestor,
//!   unsigned if keyless).
//!
//! ## Why every test drives the live HTTP endpoint
//!
//! An integration-test file is one binary: a reference to a not-yet-existing
//! symbol (`cyphr_server::revoke::…`) would fail the whole binary to compile,
//! so *no* test could exhibit its semantic red baseline. Every test therefore
//! goes through `build_router` + a real request and fails on SEMANTIC grounds
//! against the current tip -- the route 404s, or a would-be-revoked key still
//! logs in -- never on a missing symbol or a missing file.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use tempfile::TempDir;
use test_fixtures::Pool;

mod common;

/// The naked-revoke endpoint (see the module-level contract).
const REVOKE_URI: &str = "/revoke";

/// The audience keyed states name so their login route accepts logins.
const AUDIENCE: &str = "cyphr.me";

/// A fixed, valid `rvk`/`now` (positive, well under 2^53-1): the timestamp a
/// naked revoke declares. Reused so signatures are reproducible across a test.
const RVK: i64 = 1_700_000_000;

// ========================================================================
// State + bootstrap helpers
// ========================================================================

/// A keyed `AppState` (fresh Ed25519 signing identity, an audience) over
/// `data_dir`, reusing the signing key at `key_path`. Reusing the same
/// `key_path` across constructions is what lets the restart test rebuild the
/// *same* server over the same data dir.
fn keyed_state_at(data_dir: &Path, key_path: &Path) -> Arc<AppState> {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };
    Arc::new(AppState::new(config).expect("open keyed AppState"))
}

/// A fresh keyed state plus the `TempDir` backing it. Hold the guard for the
/// test's lifetime (dropping it deletes the on-disk store).
fn fresh_keyed_state() -> (Arc<AppState>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let state = keyed_state_at(&dir.path().join("data"), &key_path);
    (state, dir)
}

/// Bootstrap `pid` with genesis `golden` plus an added active key `key_a`,
/// both active, through the real `/push` wire path -- so `golden` and `key_a`
/// are genuinely active keys of this exact principal.
async fn bootstrap_golden_key_a(state: &Arc<AppState>, pool: &Pool, pid: &str) {
    let body = common::build_genesis_push_body(pool, pid, RVK);
    let (status, json) = common::post_json(build_router(state.clone()), "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap push must create the principal: {json:?}"
    );
}

// ========================================================================
// Coz + request builders
// ========================================================================

/// Sign `pay` with pool key `signer_name` and wrap it as a `{pay, sig}` coz
/// JSON value. Mirrors the payload shape of `tests/login.rs`'s
/// `sign_key_revoke_commit` but STOPS after `coz::sign_json` -- a naked revoke
/// is signed outside any commit, so none of the `begin_commit` /
/// `verify_and_apply` / `finalize_with_arrow` chain machinery runs (that would
/// mutate PR and defeat the PR-unchanged property).
fn sign_coz(pool: &Pool, signer_name: &str, pay: serde_json::Value) -> serde_json::Value {
    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let pay_vec = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, _cad) =
        coz::sign_json(&pay_vec, &signer.alg, &prv, &pub_key).expect("signing supported");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
    })
}

/// A self-signed naked-revoke coz: `signer_name` revokes *itself* (`pay.tmb`
/// is the signer's own thumbprint, `rvk` present, no `id`), the SPEC §6.4
/// self-revoke shape. `rvk` overridable to exercise the malformed-`rvk` matrix.
fn self_revoke_coz(pool: &Pool, signer_name: &str, rvk: serde_json::Value) -> serde_json::Value {
    let signer = pool.get(signer_name).expect("signer in pool");
    let tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");
    let pay = serde_json::json!({
        "alg": signer.alg,
        "now": rvk,
        "rvk": rvk,
        "tmb": tmb_b64,
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    sign_coz(pool, signer_name, pay)
}

/// A third-party naked revoke: an OUTSIDER key `outsider_name` (not a key of
/// the named principal) declares the principal's key `target_tmb_b64`
/// compromised. `pay.tmb` is the COMPROMISED key, but the signature is the
/// outsider's, so the outsider's own key is embedded in the `key` slot for the
/// server to verify against -- the only self-describing way a witness can
/// check a signature by a key it does not hold. The exact third-party
/// verification mechanism is spec-pending (#106); this encodes the natural
/// coz-shaped one.
fn third_party_revoke_coz(
    pool: &Pool,
    outsider_name: &str,
    target_tmb_b64: &str,
) -> serde_json::Value {
    let outsider = pool.get(outsider_name).expect("outsider in pool");
    let prv = Base64UrlUnpadded::decode_vec(outsider.prv.as_ref().expect("outsider prv"))
        .expect("outsider prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&outsider.pub_key).expect("outsider pub b64");
    let pay = serde_json::json!({
        "alg": outsider.alg,
        "now": RVK,
        "rvk": RVK,
        "tmb": target_tmb_b64,
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let pay_vec = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, _cad) =
        coz::sign_json(&pay_vec, &outsider.alg, &prv, &pub_key).expect("signing supported");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {
            "alg": outsider.alg,
            "pub": outsider.pub_key,
            "tmb": outsider.compute_tmb_b64().expect("outsider tmb"),
        },
    })
}

/// Flip one bit of a coz's detached signature, leaving the payload intact.
fn corrupt_sig(mut coz: serde_json::Value) -> serde_json::Value {
    let sig_b64 = coz["sig"].as_str().expect("sig present");
    let mut sig = Base64UrlUnpadded::decode_vec(sig_b64).expect("sig b64");
    sig[0] ^= 0x01;
    coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&sig));
    coz
}

/// The naked-revoke request body: the unsigned target `principal_id` plus the
/// signed `coz`.
fn revoke_body(principal_id: &str, coz: serde_json::Value) -> String {
    serde_json::json!({ "principal_id": principal_id, "coz": coz }).to_string()
}

// ========================================================================
// Login helpers (timestamp flow; ported from tests/login.rs:269-304, which is
// a separate integration crate and cannot be imported)
// ========================================================================

/// Current wall-clock Unix seconds, so a signed login `now` lands in-window.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A signed timestamp-flow login body for `signer_name` claiming principal
/// `claimed_pr`, naming `AUDIENCE`.
fn login_body(pool: &Pool, signer_name: &str, claimed_pr: &str, now: i64) -> String {
    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let tmb = signer.compute_tmb().expect("signer tmb");

    let mut pay = coz::Pay::new();
    pay.alg = Some(signer.alg.clone());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(format!("{AUDIENCE}/cyphr/auth/login"));
    pay.extra.insert(
        "pr".to_string(),
        serde_json::Value::String(claimed_pr.into()),
    );

    let pay_bytes = serde_json::to_vec(&pay).unwrap();
    let (sig, _cad) = coz::sign_json(&pay_bytes, &signer.alg, &prv, &pub_key).expect("sign login");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).unwrap(),
        sig,
    })
    .unwrap()
}

/// POST a login for `signer` claiming `pid` and return only the status.
async fn login_status(state: &Arc<AppState>, pool: &Pool, signer: &str, pid: &str) -> StatusCode {
    let body = login_body(pool, signer, pid, now_secs());
    let (status, _) = common::post_json(build_router(state.clone()), "/auth/login", body).await;
    status
}

// ========================================================================
// 1 -- Accept a valid self-signed naked revoke
// ========================================================================

/// A well-formed self-signed `key/revoke` coz for an active key of the named
/// principal, with a valid `rvk`, is accepted (2xx).
///
/// Red baseline: `POST /revoke` 404s -- there is no endpoint at this tip.
#[tokio::test]
async fn accepts_valid_self_signed_naked_revoke() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-accept";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = common::post_json(
        build_router(state.clone()),
        REVOKE_URI,
        revoke_body(pid, coz),
    )
    .await;
    assert!(
        status.is_success(),
        "a valid self-signed naked revoke must be accepted (2xx), got {status}: {json:?}"
    );
}

// ========================================================================
// 2 -- Reject malformed / mis-targeted revokes, each a distinct 4xx (not 500)
// ========================================================================
//
// Each rejection asserts a client error (4xx: excludes both a 2xx accept and a
// 5xx panic/fault) AND a populated `{"error": …}` body. The error body is the
// red-maker: at this tip every case 404s with an EMPTY body (a route miss),
// so the error-field assertion fails -- the request is not being distinctly
// rejected, merely unrouted.

/// Assert the response is a distinct client-error rejection with a described
/// cause -- never a 2xx accept, a 5xx fault, or an empty route-miss.
fn assert_rejected(status: StatusCode, json: &serde_json::Value, case: &str) {
    assert!(
        status.is_client_error(),
        "{case}: must be a 4xx rejection (not a 2xx accept, not a 5xx fault), got {status}: \
         {json:?}"
    );
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        !err.is_empty(),
        "{case}: rejection must name its cause in an {{\"error\": …}} body, got {json:?}"
    );
}

async fn post_revoke(
    state: &Arc<AppState>,
    pid: &str,
    coz: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    common::post_json(
        build_router(state.clone()),
        REVOKE_URI,
        revoke_body(pid, coz),
    )
    .await
}

/// Each out-of-range `rvk` (zero, negative, ≥ 2^53-1, non-integer) is a
/// distinct rejection. SPEC.md:1152-1155: `rvk` must be a positive integer
/// less than 2^53-1.
#[tokio::test]
async fn rejects_malformed_rvk() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-bad-rvk";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let cases = [
        ("rvk = 0", serde_json::json!(0)),
        ("rvk negative", serde_json::json!(-1)),
        ("rvk >= 2^53-1", serde_json::json!(9_007_199_254_740_992i64)),
        ("rvk non-integer", serde_json::json!(1.5)),
    ];
    for (case, rvk) in cases {
        let coz = self_revoke_coz(&pool, "key_a", rvk);
        let (status, json) = post_revoke(&state, pid, coz).await;
        assert_rejected(status, &json, case);
    }
}

/// A revoke whose signature does not verify against its named key is rejected.
#[tokio::test]
async fn rejects_bad_signature() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-bad-sig";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = corrupt_sig(self_revoke_coz(&pool, "key_a", serde_json::json!(RVK)));
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert_rejected(status, &json, "corrupted signature");
}

/// A coz whose `typ` is not `key/revoke` is not a naked revoke and is rejected.
#[tokio::test]
async fn rejects_wrong_typ() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-wrong-typ";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let signer = pool.get("key_a").expect("key_a");
    let pay = serde_json::json!({
        "alg": signer.alg,
        "now": RVK,
        "rvk": RVK,
        "tmb": signer.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let coz = sign_coz(&pool, "key_a", pay);
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert_rejected(status, &json, "typ is not key/revoke");
}

/// A revoke whose `tmb` is a valid key that the NAMED principal does not hold
/// is rejected (never a global `tmb` index -- preserves login.rs:205). Here an
/// outsider key self-revokes while naming a principal it is not part of.
#[tokio::test]
async fn rejects_tmb_not_in_named_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-foreign-tmb";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    // `alice` is a valid key but is not golden/key_a: not a key of `pid`.
    let coz = self_revoke_coz(&pool, "alice", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert_rejected(status, &json, "tmb not held by the named principal");
}

/// A revoke naming no principal (anonymous) is unactionable by a witness and
/// is rejected -- distinct from a well-formed principal-scoped revoke.
#[tokio::test]
async fn rejects_anonymous_no_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-anon";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, "", coz).await;
    assert_rejected(status, &json, "anonymous revoke naming no principal");
}

// ========================================================================
// 3 -- The observation is durable: survives an AppState rebuild AND a reindex
// ========================================================================

/// After a naked revoke, the resulting refusal survives BOTH a full `AppState`
/// rebuild over the same data dir (a restart) AND an in-process engine
/// `reindex` -- proving the observation is durable and is NOT held in the
/// rebuildable index (`engine/mod.rs:1089`). Observed through the login gate:
/// the revoked key stays refused across both.
///
/// Red baseline: the revoke 404s (a no-op), so after restart+reindex the key
/// still logs in -- the observation never existed to survive.
#[tokio::test]
async fn observation_survives_restart_and_reindex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let data_dir = dir.path().join("data");
    let pool = common::load_pool();
    let pid = "nr-durable";

    let state1 = keyed_state_at(&data_dir, &key_path);
    bootstrap_golden_key_a(&state1, &pool, pid).await;
    // Pre-revoke sanity: key_a logs in fine.
    assert_eq!(
        login_status(&state1, &pool, "key_a", pid).await,
        StatusCode::OK,
        "key_a must log in before the naked revoke (empirical baseline)"
    );

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state1, pid, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted before durability can be tested, got {rstatus}: \
         {rjson:?}"
    );
    drop(state1);

    // Restart: a brand-new AppState over the same on-disk data dir.
    let state2 = keyed_state_at(&data_dir, &key_path);
    // Reindex in-process: rebuilds the index from blobs. An observation kept
    // only in the rebuildable index would be wiped here.
    state2
        .engine
        .reindex(&[], true)
        .await
        .expect("engine reindex");

    assert_eq!(
        login_status(&state2, &pool, "key_a", pid).await,
        StatusCode::UNAUTHORIZED,
        "the naked-revoked key must stay refused across a restart and a reindex"
    );
}

// ========================================================================
// 4 -- Login refusal: the revoked key is refused; an untouched key still works
// ========================================================================

/// After a self-signed naked revoke of `key_a`, `key_a` is refused at login
/// while `golden` (untouched, still active on-chain) still logs in -- the
/// refusal is scoped to the revoked key, not the whole principal.
///
/// Red baseline: the revoke 404s, so `key_a` still logs in (200) -- exactly
/// what the assertion says must become 401.
#[tokio::test]
async fn naked_revoked_key_refused_untouched_key_still_logs_in() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-login-refuse";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    // Baseline: key_a logs in before any revoke.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::OK,
        "key_a must log in before the naked revoke (empirical baseline)"
    );

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, pid, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted, got {rstatus}: {rjson:?}"
    );

    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::UNAUTHORIZED,
        "the naked-revoked key_a must be refused at login"
    );
    assert_eq!(
        login_status(&state, &pool, "golden", pid).await,
        StatusCode::OK,
        "an untouched key of the same principal must still log in (refusal is key-scoped)"
    );
}

// ========================================================================
// 5 -- PR is unchanged: a naked revoke mutates no chain root (§6.4)
// ========================================================================

/// The principal's tip roots (`pr`, `sr`, `ar`, `cr`, `commit_count`) are
/// byte-identical before and after a naked revoke -- SPEC §6.4: an uncommitted
/// naked revoke does not mutate PR.
///
/// Red baseline: the revoke 404s, so the accept assertion (bound to the
/// PR-unchanged property so the property is not proven vacuously) fails.
#[tokio::test]
async fn naked_revoke_does_not_mutate_pr() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-pr-unchanged";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let tip_before = tip_roots(&state, pid).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, pid, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must actually be applied for PR-unchanged to be non-vacuous, got \
         {rstatus}: {rjson:?}"
    );

    let tip_after = tip_roots(&state, pid).await;
    assert_eq!(
        tip_before, tip_after,
        "a naked revoke must not mutate any chain root (§6.4)"
    );
}

/// The tip roots that a naked revoke must leave untouched.
async fn tip_roots(state: &Arc<AppState>, pid: &str) -> serde_json::Value {
    let (status, json) =
        common::get_json(build_router(state.clone()), &format!("/tip?pr={pid}")).await;
    assert_eq!(status, StatusCode::OK, "tip must be readable: {json:?}");
    let p = common::envelope_payload(&json);
    serde_json::json!({
        "pr": p["pr"], "sr": p["sr"], "ar": p["ar"], "cr": p["cr"],
        "commit_count": p["commit_count"],
    })
}

// ========================================================================
// 6 -- A keyless server accepts and interprets a naked revoke
// ========================================================================

/// A keyless server (no signing identity of its own) still accepts and
/// interprets a naked revoke: verification is against the *principal's* keys,
/// not the server's. The revoked key is thereafter refused... but a keyless
/// server has no login route configured, so the acceptance is observed
/// directly at the endpoint (2xx).
///
/// Red baseline: the revoke 404s.
#[tokio::test]
async fn keyless_server_accepts_naked_revoke() {
    let (state, _dir) = common::keyless_server();
    let pool = common::load_pool();
    let pid = "nr-keyless";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert!(
        status.is_success(),
        "a keyless server must still accept and interpret a naked revoke, got {status}: {json:?}"
    );
}

// ========================================================================
// 7 -- The committed golden vector round-trips through the ingest path
// ========================================================================

/// The pinned golden naked-revoke coz (self-signed by `key_a`, valid `rvk`)
/// is accepted by the ingest path. A silent drift in the wire shape the server
/// accepts breaks this loudly. The fixture is committed alongside this suite
/// at `tests/golden/naked_revoke_valid.json`; it was generated by signing the
/// payload below with pool key `key_a`'s private material (see the campaign
/// scratch generator), and its signature verifies against `key_a`.
///
/// Red baseline: the revoke 404s.
#[tokio::test]
async fn golden_naked_revoke_vector_is_accepted() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-golden";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz: serde_json::Value =
        serde_json::from_str(&golden("naked_revoke_valid.json")).expect("parse golden vector");
    // The fixture is self-consistent (its signature verifies against key_a),
    // so any red here is the ingest path, not a malformed fixture.
    assert_eq!(coz["pay"]["typ"], "cyphr.me/cyphr/key/revoke");

    let (status, json) = post_revoke(&state, pid, coz).await;
    assert!(
        status.is_success(),
        "the golden naked-revoke vector must round-trip through ingest, got {status}: {json:?}"
    );
}

/// Read a committed golden vector, flat and crate-local (mirrors
/// `tests/envelope_vectors.rs:27-35`, NOT `common::load_golden`, which resolves
/// the workspace-root `tests/golden/<category>/<name>` principal-fixture shape).
fn golden(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ========================================================================
// Third-party posture (Q2, FIXED: record-and-surface, no error state, no login
// block; spec clarification pending issue #106 -- do NOT "fix" toward freeze)
// ========================================================================

/// A third-party naked revoke (an outsider declaring a principal's key
/// compromised) is recorded and surfaced but does NOT freeze the principal or
/// block its login: the compromised key still logs in, and the principal's tip
/// is unchanged. This is the ratified anti-griefing posture -- the literal
/// §6.4 "freezes the principal" reading is an unauthenticated DoS vector,
/// pending #106.
///
/// Red baseline: the endpoint 404s, so the "recorded (2xx)" assertion fails.
/// (The exact third-party verification mechanism is #106-pending; the coz is
/// built the natural coz-shaped way, embedding the outsider's key.)
#[tokio::test]
async fn third_party_revoke_recorded_but_does_not_block_login() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-third-party";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let tip_before = tip_roots(&state, pid).await;

    // `alice` (not a key of `pid`) declares `key_a` (a key of `pid`) compromised.
    let key_a_tmb = pool
        .get("key_a")
        .expect("key_a")
        .compute_tmb_b64()
        .expect("tmb");
    let coz = third_party_revoke_coz(&pool, "alice", &key_a_tmb);
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert!(
        status.is_success(),
        "a third-party naked revoke naming a known principal must be recorded/surfaced (2xx), got \
         {status}: {json:?}"
    );

    // Posture: the principal is NOT frozen and the third-party-flagged key is
    // NOT blocked -- key_a still logs in.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::OK,
        "a third-party naked revoke must NOT block the key's login (record-only, #106)"
    );
    assert_eq!(
        tip_before,
        tip_roots(&state, pid).await,
        "a third-party naked revoke must not mutate PR either"
    );
}

/// Under `ThirdPartyRevokePolicy::Reject`, a third-party naked revoke is
/// declined (4xx) rather than recorded -- and the policy is scoped to
/// third-party claims only: a self-signed revoke is still accepted, since
/// self-signed acceptance is unconditional (SPEC §6.4).
#[tokio::test]
async fn third_party_revoke_rejected_when_policy_is_reject() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key_path),
        audience: Some(AUDIENCE.to_string()),
        third_party_naked_revoke: cyphr_server::config::ThirdPartyRevokePolicy::Reject,
        ..Default::default()
    };
    let state = Arc::new(AppState::new(config).expect("open Reject-policy AppState"));
    let pool = common::load_pool();
    let pid = "nr-tp-reject";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let key_a_tmb = pool
        .get("key_a")
        .expect("key_a")
        .compute_tmb_b64()
        .expect("tmb");
    let coz = third_party_revoke_coz(&pool, "alice", &key_a_tmb);
    let (status, json) = post_revoke(&state, pid, coz).await;
    assert_rejected(status, &json, "third-party revoke under Reject policy");

    // The flag gates third-party claims only, never self-signed revokes.
    let self_coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (self_status, self_json) = post_revoke(&state, pid, self_coz).await;
    assert!(
        self_status.is_success(),
        "a self-signed revoke must still be accepted under the Reject policy, got {self_status}: \
         {self_json:?}"
    );
}
