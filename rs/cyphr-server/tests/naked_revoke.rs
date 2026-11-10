//! Acceptance suite for the witness naked-revoke ingest path (SPEC.md §6.4,
//! confirmed model) under the **disclosed-key** verification model.
//!
//! A **naked revoke** is a `key/revoke` coz signed *outside* a commit. Under
//! the confirmed §6.4 model a witness accepts one iff it is **self-signed** --
//! the key named by the coz's `tmb` signs its own revoke -- and thereafter
//! refuses that key GLOBALLY, by thumbprint, for every capability (login AND
//! push) and every principal that holds it. There is no principal scoping, no
//! third-party path, and no chain replay.
//!
//! ## The disclosed-key model (this suite is the source of truth)
//!
//! Verification never dereferences the global index's CONTENT. The request
//! DISCLOSES the public key; the server verifies by recomputing `tmb = H(pub)`
//! over the disclosed key and checking the signature against that SAME disclosed
//! key. The index collapses to a PRESENCE fence: `tmb` must be a key the server
//! has indexed (`Some`), but the indexed value is never read. This removes the
//! index from the truth path, closing an availability DoS: a poisoned index
//! entry (an attacker's pub stored under a victim's `tmb`) can no longer block
//! the victim's own emergency revoke, because the victim's revoke depends only
//! on the material the victim discloses.
//!
//! ### Endpoint contract
//!
//! - `POST /revoke`
//! - request body: the signed `key/revoke` coz PLUS its disclosed public key -- `{ "pay": {..},
//!   "sig": "<b64url>", "key": { "alg": "..", "pub": "<b64url>" } }`. The `key` field is REQUIRED:
//!   a body that discloses no key is rejected (400). There is NO `principal_id` field and NO
//!   `RevokeRequest` wrapper: death is global-by-thumbprint, so no principal is named or loaded.
//! - on acceptance: a 2xx whose payload names `revoked_tmb` (no `principal_id`, no `kind`).
//!
//! ### Verification order (each a distinct rejection)
//!
//! 1. the payload parses and its `typ` is a `key/revoke`;
//! 2. `rvk` is a positive integer below 2^53-1; the timestamp value is NOT checked, so a pre-signed
//!    `rvk`=1 is valid;
//! 3. the body discloses a `key` (else 400) and the serialized revoke is within `RVK_MAX_SIZE`;
//! 4. PRESENCE fence: `tmb` is a key this server has indexed (`Some`) -- the indexed CONTENT is
//!    never read; an unknown `tmb` is refused (400);
//! 5. BIND: the disclosed key hashes back to the named `tmb` (`tmb = H(pub)`), else 400 -- this
//!    welds the disclosed key to the named thumbprint;
//! 6. VERIFY: the signature verifies against the DISCLOSED key, else 401. A revoke signed by any
//!    key OTHER than the one `tmb` names fails here -- the entire self-signed-only rule.
//!
//! ## Why every test drives the live HTTP endpoint
//!
//! An integration-test file is one binary: a reference to a not-yet-existing
//! symbol would fail the whole binary to compile, so no test could exhibit its
//! semantic red baseline. Every test therefore goes through `build_router` + a
//! real request, and every red baseline is behavioral (a rejected accept, an
//! accepted forge, a victim's revoke blocked by a poisoned index) rather than a
//! missing symbol or a compile error.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{DeriveToken, IndexableCommit, Indexer, IndexerWrite};
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

/// Bootstrap a principal with genesis `golden` plus an added active key
/// `key_a`, both active, through the real `/push` wire path -- so `golden`
/// and `key_a` are genuinely active keys of this exact principal AND indexed
/// globally. Returns the principal's genesis-derived id (SPEC 3.1).
async fn bootstrap_golden_key_a(state: &Arc<AppState>, pool: &Pool) -> String {
    let pid = common::golden_principal_id(pool);
    let body = common::build_genesis_push_body(pool, &pid, RVK);
    let (status, json) = common::post_json(build_router(state.clone()), "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bootstrap push must create the principal: {json:?}"
    );
    pid
}

// ========================================================================
// Coz + request builders (disclosed-key shape)
// ========================================================================

/// Sign `pay` with pool key `signer_name` and return the base64url signature.
fn sign_pay(pool: &Pool, signer_name: &str, pay: &serde_json::Value) -> String {
    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let pay_vec = serde_json::to_vec(pay).expect("serialize pay");
    let (sig, _cad) =
        coz::sign_json(&pay_vec, &signer.alg, &prv, &pub_key).expect("signing supported");
    Base64UrlUnpadded::encode_string(&sig)
}

/// The disclosed `{ "alg", "pub" }` key block for pool key `name` -- the
/// REQUIRED `key` field of a disclosed-key naked revoke, in the wire shape the
/// server parses (`pub` is the base64url public key).
fn disclosed_key(pool: &Pool, name: &str) -> serde_json::Value {
    let k = pool.get(name).expect("disclosed key in pool");
    serde_json::json!({ "alg": k.alg, "pub": k.pub_key })
}

/// Wrap a custom `pay` signed by `signer_name` as a bare `{pay, sig}` body --
/// the pre-disclosure shape that discloses NO key.
fn sign_coz(pool: &Pool, signer_name: &str, pay: serde_json::Value) -> serde_json::Value {
    let sig = sign_pay(pool, signer_name, &pay);
    serde_json::json!({ "pay": pay, "sig": sig })
}

/// As [`sign_coz`], additionally disclosing `disclosed_name`'s `{alg, pub}` as
/// the REQUIRED `key` field -- the disclosed-key request shape.
fn sign_coz_disclosed(
    pool: &Pool,
    signer_name: &str,
    pay: serde_json::Value,
    disclosed_name: &str,
) -> serde_json::Value {
    let mut body = sign_coz(pool, signer_name, pay);
    body.as_object_mut()
        .unwrap()
        .insert("key".to_string(), disclosed_key(pool, disclosed_name));
    body
}

/// A `key/revoke` request naming `named_tmb_b64` as the revoked key, signed by
/// `signer_name`. `disclosed` selects the `key` field: `Some(name)` discloses
/// that pool key's `{alg, pub}` (the required disclosed-key shape); `None`
/// omits `key` entirely (the bare shape the model must reject).
///
/// The three axes -- named `tmb`, signing key, disclosed key -- are independent
/// so the forge and availability tests can drive each rejection path in
/// isolation: bind fails when the disclosed key does not hash to the named
/// `tmb`; the signature check fails when the signer is not the disclosed key.
fn revoke_body(
    pool: &Pool,
    named_tmb_b64: &str,
    signer_name: &str,
    disclosed: Option<&str>,
    rvk: serde_json::Value,
) -> serde_json::Value {
    let signer = pool.get(signer_name).expect("signer in pool");
    let pay = serde_json::json!({
        "alg": signer.alg,
        "now": rvk,
        "rvk": rvk,
        "tmb": named_tmb_b64,
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    match disclosed {
        Some(name) => sign_coz_disclosed(pool, signer_name, pay, name),
        None => sign_coz(pool, signer_name, pay),
    }
}

/// A valid self-signed naked revoke: `signer_name` revokes *itself* (`pay.tmb`
/// is the signer's own thumbprint) AND discloses its own key -- the confirmed
/// §6.4 self-revoke shape. `rvk` overridable to exercise the malformed-`rvk`
/// matrix and the pre-signed `rvk`=1 case.
fn self_revoke_coz(pool: &Pool, signer_name: &str, rvk: serde_json::Value) -> serde_json::Value {
    let tmb = tmb_b64(pool, signer_name);
    revoke_body(pool, &tmb, signer_name, Some(signer_name), rvk)
}

/// A self-signed naked revoke that discloses NO key -- the pre-disclosure bare
/// `{pay, sig}` shape. Otherwise valid (correct self-signature, valid `rvk`);
/// the disclosed-key model must reject it for lacking the required `key`.
fn self_revoke_coz_bare(
    pool: &Pool,
    signer_name: &str,
    rvk: serde_json::Value,
) -> serde_json::Value {
    let tmb = tmb_b64(pool, signer_name);
    revoke_body(pool, &tmb, signer_name, None, rvk)
}

/// The base64url thumbprint of pool key `name`.
fn tmb_b64(pool: &Pool, name: &str) -> String {
    pool.get(name)
        .expect("key in pool")
        .compute_tmb_b64()
        .expect("tmb")
}

/// POST a naked-revoke body to `/revoke` and return the status + parsed body.
async fn post_revoke(
    state: &Arc<AppState>,
    coz: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    common::post_json(build_router(state.clone()), REVOKE_URI, coz.to_string()).await
}

/// Assert the response is a distinct client-error rejection with a described
/// cause -- never a 2xx accept, a 5xx fault, or an empty route/parse miss.
fn assert_rejected(status: StatusCode, json: &serde_json::Value, case: &str) {
    assert!(
        status.is_client_error(),
        "{case}: must be a 4xx rejection (not a 2xx accept, not a 5xx fault), got {status}: \
         {json:?}"
    );
    let err = json["payload"]["error"]
        .as_str()
        .or_else(|| json["error"].as_str())
        .unwrap_or("");
    assert!(
        !err.is_empty(),
        "{case}: rejection must name its cause in an {{\"error\": …}} body, got {json:?}"
    );
}

// ========================================================================
// Login helpers (timestamp flow; ported from tests/login.rs, a separate
// integration crate that cannot be imported)
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
// Push helpers (a follow-up commit signed by a named key, so a *dead* signing
// key can be exercised at the push gate).
// ========================================================================

/// A push body's blob list, base64url-encoded, wrapped with `principal_id`.
fn push_body(pid: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": pid,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// Bootstrap `pid` over real HTTP with its genesis commit (SPEC 5.1), in
/// which `genesis_name` creates itself and `added_name`. `pid` must be that
/// genesis's PG (`common::genesis_push_id`).
async fn bootstrap_via_push(
    state: &Arc<AppState>,
    pool: &Pool,
    pid: &str,
    genesis_name: &str,
    added_name: &str,
    now: i64,
) {
    let body = common::build_genesis_push_body_with(pool, genesis_name, added_name, pid, now);
    let (status, json) = common::post_json(build_router(state.clone()), "/push", body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis bootstrap push for {pid} must succeed: {json:?}"
    );
}

/// Build a follow-up push body for the existing `pid` (bootstrapped by
/// [`bootstrap_via_push`] with `genesis_name` + `genesis_added` at
/// `genesis_now`): a fresh "add `added_name`" commit signed by
/// `signer_name`, chained onto the genesis commit. The signing key
/// `signer_name` is the one the push gate must death-check.
#[allow(clippy::too_many_arguments)]
fn followup_push_body(
    pool: &Pool,
    pid: &str,
    genesis_name: &str,
    genesis_added: &str,
    genesis_now: i64,
    signer_name: &str,
    added_name: &str,
    now: i64,
) -> String {
    let principal =
        common::genesis_pushed_principal(pool, genesis_name, genesis_added, genesis_now);
    let blobs = common::sign_key_create_commit(principal, pool, signer_name, added_name, now);
    push_body(pid, &blobs)
}

async fn post_push(state: &Arc<AppState>, body: String) -> (StatusCode, serde_json::Value) {
    common::post_json(build_router(state.clone()), "/push", body).await
}

// ========================================================================
// 1 -- Accept a valid self-signed naked revoke (self-signed-only accepts)
// ========================================================================

/// A well-formed self-signed `key/revoke` disclosing its own key, with a valid
/// `rvk`, is accepted (2xx). Its response names `revoked_tmb` and carries
/// neither the deleted `principal_id` nor the deleted `kind`.
///
/// Behavior: preserved by the disclosed-key rework -- a valid self-signed
/// revoke stays accepted (green on both the merged and reworked server), now
/// carrying its disclosed key. The load-bearing behavioral change is exercised
/// by the poisoned-index and keyless-body tests below.
#[tokio::test]
async fn accepts_valid_self_signed_naked_revoke() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, coz).await;
    assert!(
        status.is_success(),
        "a valid self-signed naked revoke must be accepted (2xx), got {status}: {json:?}"
    );

    let payload = common::envelope_payload(&json);
    assert_eq!(
        payload["revoked_tmb"].as_str(),
        Some(tmb_b64(&pool, "key_a").as_str()),
        "the accept response must name the revoked key's thumbprint: {json:?}"
    );
    assert!(
        payload.get("principal_id").is_none(),
        "the response must not carry the deleted principal_id field: {json:?}"
    );
    assert!(
        payload.get("kind").is_none(),
        "the response must not carry the deleted self/third-party kind field: {json:?}"
    );
}

// ========================================================================
// 2 -- The disclosed-key defenses: keyless body, forge paths, availability
// ========================================================================

/// A revoke body that discloses NO `key` is rejected (the disclosed key is
/// REQUIRED under the reworked model): a bare `{pay, sig}`, otherwise a valid
/// self-signed revoke, must be refused for lacking the disclosed key.
///
/// Red baseline (merged, index-based server): the bare `{pay, sig}` IS the shape
/// the merged handler accepts -- it resolves `tmb -> pub` through the index and
/// verifies the self-signature -- so this otherwise-valid revoke is ACCEPTED
/// (2xx). `assert_rejected` therefore fails against the merged server: the
/// requirement to disclose the key is the missing behavior.
#[tokio::test]
async fn keyless_revoke_body_is_rejected() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let coz = self_revoke_coz_bare(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(
        status,
        &json,
        "naked revoke body that discloses no public key",
    );
}

/// FORGE STAYS CLOSED (bind path): a revoke naming the victim's `tmb` but
/// disclosing a NON-victim key (`H(disclosed) != victim tmb`) is rejected, and
/// the victim key stays alive. The attacker `alice` discloses her own key and
/// signs with it, naming the victim `key_a`'s thumbprint.
///
/// Behavior: green on both servers, but by DIFFERENT paths -- the reworked
/// server rejects at the BIND (`H(alice pub) != key_a tmb`, 400) before any
/// signature check; the merged server ignores the disclosed key, resolves
/// `key_a`'s real pub from the (unpoisoned) index, and rejects when alice's
/// signature fails against it (401). This pins that the bind alone refuses a
/// mismatched disclosed key.
#[tokio::test]
async fn forge_disclosing_non_victim_key_is_rejected() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = bootstrap_golden_key_a(&state, &pool).await;
    let pid = pid.as_str();

    let coz = revoke_body(
        &pool,
        &tmb_b64(&pool, "key_a"),
        "alice",
        Some("alice"),
        serde_json::json!(RVK),
    );
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(
        status,
        &json,
        "revoke naming the victim tmb but disclosing a non-victim key",
    );

    // The victim's real key is untouched.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::OK,
        "the victim key must stay alive after the mismatched-disclosure forge is rejected"
    );
}

/// FORGE STAYS CLOSED (signature path): a revoke disclosing the victim's REAL
/// key (public, so anyone can present it) but signed by an ATTACKER key is
/// rejected, and the victim key stays alive. `golden` (a valid sibling key of
/// the same principal) signs a revoke naming `key_a` and discloses `key_a`'s
/// real pub -- the disclosure binds, but the signature does not verify against
/// it. This single signature check IS the self-signed-only rule; even a sibling
/// key cannot revoke another.
///
/// Behavior: green on both servers (the merged server rejects the non-self
/// signature against the honest indexed pub; the reworked server rejects it
/// against the disclosed pub, 401). Pins that binding the disclosure does not
/// weaken the self-signed-only requirement.
#[tokio::test]
async fn forge_disclosing_victim_key_signed_by_other_is_rejected() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = bootstrap_golden_key_a(&state, &pool).await;
    let pid = pid.as_str();

    let coz = revoke_body(
        &pool,
        &tmb_b64(&pool, "key_a"),
        "golden",
        Some("key_a"),
        serde_json::json!(RVK),
    );
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(
        status,
        &json,
        "revoke disclosing the victim key but signed by a different key",
    );

    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::OK,
        "the victim key must stay alive after the wrong-signer forge is rejected"
    );
}

/// AVAILABILITY (the load-bearing behavioral change): a poisoned index entry
/// must NOT block the victim's own emergency revoke. An unauthenticated
/// attacker poisons `index[victim tmb] -> attacker pub`; the victim then revokes
/// their OWN key, disclosing their real key and self-signing. Because the
/// reworked server verifies against the DISCLOSED key (never the index content),
/// the victim's revoke depends only on material the victim controls and MUST
/// SUCCEED.
///
/// Red baseline (merged, index-based server): the merged `interpret` resolves
/// `tmb -> pub` from the poisoned index (attacker pub), recomputes
/// `H(attacker pub) != victim tmb`, and REJECTS (400) -- the merged
/// point-of-use recheck, fed poisoned content, blocks the victim's own
/// legitimate revoke. So `assert!(rstatus.is_success())` fails against the
/// merged server, and it fails precisely because the poisoned index entry
/// blocks the victim (the poison-took precondition -- `index[victim] ==
/// attacker pub` -- is asserted first and holds, so the block is genuine, not a
/// setup miss). This is the §6.4 emergency-path DoS the rework closes.
#[tokio::test]
async fn poisoned_index_does_not_block_victims_own_revoke() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();

    // Victim: a normal principal (golden genesis adds key_a). key_a's real
    // thumbprint V = H(key_a pub) is indexed to key_a's real pub.
    bootstrap_golden_key_a(&state, &pool).await;
    let victim_tmb = tmb_b64(&pool, "key_a");

    // Attack: try to overwrite index[V] -> attacker (alice) pub via a fresh
    // attacker principal's unauthenticated genesis push with a swapped sidecar
    // pub. `alice` is a distinct key whose private half the attacker holds.
    let body = poison_genesis_push_body(&pool, "bob", "key_a", "alice", RVK);
    let (pstatus, pjson) = post_push(&state, body).await;
    assert!(
        pstatus.is_client_error(),
        "a push whose sidecar pub does not hash to its tmb must be refused: {pstatus} {pjson:?}"
    );

    // The poison did not take, so the revoke below runs against a clean
    // index. The disclosed-key rule (never the index content) still decides
    // the outcome: that independence is what this test guards.
    let indexed = state
        .engine
        .indexer()
        .get_key(&victim_tmb)
        .await
        .expect("index lookup succeeds")
        .expect("V is still indexed after the refused poison push");
    assert_eq!(
        indexed.public_key,
        pool.get("key_a").expect("key_a").pub_key,
        "index[V] must still resolve to the victim's real pub"
    );

    // Poison the index directly: the wire can no longer do it, but the
    // victim's emergency revoke must not depend on the index being clean.
    poison_index_directly(&state, &pool, &victim_tmb, "alice").await;

    // The victim's OWN emergency revoke: discloses key_a's REAL key, self-signed
    // by key_a. It must succeed despite the poisoned index.
    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the victim's own self-signed revoke (disclosing its real key) must SUCCEED despite the \
         poisoned index entry -- a poisoned index must never block the §6.4 emergency path, got \
         {rstatus}: {rjson:?}"
    );

    // The revoke was interpreted against the victim's own thumbprint.
    let payload = common::envelope_payload(&rjson);
    assert_eq!(
        payload["revoked_tmb"].as_str(),
        Some(victim_tmb.as_str()),
        "the accepted revoke must name the victim's own thumbprint: {rjson:?}"
    );
}

// ========================================================================
// 3 -- Reject malformed / mis-signed / unknown revokes, each a distinct 4xx
// ========================================================================

/// Each out-of-range `rvk` (zero, negative, ≥ 2^53-1, non-integer) is a
/// distinct rejection: `rvk` must be a positive integer below 2^53-1.
///
/// Behavior: green on both servers (the `rvk` bound is unchanged); the revoke
/// discloses its key so it reaches the `rvk` check.
#[tokio::test]
async fn rejects_malformed_rvk() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let cases = [
        ("rvk = 0", serde_json::json!(0)),
        ("rvk negative", serde_json::json!(-1)),
        ("rvk >= 2^53-1", serde_json::json!(9_007_199_254_740_992i64)),
        ("rvk non-integer", serde_json::json!(1.5)),
    ];
    for (case, rvk) in cases {
        let coz = self_revoke_coz(&pool, "key_a", rvk);
        let (status, json) = post_revoke(&state, coz).await;
        assert_rejected(status, &json, case);
    }
}

/// A coz whose `typ` is not `key/revoke` is not a naked revoke and is rejected,
/// even when it discloses a valid key.
///
/// Behavior: green on both servers (the `typ` gate is unchanged).
#[tokio::test]
async fn rejects_wrong_typ() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let signer = pool.get("key_a").expect("key_a");
    let pay = serde_json::json!({
        "alg": signer.alg,
        "now": RVK,
        "rvk": RVK,
        "tmb": signer.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let coz = sign_coz_disclosed(&pool, "key_a", pay, "key_a");
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(status, &json, "typ is not key/revoke");
}

/// The operator's quota bounds revokes of keys nobody here holds, never the
/// revoke of a held key (SPEC 6.4): with `[limits] max_dead_keys = 1` and the
/// set filled by an unseen key's revoke, the self-revoke of a key a pushed
/// principal holds is still recorded and the key is dead, while a second
/// unseen key's revoke is refused `507` and stays alive. Turns red if the
/// ceiling denies the held key's emergency revoke, or does not bound unseen
/// keys. End-to-end: yes (`/push`, `/revoke` over HTTP).
#[tokio::test]
async fn the_ceiling_never_refuses_a_held_keys_revoke() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let mut config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key_path),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };
    config.limits.max_dead_keys = 1;
    let state = Arc::new(AppState::new(config).expect("open keyed AppState"));
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;
    let tmb = |name: &str| {
        pool.get(name)
            .expect("pool key")
            .compute_tmb()
            .expect("tmb")
    };

    let (status, json) = post_revoke(
        &state,
        self_revoke_coz(&pool, "alice", serde_json::json!(RVK)),
    )
    .await;
    assert!(
        status.is_success(),
        "an unseen key fills the set: {status} {json:?}"
    );

    let (status, json) = post_revoke(
        &state,
        self_revoke_coz(&pool, "key_a", serde_json::json!(RVK)),
    )
    .await;
    assert!(
        status.is_success(),
        "a held key's revoke is recorded past the ceiling: {status} {json:?}"
    );
    assert!(
        state
            .observations
            .is_dead(&tmb("key_a"))
            .await
            .expect("death set"),
        "the held key is dead"
    );

    let (status, json) = post_revoke(
        &state,
        self_revoke_coz(&pool, "bob", serde_json::json!(RVK)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INSUFFICIENT_STORAGE,
        "a second unseen key past the ceiling is refused: {json:?}"
    );
    assert!(
        !state
            .observations
            .is_dead(&tmb("bob"))
            .await
            .expect("death set"),
        "the refused revoke recorded nothing"
    );
}

// ========================================================================
// 4 -- Pre-signed and idempotent acceptance (timestamp not validated)
// ========================================================================

/// A pre-signed revoke with `rvk`=1 is accepted: the confirmed model requires
/// only that `rvk` be a positive integer below 2^53-1 and does NOT validate
/// the timestamp value.
///
/// Behavior: green on both servers (timestamp still unvalidated).
#[tokio::test]
async fn accepts_presigned_rvk_one() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(1));
    let (status, json) = post_revoke(&state, coz).await;
    assert!(
        status.is_success(),
        "a pre-signed rvk=1 revoke must be accepted (timestamp not validated), got {status}: \
         {json:?}"
    );
}

/// Re-revoking an already-dead key is an accepted no-op: `record` is
/// idempotent by thumbprint.
///
/// Behavior: green on both servers (idempotent record is unchanged).
#[tokio::test]
async fn idempotent_re_revoke() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let first = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (s1, j1) = post_revoke(&state, first).await;
    assert!(
        s1.is_success(),
        "first revoke must be accepted, got {s1}: {j1:?}"
    );

    let second = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (s2, j2) = post_revoke(&state, second).await;
    assert!(
        s2.is_success(),
        "re-revoking an already-dead key must be an accepted no-op, got {s2}: {j2:?}"
    );
}

// ========================================================================
// 5 -- Durability: the death record survives an AppState rebuild AND a reindex
// ========================================================================

/// After a naked revoke, the resulting refusal survives BOTH a full `AppState`
/// rebuild over the same data dir (a restart) AND an in-process engine
/// `rebuild_index_from_scratch` -- proving the death record is durable and is NOT held in the
/// rebuildable index. Observed through the login gate: the revoked key stays
/// refused across both.
///
/// Behavior: green on both servers (durability is unchanged); the accept
/// precondition uses the disclosed-key shape.
#[tokio::test]
async fn death_record_survives_restart_and_reindex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let data_dir = dir.path().join("data");
    let pool = common::load_pool();

    let state1 = keyed_state_at(&data_dir, &key_path);
    let pid = bootstrap_golden_key_a(&state1, &pool).await;
    let pid = pid.as_str();
    // Pre-revoke sanity: key_a logs in fine.
    assert_eq!(
        login_status(&state1, &pool, "key_a", pid).await,
        StatusCode::OK,
        "key_a must log in before the naked revoke (empirical baseline)"
    );

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state1, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted before durability can be tested, got {rstatus}: \
         {rjson:?}"
    );
    drop(state1);

    // Restart: a brand-new AppState over the same on-disk data dir.
    let state2 = keyed_state_at(&data_dir, &key_path);
    // Reindex in-process: rebuilds the index from blobs. A record kept only in
    // the rebuildable index would be wiped here.
    state2
        .engine
        .rebuild_index_from_scratch()
        .await
        .expect("engine rebuild");

    assert_eq!(
        login_status(&state2, &pool, "key_a", pid).await,
        StatusCode::UNAUTHORIZED,
        "the naked-revoked key must stay refused across a restart and a reindex"
    );
}

// ========================================================================
// 6 -- Login refusal + key-scoping: the dead key is refused, siblings survive
// ========================================================================

/// After a self-signed naked revoke of `key_a`, `key_a` is refused at login
/// while `golden` (untouched, still active on-chain) still logs in -- the
/// refusal is scoped to the revoked key, not the whole principal.
///
/// Behavior: green on both servers (login refusal + key-scoping unchanged).
// @docket: signon-disowned-key :: scripts/docket-run signon-disowned-key
#[tokio::test]
async fn revoked_key_refused_at_login_sibling_survives() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = bootstrap_golden_key_a(&state, &pool).await;
    let pid = pid.as_str();

    // Baseline: key_a logs in before any revoke.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid).await,
        StatusCode::OK,
        "key_a must log in before the naked revoke (empirical baseline)"
    );

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
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
        "an untouched sibling key of the same principal must still log in (refusal is key-scoped)"
    );
}

// ========================================================================
// 7 -- Global death across capabilities: the dead key is refused at PUSH too
// ========================================================================

/// After revoking `key_a`, a `/push` whose follow-up commit is SIGNED BY
/// `key_a` is refused -- the death is global across capabilities, not just
/// login. The refusal is a distinct auth-shaped rejection (401/403), never a
/// 2xx accept and never a 409 conflict (which would be a false green from a
/// stale-predecessor collision rather than the death gate).
///
/// Behavior: green on both servers (the push death gate is unchanged); the
/// accept precondition uses the disclosed-key shape.
#[tokio::test]
async fn revoked_key_refused_at_push() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = common::golden_principal_id(&pool);
    let pid = pid.as_str();
    bootstrap_via_push(&state, &pool, pid, "golden", "key_a", RVK).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted before the push gate can be tested, got {rstatus}: \
         {rjson:?}"
    );

    // A follow-up commit signed by the now-dead key_a.
    let body = followup_push_body(
        &pool,
        pid,
        "golden",
        "key_a",
        RVK,
        "key_a",
        "carol",
        RVK + 100,
    );
    let (status, json) = post_push(&state, body).await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "a push signed by a globally-dead key must be refused (401/403), not accepted and not a \
         409 conflict, got {status}: {json:?}"
    );
    let err = json["payload"]["error"]
        .as_str()
        .or_else(|| json["error"].as_str())
        .unwrap_or("");
    assert!(
        !err.is_empty(),
        "the push refusal must name its cause in an {{\"error\": …}} body, got {json:?}"
    );
}

/// A sibling key still pushes after another key of the principal is revoked:
/// only the dead `key_a` is refused, so `golden` authors a follow-up commit
/// normally. The push-side dual of the login key-scoping test; it pins that a
/// push death-check must not over-reach past the revoked thumbprint.
///
/// Behavior: green on both servers (push death-check is key-scoped, unchanged).
#[tokio::test]
async fn sibling_key_still_pushes_after_revoke() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = common::golden_principal_id(&pool);
    let pid = pid.as_str();
    bootstrap_via_push(&state, &pool, pid, "golden", "key_a", RVK).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted first, got {rstatus}: {rjson:?}"
    );

    // A follow-up commit signed by the still-live golden.
    let body = followup_push_body(
        &pool,
        pid,
        "golden",
        "key_a",
        RVK,
        "golden",
        "carol",
        RVK + 100,
    );
    let (status, json) = post_push(&state, body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a push signed by a live sibling key must still succeed after another key is revoked: \
         {json:?}"
    );
}

// ========================================================================
// 8 -- Global death across principals: one revoke kills the key everywhere
// ========================================================================

/// A key is dead GLOBALLY by thumbprint: one naked revoke (which names no
/// principal) refuses the key on EVERY principal that holds it, and each
/// principal's other keys keep working. `key_a` is added to two independent
/// principals (distinct genesis keys `golden` and `bob`); revoking it once
/// refuses `key_a` on both, while `golden` and `bob` still log in.
///
/// This is the decisive test between the confirmed global model and the
/// superseded principal-scoped one: a per-principal death-set would refuse
/// `key_a` on only the (unnamed) principal, leaving the other's `key_a` live.
///
/// Behavior: green on both servers (global-by-thumbprint death unchanged).
#[tokio::test]
async fn revoked_key_dead_globally_across_principals() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid1 = common::genesis_push_id(&pool, "golden", "key_a");
    let pid2 = common::genesis_push_id(&pool, "bob", "key_a");
    let (pid1, pid2) = (pid1.as_str(), pid2.as_str());

    // Two independent principals, distinct genesis keys, both holding key_a.
    bootstrap_via_push(&state, &pool, pid1, "golden", "key_a", RVK).await;
    bootstrap_via_push(&state, &pool, pid2, "bob", "key_a", RVK).await;

    // Baseline: key_a logs in on both principals before the revoke.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid1).await,
        StatusCode::OK,
        "key_a must log in on pid1 before the revoke (empirical baseline)"
    );
    assert_eq!(
        login_status(&state, &pool, "key_a", pid2).await,
        StatusCode::OK,
        "key_a must log in on pid2 before the revoke (empirical baseline)"
    );

    // One revoke, naming no principal.
    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted, got {rstatus}: {rjson:?}"
    );

    // key_a is now refused on BOTH principals -- global death.
    assert_eq!(
        login_status(&state, &pool, "key_a", pid1).await,
        StatusCode::UNAUTHORIZED,
        "key_a must be refused on pid1 after the global revoke"
    );
    assert_eq!(
        login_status(&state, &pool, "key_a", pid2).await,
        StatusCode::UNAUTHORIZED,
        "key_a must be refused on pid2 after the global revoke (global-by-thumbprint)"
    );

    // Each principal's genesis key is untouched.
    assert_eq!(
        login_status(&state, &pool, "golden", pid1).await,
        StatusCode::OK,
        "pid1's golden key must still log in (only key_a died)"
    );
    assert_eq!(
        login_status(&state, &pool, "bob", pid2).await,
        StatusCode::OK,
        "pid2's bob key must still log in (only key_a died)"
    );
}

// ========================================================================
// 9 -- PR is unchanged: a naked revoke mutates no chain root (§6.4)
// ========================================================================

/// The principal's tip roots (`pr`, `sr`, `ar`, `cr`, `commit_count`) are
/// byte-identical before and after a naked revoke -- an uncommitted naked
/// revoke does not mutate PR.
///
/// Behavior: green on both servers (a naked revoke still mutates no PR); the
/// accept assertion (bound to the PR-unchanged property so the property is not
/// proven vacuously) uses the disclosed-key shape.
#[tokio::test]
async fn naked_revoke_does_not_mutate_pr() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = bootstrap_golden_key_a(&state, &pool).await;
    let pid = pid.as_str();

    let tip_before = tip_roots(&state, pid).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be applied for PR-unchanged to be non-vacuous, got {rstatus}: \
         {rjson:?}"
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
// 10 -- A keyless server accepts and interprets a naked revoke
// ========================================================================

/// A keyless server (no signing identity of its own) still accepts and
/// interprets a naked revoke: verification is against the disclosed key, the
/// engine's global key index (presence), and the death-set, none of which needs
/// the server's signing identity. Observed directly at the endpoint (2xx),
/// since a keyless server has no login route configured.
///
/// Behavior: green on both servers (a keyless server still interprets a revoke).
#[tokio::test]
async fn keyless_server_accepts_naked_revoke() {
    let (state, _dir) = common::keyless_server();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, coz).await;
    assert!(
        status.is_success(),
        "a keyless server must still accept and interpret a naked revoke, got {status}: {json:?}"
    );
}

// ========================================================================
// 11 -- The committed golden vector round-trips through the ingest path
// ========================================================================

/// The pinned golden naked-revoke coz (self-signed by `key_a`, disclosing
/// `key_a`'s key, valid `rvk`) is accepted by the ingest path. A silent drift in
/// the wire shape the server accepts breaks this loudly. The fixture is
/// committed alongside this suite at `tests/golden/naked_revoke_valid.json`, in
/// the disclosed-key request shape; its signature verifies against `key_a` and
/// its disclosed `pub` hashes to its `tmb`.
///
/// Behavior: green on both servers -- the merged server ignores the disclosed
/// `key` and resolves `key_a` from the index; the reworked server binds and
/// verifies against the disclosed `key`.
#[tokio::test]
async fn golden_naked_revoke_vector_is_accepted() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let coz: serde_json::Value =
        serde_json::from_str(&golden("naked_revoke_valid.json")).expect("parse golden vector");
    // The fixture is self-consistent: a self-signed key/revoke naming key_a and
    // disclosing key_a's key.
    assert_eq!(coz["pay"]["typ"], "cyphr.me/cyphr/key/revoke");
    assert_eq!(
        coz["pay"]["tmb"].as_str(),
        Some(tmb_b64(&pool, "key_a").as_str()),
        "the golden fixture must name key_a's thumbprint (self-signed)"
    );
    assert_eq!(
        coz["key"]["pub"].as_str(),
        Some(pool.get("key_a").expect("key_a").pub_key.as_str()),
        "the golden fixture must disclose key_a's real public key"
    );

    let (status, json) = post_revoke(&state, coz).await;
    assert!(
        status.is_success(),
        "the golden naked-revoke vector must round-trip through ingest, got {status}: {json:?}"
    );
}

/// Read a committed golden vector, flat and crate-local (mirrors
/// `tests/envelope_vectors.rs`, NOT `common::load_golden`, which resolves the
/// workspace-root `tests/golden/<category>/<name>` principal-fixture shape).
fn golden(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ========================================================================
// 12 -- HARDENING R1: the unauthenticated index-poisoning key-kill forge
// ========================================================================

/// Overwrite `index[victim tmb]` with `attacker_key_name`'s pub, directly
/// through the test-only indexer write.
///
/// The wire can no longer do this (a sidecar whose `tmb` is not its pub's
/// thumbprint is refused), so this stands in for any residual path that
/// could corrupt the index (a bug, a bad import, disk corruption). The
/// revoke path must not depend on the index being clean: it verifies the
/// DISCLOSED key, never the indexed one.
async fn poison_index_directly(
    state: &Arc<AppState>,
    pool: &Pool,
    victim_tmb_b64: &str,
    attacker_key_name: &str,
) {
    let attacker = pool.get(attacker_key_name).expect("attacker key in pool");
    let poison = IndexableCommit {
        pg: Vec::new(),
        principal_id: "SHA-256:nr-poisoned-index".to_string(),
        commit_ids: vec!["SHA-256:POISON_COMMIT".to_string()],
        sequence: 0,
        pre: None,
        prs: vec!["SHA-256:POISON_PR".to_string()],
        srs: vec!["SHA-256:POISON_SR".to_string()],
        ars: vec!["SHA-256:POISON_AR".to_string()],
        crs: vec!["SHA-256:POISON_CR".to_string()],
        blob_hashes: vec![Blake3Hash::from_bytes([7u8; 32])],
        cozies: vec![],
        timestamp: 1_700_000_000,
        keys: vec![cyphr_storage::index::PublicKeyInfo {
            thumbprint: victim_tmb_b64.to_string(),
            algorithm: attacker.alg.clone(),
            public_key: attacker.pub_key.clone(),
        }],
    };
    state
        .engine
        .indexer()
        .index_commit(&poison, &DeriveToken::for_conformance_tests())
        .await
        .expect("direct index poisoning");
    let indexed = state
        .engine
        .indexer()
        .get_key(victim_tmb_b64)
        .await
        .expect("index lookup succeeds")
        .expect("the poisoned entry is indexed");
    assert_eq!(
        indexed.public_key, attacker.pub_key,
        "precondition: index[V] must now resolve to the attacker's pub"
    );
}

/// Build a fresh ATTACKER principal's genesis push that tries to POISON the
/// global key index: the signed `key/create` introduces `victim_key_name`'s
/// real thumbprint, but the unsigned sidecar's `pub` is swapped for
/// `attacker_key_name`'s, so that (if accepted) `index[victim tmb]` would
/// resolve to the attacker's key. The attacker holds `attacker_key_name`'s
/// private key and would sign the forged revoke with it.
///
/// The genesis commit is built honestly through `Principal` (a forged `Key`
/// cannot be constructed: `tmb` is bound to `pub`): `genesis_name` creates
/// itself and the victim key. Then the victim `key/create`'s sidecar is
/// rewritten on the wire, which is the only place the attack remains
/// expressible. The push names the genesis's own PG, so only the server's
/// key-binding check stands between this body and the index.
fn poison_genesis_push_body(
    pool: &Pool,
    genesis_name: &str,
    victim_key_name: &str,
    attacker_key_name: &str,
    now: i64,
) -> String {
    let attacker_pid = common::genesis_push_id(pool, genesis_name, victim_key_name);
    let victim_tmb = tmb_b64(pool, victim_key_name);
    let attacker = pool.get(attacker_key_name).expect("attacker key in pool");
    let key = |name: &str| {
        pool.get(name)
            .expect("key in pool")
            .key()
            .expect("pool key")
    };
    let mut principal = cyphr::Principal::explicit(vec![key(genesis_name), key(victim_key_name)])
        .expect("explicit genesis");
    let signer = pool
        .get(genesis_name)
        .expect("genesis key in pool")
        .software_signer()
        .expect("genesis signer");
    let cozies = principal
        .commit_genesis(&signer, now, "cyphr.me")
        .expect("the honest genesis commits before the sidecar is swapped");

    // The POISONED sidecar: declared thumbprint = the victim's V, but the
    // public key is the attacker's own (whose private key signs the revoke).
    let mut swapped = 0;
    let blobs: Vec<Vec<u8>> = cozies
        .into_iter()
        .map(|mut coz| {
            if coz["key"]["tmb"].as_str() == Some(victim_tmb.as_str()) {
                coz["key"]["pub"] = serde_json::json!(attacker.pub_key);
                swapped += 1;
            }
            serde_json::to_vec(&coz).expect("cozy serializes")
        })
        .collect();
    assert_eq!(
        swapped, 1,
        "exactly the victim key/create's sidecar is swapped"
    );

    push_body(&attacker_pid, &blobs)
}

/// The BLOCKING R1 exploit, mounted end-to-end: an unauthenticated attacker
/// poisons the global key index so the victim's thumbprint V resolves to the
/// ATTACKER's public key, then forges a naked revoke of V. Under the
/// disclosed-key model the attacker must disclose a `key`; disclosing their own
/// key fails the BIND (`H(attacker pub) != V`). The forge MUST be rejected and
/// the victim's real key MUST stay alive.
///
/// Behavior: green on both servers -- the merged server rejects via its
/// point-of-use recheck (`H(indexed attacker pub) != V`, 400); the reworked
/// server rejects at the bind against the DISCLOSED key (400). The poison-took
/// precondition (push 201 + `index[V]` == attacker pub) is asserted first and
/// holds on both servers, so the rejection is genuine, not a setup miss.
///
/// This is distinct from `forge_disclosing_non_victim_key_is_rejected`: that
/// test never poisons the index. Here `index[V]` is the attacker pub, proving
/// that even a poisoned index cannot turn the forge into an accept.
#[tokio::test]
async fn index_poisoning_naked_revoke_forge_is_rejected() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();

    // Victim: a normal principal (golden genesis adds key_a). key_a's real
    // thumbprint V = H(key_a pub) is indexed to key_a's real pub.
    let victim_pid = bootstrap_golden_key_a(&state, &pool).await;
    let victim_pid = victim_pid.as_str();
    let victim_tmb = tmb_b64(&pool, "key_a");

    // Baseline: the victim key logs in before any attack.
    assert_eq!(
        login_status(&state, &pool, "key_a", victim_pid).await,
        StatusCode::OK,
        "the victim key must log in before the attack (empirical baseline)"
    );

    // Attack step 1: try to overwrite index[V] -> attacker (alice) pub via a
    // fresh attacker principal's unauthenticated genesis push whose sidecar
    // `pub` is swapped. `alice` is a distinct key whose private half the
    // attacker holds (to sign the forge). The attacker principal's id is its
    // genesis-derived id, so the refusal below is for the swapped sidecar.
    let body = poison_genesis_push_body(&pool, "bob", "key_a", "alice", RVK);
    let (pstatus, pjson) = post_push(&state, body).await;
    assert!(
        pstatus.is_client_error(),
        "a push whose sidecar pub does not hash to its tmb must be refused: {pstatus} {pjson:?}"
    );

    // The poison did not take: the global index still resolves the victim's
    // thumbprint to the victim's real pub, so the forge below is rejected on
    // its own merits (the disclosed key does not bind), not on a setup miss.
    let indexed = state
        .engine
        .indexer()
        .get_key(&victim_tmb)
        .await
        .expect("index lookup succeeds")
        .expect("V is still indexed after the refused poison push");
    assert_eq!(
        indexed.public_key,
        pool.get("key_a").expect("key_a").pub_key,
        "index[V] must still resolve to the victim's real pub"
    );

    // Poison the index directly instead: a wire push can no longer do it.
    poison_index_directly(&state, &pool, &victim_tmb, "alice").await;

    // Attack step 2 (against the directly poisoned index): forge a naked revoke of V, signed with
    // and disclosing the ATTACKER key. The disclosed attacker pub does not hash to V, so the bind
    // rejects it.
    let coz = revoke_body(
        &pool,
        &victim_tmb,
        "alice",
        Some("alice"),
        serde_json::json!(RVK),
    );
    let (rstatus, rjson) = post_revoke(&state, coz).await;

    // The forged revoke must be rejected...
    assert_rejected(
        rstatus,
        &rjson,
        "index-poisoning revoke forge (disclosed attacker key does not hash to the victim tmb)",
    );
    // ...and the victim's real key must survive it -- still logs in.
    assert_eq!(
        login_status(&state, &pool, "key_a", victim_pid).await,
        StatusCode::OK,
        "the victim's real key must stay alive after the forged revoke is rejected"
    );
}

// ========================================================================
// 13 -- HARDENING R-size: bound the revoke coz to coz's RVK_MAX_SIZE
// ========================================================================

/// A self-signed naked revoke whose body exceeds coz's `RVK_MAX_SIZE` (2048
/// bytes) is rejected. The oversize is real payload the signature covers (a
/// large `pad` field), so it is a semantically valid revoke that only the size
/// bound rejects -- never a parse or signature failure.
///
/// Behavior: green on both servers (the `RVK_MAX_SIZE` bound over the serialized
/// payload is unchanged); the revoke discloses key_a's key so it reaches the
/// size check.
#[tokio::test]
async fn oversize_naked_revoke_is_rejected() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    bootstrap_golden_key_a(&state, &pool).await;

    let signer = pool.get("key_a").expect("key_a");
    // Pad well past RVK_MAX_SIZE (but far under any default transport limit),
    // so the body exceeds the bound at both the payload and the wire level.
    let pad = "A".repeat(coz::RVK_MAX_SIZE * 2);
    let pay = serde_json::json!({
        "alg": signer.alg,
        "now": RVK,
        "pad": pad,
        "rvk": RVK,
        "tmb": tmb_b64(&pool, "key_a"),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let coz = sign_coz_disclosed(&pool, "key_a", pay, "key_a");
    assert!(
        coz.to_string().len() > coz::RVK_MAX_SIZE,
        "the test body must exceed RVK_MAX_SIZE to exercise the bound"
    );

    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(
        status,
        &json,
        "revoke body exceeding RVK_MAX_SIZE (2048 bytes)",
    );
}

// ========================================================================
// 14 -- HARDENING R2: the death record is durable across a store reopen
// ========================================================================
