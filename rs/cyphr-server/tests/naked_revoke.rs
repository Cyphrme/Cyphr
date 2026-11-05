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
use cyphr_server::observation::ObservationStore;
use cyphr_server::{AppState, build_router};
use cyphr_storage::index::Indexer;
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
/// are genuinely active keys of this exact principal AND indexed globally.
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

/// Flip one bit of a coz's detached signature, leaving payload and disclosed
/// key intact.
fn corrupt_sig(mut coz: serde_json::Value) -> serde_json::Value {
    let sig_b64 = coz["sig"].as_str().expect("sig present");
    let mut sig = Base64UrlUnpadded::decode_vec(sig_b64).expect("sig b64");
    sig[0] ^= 0x01;
    coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&sig));
    coz
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
// key can be exercised at the push gate). These mirror tests/route_protection.rs
// -- a separate integration crate that cannot be imported; the common harness's
// `sign_key_create_commit` does not return the CommitEntry a replay needs, so
// the entry-returning variant is reproduced here.
// ========================================================================

/// Sign a fresh "add `new_key_name`" commit onto `principal`, signed by
/// `signer_name`. Returns the new commit's raw coz blobs (wire-ready) plus its
/// `CommitEntry`, the latter so a caller can replay it onto a FRESH principal
/// (`Principal::clone()` shares the durable log rather than deep-copying, so
/// two clones both appending "the next commit" collide on one leaf).
fn sign_key_create_commit(
    mut principal: cyphr::Principal,
    pool: &Pool,
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

/// A push body's blob list, base64url-encoded, wrapped with `principal_id`.
fn push_body(pid: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": pid,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// The genesis `cyphr::Key` for pool key `name` (first_seen 0, like a fixture
/// genesis).
fn genesis_key(pool: &Pool, name: &str) -> cyphr::Key {
    let k = pool.get(name).expect("genesis key in pool");
    cyphr::Key {
        alg: k.alg.clone(),
        tmb: k.compute_tmb().expect("genesis tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&k.pub_key).expect("genesis pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Bootstrap `pid` over real HTTP with an implicit `genesis_name` genesis that
/// adds `added_name`, and return the genesis key + entry so a follow-up push
/// can chain onto it. An HTTP-bootstrapped principal is the only valid target
/// for a genesis-less follow-up push (`resolve_genesis` re-derives genesis
/// from the first stored commit's embedded key).
async fn bootstrap_via_push(
    state: &Arc<AppState>,
    pool: &Pool,
    pid: &str,
    genesis_name: &str,
    added_name: &str,
    now: i64,
) -> (cyphr::Key, cyphr_storage::CommitEntry) {
    let gkey = genesis_key(pool, genesis_name);
    let principal = cyphr::Principal::implicit(gkey.clone()).expect("implicit genesis");
    let (mut blobs, entry) = sign_key_create_commit(principal, pool, genesis_name, added_name, now);

    // The closing cozy of a never-before-seen principal's genesis carries the
    // embedded genesis key `resolve_genesis` needs.
    let closing_idx = blobs.len() - 1;
    let mut closing: serde_json::Value = serde_json::from_slice(&blobs[closing_idx]).unwrap();
    closing.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": gkey.alg,
            "pub": pool.get(genesis_name).unwrap().pub_key,
            "tmb": Base64UrlUnpadded::encode_string(gkey.tmb.as_bytes()),
        }),
    );
    blobs[closing_idx] = serde_json::to_vec(&closing).unwrap();

    let (status, json) =
        common::post_json(build_router(state.clone()), "/push", push_body(pid, &blobs)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis bootstrap push for {pid} must succeed: {json:?}"
    );
    (gkey, entry)
}

/// Build a genesis-less follow-up push body for the existing `pid`: replay the
/// genesis commit onto a fresh principal, then a fresh "add `added_name`"
/// commit signed by `signer_name`. The signing key `signer_name` is the one
/// the push gate must death-check.
fn followup_push_body(
    pool: &Pool,
    pid: &str,
    genesis_key: cyphr::Key,
    genesis_entry: &cyphr_storage::CommitEntry,
    signer_name: &str,
    added_name: &str,
    now: i64,
) -> String {
    let replayed = cyphr_storage::load_principal_from_commits(
        cyphr_storage::Genesis::Implicit(genesis_key),
        std::slice::from_ref(genesis_entry),
    )
    .expect("replay the genesis commit onto a fresh principal");
    let (blobs, _entry) = sign_key_create_commit(replayed, pool, signer_name, added_name, now);
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
    let pid = "nr-accept";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-keyless-body";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-forge-bind";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-forge-sig";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let victim_pid = "nr-avail-victim";
    bootstrap_golden_key_a(&state, &pool, victim_pid).await;
    let victim_tmb = tmb_b64(&pool, "key_a");

    // Attack: overwrite index[V] -> attacker (alice) pub via a fresh attacker
    // principal's unauthenticated poison genesis push. `alice` is a distinct
    // key whose private half the attacker holds.
    let body =
        poison_genesis_push_body(&pool, "nr-avail-attacker", "bob", "alice", &victim_tmb, RVK);
    let (pstatus, pjson) = post_push(&state, body).await;
    assert_eq!(
        pstatus,
        StatusCode::CREATED,
        "the unauthenticated poison push must be accepted -- the key-introduction tmb==H(pub) gap \
         it exploits is out of this node's scope: {pjson:?}"
    );

    // Poison-took precondition: the global index now returns the ATTACKER pub
    // for the victim's thumbprint. Asserting it makes the DoS genuine (not a
    // vacuous no-poison pass).
    let poisoned = state
        .engine
        .indexer()
        .get_key(&victim_tmb)
        .await
        .expect("index lookup succeeds")
        .expect("V is still indexed after the poison push");
    assert_eq!(
        poisoned.public_key,
        pool.get("alice").expect("alice").pub_key,
        "index[V] must now resolve to the attacker's pub -- the DoS precondition"
    );

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
        let (status, json) = post_revoke(&state, coz).await;
        assert_rejected(status, &json, case);
    }
}

/// A revoke whose signature does not verify against its disclosed key is
/// rejected.
///
/// Behavior: green on both servers -- the reworked server verifies the
/// corrupted signature against the disclosed key (401); the merged server
/// against the indexed key. The disclosed key is intact; only the signature is
/// corrupted.
#[tokio::test]
async fn rejects_bad_signature() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-bad-sig";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = corrupt_sig(self_revoke_coz(&pool, "key_a", serde_json::json!(RVK)));
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(status, &json, "corrupted signature");
}

/// A coz whose `typ` is not `key/revoke` is not a naked revoke and is rejected,
/// even when it discloses a valid key.
///
/// Behavior: green on both servers (the `typ` gate is unchanged).
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
    let coz = sign_coz_disclosed(&pool, "key_a", pay, "key_a");
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(status, &json, "typ is not key/revoke");
}

/// A revoke for a `tmb` this server never indexed is rejected by the PRESENCE
/// fence: the global key index has no entry for it, so the revoke is refused
/// even with a valid disclosed self-signed key (the head-ratified conservative
/// bound -- unknown keys are refused). `alice` is a valid pool key never pushed
/// to this server, self-signing and disclosing its own revoke.
///
/// Behavior: green on both servers (both refuse an unindexed `tmb`); the
/// reworked server refuses at the presence fence, the merged server at the
/// key-index miss.
#[tokio::test]
async fn rejects_unknown_tmb() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-unknown-tmb";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz = self_revoke_coz(&pool, "alice", serde_json::json!(RVK));
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(status, &json, "tmb never indexed by this server");
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
    let pid = "nr-presigned";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-idempotent";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
/// `reindex` -- proving the death record is durable and is NOT held in the
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
// 6 -- Login refusal + key-scoping: the dead key is refused, siblings survive
// ========================================================================

/// After a self-signed naked revoke of `key_a`, `key_a` is refused at login
/// while `golden` (untouched, still active on-chain) still logs in -- the
/// refusal is scoped to the revoked key, not the whole principal.
///
/// Behavior: green on both servers (login refusal + key-scoping unchanged).
// docket: signon-disowned-key :: scripts/docket-test signon-disowned-key
#[tokio::test]
async fn revoked_key_refused_at_login_sibling_survives() {
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
    let pid = "nr-push-death";
    let (gkey, gentry) = bootstrap_via_push(&state, &pool, pid, "golden", "key_a", RVK).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted before the push gate can be tested, got {rstatus}: \
         {rjson:?}"
    );

    // A follow-up commit signed by the now-dead key_a.
    let body = followup_push_body(&pool, pid, gkey, &gentry, "key_a", "carol", RVK + 100);
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
    let pid = "nr-push-sibling";
    let (gkey, gentry) = bootstrap_via_push(&state, &pool, pid, "golden", "key_a", RVK).await;

    let coz = self_revoke_coz(&pool, "key_a", serde_json::json!(RVK));
    let (rstatus, rjson) = post_revoke(&state, coz).await;
    assert!(
        rstatus.is_success(),
        "the naked revoke must be accepted first, got {rstatus}: {rjson:?}"
    );

    // A follow-up commit signed by the still-live golden.
    let body = followup_push_body(&pool, pid, gkey, &gentry, "golden", "carol", RVK + 100);
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
    let pid1 = "nr-global-1";
    let pid2 = "nr-global-2";

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
    let pid = "nr-pr-unchanged";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-keyless";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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
    let pid = "nr-golden";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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

/// Build a fresh ATTACKER principal's genesis push whose single added key is
/// POISONED: the embedded key block declares `declared_tmb_b64` (the victim
/// thumbprint to hijack) while carrying `attacker_key_name`'s REAL public key.
///
/// No key-introduction site enforces `tmb == H(pub)`, and the global key index
/// trusts the client-declared `tmb`, overwriting on reuse -- so pushing this
/// overwrites `index[declared_tmb_b64]` to point at the attacker's pubkey. The
/// new-principal genesis push is unauthenticated (`genesis_name` self-authorizes
/// it), so no existing credential is needed. The attacker holds
/// `attacker_key_name`'s private key and will sign the forged revoke with it.
///
/// (The key-introduction `tmb == H(pub)` gap this exploits is broader than
/// revoke and out of this node's scope; the disclosed-key verification in
/// `interpret` is what closes the revoke exploit.)
fn poison_genesis_push_body(
    pool: &Pool,
    attacker_pid: &str,
    genesis_name: &str,
    attacker_key_name: &str,
    declared_tmb_b64: &str,
    now: i64,
) -> String {
    let genesis = pool.get(genesis_name).expect("genesis key in pool");
    let attacker = pool.get(attacker_key_name).expect("attacker key in pool");

    let genesis_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb");
    let genesis_prv = Base64UrlUnpadded::decode_vec(genesis.prv.as_ref().expect("genesis prv"))
        .expect("genesis prv b64");
    let genesis_pub = Base64UrlUnpadded::decode_vec(&genesis.pub_key).expect("genesis pub b64");

    // A key/create whose DECLARED new-key id is the victim's thumbprint.
    let pay_value = serde_json::json!({
        "alg": genesis.alg,
        "id": declared_tmb_b64,
        "now": now,
        "tmb": genesis_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_vec = serde_json::to_vec(&pay_value).unwrap();
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &genesis.alg, &genesis_prv, &genesis_pub)
        .expect("signing supported");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &genesis.alg).expect("czd for this algorithm");

    // The POISONED key: declared thumbprint = the victim's V, but the actual
    // public key is the attacker's own (whose private key signs the revoke).
    let victim_tmb_bytes =
        Base64UrlUnpadded::decode_vec(declared_tmb_b64).expect("victim tmb base64");
    let attacker_pub =
        Base64UrlUnpadded::decode_vec(&attacker.pub_key).expect("attacker pub base64");
    let poisoned_key = cyphr::Key {
        alg: attacker.alg.clone(),
        tmb: coz::Thumbprint::from_bytes(victim_tmb_bytes),
        pub_key: attacker_pub,
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let genesis_key = cyphr::Key {
        alg: genesis.alg.clone(),
        tmb: genesis.compute_tmb().expect("genesis tmb"),
        pub_key: genesis_pub.clone(),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    let mut principal = cyphr::Principal::implicit(genesis_key.clone()).expect("implicit genesis");

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(poisoned_key))
        .expect("poison key/create must verify (no tmb==H(pub) gate at key introduction)");
    let genesis_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&genesis_tmb_b64).expect("genesis tmb base64"),
    );
    scope
        .finalize_with_arrow(
            &genesis.alg,
            &genesis_prv,
            &genesis_pub,
            &genesis_tmb,
            now,
            "cyphr.me",
        )
        .expect("poison commit should finalize");

    let entries = cyphr_storage::export_commits(&principal).expect("export the poison commit");
    let new_commit = entries.last().expect("at least one commit after finalize");

    // Embed the (poisoned) key block on the key-introducing cozy, then the
    // genesis key on the closing cozy -- the never-before-seen-principal wire
    // contract `resolve_genesis` requires.
    let mut key_idx = 0;
    let mut blobs: Vec<Vec<u8>> = new_commit
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

    let closing_idx = blobs.len() - 1;
    let mut closing: serde_json::Value = serde_json::from_slice(&blobs[closing_idx]).unwrap();
    closing.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": genesis_key.alg,
            "pub": genesis.pub_key,
            "tmb": genesis_tmb_b64,
        }),
    );
    blobs[closing_idx] = serde_json::to_vec(&closing).unwrap();

    push_body(attacker_pid, &blobs)
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
    let victim_pid = "nr-poison-victim";
    bootstrap_golden_key_a(&state, &pool, victim_pid).await;
    let victim_tmb = tmb_b64(&pool, "key_a");

    // Baseline: the victim key logs in before any attack.
    assert_eq!(
        login_status(&state, &pool, "key_a", victim_pid).await,
        StatusCode::OK,
        "the victim key must log in before the attack (empirical baseline)"
    );

    // Attack step 1: overwrite index[V] -> attacker (alice) pub via a fresh
    // attacker principal's unauthenticated poison genesis push. `alice` is a
    // distinct key whose private half the attacker holds (to sign the forge).
    let body = poison_genesis_push_body(
        &pool,
        "nr-poison-attacker",
        "bob",
        "alice",
        &victim_tmb,
        RVK,
    );
    let (pstatus, pjson) = post_push(&state, body).await;
    assert_eq!(
        pstatus,
        StatusCode::CREATED,
        "the unauthenticated poison push must be accepted -- the key-introduction tmb==H(pub) gap \
         it exploits is out of this node's scope: {pjson:?}"
    );

    // Poison-took precondition: the global index now returns the ATTACKER pub
    // for the victim's thumbprint. If this failed, the test would be vacuous
    // (no real poisoning); asserting it makes the attack genuine.
    let poisoned = state
        .engine
        .indexer()
        .get_key(&victim_tmb)
        .await
        .expect("index lookup succeeds")
        .expect("V is still indexed after the poison push");
    assert_eq!(
        poisoned.public_key,
        pool.get("alice").expect("alice").pub_key,
        "index[V] must now resolve to the attacker's pub -- the attack precondition"
    );

    // Attack step 2: forge a naked revoke of V, signed with and disclosing the
    // ATTACKER key. The disclosed attacker pub does not hash to V, so the bind
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
    let pid = "nr-oversize";
    bootstrap_golden_key_a(&state, &pool, pid).await;

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

/// A recorded death survives a fresh `ObservationStore` opened over the same
/// on-disk directory: after `record`, a brand-new store instance reading the
/// same path still reports the key dead. This pins the durability barrier R2
/// hardens -- an ack of `recorded: true` must not be a lie a crash can undo.
///
/// Baseline note: if fjall's configured durability already persists a `record`
/// before this reopen sees it, this passes against the current impl and is kept
/// as regression coverage. It cannot, in-process, simulate a true crash BEFORE
/// fjall's WAL flush (the precise R2 window); the impl-worker must assess
/// whether `record` needs an explicit synchronous `persist` before returning
/// `recorded: true`.
#[tokio::test]
async fn death_record_durable_across_store_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_path = dir.path().join("observations");
    let pool = common::load_pool();
    let dead_tmb = pool
        .get("key_a")
        .expect("key_a")
        .compute_tmb()
        .expect("tmb");

    {
        let store = ObservationStore::open(&store_path).expect("open death-set store");
        store
            .record(&dead_tmb, serde_json::json!({ "note": "naked revoke" }))
            .await
            .expect("record the death");
        assert!(
            store.is_dead(&dead_tmb).await.expect("is_dead"),
            "the key must be dead in the recording store instance"
        );
    }

    // A brand-new store over the same directory -- the death must persist.
    let reopened = ObservationStore::open(&store_path).expect("reopen death-set store");
    assert!(
        reopened
            .is_dead(&dead_tmb)
            .await
            .expect("is_dead after reopen"),
        "the death record must survive a store reopen over the same data dir"
    );
}
