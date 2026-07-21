//! Acceptance suite for the witness naked-revoke ingest path (SPEC.md §6.4,
//! confirmed model).
//!
//! A **naked revoke** is a `key/revoke` coz signed *outside* a commit. Under
//! the confirmed §6.4 model a witness accepts one iff it is **self-signed** --
//! the key named by the coz's `tmb` signs its own revoke -- and thereafter
//! refuses that key GLOBALLY, by thumbprint, for every capability (login AND
//! push) and every principal that holds it. There is no principal scoping, no
//! third-party path, and no chain replay: verification resolves `tmb ->
//! pubkey` through the engine's global key index and checks one signature.
//!
//! ## Endpoint contract (this suite is the source of truth)
//!
//! - `POST /revoke`
//! - request body: the signed `key/revoke` coz ITSELF -- a bare `{ "pay": {..}, "sig": "<b64url>"
//!   }`, mirroring `/auth/login`'s `Json<CozJson>`. There is NO `principal_id` field and NO
//!   `RevokeRequest` wrapper: death is global-by-thumbprint, so no principal is named or loaded.
//! - on acceptance: a 2xx whose payload names `revoked_tmb` (no `principal_id`, no `kind`).
//!
//! ## Why every test drives the live HTTP endpoint
//!
//! An integration-test file is one binary: a reference to a not-yet-existing
//! symbol would fail the whole binary to compile, so no test could exhibit its
//! semantic red baseline. Every test therefore goes through `build_router` + a
//! real request. Against the current (superseded, principal-scoped) tip the
//! reds are behavioral: the endpoint does not accept the bare-coz request
//! shape, the global death-set / `is_dead` gate does not exist, and `/push`
//! does not death-check a signing key -- never a missing symbol or file.

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
// Coz + request builders
// ========================================================================

/// Sign `pay` with pool key `signer_name` and wrap it as a `{pay, sig}` coz
/// JSON value -- the bare-coz request body the confirmed model accepts. A
/// naked revoke is signed outside any commit, so none of the `begin_commit` /
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

/// A `key/revoke` coz naming `named_tmb_b64` as the revoked key but signed by
/// `signer_name`. When `signer_name` IS the key named by `named_tmb_b64` this
/// is a self-signed revoke (accepted); when it is any other key the signature
/// will not verify against the named key and the revoke is rejected -- the
/// single check that IS the self-signed-only rule.
fn revoke_coz_named(
    pool: &Pool,
    named_tmb_b64: &str,
    signer_name: &str,
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
    sign_coz(pool, signer_name, pay)
}

/// A self-signed naked-revoke coz: `signer_name` revokes *itself* (`pay.tmb`
/// is the signer's own thumbprint), the confirmed §6.4 self-revoke shape.
/// `rvk` overridable to exercise the malformed-`rvk` matrix and the pre-signed
/// `rvk`=1 case.
fn self_revoke_coz(pool: &Pool, signer_name: &str, rvk: serde_json::Value) -> serde_json::Value {
    let tmb_b64 = pool
        .get(signer_name)
        .expect("signer in pool")
        .compute_tmb_b64()
        .expect("signer tmb");
    revoke_coz_named(pool, &tmb_b64, signer_name, rvk)
}

/// Flip one bit of a coz's detached signature, leaving the payload intact.
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

/// POST a bare naked-revoke coz to `/revoke` and return the status + parsed
/// body. The body IS the coz (no wrapper): the confirmed request shape.
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
    let err = json["error"].as_str().unwrap_or("");
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

/// A well-formed self-signed `key/revoke` coz for an indexed key, with a valid
/// `rvk`, is accepted (2xx). Its response names `revoked_tmb` and carries
/// neither the deleted `principal_id` nor the deleted `kind`.
///
/// Red baseline: the endpoint does not accept the bare-coz request shape (the
/// current handler deserializes `{principal_id, coz}`), so the post is not a
/// success and the response has no `revoked_tmb`.
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
// 2 -- Reject malformed / mis-signed / unknown revokes, each a distinct 4xx
// ========================================================================

/// Each out-of-range `rvk` (zero, negative, ≥ 2^53-1, non-integer) is a
/// distinct rejection: `rvk` must be a positive integer below 2^53-1.
///
/// Red baseline: the bare-coz shape is unsupported, so each case fails to
/// route into the revoke logic that would distinctly reject it.
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

/// A revoke whose signature does not verify against its named key is rejected.
///
/// Red baseline: the bare-coz shape is unsupported.
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

/// A coz whose `typ` is not `key/revoke` is not a naked revoke and is rejected.
///
/// Red baseline: the bare-coz shape is unsupported.
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
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(status, &json, "typ is not key/revoke");
}

/// A revoke signed by a DIFFERENT key than it names is rejected: the signature
/// does not verify against the named key's public key. This single check IS
/// the self-signed-only rule -- there is no third-party "recorded" path. Here
/// `golden` (a valid, indexed sibling key of the same principal) signs a
/// revoke naming `key_a`; even a sibling key cannot revoke another.
///
/// Red baseline: the bare-coz shape is unsupported. (Once the shape is
/// accepted, the resolve-tmb-then-verify path rejects the non-self signature.)
#[tokio::test]
async fn rejects_revoke_signed_by_different_key() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-not-self";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    // `golden` signs, but the coz names `key_a`: the signature will not verify
    // against key_a's public key.
    let coz = revoke_coz_named(
        &pool,
        &tmb_b64(&pool, "key_a"),
        "golden",
        serde_json::json!(RVK),
    );
    let (status, json) = post_revoke(&state, coz).await;
    assert_rejected(
        status,
        &json,
        "revoke signed by a key other than the one it names",
    );
}

/// A revoke for a `tmb` this server never indexed is rejected: the global key
/// lookup returns nothing to verify against. `alice` is a valid pool key never
/// pushed to this server, self-signing its own revoke.
///
/// Red baseline: the bare-coz shape is unsupported. (Once accepted, the global
/// `get_key(alice)` miss rejects it.)
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
// 3 -- Pre-signed and idempotent acceptance (timestamp not validated)
// ========================================================================

/// A pre-signed revoke with `rvk`=1 is accepted: the confirmed model requires
/// only that `rvk` be a positive integer below 2^53-1 and does NOT validate
/// the timestamp value.
///
/// Red baseline: the bare-coz shape is unsupported.
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
/// Red baseline: the bare-coz shape is unsupported (the first revoke already
/// fails, so the second cannot be a no-op over an existing record).
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
// 4 -- Durability: the death record survives an AppState rebuild AND a reindex
// ========================================================================

/// After a naked revoke, the resulting refusal survives BOTH a full `AppState`
/// rebuild over the same data dir (a restart) AND an in-process engine
/// `reindex` -- proving the death record is durable and is NOT held in the
/// rebuildable index. Observed through the login gate: the revoked key stays
/// refused across both.
///
/// Red baseline: the revoke is not accepted (bare-coz shape unsupported), so
/// after restart+reindex the key still logs in -- the record never existed to
/// survive.
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
// 5 -- Login refusal + key-scoping: the dead key is refused, siblings survive
// ========================================================================

/// After a self-signed naked revoke of `key_a`, `key_a` is refused at login
/// while `golden` (untouched, still active on-chain) still logs in -- the
/// refusal is scoped to the revoked key, not the whole principal.
///
/// Red baseline: the revoke is not accepted, so `key_a` still logs in (200) --
/// exactly what the assertion says must become 401.
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
// 6 -- Global death across capabilities: the dead key is refused at PUSH too
// ========================================================================

/// After revoking `key_a`, a `/push` whose follow-up commit is SIGNED BY
/// `key_a` is refused -- the death is global across capabilities, not just
/// login. The refusal is a distinct auth-shaped rejection (401/403), never a
/// 2xx accept and never a 409 conflict (which would be a false green from a
/// stale-predecessor collision rather than the death gate).
///
/// Red baseline: `/push` has no death-check, so a commit signed by the
/// (not-actually-revoked, bare-coz-unsupported) key_a is accepted (201) --
/// exactly what must become a refusal.
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
    assert!(
        !json["error"].as_str().unwrap_or("").is_empty(),
        "the push refusal must name its cause in an {{\"error\": …}} body, got {json:?}"
    );
}

/// A sibling key still pushes after another key of the principal is revoked:
/// only the dead `key_a` is refused, so `golden` authors a follow-up commit
/// normally. The push-side dual of the login key-scoping test; it pins that a
/// push death-check must not over-reach past the revoked thumbprint.
///
/// Red baseline: the revoke is not accepted (bare-coz shape unsupported), so
/// the assertion that it must be accepted fails before the sibling push runs.
/// Once the revoke path lands, an over-broad push death-check that refused the
/// live `golden` would fail the final assertion.
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
// 7 -- Global death across principals: one revoke kills the key everywhere
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
/// Red baseline: the revoke is not accepted (bare-coz shape unsupported), so
/// both principals' `key_a` still log in.
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
// 8 -- PR is unchanged: a naked revoke mutates no chain root (§6.4)
// ========================================================================

/// The principal's tip roots (`pr`, `sr`, `ar`, `cr`, `commit_count`) are
/// byte-identical before and after a naked revoke -- an uncommitted naked
/// revoke does not mutate PR.
///
/// Red baseline: the revoke is not accepted, so the accept assertion (bound to
/// the PR-unchanged property so the property is not proven vacuously) fails.
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
// 9 -- A keyless server accepts and interprets a naked revoke
// ========================================================================

/// A keyless server (no signing identity of its own) still accepts and
/// interprets a naked revoke: verification is against the *engine's* global
/// key index and the death-set, neither of which needs the server's signing
/// identity. Observed directly at the endpoint (2xx), since a keyless server
/// has no login route configured.
///
/// Red baseline: the bare-coz shape is unsupported.
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
// 10 -- The committed golden vector round-trips through the ingest path
// ========================================================================

/// The pinned golden naked-revoke coz (self-signed by `key_a`, valid `rvk`) is
/// accepted by the ingest path. A silent drift in the wire shape the server
/// accepts breaks this loudly. The fixture is committed alongside this suite at
/// `tests/golden/naked_revoke_valid.json`, already in the bare-coz request
/// shape; its signature verifies against `key_a`.
///
/// Red baseline: the bare-coz shape is unsupported.
#[tokio::test]
async fn golden_naked_revoke_vector_is_accepted() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "nr-golden";
    bootstrap_golden_key_a(&state, &pool, pid).await;

    let coz: serde_json::Value =
        serde_json::from_str(&golden("naked_revoke_valid.json")).expect("parse golden vector");
    // The fixture is self-consistent: a self-signed key/revoke naming key_a.
    assert_eq!(coz["pay"]["typ"], "cyphr.me/cyphr/key/revoke");
    assert_eq!(
        coz["pay"]["tmb"].as_str(),
        Some(tmb_b64(&pool, "key_a").as_str()),
        "the golden fixture must name key_a's thumbprint (self-signed)"
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
