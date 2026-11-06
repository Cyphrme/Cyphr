//! W1 (time and portability), server tier: the `now` of every pushed coz is
//! bounded, and history replays regardless of the clock.
//!
//! The claim: no message from the future is accepted, and an old chain still
//! verifies later. Two rules back it (nrd's future-timestamp ruling; SPEC 6.4,
//! `now` is an integer in `1..2^53-1`):
//!
//! 1. a coz whose `now` is above the verifier clock plus a small drift, or outside `1..2^53-1`, is
//!    refused through `POST /push` with a typed (4xx) error naming the timestamp, and nothing
//!    lands;
//! 2. a chain dated far before the clock is accepted and keeps loading.
//!
//! Wire bundles are authored by taking the core-built bundle at a legitimate
//! `now` and re-signing its cozies at the probed `now`. The core
//! builder would refuse to author the probed value once the rule is enforced
//! (see the note in `spec_conformance.rs`), so the probe cannot go through
//! it. The closing `commit/create` keeps its original arrow, which no longer
//! matches; the refusal must therefore name the timestamp, not the arrow,
//! which pins that the bound is checked as the coz is applied and not as a
//! side effect of some later mismatch.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    build_genesis_push_body, envelope_payload, get_json, golden_principal_id, keyless_server,
    load_pool, post_json,
};

/// A legitimate, long-past timestamp: the control the probes deviate from.
const OLD: i64 = 1_700_100_000;
/// 2^53 - 1, the largest `now` in range (SPEC 6.4).
const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn wall_clock() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let k = coz::Alg::Ed25519.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn b64(t: &coz::Thumbprint) -> String {
    Base64UrlUnpadded::encode_string(t.as_bytes())
}

fn sign(k: &Kp, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

/// Apply the same `now` through both core entry paths (a data action and a
/// `key/create` commit) on a default `Principal`.
fn now_outcomes(at: i64) -> (cyphr::error::Result<()>, cyphr::error::Result<()>) {
    let (g, k2) = (kp(), kp());
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    let (pay, sig, czd) = sign(
        &g,
        serde_json::json!({"alg": g.alg, "now": at, "tmb": b64(&g.tmb), "typ": "cyphr.me/cyphr/data/x"}),
    );
    let action = p.verify_and_record_action(&pay, &sig, czd).map(|_| ());
    let create = (|| {
        let (pay, sig, czd) = sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": b64(&k2.tmb), "now": at, "tmb": b64(&g.tmb),
                               "typ": "cyphr.me/cyphr/key/create"}),
        );
        let mut scope = p.begin_commit();
        scope.verify_and_apply(&pay, &sig, czd, Some(key_of(&k2)))?;
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb),
                at,
                "cyphr.me",
            )
            .map(|_| ())
    })();
    (action, create)
}

/// Backs the future-timestamp rule: a `now` beyond the verifier clock plus a
/// small drift is refused on every entry path, whatever the magnitude.
/// Scenario, default `Principal`: a data action and a `key/create` commit
/// dated 2^53 - 1 (the largest in-range value, centuries ahead) and
/// `i64::MAX` are applied. In-range-but-future must be the typed
/// `TimestampFuture`; `i64::MAX` is out of range and need only be refused.
/// Turns red if a far-future `now` is accepted on any path (the SC1-F5 red
/// covers a day ahead; this covers the extremes, where a clock-plus-drift sum
/// can also overflow). Unit-level on purpose: the extremes cannot be authored
/// through the server builder. Lives here, not in the core `spec_conformance.rs`,
/// because that file's map test demands a docs row for every red there.
#[test]
fn now_bound_far_future_is_refused_on_every_entry_path() {
    let (action, create) = now_outcomes(MAX_SAFE);
    assert!(
        matches!(action, Err(cyphr::Error::TimestampFuture)),
        "action at 2^53 - 1: {action:?}"
    );
    assert!(
        matches!(create, Err(cyphr::Error::TimestampFuture)),
        "key/create at 2^53 - 1: {create:?}"
    );
    let (action, create) = now_outcomes(i64::MAX);
    assert!(action.is_err(), "action at i64::MAX accepted");
    assert!(create.is_err(), "key/create at i64::MAX accepted");
}

/// Backs SPEC 6.4: the 2^53 - 1 ceiling holds whatever the clock says.
/// Scenario: a principal whose injected clock is broken (reads `i64::MAX`)
/// is offered a data action at 2^53; it is refused, while 2^53 - 1 is
/// accepted. Turns red if the range ceiling is dropped and only the clock
/// bounds `now`. Unit-level on purpose: only an injected clock can reach it.
#[test]
fn now_bound_range_ceiling_holds_for_a_runaway_clock() {
    let outcome = |at: i64| {
        let g = kp();
        let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
        p.set_clock(|| i64::MAX);
        let (pay, sig, czd) = sign(
            &g,
            serde_json::json!({"alg": g.alg, "now": at, "tmb": b64(&g.tmb), "typ": "cyphr.me/cyphr/data/x"}),
        );
        p.verify_and_record_action(&pay, &sig, czd).map(|_| ())
    };
    outcome(MAX_SAFE).expect("control: 2^53 - 1 is in range");
    assert!(
        matches!(outcome(MAX_SAFE + 1), Err(cyphr::Error::TimestampFuture)),
        "2^53 accepted under a runaway clock"
    );
}

/// `body` with every coz (the genesis key's `key/create` and the closing
/// `commit/create`, both signed by `golden`) re-signed at `now`. One shared
/// `now` keeps the bundle monotone, so the only defect left in it is the
/// probed value (and the stale arrow described in the module docs).
fn retimed(pool: &test_fixtures::Pool, body: &str, now: i64) -> String {
    let golden = pool.get("golden").expect("golden in pool");
    let prv =
        Base64UrlUnpadded::decode_vec(golden.prv.as_ref().expect("golden prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub b64");

    let mut json: serde_json::Value = serde_json::from_str(body).expect("push body is JSON");
    for blob in json["blobs"].as_array_mut().expect("blobs array") {
        let raw =
            Base64UrlUnpadded::decode_vec(blob.as_str().expect("blob string")).expect("blob b64");
        let mut coz: serde_json::Value = serde_json::from_slice(&raw).expect("blob is JSON");
        coz["pay"]["now"] = serde_json::json!(now);
        coz["pay"].as_object_mut().expect("pay object").sort_keys();
        let pay = serde_json::to_vec(&coz["pay"]).expect("serialize pay");
        let (sig, _cad) = coz::sign_json(&pay, &golden.alg, &prv, &pubb).expect("sign");
        coz["sig"] = serde_json::json!(Base64UrlUnpadded::encode_string(&sig));
        *blob = serde_json::Value::String(Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(&coz).expect("serialize coz"),
        ));
    }
    json.to_string()
}

/// Push `body` to a fresh keyless server and assert it is refused with a
/// typed 4xx whose message names the timestamp, leaving no principal.
async fn assert_refused_for_time(pool: &test_fixtures::Pool, body: String, label: &str) {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, resp) = post_json(app.clone(), "/push", body).await;
    let text = resp["payload"]["error"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    // Whole words only: "unknown" contains "now".
    let words: Vec<&str> = text.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    assert!(
        matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "{label}: expected a 400/422 refusal, got {status}: {resp:?}"
    );
    assert!(
        words.contains(&"timestamp") || words.contains(&"now"),
        "{label}: the refusal must name the timestamp, got: {resp:?}"
    );
    let (tip, _) = get_json(app, &format!("/tip?pr={}", golden_principal_id(pool))).await;
    assert_eq!(tip, StatusCode::NOT_FOUND, "{label}: nothing may land");
}

/// Backs: no message from the future is accepted. Scenario: a genesis bundle
/// whose cozies are dated a day ahead, at 2^53 - 1 (in range, far future),
/// and at `i64::MAX` is pushed to a fresh server; each is refused with a
/// typed timestamp error and the principal does not exist afterwards. Turns
/// red if a far-future `now` is accepted, or is refused only as a side effect
/// of something else (the default config today: tolerance is disabled, so the
/// coz is applied and the refusal, if any, names the arrow). End to end: yes
/// (HTTP, engine, store).
#[tokio::test]
async fn push_refuses_a_now_above_clock_plus_drift() {
    let pool = load_pool();
    let id = golden_principal_id(&pool);
    let base = build_genesis_push_body(&pool, &id, OLD);
    for (label, now) in [
        ("a day ahead", wall_clock() + 86_400),
        ("2^53 - 1", MAX_SAFE),
        ("i64::MAX", i64::MAX),
    ] {
        assert_refused_for_time(&pool, retimed(&pool, &base, now), label).await;
    }
}

/// Backs SPEC 6.4: `now` is a positive integer below 2^53. Scenario: the same
/// genesis bundle with its cozies at 0, -1 and 2^53 is pushed; each is
/// refused with a typed timestamp error and nothing lands. Turns red if an
/// out-of-range `now` is accepted or is refused without naming the
/// timestamp. 2^53 - 1 is not probed here: it is in range and is covered by
/// the far-future case above. End to end: yes.
#[tokio::test]
async fn push_refuses_a_now_outside_the_safe_integer_range() {
    let pool = load_pool();
    let id = golden_principal_id(&pool);
    let base = build_genesis_push_body(&pool, &id, OLD);
    for (label, now) in [("zero", 0_i64), ("negative", -1), ("2^53", MAX_SAFE + 1)] {
        assert_refused_for_time(&pool, retimed(&pool, &base, now), label).await;
    }
}

/// Backs: history replays regardless of the clock. Scenario: a chain dated
/// years before the wall clock is pushed and accepted, and the principal then
/// loads from the store (a full replay) on every read. Turns red if the
/// bound is applied as a two-sided window around the clock on replay, which
/// would strand every old chain. A green characterization: it must survive
/// the fix. End to end: yes.
#[tokio::test]
async fn old_dated_history_is_accepted_and_replays() {
    let pool = load_pool();
    let id = golden_principal_id(&pool);
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (status, resp) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, OLD),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resp:?}");

    let (status, tip) = get_json(app, &format!("/tip?pr={id}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");
    assert_eq!(envelope_payload(&tip)["commit_count"], serde_json::json!(1));
}
