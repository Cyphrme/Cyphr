//! Equivocation evidence: a pure verification helper proving that two
//! conflicting signed tip reports about the same principal state
//! constitute portable, self-contained proof of server misbehavior
//! (`docs/specs/receipts.md`'s equivocation section).
//!
//! Detection is verifier-side and stateless -- the server neither detects
//! nor stores anything; these tests exercise
//! [`cyphr_server::receipt::check_equivocation`] directly on retained coz
//! bytes, exactly as an offline verifier would.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::receipt::{self, EquivocationVerdict, Roots};
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use proptest::prelude::*;
use tower::ServiceExt;

mod common;

/// Drive a receipt constructor from a synchronous `proptest!` body, which
/// has no runtime of its own.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build a current-thread runtime")
        .block_on(fut)
}

// ========================================================================
// Fixture helpers (mirrored from tests/receipts.rs, which is a separate
// integration-test crate and cannot be imported here)
// ========================================================================

fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

/// Write a fresh signing key file for a fixed 32-byte Ed25519 seed and
/// load it -- deterministic, reproducible identities distinct from the
/// pooled test fixtures (mirrors `tests/receipts.rs`'s `fixed_identity`).
fn identity_with_seed(seed: u8) -> (tempfile::TempDir, ServerIdentity) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("signing-key.json");

    let prv_key = [seed; 32];
    let pub_key = coz::Alg::Ed25519
        .derive_public_key(&prv_key)
        .expect("derive public key from fixed seed");

    let file = serde_json::json!({
        "alg": coz::Alg::Ed25519.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&pub_key),
        "prv_key": Base64UrlUnpadded::encode_string(&prv_key),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
    (dir, identity)
}

fn write_signing_key(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    let file = serde_json::json!({
        "alg": kp.alg.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    path
}

fn keyed_appstate(data_dir: &std::path::Path, key_path: &std::path::Path) -> AppState {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    AppState::new(config).expect("keyed AppState opens")
}

/// A keyed, bootstrapped `AppState` -- the attestor condition -- plus the
/// live identity handle used to sign the conflicting second report under
/// the SAME key as the real endpoint's first report.
async fn attestor_state(dir: &std::path::Path) -> (Arc<AppState>, Arc<ServerIdentity>) {
    let key_path = write_signing_key(dir);
    let mut state = keyed_appstate(&dir.join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");

    let sp = ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(sp));

    (Arc::new(state), identity)
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

/// Re-stamp a signed tip report's `sequence` claim and re-sign -- the
/// dishonest-signer move: `receipt::tip_report`'s public constructor only
/// ever composes a `u64` sequence, so reaching any other JSON
/// representation requires stamping the pay directly, exactly as a signer
/// hand-crafting its own reports would.
fn restamp_sequence(
    mut tip: coz::CozJson,
    identity: &ServerIdentity,
    s: serde_json::Value,
) -> coz::CozJson {
    tip.pay["sequence"] = s;
    let pay_bytes = serde_json::to_vec(&tip.pay).expect("serialize restamped pay");
    let (sig, _cad) = identity.sign(&pay_bytes).expect("re-sign restamped pay");
    tip.sig = sig;
    tip
}

/// Render a distinct, valid SHA-256 digest string from a repeated seed
/// byte. `check_equivocation`/`receipt::tip_report` parse
/// `commit_id`/`roots` as `TaggedDigest`, so this suite's placeholders,
/// which used to be human-readable or hand-typed repeated-letter
/// literals, must genuinely parse. `pr` is NOT tagged -- see
/// [`principal_digest`].
fn digest(byte: u8) -> String {
    TaggedDigest::new(HashAlg::Sha256, vec![byte; 32])
        .expect("32 bytes is SHA-256's expected digest length")
        .to_string()
}

/// Render a distinct, valid BARE genesis-identifier string from a
/// repeated seed byte -- the untagged counterpart to [`digest`]. A
/// receipt's top-level `pr` is the attested principal's genesis
/// identifier: SPEC §2.2.3's DEFAULT (untagged) identifier form, not the
/// `TaggedDigest` `roots`/`commit_id` use under their labeled exemption.
/// Every `pr`/`principal_id` fixture in this suite uses this helper,
/// never [`digest`].
fn principal_digest(byte: u8) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(&[byte; 32])
}

/// Two root sets that differ only in `cr`, standing in for a conflicting
/// commit outcome at the same chain position. Generated via [`digest`]
/// rather than hand-typed repeated-letter literals: a repeated-letter
/// base64url block is canonical only when the letter's value is zero
/// (`A`) -- `B`/`C`/`D`/`E` blocks of the same shape leave nonzero
/// trailing bits in the final character, which `TaggedDigest::from_str`'s
/// strict decoder rejects even though a lenient decoder would accept them.
fn roots_a() -> Roots {
    Roots {
        pr: digest(0xb1),
        sr: Some(digest(0xb2)),
        ar: Some(digest(0xb3)),
        cr: Some(digest(0xb4)),
    }
}

fn roots_b() -> Roots {
    Roots {
        cr: Some(digest(0xb5)),
        ..roots_a()
    }
}

// ========================================================================
// Proven arms -- at least one report obtained through the REAL endpoint
// ========================================================================

/// A real tip report (obtained through `/tip`) and a second, conflicting
/// report signed by the SAME real key -- the degenerate, same-key form of
/// the pinned predicate -- prove equivocation.
#[tokio::test]
async fn same_key_pair_proves_equivocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    // The principal id must be the genesis-derived id: the PG of the
    // genesis commit pushed below (SPEC 5.1).
    let principal_id = common::golden_principal_id(&pool).await;
    let principal_id = principal_id.as_str();
    let now = 1_700_100_000;
    let push_body = common::build_genesis_push_body(&pool, principal_id, now).await;
    let (push_status, _) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    assert_eq!(
        tip_envelope["statement"]["kind"],
        serde_json::json!("signed"),
        "the report under test must itself be a real signed tip report: {tip_envelope:?}"
    );
    let real: coz::CozJson = serde_json::from_value(tip_envelope["statement"]["coz"].clone())
        .expect("real tip cozy deserializes");

    let real_pr = real.pay["pr"].as_str().expect("real pr").to_string();
    let real_sequence = real.pay["sequence"].as_u64().expect("real sequence");
    let real_commit_count = real.pay["commit_count"]
        .as_u64()
        .expect("real commit_count");
    let real_last_updated = real.pay["last_updated"]
        .as_i64()
        .expect("real last_updated");

    let conflicting = receipt::tip_report(
        identity.as_ref(),
        now,
        real_pr,
        real_sequence,
        digest(0x50),
        &roots_b(),
        real_commit_count,
        real_last_updated,
    )
    .await
    .expect("compose a conflicting tip report under the same key");

    assert_eq!(
        receipt::check_equivocation(&real, identity.pub_key(), &conflicting, identity.pub_key()),
        EquivocationVerdict::Proven
    );
}

/// A real tip report and a second, conflicting report signed by a
/// DIFFERENT real key also prove equivocation -- the cross-key-rotation
/// case the pinned predicate covers. Chain-membership verification (that
/// both keys were active for the same principal) is the caller's
/// documented obligation, not exercised here: this test targets only the
/// pure predicate.
#[tokio::test]
async fn cross_key_pair_proves_equivocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    // The principal id must be the genesis-derived id: the PG of the
    // genesis commit pushed below (SPEC 5.1).
    let principal_id = common::golden_principal_id(&pool).await;
    let principal_id = principal_id.as_str();
    let now = 1_700_200_000;
    let push_body = common::build_genesis_push_body(&pool, principal_id, now).await;
    let (push_status, _) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    let real: coz::CozJson = serde_json::from_value(tip_envelope["statement"]["coz"].clone())
        .expect("real tip cozy deserializes");

    let real_pr = real.pay["pr"].as_str().expect("real pr").to_string();
    let real_sequence = real.pay["sequence"].as_u64().expect("real sequence");
    let real_commit_count = real.pay["commit_count"]
        .as_u64()
        .expect("real commit_count");
    let real_last_updated = real.pay["last_updated"]
        .as_i64()
        .expect("real last_updated");

    let (_dir2, rotated_identity) = identity_with_seed(0x22);
    let conflicting = receipt::tip_report(
        &rotated_identity,
        now,
        real_pr,
        real_sequence,
        digest(0x50),
        &roots_b(),
        real_commit_count,
        real_last_updated,
    )
    .await
    .expect("compose a conflicting tip report under the rotated key");

    assert_eq!(
        receipt::check_equivocation(
            &real,
            identity.pub_key(),
            &conflicting,
            rotated_identity.pub_key()
        ),
        EquivocationVerdict::Proven
    );
}

// ========================================================================
// Diagnosed non-equivocation arms -- constructed directly, no real
// endpoint required (the helper is pure; input provenance does not
// change what it proves)
// ========================================================================

/// Two reports attesting different principals are not a conflict about
/// the same principal state.
#[tokio::test]
async fn different_principal_pair_is_not_equivocation() {
    let (_dir, identity) = identity_with_seed(0x11);
    let a = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x11),
        3,
        digest(0x21),
        &roots_b(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::DifferentPrincipal
    );
}

/// Two reports attesting different sequence positions are not a
/// conflict -- the chain simply advanced.
#[tokio::test]
async fn different_sequence_pair_is_not_equivocation() {
    let (_dir, identity) = identity_with_seed(0x11);
    let a = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_100,
        principal_digest(0x10),
        4,
        digest(0x21),
        &roots_b(),
        5,
        1_700_000_100,
    )
    .await
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::DifferentSequence
    );
}

/// A report checked against the WRONG key fails signature verification --
/// no diagnosis beyond "not proven" is drawn from an unverifiable claim.
#[tokio::test]
async fn bad_signature_pair_is_not_equivocation() {
    let (_dir, identity) = identity_with_seed(0x11);
    let (_dir2, wrong_identity) = identity_with_seed(0x22);
    let a = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x21),
        &roots_b(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, wrong_identity.pub_key()),
        EquivocationVerdict::InvalidSignature
    );
}

/// A commit receipt smuggled in as the second report is rejected by
/// `typ` before any claim comparison runs.
#[tokio::test]
async fn wrong_typ_pair_is_not_equivocation() {
    let (_dir, identity) = identity_with_seed(0x11);
    let tip = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
        4,
        1_700_000_000,
    )
    .await
    .expect("compose tip report");
    let commit = receipt::commit_receipt(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
    )
    .await
    .expect("compose commit receipt");

    assert_eq!(
        receipt::check_equivocation(&tip, identity.pub_key(), &commit, identity.pub_key()),
        EquivocationVerdict::WrongTyp
    );
}

// ========================================================================
// A report that fails to canonicalize is diagnosed `Malformed`, distinct
// from every other outcome, so a consumer cannot read it as "no conflict".
// ========================================================================

/// Re-stamp a signed tip report's `pr` claim and re-sign -- the `pr`
/// counterpart to [`restamp_sequence`], needed to reach `pr` shapes
/// `receipt::tip_report`'s public constructor (which requires a valid
/// genesis identifier at construction, per ND's F1 fix) refuses to
/// compose directly.
fn restamp_pr(
    mut tip: coz::CozJson,
    identity: &ServerIdentity,
    p: serde_json::Value,
) -> coz::CozJson {
    tip.pay["pr"] = p;
    let pay_bytes = serde_json::to_vec(&tip.pay).expect("serialize restamped pay");
    let (sig, _cad) = identity.sign(&pay_bytes).expect("re-sign restamped pay");
    tip.sig = sig;
    tip
}

/// A JSON shape that is malformed for BOTH `pr` and `sequence` under ND's
/// field-disposition ruling (`receipt.rs`'s `TipReportParseError`): a short
/// alnum string forced to start with a non-digit is never a clean decimal
/// integer (so never a canonical `sequence` string) and, capped well under
/// 43 characters -- the shortest valid base64url encoding of a supported
/// 32-byte digest -- is never long enough to be a canonical `pr` either;
/// `null`, a bool, a short array, and a negative integer are not a JSON
/// string at all, so they fail `pr`'s string-only gate, and (being neither
/// a number nor a digit-string) `sequence`'s canonicalization gate alike.
fn malformed_field_strategy() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        prop::collection::vec(any::<i32>(), 0..4).prop_map(|v| serde_json::json!(v)),
        "[a-zA-Z_-][a-zA-Z0-9_-]{0,30}".prop_map(serde_json::Value::from),
        (1i64..=i64::MAX).prop_map(|n| serde_json::Value::from(-n)),
    ]
}

proptest! {
    /// Decorrelated coverage of ND.2a/ND.2c from N1's own suite: a report
    /// whose `pr` OR `sequence` fails to canonicalize is diagnosed
    /// `Malformed` by `check_equivocation` -- never silently read as
    /// `Proven` (a false claim raised on unparseable input) and never
    /// silently read as `DifferentPrincipal`/`DifferentSequence`/
    /// `IdenticalClaims` (indistinguishable from an honest non-conflict).
    /// GREEN: this is ND's own boundary-side property, already
    /// implemented; N1 asserts it again from the consumer side of the
    /// typed contract it no longer implements itself (S3/S5.1).
    #[test]
    fn equivocation_malformed_field_yields_malformed_verdict_property(
        malformed_on_pr in any::<bool>(),
        malformed_value in malformed_field_strategy(),
    ) {
        let (_dir, identity) = identity_with_seed(0x11);
        let pr = principal_digest(0x40);

        let a = block_on(receipt::tip_report(
            &identity,
            1_700_000_000,
            &pr,
            0,
            digest(0x41),
            &roots_a(),
            1,
            1_700_000_000,
        ))
        .expect("compose well-formed report a");
        let b = block_on(receipt::tip_report(
            &identity,
            1_700_000_000,
            &pr,
            0,
            digest(0x42),
            &roots_a(),
            1,
            1_700_000_000,
        ))
        .expect("compose well-formed report b (conflicting commit_id)");

        let a = if malformed_on_pr {
            restamp_pr(a, &identity, malformed_value.clone())
        } else {
            restamp_sequence(a, &identity, malformed_value.clone())
        };

        let verdict = receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key());
        prop_assert_eq!(
            verdict,
            EquivocationVerdict::Malformed,
            "a report with malformed {} = {:?} MUST diagnose Malformed, not silently Proven or \
             silently folded in with an honest non-conflict verdict",
            if malformed_on_pr { "pr" } else { "sequence" },
            malformed_value
        );
    }
}
