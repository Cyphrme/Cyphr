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
use cyphr_server::{AppState, build_router, consistency};
use http_body_util::BodyExt;
use proptest::prelude::*;
use tower::ServiceExt;

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
    let mut blobs = sign_key_create_commit(principal, pool, "golden", "key_a", now);

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
/// byte -- the same convention `tests/cross_witness.rs` established
/// (`455894a`). `check_equivocation`/`receipt::tip_report` parse
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
        sr: digest(0xb2),
        ar: digest(0xb3),
        cr: digest(0xb4),
    }
}

fn roots_b() -> Roots {
    Roots {
        cr: digest(0xb5),
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
    let principal_id_digest = principal_digest(0x30);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_100_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);
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
        &identity,
        now,
        real_pr,
        real_sequence,
        digest(0x50),
        &roots_b(),
        real_commit_count,
        real_last_updated,
    )
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
    let principal_id_digest = principal_digest(0x31);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_200_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);
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

/// A same-key pair sharing `commit_id` but differing only in `roots` --
/// isolating the disjunction's two halves. Both arms above differ in
/// BOTH `commit_id` AND `roots` simultaneously, so neither would catch
/// a regression that turned the `IdenticalClaims` check's `&&` into
/// `||`: a roots-only conflict (the same reported commit outcome, a
/// different reported chain state) would then be misdiagnosed as
/// identical and silently dropped.
#[test]
fn same_commit_id_differing_roots_still_proves_equivocation() {
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
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_b(),
        4,
        1_700_000_000,
    )
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::Proven
    );
}

/// N1.9b (F1): the same logical `sequence` claimed as a raw JSON number in
/// one report and as its decimal string in the other, with conflicting
/// `commit_id`, still proves equivocation. A dishonest signer controls its
/// reports' bytes: hand-crafting `5` for one witness and `"5"` for another
/// would otherwise read as "different sequence" and evade the pinned
/// predicate entirely -- the same logical claim in two representations is
/// one claim, not two positions.
#[test]
fn asymmetric_type_sequence_proves_equivocation() {
    let (_dir, identity) = identity_with_seed(0x11);
    let a = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x15),
        5,
        digest(0x25),
        &roots_a(),
        6,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x15),
        5,
        digest(0x26),
        &roots_b(),
        6,
        1_700_000_000,
    )
    .expect("compose report b");
    let b = restamp_sequence(b, &identity, serde_json::json!("5"));

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::Proven,
        "the same logical sequence in different JSON representations MUST NOT evade the pinned \
         predicate"
    );
}

// ========================================================================
// Diagnosed non-equivocation arms -- constructed directly, no real
// endpoint required (the helper is pure; input provenance does not
// change what it proves)
// ========================================================================

/// Two claim-identical reports are not a conflict.
#[test]
fn identical_claims_pair_is_not_equivocation() {
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
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::IdenticalClaims
    );
}

/// Two reports attesting different principals are not a conflict about
/// the same principal state.
#[test]
fn different_principal_pair_is_not_equivocation() {
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
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::DifferentPrincipal
    );
}

/// Two reports attesting different sequence positions are not a
/// conflict -- the chain simply advanced.
#[test]
fn different_sequence_pair_is_not_equivocation() {
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
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key()),
        EquivocationVerdict::DifferentSequence
    );
}

/// A report checked against the WRONG key fails signature verification --
/// no diagnosis beyond "not proven" is drawn from an unverifiable claim.
#[test]
fn bad_signature_pair_is_not_equivocation() {
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
    .expect("compose report b");

    assert_eq!(
        receipt::check_equivocation(&a, identity.pub_key(), &b, wrong_identity.pub_key()),
        EquivocationVerdict::InvalidSignature
    );
}

/// A commit receipt smuggled in as the second report is rejected by
/// `typ` before any claim comparison runs.
#[test]
fn wrong_typ_pair_is_not_equivocation() {
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
    .expect("compose tip report");
    let commit = receipt::commit_receipt(
        &identity,
        1_700_000_000,
        principal_digest(0x10),
        3,
        digest(0x20),
        &roots_a(),
    )
    .expect("compose commit receipt");

    assert_eq!(
        receipt::check_equivocation(&tip, identity.pub_key(), &commit, identity.pub_key()),
        EquivocationVerdict::WrongTyp
    );
}

// ========================================================================
// N1 (rework, redirected against ND's landed typed contract): the
// `Malformed` verdict's own doc comment names a two-sided gap --
// `check_equivocation` diagnoses a report that fails to canonicalize as
// DISTINCT from every other outcome (ND's boundary-side property; already
// implemented and covered by ND's own suite), but NO consumer in
// `consistency.rs` reads that distinction as anything other than "no
// conflict" -- `check_cross_witness_consistency`, `verify_evidence_offline`,
// and `detect_fork_unverified` each compare `verdict == Proven` only, so a
// malformed report and an honest non-conflicting pair are indistinguishable
// at every current call site. Four properties close N1's half of this from
// its own file surface: the first is decorrelated coverage of ND's already-
// landed boundary property (GREEN); the other three each pin one consumer
// site and require it to stop folding the two apart (RED -- unsatisfiable by
// the current implementation, which still folds `Malformed` into the same
// value an honest agreeing pair produces at every site, until a fix makes
// them observably distinct; see each property's own doc for why that RED is
// by design, not a broken test). `verify_evidence_offline`/
// `detect_fork_unverified` were widened from bare `bool` to `Option<bool>`
// as part of this rework -- scaffolding only, so the invariant becomes
// expressible; every path still returns `Some` today, matching the old
// `bool` behavior exactly, which is why their properties are still red.
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

        let a = receipt::tip_report(
            &identity,
            1_700_000_000,
            &pr,
            0,
            digest(0x41),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose well-formed report a");
        let b = receipt::tip_report(
            &identity,
            1_700_000_000,
            &pr,
            0,
            digest(0x42),
            &roots_a(),
            1,
            1_700_000_000,
        )
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

    /// The consumer half of ND's two-sided contract (S5.1): a report that
    /// fails to canonicalize MUST read differently at
    /// `consistency::check_cross_witness_consistency` than a genuinely
    /// honest, agreeing pair -- both silently collapsing to `None` is
    /// exactly the fold `EquivocationVerdict::Malformed`'s own doc comment
    /// names as still open ("no consumer currently reads it as distinct
    /// from an honest non-conflict"). RED BY DESIGN: `check_cross_witness_
    /// consistency`'s three call sites in `consistency.rs` each compare
    /// `verdict == Proven` only, so today BOTH cases below return bare
    /// `None` and this assertion is unsatisfiable -- that is the live gap
    /// this property pins, not a broken test. It does not prescribe the
    /// fix's shape (a changed return value on the existing function is the
    /// minimal one; a companion function is another) -- only that the two
    /// outcomes become observably distinct.
    #[test]
    fn malformed_pair_is_distinguishable_from_honest_agreement_at_consumer(
        malformed_on_pr in any::<bool>(),
        malformed_value in malformed_field_strategy(),
    ) {
        let (_dir_a, identity_a) = identity_with_seed(0x11);
        let (_dir_b, identity_b) = identity_with_seed(0x22);
        let pr = principal_digest(0x50);

        // Attack shape: one report hand-crafted to fail canonicalization,
        // paired with a genuinely conflicting well-formed counterpart --
        // the live evasion (an attacker makes one report fail to parse
        // instead of making the raw comparison see two different values).
        let a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            0,
            digest(0x51),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report a");
        let b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            0,
            digest(0x52),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report b");
        let a = if malformed_on_pr {
            restamp_pr(a, &identity_a, malformed_value.clone())
        } else {
            restamp_sequence(a, &identity_a, malformed_value.clone())
        };

        let malformed_claim = consistency::check_cross_witness_consistency(&[
            (&a, identity_a.pub_key()),
            (&b, identity_b.pub_key()),
        ]);

        // Control: a fully honest, genuinely agreeing pair -- the ONE
        // outcome a malformed report must never be indistinguishable from.
        let honest_a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            1,
            digest(0x53),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report a");
        let honest_b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            1,
            digest(0x53),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report b");
        let honest_claim = consistency::check_cross_witness_consistency(&[
            (&honest_a, identity_a.pub_key()),
            (&honest_b, identity_b.pub_key()),
        ]);

        prop_assert_ne!(
            malformed_claim,
            honest_claim,
            "a pair where one report fails to canonicalize (malformed_on_pr={}, \
             malformed_value={:?}) MUST read differently at check_cross_witness_consistency \
             than a genuinely honest agreeing pair",
            malformed_on_pr,
            malformed_value
        );
    }

    /// The same consumer-side contract as
    /// `malformed_pair_is_distinguishable_from_honest_agreement_at_consumer`,
    /// pinned at `verify_evidence_offline` instead of
    /// `check_cross_witness_consistency` -- the second of the three
    /// identically-folding call sites `EquivocationVerdict::Malformed`'s doc
    /// names. RED BY DESIGN: `verify_evidence_offline` was widened to
    /// `Option<bool>` by this rework so the invariant is expressible at all,
    /// but every path still returns `Some(bool)` -- a malformed pair and an
    /// honest agreeing pair both currently yield `Some(false)`, so this
    /// assertion is unsatisfiable until the fold at THIS site (not
    /// `check_cross_witness_consistency`, already pinned above) is closed.
    #[test]
    fn malformed_pair_is_distinguishable_from_honest_agreement_at_verify_evidence_offline(
        malformed_on_pr in any::<bool>(),
        malformed_value in malformed_field_strategy(),
    ) {
        let (_dir_a, identity_a) = identity_with_seed(0x11);
        let (_dir_b, identity_b) = identity_with_seed(0x22);
        let pr = principal_digest(0x54);

        // Attack shape, as the consumer property above: one report
        // hand-crafted to fail canonicalization, paired with a genuinely
        // conflicting well-formed counterpart.
        let a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            0,
            digest(0x55),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report a");
        let b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            0,
            digest(0x56),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report b");
        let a = if malformed_on_pr {
            restamp_pr(a, &identity_a, malformed_value.clone())
        } else {
            restamp_sequence(a, &identity_a, malformed_value.clone())
        };

        let malformed_result = consistency::verify_evidence_offline(
            &a,
            identity_a.pub_key(),
            &b,
            identity_b.pub_key(),
        );

        // Control: a fully honest, genuinely agreeing pair.
        let honest_a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            1,
            digest(0x57),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report a");
        let honest_b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            1,
            digest(0x57),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report b");
        let honest_result = consistency::verify_evidence_offline(
            &honest_a,
            identity_a.pub_key(),
            &honest_b,
            identity_b.pub_key(),
        );

        prop_assert_ne!(
            malformed_result,
            honest_result,
            "a pair where one report fails to canonicalize (malformed_on_pr={}, \
             malformed_value={:?}) MUST read differently at verify_evidence_offline than a \
             genuinely honest agreeing pair",
            malformed_on_pr,
            malformed_value
        );
    }

    /// As the two properties above, pinned at `detect_fork_unverified` --
    /// the third and last of the three identically-folding call sites.
    /// RED BY DESIGN, same reason: widened to `Option<bool>` as scaffolding,
    /// but every path still returns `Some(bool)`, so a malformed pair and an
    /// honest agreeing pair both currently yield `Some(false)` here too.
    #[test]
    fn malformed_pair_is_distinguishable_from_honest_agreement_at_detect_fork_unverified(
        malformed_on_pr in any::<bool>(),
        malformed_value in malformed_field_strategy(),
    ) {
        let (_dir_a, identity_a) = identity_with_seed(0x11);
        let (_dir_b, identity_b) = identity_with_seed(0x22);
        let pr = principal_digest(0x58);

        let a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            0,
            digest(0x59),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report a");
        let b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            0,
            digest(0x5a),
            &roots_a(),
            1,
            1_700_000_000,
        )
        .expect("compose conflicting report b");
        let a = if malformed_on_pr {
            restamp_pr(a, &identity_a, malformed_value.clone())
        } else {
            restamp_sequence(a, &identity_a, malformed_value.clone())
        };

        let malformed_result =
            consistency::detect_fork_unverified(&a, identity_a.pub_key(), &b, identity_b.pub_key());

        let honest_a = receipt::tip_report(
            &identity_a,
            1_700_000_000,
            &pr,
            1,
            digest(0x5b),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report a");
        let honest_b = receipt::tip_report(
            &identity_b,
            1_700_000_000,
            &pr,
            1,
            digest(0x5b),
            &roots_a(),
            2,
            1_700_000_000,
        )
        .expect("compose honest agreeing report b");
        let honest_result = consistency::detect_fork_unverified(
            &honest_a,
            identity_a.pub_key(),
            &honest_b,
            identity_b.pub_key(),
        );

        prop_assert_ne!(
            malformed_result,
            honest_result,
            "a pair where one report fails to canonicalize (malformed_on_pr={}, \
             malformed_value={:?}) MUST read differently at detect_fork_unverified than a \
             genuinely honest agreeing pair",
            malformed_on_pr,
            malformed_value
        );
    }
}
