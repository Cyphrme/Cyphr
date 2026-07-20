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
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::receipt::{self, EquivocationVerdict, Roots};
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
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

/// Two root sets that differ only in `cr`, standing in for a conflicting
/// commit outcome at the same chain position.
fn roots_a() -> Roots {
    Roots {
        pr: "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        sr: "SHA-256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        ar: "SHA-256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
        cr: "SHA-256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_string(),
    }
}

fn roots_b() -> Roots {
    Roots {
        cr: "SHA-256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
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
    let principal_id = "equivocation-same-key-principal";
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
        "SHA-256:conflictingcommitid00000000000000000000000",
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
    let principal_id = "equivocation-cross-key-principal";
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
        "SHA-256:conflictingcommitid00000000000000000000000",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        "principal-x",
        3,
        "commit-a",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        "principal-x",
        3,
        "commit-a",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        "principal-y",
        3,
        "commit-b",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_100,
        "principal-x",
        4,
        "commit-b",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose report a");
    let b = receipt::tip_report(
        &identity,
        1_700_000_000,
        "principal-x",
        3,
        "commit-b",
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
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
        4,
        1_700_000_000,
    )
    .expect("compose tip report");
    let commit = receipt::commit_receipt(
        &identity,
        1_700_000_000,
        "principal-x",
        3,
        "commit-a",
        &roots_a(),
    )
    .expect("compose commit receipt");

    assert_eq!(
        receipt::check_equivocation(&tip, identity.pub_key(), &commit, identity.pub_key()),
        EquivocationVerdict::WrongTyp
    );
}
