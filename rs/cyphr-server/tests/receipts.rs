//! Signed server receipts (`docs/specs/receipts.md`).
//!
//! An attestor -- a keyed, bootstrapped server, `(Some(principal),
//! Some(identity))` -- signs a commit-acceptance receipt into `/push`'s
//! statement slot and a tip report into `/tip`'s, following the bearer
//! token's compose-and-sign pattern (`src/auth/token.rs`). Every other
//! configuration (keyless, or keyed-but-unbootstrapped) stays honestly
//! `Envelope::unsigned`, exactly as before this design.
//!
//! The spine test, `offline_verification_replays_chain_and_verifies_commit_receipt`,
//! proves offline verification end-to-end: a client pins the PG from `/server`,
//! reconstructs `Genesis::Explicit` from the published genesis-key hint,
//! replays the server's own chain (fetched via the ordinary public
//! `/patch` surface) into a second, independent local engine, and verifies
//! the receipt's signature with plain `coz::verify_json` -- never touching
//! the server's own engine, state, or the discovery response's own
//! current-key claim.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

// ========================================================================
// Fixture helpers (mirrored from tests/e2e.rs, tests/keyless_matrix.rs, and
// tests/identity_publication.rs, which are separate integration-test
// crates and cannot be imported here)
// ========================================================================

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
/// `signer_name`. Returns the new commit's raw coz blob bytes, wire-ready
/// for `submit_commit`. Mirrors the helper of the same name in
/// `tests/e2e.rs` / `tests/keyless_matrix.rs`.
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

/// Build a brand-new principal's genesis push HTTP body: a `key/create`
/// closed by `commit/create`, the genesis key embedded on the closing
/// cozy. Mirrors `build_genesis_push_body` in `tests/keyless_matrix.rs`.
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

/// Write a fresh Ed25519 signing key file and return its path.
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

/// A keyed `AppState` whose signing key is `key_path`. Mirrors what
/// `serve` constructs before it bootstraps the principal.
fn keyed_appstate(data_dir: &std::path::Path, key_path: &std::path::Path) -> AppState {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    AppState::new(config).expect("keyed AppState opens")
}

/// A keyed, bootstrapped `AppState` -- the attestor condition -- plus the
/// live identity handle used to check receipt claims against.
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

/// An `AppState` with a temporary database and NO signing identity.
fn keyless_state() -> Arc<AppState> {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    std::mem::forget(temp_dir);
    Arc::new(AppState::new(config).expect("failed to open keyless AppState"))
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

/// Assert `body` is an explicitly unsigned envelope and return its
/// `payload`.
fn assert_unsigned_envelope(body: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(body["v"], serde_json::json!(1), "envelope v=1: {body:?}");
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("unsigned"),
        "expected an explicitly unsigned statement: {body:?}"
    );
    &body["payload"]
}

/// Assert `body` carries a signed statement stamped `expected_typ`, whose
/// signature verifies against `identity`'s key. Returns `(payload,
/// claims)`, where `claims` is the receipt's `pay` object.
fn assert_signed_envelope_claims<'a>(
    body: &'a serde_json::Value,
    expected_typ: &str,
    identity: &ServerIdentity,
) -> (&'a serde_json::Value, serde_json::Value) {
    assert_eq!(body["v"], serde_json::json!(1), "envelope v=1: {body:?}");
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("signed"),
        "an attestor's response must carry a signed statement: {body:?}"
    );
    let coz = &body["statement"]["coz"];
    let pay = coz["pay"].clone();

    let expected_tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("thumbprint");
    assert_eq!(pay["alg"], serde_json::json!(identity.alg().name()));
    assert_eq!(
        pay["tmb"],
        serde_json::json!(Base64UrlUnpadded::encode_string(expected_tmb.as_bytes()))
    );
    assert_eq!(
        pay["typ"],
        serde_json::json!(expected_typ),
        "receipt typ must be dedicated to its kind, distinct from the bearer-token typ: {pay:?}"
    );

    let sig = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().expect("sig is a string"))
        .expect("sig is valid base64url");
    let pay_json = serde_json::to_vec(&pay).expect("pay re-serializes");
    assert_eq!(
        identity.verify(&pay_json, &sig),
        Some(true),
        "the receipt must verify against the issuing identity's own key: {pay:?}"
    );

    (&body["payload"], pay)
}

// ========================================================================
// Attestor mode: signed commit receipts and tip reports
// ========================================================================

/// An attestor's push response carries a signed commit-acceptance receipt
/// whose claims match the accepted commit's resulting state, claim by
/// claim (ac-commit-receipt).
#[tokio::test]
async fn attestor_push_response_carries_signed_commit_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id = "receipt-commit-principal";
    let now = 1_700_000_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    let (push_status, push_envelope) = post_json(app, "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");

    let (payload, claims) =
        assert_signed_envelope_claims(&push_envelope, "cyphr-server/receipt/commit", &identity);

    // Cross-check the claims against the push response's OWN payload,
    // claim-by-claim -- the payload now carries the accepted commit's
    // facts directly, so no follow-up read is needed to verify them.
    assert_eq!(claims["pr"], serde_json::json!(principal_id));
    assert_eq!(claims["sequence"], payload["sequence"]);
    assert_eq!(claims["commit_id"], payload["commit_id"]);
    assert_eq!(claims["roots"]["pr"], payload["roots"]["pr"]);
    assert_eq!(claims["roots"]["sr"], payload["roots"]["sr"]);
    assert_eq!(claims["roots"]["ar"], payload["roots"]["ar"]);
    assert_eq!(claims["roots"]["cr"], payload["roots"]["cr"]);
}

/// An attestor's tip response carries a signed tip report whose claims
/// match the tip payload (ac-tip-report).
#[tokio::test]
async fn attestor_tip_response_carries_signed_tip_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id = "receipt-tip-principal";
    let now = 1_700_000_100;
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (push_status, _) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");

    let (payload, claims) =
        assert_signed_envelope_claims(&tip_envelope, "cyphr-server/receipt/tip", &identity);

    assert_eq!(claims["pr"], serde_json::json!(principal_id));
    assert_eq!(
        claims["sequence"],
        serde_json::json!(payload["commit_count"].as_u64().unwrap() - 1)
    );
    assert_eq!(claims["commit_id"], payload["commit_id"]);
    assert_eq!(claims["roots"]["pr"], payload["pr"]);
    assert_eq!(claims["roots"]["sr"], payload["sr"]);
    assert_eq!(claims["roots"]["ar"], payload["ar"]);
    assert_eq!(claims["roots"]["cr"], payload["cr"]);
    assert_eq!(claims["commit_count"], payload["commit_count"]);
    assert_eq!(claims["last_updated"], payload["last_updated"]);
}

// ========================================================================
// Non-attestor configurations stay honestly unsigned (c-attestor-only-signs)
// ========================================================================

/// A keyless server's push and tip responses stay explicitly unsigned --
/// byte-compatible with the pre-receipts behavior the keyless matrix
/// pins.
#[tokio::test]
async fn keyless_push_and_tip_responses_stay_unsigned() {
    let pool = load_pool();
    let principal_id = "receipt-keyless-principal";
    let now = 1_700_000_200;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    let app = build_router(keyless_state());
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");
    assert_unsigned_envelope(&push_envelope);

    let (tip_status, tip_envelope) = get_json(app, &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    assert_unsigned_envelope(&tip_envelope);
}

/// A keyed-but-unbootstrapped server (only reachable when the router is
/// built without `serve()`, e.g. this test) is not yet an attestor: no
/// established chain means nothing honest to attest, so push and tip stay
/// unsigned exactly as on a keyless server.
#[tokio::test]
async fn keyed_but_unbootstrapped_push_and_tip_responses_stay_unsigned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let state = keyed_appstate(&dir.path().join("data"), &key_path);
    assert!(state.identity.is_some(), "state is keyed");
    assert!(
        state.principal.is_none(),
        "principal was never bootstrapped"
    );

    let pool = load_pool();
    let principal_id = "receipt-unbootstrapped-principal";
    let now = 1_700_000_300;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    let app = build_router(Arc::new(state));
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");
    assert_unsigned_envelope(&push_envelope);

    let (tip_status, tip_envelope) = get_json(app, &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    assert_unsigned_envelope(&tip_envelope);
}

// ========================================================================
// Discovery: genesis-key hint (ac-discovery-extended)
// ========================================================================

/// An attestor's discovery payload carries the genesis-key fields the
/// offline verifier needs to reconstruct `Genesis::Explicit`, distinct
/// from the current-key fields already published.
#[tokio::test]
async fn attestor_discovery_payload_carries_genesis_key_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let (status, envelope) = get_json(app, "/server").await;
    assert_eq!(status, StatusCode::OK, "{envelope:?}");
    let payload = &envelope["payload"];
    assert_eq!(payload["tier"], serde_json::json!("attestor"));

    let genesis = &payload["genesis"];
    assert_eq!(genesis["alg"], serde_json::json!(identity.alg().name()));
    assert_eq!(
        genesis["pub"],
        serde_json::json!(Base64UrlUnpadded::encode_string(identity.pub_key())),
        "on a fresh bootstrap the genesis key IS the current key"
    );
    let tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("thumbprint");
    assert_eq!(
        genesis["tmb"],
        serde_json::json!(Base64UrlUnpadded::encode_string(tmb.as_bytes()))
    );
    assert!(
        genesis["first_seen"].is_i64() || genesis["first_seen"].is_u64(),
        "genesis carries a first_seen timestamp: {genesis:?}"
    );
}

// ========================================================================
// Offline verification: this section's spine test
// ========================================================================

/// A client pins the PG from `/server`, reconstructs `Genesis::Explicit`
/// from the published genesis-key hint, replays the server's own chain
/// (fetched via the ordinary public `/patch` surface) into a SECOND,
/// independent local engine, and verifies a push receipt's signature with
/// plain `coz::verify_json` -- entirely offline, using only HTTP
/// responses and local replay, never the server's own engine or state.
#[tokio::test]
async fn offline_verification_replays_chain_and_verifies_commit_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, _identity) = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id = "offline-verify-principal";
    let now = 1_700_000_400;
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");
    assert_eq!(
        push_envelope["statement"]["kind"],
        serde_json::json!("signed"),
        "the receipt under verification must itself be signed: {push_envelope:?}"
    );
    let receipt_coz = push_envelope["statement"]["coz"].clone();

    // Step 1: pin the PG and the genesis-key hint from discovery.
    let (_, discovery_envelope) = get_json(app.clone(), "/server").await;
    let discovery = &discovery_envelope["payload"];
    let pinned_pg = discovery["pg"].as_str().expect("attestor pg").to_string();
    let genesis = &discovery["genesis"];
    let genesis_key = cyphr::Key {
        alg: genesis["alg"].as_str().expect("genesis alg").to_string(),
        tmb: coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(genesis["tmb"].as_str().expect("genesis tmb"))
                .expect("valid genesis tmb base64"),
        ),
        pub_key: Base64UrlUnpadded::decode_vec(genesis["pub"].as_str().expect("genesis pub"))
            .expect("valid genesis pub base64"),
        first_seen: genesis["first_seen"].as_i64().expect("genesis first_seen"),
        last_used: None,
        revocation: None,
        tag: None,
    };

    // Step 2: the genesis key is a HINT, made trustless by re-deriving the
    // PG from it alone -- never trusting discovery's `pg` claim directly.
    let client = cyphr::Principal::explicit(vec![genesis_key.clone()])
        .expect("the published genesis key reconstructs an explicit genesis");
    let derived_pg = client
        .pr_tagged()
        .expect("pr_tagged for the reconstructed genesis");
    assert_eq!(
        derived_pg, pinned_pg,
        "the genesis key must derive the pinned PG"
    );

    // Step 3: fetch the server's own chain via the ordinary public /patch
    // surface -- the server is an ordinary principal in its own store.
    let (patch_status, patch_envelope) =
        get_json(app.clone(), &format!("/patch?pr={pinned_pg}")).await;
    assert_eq!(patch_status, StatusCode::OK, "{patch_envelope:?}");
    let entries = patch_envelope["payload"]["entries"]
        .as_array()
        .expect("patch entries");
    assert!(
        !entries.is_empty(),
        "the server's own chain must have at least a genesis commit"
    );

    // Step 4: replay into a SECOND, independent local engine -- never the
    // server's own engine or state.
    let local_engine = cyphr_storage::engine::StorageEngine::new(
        cyphr_storage::blob::MemoryBlobStore::new(),
        cyphr_storage::index::MemoryIndexer::new(),
    );
    for entry in entries {
        let blobs: Vec<Vec<u8>> = entry["blobs"]
            .as_array()
            .expect("entry blobs")
            .iter()
            .map(|b| {
                Base64UrlUnpadded::decode_vec(b.as_str().expect("blob is base64url string"))
                    .expect("valid blob base64")
            })
            .collect();
        let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        local_engine
            .submit_commit(
                &pinned_pg,
                Some(cyphr_storage::Genesis::Explicit(vec![genesis_key.clone()])),
                &blob_refs,
            )
            .await
            .expect("replay a server-chain commit into the local engine");
    }

    let replayed = local_engine
        .load_principal(
            &pinned_pg,
            cyphr_storage::Genesis::Explicit(vec![genesis_key.clone()]),
        )
        .await
        .expect("load the fully replayed principal");

    // Step 5: the receipt's signing key must be active in the
    // INDEPENDENTLY REPLAYED chain -- not merely asserted by discovery.
    let receipt_tmb_bytes =
        Base64UrlUnpadded::decode_vec(receipt_coz["pay"]["tmb"].as_str().expect("receipt tmb"))
            .expect("valid receipt tmb base64");
    let receipt_tmb = coz::Thumbprint::from_bytes(receipt_tmb_bytes);
    assert!(
        replayed.is_key_active(&receipt_tmb),
        "the receipt's signing key must be active in the replayed chain"
    );
    let active_key = replayed
        .get_key(&receipt_tmb)
        .expect("the active key's material is available from the replayed chain");

    // Step 6: verify the receipt signature with plain coz::verify_json,
    // using ONLY the replay-derived key -- never discovery's current-key
    // claim, and no bespoke crypto.
    let receipt_alg = receipt_coz["pay"]["alg"].as_str().expect("receipt alg");
    let receipt_sig =
        Base64UrlUnpadded::decode_vec(receipt_coz["sig"].as_str().expect("receipt sig"))
            .expect("valid receipt sig base64");
    let pay_json = serde_json::to_vec(&receipt_coz["pay"]).expect("pay re-serializes");
    assert_eq!(
        coz::verify_json(&pay_json, &receipt_sig, receipt_alg, &active_key.pub_key),
        Some(true),
        "the receipt signature must verify against the replay-derived active key"
    );
}

// ========================================================================
// Golden vectors: byte-exact receipt payloads (ac-vectors)
// ========================================================================

/// A fixed principal genesis id, reused from the token/envelope vectors
/// for a stable, recognizable payload.
const VECTOR_PR: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

const VECTOR_COMMIT_ID: &str = "SHA-256:xqpTU08NP55MvCAHpMiZN5BIhRgwvHJ5_waQpeDzNao";

fn vector_roots() -> cyphr_server::receipt::Roots {
    cyphr_server::receipt::Roots {
        pr: "SHA-256:GOJBQfC618_bQh9QHQ5ZCWwH1I6tbtDx9-RP1i6Rcjc".to_string(),
        sr: "SHA-256:GX18yag2JnVI-w51geLW-RyoggGMxjmIsBJhuzNfaBI".to_string(),
        ar: "SHA-256:GX18yag2JnVI-w51geLW-RyoggGMxjmIsBJhuzNfaBI".to_string(),
        cr: "SHA-256:xqpTU08NP55MvCAHpMiZN5BIhRgwvHJ5_waQpeDzNao".to_string(),
    }
}

/// Load a deterministic Ed25519 identity from a fixed seed, mirroring the
/// token and envelope golden-vector fixtures.
fn fixed_identity() -> (tempfile::TempDir, ServerIdentity) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("signing-key.json");

    let prv_key = [0x11u8; 32];
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

/// Read a committed golden vector, trimming a trailing newline so the
/// file can end in one.
fn golden(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .trim_end()
        .to_string()
}

#[test]
fn commit_receipt_matches_golden_vector() {
    let (_dir, identity) = fixed_identity();
    let coz = cyphr_server::receipt::commit_receipt(
        &identity,
        1_700_000_000,
        VECTOR_PR,
        0,
        VECTOR_COMMIT_ID,
        &vector_roots(),
    )
    .expect("compose and sign commit receipt");

    let wire = serde_json::to_string(&coz).unwrap();
    assert_eq!(wire, golden("receipt_commit.json"));

    let pay_json = serde_json::to_vec(&coz.pay).unwrap();
    assert_eq!(
        identity.verify(&pay_json, &coz.sig),
        Some(true),
        "the golden commit receipt must itself verify against its fixed key"
    );
}

#[test]
fn tip_report_matches_golden_vector() {
    let (_dir, identity) = fixed_identity();
    let coz = cyphr_server::receipt::tip_report(
        &identity,
        1_700_000_000,
        VECTOR_PR,
        0,
        VECTOR_COMMIT_ID,
        &vector_roots(),
        1,
        1_700_000_000,
    )
    .expect("compose and sign tip report");

    let wire = serde_json::to_string(&coz).unwrap();
    assert_eq!(wire, golden("receipt_tip.json"));

    let pay_json = serde_json::to_vec(&coz.pay).unwrap();
    assert_eq!(
        identity.verify(&pay_json, &coz.sig),
        Some(true),
        "the golden tip report must itself verify against its fixed key"
    );
}
