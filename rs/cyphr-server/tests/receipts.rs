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

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::build_router;

mod common;

use common::{
    attestor_server, build_genesis_push_body, envelope_payload, get_json, keyed_appstate,
    keyless_server, load_pool, post_json, write_signing_key,
};

/// Render a distinct, valid genesis-identifier string from a repeated
/// seed byte -- BARE b64ut, no algorithm tag (SPEC §2.2.3's DEFAULT
/// identifier form; tagging is `roots`/`commit_id`'s labeled exemption,
/// not a principal's genesis identifier -- `docs/specs/receipts.md`).
/// `receipt::tip_report`/`commit_receipt` refuse a malformed `pr`, so
/// these principal identifiers must genuinely parse. Named
/// `principal_digest` (not `digest`) to stay distinct from the TAGGED
/// digest helper other test files use for `commit_id`/`roots` fixtures --
/// same shape, different wire form, never interchangeable.
fn principal_digest(byte: u8) -> String {
    Base64UrlUnpadded::encode_string(&[byte; 32])
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
    let (state, identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id_digest = principal_digest(0x01);
    let principal_id = principal_id_digest.as_str();
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
    let (state, identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id_digest = principal_digest(0x02);
    let principal_id = principal_id_digest.as_str();
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

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");
    envelope_payload(&push_envelope);

    let (tip_status, tip_envelope) = get_json(app, &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    envelope_payload(&tip_envelope);
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
    envelope_payload(&push_envelope);

    let (tip_status, tip_envelope) = get_json(app, &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    envelope_payload(&tip_envelope);
}

// ========================================================================
// Discovery: genesis-key hint (ac-discovery-extended)
// ========================================================================

/// An attestor's discovery payload carries the genesis-key fields the
/// offline verifier needs to reconstruct `Genesis::Explicit`, distinct
/// from the current-key fields already published.
#[tokio::test]
async fn attestor_discovery_payload_carries_genesis_key_fields() {
    let (state, identity, _dir) = attestor_server().await;
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
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id_digest = principal_digest(0x03);
    let principal_id = principal_id_digest.as_str();
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
/// for a stable, recognizable payload -- the same bytes (0x01..0x20),
/// BARE: a receipt's top-level `pr` is the attested principal's genesis
/// identifier, SPEC §2.2.3's DEFAULT (untagged) identifier form, not the
/// `TaggedDigest` `roots`/`commit_id` use under their labeled exemption
/// (Amendment A2, `ND-typed-witness-domain.md`) -- the SAME untagged form
/// `token.rs`/`envelope_vectors.rs`'s `pr`/`principal_id` claims already use.
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
