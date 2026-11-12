//! Third-party key-inclusion portability (issue #19,
//! `docs/specs/proof-portability.md`).
//!
//! `Principal::verify_key_inclusion` only lets a caller who already owns and
//! trusts a live `Principal` check key inclusion. This suite proves the
//! portable alternative: a verifier holding nothing but a pinned server PG,
//! a signed tip report, a set of proof hops, and a thumbprint -- never the
//! foreign principal itself, never a live query against it -- can still
//! establish key inclusion, using only `cyphr::verify_key_inclusion` and
//! `coz::verify_json`.
//!
//! Every test below is built from a shared fixture with two clearly
//! separated phases:
//!
//! - **PROVER phase** (`build_fixture`): materializes a foreign principal (owned by this fixture,
//!   standing in for the principal's real owner or the server), pushes it to a live attestor, and
//!   reconstructs the 4-hop KT -> AR-node -> SR-node -> PT chain from public APIs alone --
//!   `active_algs`/`active_keys`/`data_root` plus `KeyTree`/`AuthTree`/`StateTree::build_tree` for
//!   hops 1-3, and the new `Principal::sr_inclusion_proof` accessor for hop 4. It also performs the
//!   offline tip-authentication procedure (`docs/specs/receipts.md`): replaying the SERVER's OWN
//!   identity chain (never the foreign principal's) to derive the tip report's genuinely active
//!   signing key.
//! - **VERIFIER phase** (`third_party_verify_key_inclusion`): a standalone function whose signature
//!   is the audit surface for `c-third-party- verifier` -- it takes no `Principal`, no `AppState`,
//!   no engine, no network handle, nothing but the tip report's claims/signature, the hops, the
//!   replay-derived active key, and the target algorithm and thumbprint. It cannot touch the
//!   foreign principal or the server even by accident.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::semantic_tree::{AuthTree, KeyTree, StateTree};
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, LeafProof};
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// A push body: `principal_id` and `bundle` in the wire form (SPEC 4.6.2).
fn push_body(principal_id: &str, bundle: &cyphr::replay::WireBundle) -> String {
    let mut body = serde_json::to_value(bundle).expect("bundle serializes");
    body["principal_id"] = principal_id.into();
    body.to_string()
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

async fn attestor_state(dir: &std::path::Path) -> Arc<AppState> {
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

    Arc::new(state)
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

/// Build a brand-new "foreign" principal -- owned by the prover, never by
/// the verifier -- with two active keys (the golden genesis key and
/// `key_a`, both created by its genesis commit, SPEC 5.1), and its genesis
/// push HTTP body. Returns the materialized `Principal` (for prover-side
/// hop generation), its id (the PG) and the wire body, because the prover
/// phase needs the resulting `Principal` object itself, not just its wire
/// bytes.
async fn build_foreign_principal_and_push_body(
    pool: &test_fixtures::Pool,
    now: i64,
) -> (cyphr::Principal, String, String) {
    let key = |name: &str| {
        pool.get(name)
            .expect("key in pool")
            .key()
            .expect("pool key")
    };
    let mut principal = cyphr::Principal::implicit(key("golden"))
        .await
        .expect("genesis");
    let blobs = test_fixtures::bundle::genesis_bundle(
        &mut principal,
        pool.get("golden").expect("golden key in pool"),
        &[key("key_a")],
        now,
    )
    .await
    .expect("genesis commit");
    let principal_id = test_fixtures::bundle::genesis_id(&blobs).expect("PG");

    let body = push_body(&principal_id, &blobs);

    (principal, principal_id, body)
}

// ========================================================================
// The VERIFIER phase (c-third-party-verifier)
// ========================================================================

/// Verify that the key with thumbprint `tmb` is included under the
/// principal attested by `tip_pay`/`tip_sig` -- the third party's ENTIRE
/// input surface, by design: no `Principal`, no `AppState`, no engine, no
/// network handle appears anywhere in this signature, so a reviewer can
/// confirm the third-party framing from the type signature alone.
///
/// `tip_active_key` is the server identity's public key, already
/// authenticated by replaying the SERVER's own chain per
/// `docs/specs/receipts.md`'s offline procedure (steps 1-5, performed by
/// the caller before this function runs) -- this function performs only
/// step 6 (the signature check) plus the key-inclusion check itself.
///
/// `roots[0]` (KR) is not a tip-report claim -- the signed tip only carries
/// `{pr, sr, ar, cr}` -- so it is derived from `hops[1]`'s own leaf value
/// instead of read from an independent source. This is still sound: hop 1
/// is itself checked (inside `cyphr::verify_key_inclusion`) against
/// `roots[1]` (AR), which IS an independently-trusted tip claim, so an
/// attacker cannot substitute a forged KR here without breaking hop 1's own
/// Merkle verification against the real AR. See
/// `docs/specs/proof-portability.md`'s design note.
fn third_party_verify_key_inclusion(
    alg: HashAlg,
    tmb: &Thumbprint,
    hops: &[LeafProof],
    tip_pay: &serde_json::Value,
    tip_sig: &[u8],
    tip_active_key: &[u8],
) -> bool {
    let Some(sig_alg) = tip_pay["alg"].as_str() else {
        return false;
    };
    let Ok(pay_json) = serde_json::to_vec(tip_pay) else {
        return false;
    };
    if coz::verify_json(&pay_json, tip_sig, sig_alg, tip_active_key) != Some(true) {
        return false;
    }

    let (Some(ar_str), Some(sr_str), Some(pr_str)) = (
        tip_pay["roots"]["ar"].as_str(),
        tip_pay["roots"]["sr"].as_str(),
        tip_pay["roots"]["pr"].as_str(),
    ) else {
        return false;
    };
    let (Ok(ar), Ok(sr), Ok(pr)) = (
        ar_str.parse::<TaggedDigest>(),
        sr_str.parse::<TaggedDigest>(),
        pr_str.parse::<TaggedDigest>(),
    ) else {
        return false;
    };

    let Some(hop2) = hops.get(1) else {
        return false;
    };
    let kr = hop2.leaf_hash.clone();

    let roots: [&[u8]; 4] = [&kr, ar.as_bytes(), sr.as_bytes(), pr.as_bytes()];
    // The thumbprints asked about are the foreign principal's genesis keys
    // (`golden`, `key_a`: ES256 in the pool) or a synthetic 32-byte value,
    // so each is a SHA-256 leaf.
    cyphr::verify_key_inclusion(alg, (tmb.as_bytes(), HashAlg::Sha256), hops, &roots)
}

// ========================================================================
// The PROVER phase + tip authentication -- shared fixture
// ========================================================================

struct PortabilityFixture {
    alg: HashAlg,
    tmb_a: Thumbprint,
    hops: Vec<LeafProof>,
    tip_pay: serde_json::Value,
    tip_sig: Vec<u8>,
    tip_active_key: Vec<u8>,
    never_active_tmb: Thumbprint,
}

async fn build_fixture() -> PortabilityFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = attestor_state(dir.path()).await;
    let app = build_router(state);

    let pool = load_pool();
    let now = 1_700_100_000;
    // ---- PROVER: materialize the foreign principal and push it ----
    let (foreign_principal, principal_id, push_body) =
        build_foreign_principal_and_push_body(&pool, now).await;
    let principal_id = principal_id.as_str();
    let (push_status, push_envelope) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "{push_envelope:?}");

    // ---- PROVER: reconstruct the 4-hop chain from public APIs alone ----
    let alg = HashAlg::Sha256;
    let alg_id = hash_alg_to_u64(alg);
    let active_algs = foreign_principal.active_algs();
    let thumbprints: Vec<&Thumbprint> = foreign_principal.active_keys().map(|k| k.tmb()).collect();
    assert_eq!(thumbprints.len(), 2, "the two genesis keys");
    let tmb_a = thumbprints[0].clone();

    let leaves: Vec<_> = foreign_principal
        .active_keys()
        .map(cyphr::semantic_tree::key_leaf)
        .collect();
    let kt = KeyTree::build_tree(&leaves, &active_algs).expect("build KT");
    let kr = kt.root(&active_algs).expect("KR");
    let ar_node = AuthTree::build_tree(&kr, &active_algs).expect("build AR-node");
    let ar = ar_node.root(&active_algs).expect("AR");
    let sr_node = StateTree::build_tree(&ar, foreign_principal.data_root(), &active_algs)
        .expect("build SR-node");

    let mut sorted: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    sorted.sort();
    let index = sorted
        .iter()
        .position(|&b| b == tmb_a.as_bytes())
        .expect("tmb_a is among the active thumbprints") as u64;

    let hops = vec![
        kt.thumbprint_inclusion_proof(alg_id, index)
            .expect("hop 1: thumbprint in KR"),
        ar_node.kr_inclusion_proof(alg_id).expect("hop 2: KR in AR"),
        sr_node.ar_inclusion_proof(alg_id).expect("hop 3: AR in SR"),
        foreign_principal
            .sr_inclusion_proof(alg)
            .expect("hop 4: SR in PR"),
    ];

    // ---- fetch the signed tip report attesting the foreign principal ----
    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK, "{tip_envelope:?}");
    assert_eq!(
        tip_envelope["statement"]["kind"],
        serde_json::json!("signed"),
        "the tip report under test must itself be signed: {tip_envelope:?}"
    );
    let tip_coz = tip_envelope["statement"]["coz"].clone();
    let tip_pay = tip_coz["pay"].clone();
    let tip_sig = Base64UrlUnpadded::decode_vec(tip_coz["sig"].as_str().expect("sig is a string"))
        .expect("valid tip sig base64");

    // ---- authenticate the tip report per docs/specs/receipts.md's offline
    //      procedure: pin + re-derive the SERVER's OWN PG, replay the
    //      SERVER's OWN chain (never the foreign principal's), confirm the
    //      signing key is active there ----
    let (_, discovery_envelope) = get_json(app.clone(), "/server").await;
    let discovery = &discovery_envelope["payload"];
    let pinned_server_pg = discovery["pg"].as_str().expect("attestor pg").to_string();
    let genesis = &discovery["genesis"];
    let genesis_key = cyphr::Key::new(
        genesis["alg"].as_str().expect("genesis alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(genesis["tmb"].as_str().expect("genesis tmb"))
                .expect("valid genesis tmb base64"),
        ),
        Base64UrlUnpadded::decode_vec(genesis["pub"].as_str().expect("genesis pub"))
            .expect("valid genesis pub base64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(genesis["first_seen"].as_i64().expect("genesis first_seen"));

    let client = cyphr::Principal::implicit(genesis_key.clone())
        .await
        .expect("the published genesis key reconstructs the genesis");
    let derived_server_pg = client
        .pr_tagged()
        .expect("pr_tagged for the reconstructed genesis");
    assert_eq!(
        derived_server_pg, pinned_server_pg,
        "the server's genesis key must derive its own pinned PG"
    );

    let (patch_status, patch_envelope) =
        get_json(app.clone(), &format!("/patch?pr={pinned_server_pg}")).await;
    assert_eq!(patch_status, StatusCode::OK, "{patch_envelope:?}");
    let entries = patch_envelope["payload"]["entries"]
        .as_array()
        .expect("patch entries");
    assert!(
        !entries.is_empty(),
        "the server's own chain must have at least a genesis commit"
    );

    let local_engine = cyphr_storage::engine::StorageEngine::new(
        cyphr_storage::blob::MemoryBlobStore::new(),
        cyphr_storage::index::MemoryIndexer::new(),
    );
    for entry in entries {
        let blobs: cyphr::replay::WireBundle =
            serde_json::from_value(entry.clone()).expect("entry bundle");
        local_engine
            .submit_commit(
                &pinned_server_pg,
                Some(cyphr_storage::Genesis::Disclosed(vec![genesis_key.clone()])),
                &blobs,
            )
            .await
            .expect("replay a server-chain commit into the local engine");
    }
    let replayed_server = local_engine
        .load_principal(
            &pinned_server_pg,
            cyphr_storage::Genesis::Disclosed(vec![genesis_key.clone()]),
        )
        .await
        .expect("load the fully replayed server principal");

    let tip_tmb_bytes = Base64UrlUnpadded::decode_vec(tip_pay["tmb"].as_str().expect("tip tmb"))
        .expect("valid tip tmb base64");
    let tip_tmb = coz::Thumbprint::from_bytes(tip_tmb_bytes);
    assert!(
        replayed_server.is_key_active(&tip_tmb),
        "the tip report's signing key must be active in the replayed server chain"
    );
    let tip_active_key = replayed_server
        .get_key(&tip_tmb)
        .expect("the active key's material is available from the replayed chain")
        .pub_key()
        .to_vec();

    let never_active_tmb = Thumbprint::from_bytes(vec![0x99; 32]);

    PortabilityFixture {
        alg,
        tmb_a,
        hops,
        tip_pay,
        tip_sig,
        tip_active_key,
        never_active_tmb,
    }
}

// ========================================================================
// Tests
// ========================================================================

/// ac-portable-verification (positive case): a verifier holding only the
/// tip report, the hops, and the tmb -- never the foreign principal --
/// proves key inclusion.
#[tokio::test]
async fn third_party_verifies_key_inclusion_from_tip_report_alone() {
    let f = build_fixture().await;
    assert!(third_party_verify_key_inclusion(
        f.alg,
        &f.tmb_a,
        &f.hops,
        &f.tip_pay,
        &f.tip_sig,
        &f.tip_active_key,
    ));
}

/// c-negative-case (wrong identity): a thumbprint that never named any
/// active key on the foreign principal must be rejected, even against a
/// genuine hop chain for a different, real key.
#[tokio::test]
async fn third_party_rejects_thumbprint_never_active() {
    let f = build_fixture().await;
    assert!(!third_party_verify_key_inclusion(
        f.alg,
        &f.never_active_tmb,
        &f.hops,
        &f.tip_pay,
        &f.tip_sig,
        &f.tip_active_key,
    ));
}

/// c-negative-case (tampered chain): flipping a byte in hop 1's leaf value
/// must be rejected, even though the tmb, the remaining hops, and the tip
/// report are all genuine.
#[tokio::test]
async fn third_party_rejects_tampered_hop() {
    let f = build_fixture().await;
    let mut tampered_hops = f.hops.clone();
    tampered_hops[0].leaf_hash[0] ^= 0xFF;

    assert!(!third_party_verify_key_inclusion(
        f.alg,
        &f.tmb_a,
        &tampered_hops,
        &f.tip_pay,
        &f.tip_sig,
        &f.tip_active_key,
    ));
}

/// c-negative-case (tampered chain, interior hop): flipping a byte in hop
/// 2's (AR-node) leaf value -- while hop 1 and the tmb under test stay
/// byte-for-byte genuine -- must be rejected. Unlike
/// `third_party_rejects_tampered_hop` above (which tampers hop 1 and is
/// caught by `cyphr::verify_key_inclusion`'s identity-binding precheck,
/// before the Merkle chain is ever walked), this test corrupts a hop the
/// precheck never inspects, so rejection can only come from the chain
/// itself: `roots[0]` (KR) is derived from hop 2's own leaf value (see
/// `docs/specs/proof-portability.md`'s `[portability-r-kr-derivation]`
/// ruling), so the corruption simultaneously breaks hop 1's Merkle proof
/// against the now-forged derived KR *and* hop 2's Merkle proof against
/// the tip-attested AR root -- exactly the two independent failure modes
/// that ruling's soundness argument rests on.
#[tokio::test]
async fn third_party_rejects_tampered_ar_node_hop() {
    let f = build_fixture().await;
    let mut tampered_hops = f.hops.clone();
    tampered_hops[1].leaf_hash[0] ^= 0xFF;

    assert!(!third_party_verify_key_inclusion(
        f.alg,
        &f.tmb_a,
        &tampered_hops,
        &f.tip_pay,
        &f.tip_sig,
        &f.tip_active_key,
    ));
}
