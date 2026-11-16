//! Acceptance test suite for Node N2: Witness Mode.
//!
//! Evaluates criteria N2.1 – N2.6:
//! - `witness_mode_starts` (N2.1): Server starts successfully when configured in witness mode.
//! - `all_write_routes_refused` (N2.2): Structural write refusal for all write routes in witness
//!   mode.
//! - `syncs_from_authority` (N2.3): Witness node syncs state from authority node.
//! - `rejects_unverifiable_delta` (N2.4): Witness node rejects unverifiable state deltas.
//! - `serves_only_self_verified` (N2.5): Adversarial check ensuring only self-verified state is
//!   served.
//! - `responses_carry_freshness` (N2.6): Responses from witness node carry required freshness
//!   indicators.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::config::{AuthorityIdentity, ServerConfig, ServerMode};
use cyphr_server::sync::{SyncOutcome, sync_from_authority};
use cyphr_server::{AppState, build_app_router, receipt};
use cyphr_storage::blob::{Blake3Hash, BlobStore};
use cyphr_storage::index::{DeriveToken, IndexableCommit, IndexerWrite};

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// The id a `/tip` response reports for `principal_id`: its bare digest
/// (routes report the stored PG without its algorithm label).
fn reported_id(principal_id: &str) -> &str {
    cyphr_storage::engine::bare_digest(principal_id)
}

// ========================================================================
// Acceptance Criteria N2.1 – N2.6
// ========================================================================

/// N2.2: `all_write_routes_refused`
///
/// Structural write refusal: In Witness mode, ALL state-mutating (write) endpoints
/// (`POST /push`, `POST /revoke`,
/// and unmapped mutating routes like `POST /unmapped_write_route_test`) MUST be
/// structurally refused with a non-success write-refusal HTTP status code (403 Forbidden,
/// 405 Method Not Allowed, or 501 Not Implemented) and an unsigned response envelope
/// (`statement.kind == "unsigned"`).
#[tokio::test]
async fn all_write_routes_refused() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: temp_dir.path().join("data"),
        ..Default::default()
    };

    let state = Arc::new(AppState::new(config).expect("AppState initialization"));
    let app = build_app_router(state.clone()).expect("app router initialization");

    let pool = load_pool();
    let push_body = build_genesis_push_body(
        &pool,
        &common::golden_principal_id(&pool).await,
        1_700_000_000,
    )
    .await;

    // 1. POST /push MUST be refused in witness mode with an unsigned envelope
    let (push_status, push_json) = post_json(app.clone(), "/push", push_body).await;
    assert!(
        push_status == StatusCode::FORBIDDEN
            || push_status == StatusCode::METHOD_NOT_ALLOWED
            || push_status == StatusCode::NOT_IMPLEMENTED,
        "POST /push in witness mode MUST be structurally refused (403/405/501), got status \
         {push_status}: {push_json:?}"
    );
    assert_eq!(
        push_json["statement"]["kind"], "unsigned",
        "push refusal envelope MUST be unsigned: {push_json:?}"
    );

    // 2. POST /revoke MUST be refused in witness mode with an unsigned envelope
    let revoke_body = serde_json::json!({
        "principal_id": common::golden_principal_id(&pool).await,
        "coz": {}
    })
    .to_string();
    let (revoke_status, revoke_json) = post_json(app.clone(), "/revoke", revoke_body).await;
    assert!(
        revoke_status == StatusCode::FORBIDDEN
            || revoke_status == StatusCode::METHOD_NOT_ALLOWED
            || revoke_status == StatusCode::NOT_IMPLEMENTED,
        "POST /revoke in witness mode MUST be structurally refused, got {revoke_status}: \
         {revoke_json:?}"
    );
    assert_eq!(
        revoke_json["statement"]["kind"], "unsigned",
        "revoke refusal envelope MUST be unsigned: {revoke_json:?}"
    );

    // 3. Unmapped/arbitrary mutating route (e.g. POST /unmapped_write_route_test) MUST be refused
    //    in witness mode with an unsigned envelope
    let unmapped_body = serde_json::json!({"test": "unmapped"}).to_string();
    let (unmapped_status, unmapped_json) =
        post_json(app.clone(), "/unmapped_write_route_test", unmapped_body).await;
    assert!(
        unmapped_status == StatusCode::FORBIDDEN
            || unmapped_status == StatusCode::METHOD_NOT_ALLOWED
            || unmapped_status == StatusCode::NOT_IMPLEMENTED,
        "unmapped write route in witness mode MUST be structurally refused, got \
         {unmapped_status}: {unmapped_json:?}"
    );
    assert_eq!(
        unmapped_json["statement"]["kind"], "unsigned",
        "unmapped write route refusal envelope MUST be unsigned: {unmapped_json:?}"
    );
}

/// N2.3: `syncs_from_authority`
///
/// Verifies that a witness node configured to sync from an authority node (via authority TCP URL)
/// pulls state and commits from the authority node so that queries to the witness node return the
/// synced state.
#[tokio::test]
async fn syncs_from_authority() {
    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let mut auth_instance = common::multi::Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let _auth_addr = auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    let now = 1_700_000_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now).await;

    // Push state to authority node
    let (push_status, push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "authority push must succeed: {push_res:?}"
    );

    // Construct witness node configured with authority_url
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        authority_url: Some(auth_url),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // Query witness node for principal tip after sync from authority
    let (witness_tip_status, witness_tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={principal_id}")).await;

    assert_eq!(
        witness_tip_status,
        StatusCode::OK,
        "witness node MUST serve synced state from authority node, got status \
         {witness_tip_status}: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);
    assert_eq!(
        payload["principal_id"],
        reported_id(principal_id),
        "witness tip response payload must match synced principal"
    );
}

/// N2.4: `rejects_unverifiable_delta`
///
/// Verifies that a witness node configured with authority TCP URL REJECTS unverifiable,
/// corrupted, or forged state deltas from an authority node, refusing to apply them to its local
/// storage. The authority's index is corrupted by an entry no commit manifest backs: the index is
/// a cache of the blob store (I1), so the authority refuses its `/patch` as inconsistent (500)
/// rather than serve the entry, and the witness keeps the valid history it synced before.
#[tokio::test]
async fn rejects_unverifiable_delta() {
    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let mut auth_instance = common::multi::Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let _auth_addr = auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    let now = 1_700_000_000;

    // 1. Establish valid principal on authority
    let push_body = build_genesis_push_body(&pool, principal_id, now).await;
    let (push_status, _push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    // 3. Construct witness node configured with authority_url
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        authority_url: Some(auth_url),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // The witness syncs the valid history first.
    let (synced, synced_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(synced, StatusCode::OK, "initial sync: {synced_json:?}");

    // 2. Corrupt index/state on authority node so it presents an unverifiable state delta
    let dummy_bytes = vec![7u8; 32];
    let dummy_hash = Blake3Hash::from_bytes(*blake3::hash(&dummy_bytes).as_bytes());
    auth_state
        .engine
        .blob_store()
        .put(&dummy_bytes)
        .await
        .expect("put dummy blob");

    let corrupt_commit = IndexableCommit {
        pg: Vec::new(),
        principal_id: principal_id.to_string(),
        commit_ids: vec!["SHA-256:CORRUPTED_COMMIT_999999999999999999999999".to_string()],
        sequence: 99,
        pre: None,
        prs: vec!["SHA-256:CORRUPT_PR_FORGED_ROOT".to_string()],
        srs: vec!["SHA-256:CORRUPT_SR_FORGED_ROOT".to_string()],
        ars: vec!["SHA-256:CORRUPT_AR_FORGED_ROOT".to_string()],
        crs: vec!["SHA-256:CORRUPT_CR_FORGED_ROOT".to_string()],
        blob_hashes: vec![dummy_hash],
        cozies: vec![],
        timestamp: now,
        keys: vec![],
    };
    auth_state
        .engine
        .indexer()
        .index_commit(&corrupt_commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("corrupt index_commit");

    // The authority refuses to serve a history its record does not back.
    let (patch_status, patch_json) =
        get_json(auth_app.clone(), &format!("/patch?pr={principal_id}")).await;
    assert_eq!(
        patch_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a patch over an unbacked index entry must be refused, not served: {patch_json:?}"
    );

    // 4. Witness sync from authority MUST succeed for valid history but REJECT the corrupted delta
    let (witness_tip_status, witness_tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={principal_id}")).await;

    // Witness node MUST serve valid synced state, NOT the corrupted forged root
    assert_eq!(
        witness_tip_status,
        StatusCode::OK,
        "witness node MUST sync valid history from authority, got: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);

    // BIND THE CLAIM. `TipResponse` is FLAT: the served roots live at
    // payload.pr/sr/ar/cr, NOT under a `roots` object. The original assertion
    // indexed payload["roots"]["pr"], which is always `Null` (no such object),
    // so `assert_ne!(Null, "…")` held for every program state -- it could not
    // fail even against a witness that served the forged root verbatim. Index
    // the real fields.
    assert_ne!(
        payload["pr"], "SHA-256:CORRUPT_PR_FORGED_ROOT",
        "witness MUST NOT serve the forged PR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["sr"], "SHA-256:CORRUPT_SR_FORGED_ROOT",
        "witness MUST NOT serve the forged SR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["ar"], "SHA-256:CORRUPT_AR_FORGED_ROOT",
        "witness MUST NOT serve the forged AR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["cr"], "SHA-256:CORRUPT_CR_FORGED_ROOT",
        "witness MUST NOT serve the forged CR root: {witness_tip_json:?}"
    );

    // POSITIVE BINDING. A negative assertion alone still passes on an error
    // envelope or an unrelated shape. The witness's state must be EXACTLY the
    // legitimate genesis it verified: commit_count 1 (never the injected
    // sequence 99), and the served commit_id must not be the forged one.
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "witness must hold exactly the legitimate genesis (commit_count 1), never advance to the \
         injected sequence-99 delta: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["commit_id"], "SHA-256:CORRUPTED_COMMIT_999999999999999999999999",
        "witness must serve the legitimate genesis commit, not the forged one: \
         {witness_tip_json:?}"
    );
}

/// N2.6: `responses_carry_freshness`
///
/// Verifies that all read API responses from a witness node carry required protocol
/// freshness metadata (non-zero timestamp 'now' or 'last_updated', envelope version v=1,
/// and statement markers) on both GET /server and state read queries (GET /tip).
#[tokio::test]
async fn responses_carry_freshness() {
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // 1. GET /server on witness node
    let (server_status, server_json) = get_json(witness_app.clone(), "/server").await;
    assert_eq!(
        server_status,
        StatusCode::OK,
        "GET /server on witness node MUST succeed: {server_json:?}"
    );

    let payload = common::envelope_payload(&server_json);

    // Verify freshness timestamp field is present and positive on /server
    let server_timestamp = payload
        .get("now")
        .or_else(|| payload.get("last_updated"))
        .or_else(|| payload.get("timestamp"))
        .and_then(|v| v.as_i64())
        .expect(
            "witness GET /server response payload MUST carry a freshness timestamp ('now', \
             'last_updated', or 'timestamp')",
        );

    assert!(
        server_timestamp > 0,
        "freshness timestamp on GET /server MUST be positive, got: {server_timestamp}"
    );

    // Verify witness mode is reported in server info metadata
    let mode_str = payload
        .get("mode")
        .and_then(|v| v.as_str())
        .expect("server info MUST report mode in payload");

    assert_eq!(
        mode_str, "witness",
        "server info mode MUST be 'witness', got: {mode_str}"
    );

    // 2. GET /tip state read query on witness node MUST carry freshness metadata
    let (_tip_status, tip_json) =
        get_json(witness_app.clone(), "/tip?pr=n2-freshness-principal").await;
    let tip_payload = common::envelope_payload(&tip_json);
    let tip_timestamp = tip_payload
        .get("now")
        .or_else(|| tip_payload.get("last_updated"))
        .or_else(|| tip_payload.get("timestamp"))
        .or_else(|| tip_json.get("now"))
        .and_then(|v| v.as_i64())
        .expect(
            "witness GET /tip response MUST carry freshness metadata ('now', 'last_updated', or \
             'timestamp')",
        );

    assert!(
        tip_timestamp > 0,
        "freshness timestamp on GET /tip MUST be positive, got: {tip_timestamp}"
    );
}

// ========================================================================
// N2 remediation: wedge elimination + authenticated channel + ingestion
// ========================================================================
//
// These acceptance tests drive deliverables 2, 4, and 5 of the sync-channel
// node. They are RED against the current code and GREEN once the honest
// outcome type, wedge fix, authenticated channel, and ingestion gate land.
//
// Design note -- why an on-path proxy / fixed mock, not two plain servers:
// the threats these tests bound are alterations of what the authority served
// (truncation, injection) and of what it signed (unsigned, mis-signed,
// non-canonical). A real attestor server serves only correct, fully-signed
// patches, so it cannot exhibit the shapes under test. The proxy reuses the
// authority's GENUINE signature and only deletes/injects entries (so the
// entry-binding check, not a broken signature, is what must catch it); the
// fixed mock serves a hand-crafted body a real server would never emit.
//
// Contract these tests pin (delegated shapes made concrete, honoring S3/S6):
//   * `ServerConfig::authority_identity: Option<AuthorityIdentity>` carries the expected
//     authority's alg + PUBLIC-KEY BYTES (not a bare thumbprint -- `coz::verify_json` needs key
//     material).
//   * When `authority_identity` is set, the witness MUST verify the patch envelope's signature
//     against it AND recompute the entry-commitment over the entries as received; an unsigned /
//     mis-signed / commitment-mismatch / non-canonical-report response is a `Failed` sync that
//     applies NOTHING.
//   * When it is UNSET, the legacy unauthenticated sync path is preserved (the existing
//     `syncs_from_authority` deployment shape): the wedge fix is orthogonal to the channel and
//     holds there.
//   * The authority's signed report rides the EXISTING envelope shape -- the signed coz at
//     `statement.coz`, exactly as `GET /tip` already returns `Envelope::signed(payload,
//     tip_report_coz)` (routes.rs). This is the one load-bearing assumption about the delegated
//     wrapping; it mirrors the established pattern rather than inventing a new one.

/// Append a single `key/create` commit (introducing `new_key_name`, signed by
/// `signer_name`) onto `principal`, and return the just-appended commit's wire
/// coz blobs with the new key embedded on its key-introducing cozy.
///
/// This is the per-commit core of `common::sign_key_create_commit`, lifted here
/// so TWO commits can be built on ONE principal (that helper takes the
/// principal by value and drops it, so it cannot chain a second commit; and
/// `common` is read-only for this node). Keeping one principal across both
/// commits is what makes the second genuinely chain -- `build_second_commit_
/// push_body` builds from a fresh principal and 409s with a state-root mismatch.
async fn append_key_create(
    principal: &mut cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key_name: &str,
    now: i64,
) -> Vec<Vec<u8>> {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let new_key = pool.get(new_key_name).expect("new key in pool");

    let signer_tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");
    let new_tmb_b64 = new_key.compute_tmb_b64().expect("new key tmb");

    // Alphabetical field order matches `canonicalize_value`'s `sort_keys()`.
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
    let signer_pub = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub");
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &signer.alg, &signer_prv, &signer_pub)
        .expect("signing supported for this algorithm");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).expect("czd for this algorithm");

    let new_cyphr_key = cyphr::Key::new(
        new_key.alg.clone(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(&new_tmb_b64).expect("valid new key tmb base64"),
        ),
        Base64UrlUnpadded::decode_vec(&new_key.pub_key).expect("valid new key pub base64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(now);

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_cyphr_key))
        .expect("key/create verifies against the current principal state");
    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&signer.alg, &signer_prv, &signer_pub, &signer_tmb),
            now,
            "cyphr.me",
        )
        .await
        .expect("commit finalizes");

    let entries = cyphr_storage::export_commits(principal).expect("export commits");
    let new_commit = entries.last().expect("at least one commit after finalize");

    let mut key_idx = 0;
    new_commit
        .txs
        .iter()
        .flatten()
        .map(|v| {
            let mut coz = v.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < new_commit.keys.len() {
                let key = &new_commit.keys[key_idx];
                coz.as_object_mut().unwrap().insert(
                    "key".to_string(),
                    serde_json::json!({ "alg": key.alg, "pub": key.pub_key, "tmb": key.tmb }),
                );
                key_idx += 1;
            }
            serde_json::to_vec(&coz).expect("cozy serializes")
        })
        .collect()
}

/// Build genuine, CHAINING genesis + second-commit push bodies for one
/// principal: the genesis commit (SPEC 5.1) in which golden creates itself
/// and key_a, then a second `key/create` (key_b) signed by golden onto the
/// post-genesis state. The two-entry patch the truncation test needs.
async fn build_two_commit_push_bodies(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    now: i64,
) -> (String, String) {
    let mut bodies = build_chained_push_bodies(pool, principal_id, now, &["key_a", "key_b"]).await;
    let second = bodies.pop().expect("second commit body");
    let genesis = bodies.pop().expect("genesis body");
    (genesis, second)
}

/// A mutation applied to an upstream `/patch` JSON body by the proxy below.
type PatchMutation = Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>;

/// Spawn a mock authority that serves a FIXED JSON body for `GET /patch`
/// (any query) over a real ephemeral TCP socket. Returns its base URL and the
/// task handle -- hold the handle for the test's lifetime (drop/abort stops
/// it). Serves hand-crafted patch responses a real server would never emit.
async fn spawn_fixed_authority(body: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock authority listener");
    let addr = listener.local_addr().expect("mock authority local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Spawn an on-path proxy in front of `upstream`: for each `GET /patch` it
/// forwards the request (preserving the query), then applies `mutate` to the
/// returned JSON body. Models an on-path party altering what the authority
/// served WITHOUT touching the authority's signature.
async fn spawn_patch_proxy(
    upstream: String,
    mutate: PatchMutation,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let mutate = mutate.clone();
            async move {
                let url = match raw.0 {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                axum::Json(mutate(body))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// A running attestor authority bound on TCP, holding `principal_id`.
/// Hold the whole struct: dropping it aborts the TCP task and removes the
/// backing store.
struct RunningAuthority {
    instance: common::multi::Instance,
    url: String,
}

impl RunningAuthority {
    fn identity(&self) -> AuthorityIdentity {
        let id = self
            .instance
            .identity
            .as_ref()
            .expect("attestor authority holds a signing identity");
        AuthorityIdentity {
            alg: id.alg().name().to_string(),
            pub_key: id.pub_key().to_vec(),
        }
    }
}

/// Stand up a real attestor authority on TCP and push a genuine genesis for
/// `principal_id` over HTTP.
async fn authority_with_genesis(principal_id: &str, now: i64) -> RunningAuthority {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state,
        identity: Some(identity),
        dir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind authority TCP");
    let url = instance.url().expect("authority TCP URL");

    let pool = load_pool();
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, principal_id, now).await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "authority genesis push: {body:?}"
    );

    RunningAuthority { instance, url }
}

/// Stand up a real attestor authority on TCP holding a genuine TWO-commit
/// principal, pushed over HTTP (genesis + a chaining second commit). The
/// witness syncs HTTP-pushed principals; a fixture bootstrapped directly into
/// the engine does NOT round-trip through the witness's genesis auto-detection.
async fn authority_with_two_commits(principal_id: &str, now: i64) -> RunningAuthority {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state,
        identity: Some(identity),
        dir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind authority TCP");
    let url = instance.url().expect("authority TCP URL");

    let pool = load_pool();
    let (genesis_body, second_body) = build_two_commit_push_bodies(&pool, principal_id, now).await;
    let (s0, b0) = post_json(app.clone(), "/push", genesis_body).await;
    assert_eq!(s0, StatusCode::CREATED, "genesis push: {b0:?}");
    let (s1, b1) = post_json(app.clone(), "/push", second_body).await;
    assert_eq!(s1, StatusCode::CREATED, "second commit push: {b1:?}");

    RunningAuthority { instance, url }
}

/// Build a witness `AppState` + router pointed at `authority_url`, optionally
/// carrying an expected authority identity (the authenticated channel).
async fn witness_for(
    authority_url: &str,
    authority_identity: Option<AuthorityIdentity>,
) -> (Arc<AppState>, axum::Router) {
    let dir = tempfile::tempdir().expect("witness tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: dir.path().join("data"),
        authority_url: Some(authority_url.to_string()),
        authority_identity,
        ..Default::default()
    };
    // Leak the TempDir guard for the test's lifetime: the witness store must
    // outlive this function. Tests are short-lived processes.
    std::mem::forget(dir);
    let state = Arc::new(AppState::new(config).expect("witness AppState"));
    let app = build_app_router(state.clone()).expect("witness router");
    (state, app)
}

/// N2.1: a witness stalled by one malformed entry still applies a later good
/// entry -- no permanent wedge.
///
/// The sync audit's S4 wedge: an entry whose `blobs` array is empty aborts the
/// entire apply loop, and because nothing advanced, every later sync refetches
/// and re-aborts on the same entry -- a permanent, silent stall that also
/// blocks every GENUINE entry positioned after it. Here the malformed entry is
/// spliced BEFORE the genuine genesis, so under the current code the genesis
/// (the only real commit) never applies and the witness answers 404 forever.
/// A witness that gets past the bad entry applies the genesis and serves it.
///
/// Runs in the UNAUTHENTICATED sync mode (no expected identity): the wedge fix
/// is orthogonal to the authenticated channel and must hold on the legacy path.
#[tokio::test]
async fn sync_recovers_after_bad_entry() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_genesis(&principal, now).await;

    let bad_pr = principal.clone();
    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(move |mut body: serde_json::Value| {
            let bad_entry = serde_json::json!({
                "commit_id": "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "sequence": 0,
                "pr": bad_pr,
                "txs": [],
            });
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                entries.insert(0, bad_entry);
            }
            body
        }),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, None).await;

    // Pin the sync OUTCOME directly -- `/tip`'s HTTP status alone proves
    // only that local storage holds something (a post-apply failure
    // retains a partial apply, and `/tip` serves local state
    // unconditionally regardless of the sync's own verdict). The claim
    // under test is that the sync recovered from the wedge AND counted the
    // malformed entry as rejected, not merely that something got stored.
    let outcome = sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Synced {
                applied: 1,
                rejected: 1
            }
        ),
        "a malformed entry preceding the genesis must not permanently wedge the sync -- the \
         genuine genesis MUST be applied and the malformed entry counted as rejected: {outcome:?}"
    );

    // `/tip` still serves the synced state -- serving is the one claim
    // this HTTP round-trip is for.
    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a malformed entry preceding the genesis must not permanently wedge the sync -- the \
         genuine genesis MUST still apply and be served: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], reported_id(&principal));
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "witness must have applied the genuine genesis past the bad entry: {json:?}"
    );
}

/// N2.1 (sibling): a witness stalled by one UNVERIFIABLE entry still applies
/// a later good entry -- the wedge's SECOND trigger site.
///
/// `sync_from_authority`'s per-entry loop wedges at two structurally
/// identical `break`s: blob-DECODE failure, and `submit_commit`
/// VERIFICATION failure (sync.rs -- the "rejected unverifiable delta"
/// arm). Both share the mechanism (nothing persists progress, `from_seq`
/// is recomputed fresh, the bad entry is refetched forever), but sharing a
/// mechanism is an argument, not evidence: a fix applied only to the
/// decode `break` leaves this second, equally real wedge open while
/// `sync_recovers_after_bad_entry` goes green. This sibling exercises the
/// second site with its own diagnostic.
///
/// The proxy clones the GENUINE genesis entry and corrupts one signature
/// inside its blobs: the entry stays well-formed (valid base64, valid coz
/// JSON -- it sails past the decode stage) but fails cryptographic
/// verification inside `submit_commit`. Spliced BEFORE the genuine
/// genesis, it wedges the loop at the verification `break` under the
/// current code, so the only real commit never applies.
///
/// Runs in the UNAUTHENTICATED sync mode (no expected identity), exactly
/// as the decode-site sibling: the wedge fix is orthogonal to the
/// authenticated channel and must hold on the legacy path.
#[tokio::test]
async fn sync_recovers_after_unverifiable_entry() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_genesis(&principal, now).await;

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            let Some(entries) = body["payload"]["entries"].as_array_mut() else {
                return body;
            };
            let Some(genuine) = entries.first() else {
                return body;
            };

            // Corrupt the first blob's signature: decode the blob, flip the
            // sig's leading character to a DIFFERENT base64url character, and
            // re-encode. Everything about the entry still decodes and parses;
            // only the cryptographic check can reject it.
            let mut bad = genuine.clone();
            let blob_b64 = bad["txs"][0][0]
                .as_str()
                .expect("genuine entry blob is a base64 string")
                .to_string();
            let blob =
                Base64UrlUnpadded::decode_vec(&blob_b64).expect("genuine entry blob decodes");
            let mut coz: serde_json::Value =
                serde_json::from_slice(&blob).expect("genuine entry blob is coz JSON");
            let mut sig = coz["sig"]
                .as_str()
                .expect("genuine coz carries a sig")
                .to_string();
            let flipped = if sig.starts_with('A') { "B" } else { "A" };
            sig.replace_range(0..1, flipped);
            coz["sig"] = sig.into();
            bad["txs"][0][0] =
                Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).unwrap()).into();

            entries.insert(0, bad);
            body
        }),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, None).await;

    // Pin the sync OUTCOME directly -- see the sibling decode-site test for
    // why `/tip`'s HTTP status alone is not the claim.
    let outcome = sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Synced {
                applied: 1,
                rejected: 1
            }
        ),
        "a well-formed but UNVERIFIABLE entry preceding the genesis must not permanently wedge \
         the sync at the verification-failure break (the submit_commit arm, the wedge's second \
         trigger site) -- the genuine genesis MUST be applied and the unverifiable entry counted \
         as rejected: {outcome:?}"
    );

    // `/tip` still serves the synced state.
    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a well-formed but UNVERIFIABLE entry preceding the genesis must not permanently wedge \
         the sync at the verification-failure break (the submit_commit arm, the wedge's second \
         trigger site) -- the genuine genesis MUST still apply and be served: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], reported_id(&principal));
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "witness must have applied the genuine genesis past the unverifiable entry: {json:?}"
    );
}

/// N2.4b: a patch whose entries were TRUNCATED after signing is rejected --
/// the post-apply reconciliation catches that local state falls short of
/// what the signed report attests.
///
/// The on-path proxy drops the trailing entry of a genuinely-signed,
/// two-commit patch. Every entry that remains is authentic and the
/// authority's signature still verifies -- so a channel that only checks
/// "is the signature valid?" accepts it and applies the short prefix
/// silently, as `Synced`.
///
/// REWORK NOTE (discrepancy surfaced, not silently resolved): the base IBC's
/// N2.4b text says "nothing applied." This node's council round (attack +
/// security + architect, converged) rejected pre-apply atomicity as the
/// mechanism -- see `architect-N2-round.md`'s "digest-over-all declination":
/// a genuine chain-verified PREFIX apply is explicitly ruled SOUND ("exactly
/// one reachable from an honest, shorter serving -- monotone, no integrity
/// loss"), and this node's own S3 forbids changing what a caller serves ("log
/// distinctly and proceed to serve as today"). Under that ratified design the
/// genuine sequence-0 entry legitimately applies and `/tip` legitimately
/// keeps serving it -- checking the NEXT `/tip` call's HTTP status is no
/// longer a valid proxy for "was the truncation caught." What must hold, and
/// is asserted directly below, is that the SYNC OUTCOME reports the
/// mismatch (never `Synced`) and that local state never silently advances
/// past the withheld commit.
#[tokio::test]
async fn patch_truncated_entries_rejected() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                if entries.len() > 1 {
                    entries.pop();
                }
            }
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "a patch whose entries were truncated after signing must never report success, got \
         {outcome:?}"
    );

    // Local state may legitimately hold the sound genesis prefix (per the
    // ratified design), but must never have silently advanced to the
    // withheld second commit. Read the engine directly, not via a second
    // `/tip` round trip: the proxy's truncation is keyed on "does this
    // response hold more than one entry," so a SECOND sync attempt (with
    // `from` advanced past 0) would ask the real authority for only the
    // remaining entry, which the proxy then passes through untouched --
    // correctly resyncing on the next honest attempt, but not exercising
    // this test's property.
    let resulting = witness_state
        .engine
        .get_tip(&principal)
        .await
        .expect("local tip lookup");
    let commit_count = resulting.map(|t| t.commit_count);
    assert_eq!(
        commit_count,
        Some(1),
        "the witness must hold only the sound genesis prefix, never the withheld second commit: \
         {commit_count:?}"
    );
}

/// Sign a tip-report-shaped coz over `pay` with `identity`. The report rides
/// the wire as `{pay, sig}`; the signature is computed over the canonical `pay`
/// exactly as `coz::verify_json` re-canonicalizes it, so a validly-signed but
/// SEMANTICALLY malformed report (e.g. a non-canonical `pr`) still verifies --
/// isolating the parse gate from the signature gate.
fn sign_report(identity: &ServerIdentity, pay: serde_json::Value) -> coz::CozJson {
    let pay_bytes = serde_json::to_vec(&pay).expect("serialize report pay");
    let (sig, _cad) = identity
        .sign(&pay_bytes)
        .expect("authority signs report pay");
    coz::CozJson { pay, sig }
}

/// Stand up a real attestor, push a genesis for `principal`, and return its
/// genuine `/patch` entries array, its REAL signed `/tip` report (the
/// attestor's own `statement.coz`), and the signing identity (plus the store
/// guard to hold). The entries are authentic, so a witness with NO ingestion
/// gate would apply them -- which is exactly what the malformed-report test
/// must observe the gate PREVENT -- and the real report is the byte-genuine
/// claim set the accept-direction test derives its one-field-emptied fixture
/// from.
async fn genuine_entries_and_identity(
    principal: &str,
    now: i64,
) -> (
    serde_json::Value,
    coz::CozJson,
    Arc<ServerIdentity>,
    tempfile::TempDir,
) {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let pool = load_pool();
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, principal, now).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "genesis push: {body:?}");
    // `from` omitted entirely (genesis onward) -- the pre-N4 fixture used
    // `from=0` for this under sequence-anchor semantics, which is no longer
    // a valid anchor (Zami #140: sequence is metadata, not a digest).
    let (pstatus, patch) = get_json(app.clone(), &format!("/patch?pr={principal}")).await;
    assert_eq!(pstatus, StatusCode::OK, "authority /patch: {patch:?}");
    let entries = patch["payload"]["entries"].clone();
    assert!(
        entries.as_array().map(|e| !e.is_empty()).unwrap_or(false),
        "authority must serve at least the genesis entry: {patch:?}"
    );

    let (tstatus, tip) = get_json(app, &format!("/tip?pr={principal}")).await;
    assert_eq!(tstatus, StatusCode::OK, "authority /tip: {tip:?}");
    assert_eq!(
        tip["statement"]["kind"], "signed",
        "an attestor authority must sign its tip report: {tip:?}"
    );
    let report: coz::CozJson = serde_json::from_value(tip["statement"]["coz"].clone())
        .expect("authority tip statement.coz deserializes as a coz");

    (entries, report, identity, dir)
}

/// N2.8 (reject direction): a witness refuses to ingest a report that fails
/// `TipReport::parse`, even when it is validly signed by the expected authority.
///
/// This is the load-bearing half of the cross-node equivocation closure: ND
/// made `check_equivocation` compare TYPED values, but a report that cannot be
/// typed yields "no claim", observationally identical to the evasion. The
/// closure holds only if a malformed report never becomes a retained/applied
/// attestation in the first place -- and ingestion is this node's surface.
///
/// The mock serves GENUINE entries (a witness with no gate would apply them)
/// wrapped in `Envelope::signed` whose statement coz is a VALIDLY-SIGNED report
/// with a non-canonical `pr` (a JSON array -- `TipReport::parse`'s
/// `parse_genesis_id` rejects it; it is never unwrapped to an inner string).
/// The signature verifies (isolating the PARSE gate from the signature gate),
/// so a witness that stops at "signature valid" applies the entries. A witness
/// that parses the report before acting rejects it and applies nothing.
///
/// NB (a discrepancy surfaced): the IBC lists `sequence: "5"` as a malformed
/// example, but the merged `TipReport::parse` CANONICALIZES a decimal-string
/// sequence (`"5"` -> 5) -- it is accepted, not rejected. The genuinely
/// non-canonical shape used here is `pr: [..]`; a malformed sequence would be
/// `"5x"`/`""`/`true`, never `"5"`.
#[tokio::test]
async fn witness_rejects_malformed_report_at_ingestion() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let (entries, _real_report, identity, _auth_dir) =
        genuine_entries_and_identity(&principal, now).await;

    let tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("authority thumbprint");
    let malformed_pay = serde_json::json!({
        "alg": identity.alg().name(),
        "now": now,
        "tmb": Base64UrlUnpadded::encode_string(tmb.as_bytes()),
        "typ": receipt::TIP_REPORT_TYP,
        // NON-CANONICAL: `pr` is a JSON array, not a bare b64ut genesis id.
        "pr": ["SHA-256:not-a-genesis-identifier"],
        "sequence": 0,
        "commit_id": TaggedDigest::new(HashAlg::Sha256, vec![0x18; 32]).unwrap().to_string(),
        "roots": {
            "pr": TaggedDigest::new(HashAlg::Sha256, vec![0x19; 32]).unwrap().to_string(),
            "sr": TaggedDigest::new(HashAlg::Sha256, vec![0x1a; 32]).unwrap().to_string(),
            "ar": TaggedDigest::new(HashAlg::Sha256, vec![0x1b; 32]).unwrap().to_string(),
            "cr": "",
        },
    });
    let report = sign_report(&identity, malformed_pay);

    // PIN that the violating shape is exactly what the invariant demands: the
    // report carries a VALID signature by the expected authority AND is
    // REJECTED by the gate's own parser. Together these isolate the PARSE gate
    // from the signature gate -- a rejection under test cannot be blamed on a
    // bad signature, and the report genuinely fails `TipReport::parse`.
    assert_eq!(
        coz::verify_json(
            &serde_json::to_vec(&report.pay).unwrap(),
            &report.sig,
            identity.alg().name(),
            identity.pub_key(),
        ),
        Some(true),
        "the malformed report MUST be validly signed by the expected authority"
    );
    assert!(
        receipt::TipReport::parse(&report).is_err(),
        "the report MUST fail TipReport::parse (the ingestion gate's own parser)"
    );

    let body = serde_json::json!({
        "v": 1,
        "payload": { "principal_id": principal, "entries": entries },
        "statement": { "kind": "signed", "coz": serde_json::to_value(&report).unwrap() },
    });
    let (mock_url, _mock) = spawn_fixed_authority(body).await;

    let expected = AuthorityIdentity {
        alg: identity.alg().name().to_string(),
        pub_key: identity.pub_key().to_vec(),
    };
    let (_witness_state, witness_app) = witness_for(&mock_url, Some(expected)).await;

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a validly-signed but NON-CANONICAL report must be refused at ingestion -- its (genuine) \
         entries must NOT be applied or served: {json:?}"
    );
}

// N2.8 (accept direction): a report with an ABSENT commit root -- a
// principal legitimately in the no-commit-root state -- must be accepted
// at ingestion, not over-rejected. Formerly pinned here as an
// integration test; cut because no push path on this authority produces a
// witness-resulting tip whose OWN `cr` is empty (`stage_commit` writes
// a real CR on every finalized commit), so a wire fixture built by
// doctoring the *report* alone was fixture-vs-entries incoherent -- the
// witness's own applied entries carry a real `cr`, so `EntryCommitmentMismatch`
// is that fixture's correct verdict, not over-rejection. The property is
// pinned where it is actually constructible:
// `sync::tests::resulting_tip_matches_report_accepts_legitimate_empty_commit_root`.

/// Authenticated-channel positive control: a witness configured with the
/// expected authority identity, syncing an UNTAMPERED real authority, must
/// accept and serve -- the end-to-end interop bind between serve-side
/// envelope signing and sync-side verification.
///
/// Every other authenticated-channel test rejects (unsigned, mis-signed,
/// truncated, malformed report) or drives a mock; a channel implementation
/// that over-rejects the REAL authority's genuine wire shape would leave
/// all of them green while breaking every actual deployment. This is the
/// whole-loop accept that forces the two sides to interoperate once
/// serve-side signing lands. (This fixture's tip report carries a real,
/// non-empty commit root -- the empty-`cr` accept case is
/// `sync::tests::resulting_tip_matches_report_accepts_legitimate_empty_commit_root`.)
#[tokio::test]
async fn authenticated_channel_accepts_genuine_authority() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_genesis(&principal, now).await;
    let authority_identity = authority.identity();

    let (witness_state, witness_app) = witness_for(&authority.url, Some(authority_identity)).await;

    // Pin the sync OUTCOME directly, not the HTTP status: this is the
    // genesis-only accept case for the post-apply reconciliation, and
    // `/tip` serves local state unconditionally regardless of the sync
    // verdict, so its status alone cannot catch an over-strict comparison
    // there (e.g. one that rejects every genesis-only sync).
    let outcome = sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Synced {
                applied: 1,
                rejected: 0
            }
        ),
        "a witness holding the expected authority identity must accept an untampered genuine \
         authority's patch: {outcome:?}"
    );

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a witness holding the expected authority identity must accept an untampered genuine \
         authority's patch and serve the synced state: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], reported_id(&principal));
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "witness must have applied the synced genesis: {json:?}"
    );
}

// ========================================================================
// N2 rework: post-apply reconciliation against the witness's OWN resulting
// state, and the cross-principal `pr` check
// ========================================================================
//
// The prior authenticated-channel gate compared the response's claimed
// `(sequence, commit_id)` against the SAME values the signed report carries
// in the clear -- a check any on-path reader can reproduce for free, since
// it never touches anything the witness itself verifies or produces. These
// tests derive from the attack/security/architect council round on this
// node (`.scratch/campaigns/server-witness-remediation/probes/N2-hacker.md`,
// `N2-security.md`, `architect-N2-round.md`): each pins one shape that
// defeated the old gate and must be caught by the new one.

/// Spawn an on-path proxy that rewrites the REQUEST query before forwarding,
/// leaving the authority's response byte-for-byte genuine. Models a party
/// that never touches what the authority serves, only what it is asked --
/// the shape no response-integrity check can ever see.
async fn spawn_query_rewriting_proxy(
    upstream: String,
    rewrite: Arc<dyn Fn(Option<String>) -> Option<String> + Send + Sync>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let rewrite = rewrite.clone();
            async move {
                let q = rewrite(raw.0);
                let url = match q {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                axum::Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// N2 rework, fix 1: cross-principal state substitution is rejected before
/// any entry is applied.
///
/// An on-path proxy rewrites only the OUTBOUND request's `pr` from A to B;
/// the authority answers completely honestly for B. Every prior check
/// passes -- the signature verifies, the report parses, its claims are
/// internally consistent -- because the response genuinely is what it
/// claims to be, just an answer about a different principal. Principal A's
/// and B's genesis keys are genuinely distinct (`alice` vs `golden`), so
/// this is not a shared-fixture artifact: if the witness ever applied B's
/// blobs under A's identifier, A's `/tip` would come back 200 holding B's
/// chain.
#[tokio::test]
async fn cross_principal_substitution_rejected() {
    let now = 1_700_000_000;
    let pool = load_pool();
    // Distinct genesis keys (`alice` vs `golden`) give genuinely distinct
    // genesis-derived ids.
    let principal_a = common::genesis_push_id(&pool, "alice", "bob").await;
    let principal_b = common::golden_principal_id(&pool).await;

    let authority = authority_with_two_commits(&principal_b, now).await;
    let authority_identity = authority.identity();
    let (status, body) = post_json(
        authority.instance.router.clone(),
        "/push",
        common::build_genesis_push_body_with(&pool, "alice", "bob", &principal_a, now).await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "principal A genesis push: {body:?}"
    );

    // `from` omitted (genesis onward for B) -- the pre-N4 fixture rewrote it
    // to `from=0` under sequence-anchor semantics; that string is no longer
    // a valid digest anchor and is immaterial to what this test pins (the
    // rewritten `pr`, not `from`).
    let b_for_rewrite = principal_b.clone();
    let (proxy_url, _proxy) = spawn_query_rewriting_proxy(
        authority.url.clone(),
        Arc::new(move |_q: Option<String>| Some(format!("pr={b_for_rewrite}"))),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal_a).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::PrincipalMismatch
            }
        ),
        "a genuine, validly-signed response for a DIFFERENT principal must be rejected as a \
         principal mismatch before any entry applies, got {outcome:?}"
    );

    // A's own state must be untouched -- never advanced to B's chain.
    let (status_a, json_a) = get_json(witness_app, &format!("/tip?pr={principal_a}")).await;
    if status_a == StatusCode::OK {
        let payload = common::envelope_payload(&json_a);
        assert_eq!(
            payload["commit_count"].as_u64(),
            Some(1),
            "principal A must hold only its own genesis (commit_count 1), never B's chain: \
             {json_a:?}"
        );
    }
}

/// N2 rework, fix 2 (part a): a decoy top entry that preserves its victim's
/// declared `(sequence, commit_id)` labels while swapping in junk `blobs` no
/// longer defeats the channel -- the witness's post-apply resulting state,
/// not any label carried on the wire, is what gets compared against the
/// signed attestation.
///
/// Run across three polls: the withholding must be caught EVERY time, never
/// silently accepted even once.
#[tokio::test]
async fn decoy_top_entry_withholding_rejected() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            // Withhold sequence 1 on every response, leaving a decoy that
            // carries its genuine labels but junk blobs as the top entry.
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                for e in entries.iter_mut() {
                    if e["sequence"].as_u64() == Some(1) {
                        *e = serde_json::json!({
                            "commit_id": e["commit_id"].clone(),
                            "sequence": e["sequence"].clone(),
                            "pr": e["pr"].clone(),
                            "txs": [[Base64UrlUnpadded::encode_string(b"{}")]],
                        });
                    }
                }
            }
            body
        }),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    for attempt in 0..3 {
        let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
        assert!(
            matches!(
                outcome,
                cyphr_server::sync::SyncOutcome::Failed {
                    reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
                }
            ),
            "attempt {attempt}: a label-preserving decoy top entry must be caught by the \
             post-apply reconciliation on EVERY poll, got {outcome:?}"
        );
    }

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    let payload = common::envelope_payload(&json);
    assert_eq!(
        status,
        StatusCode::OK,
        "the genuine sequence-0 entry (never withheld) must still have applied: {json:?}"
    );
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "the witness must never advance past the withheld commit, and must never report success \
         while short of it: {json:?}"
    );
}

/// N2 rework, fix 2 (part b): wholesale-emptying the `entries` array of a
/// genuine, genuinely-signed response no longer reads as `UpToDate`. The
/// signed report the witness just verified proves the authority is two
/// commits ahead; the post-apply comparison against the witness's own
/// (empty) resulting state must catch that the two disagree.
#[tokio::test]
async fn empty_entries_with_advanced_report_rejected() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            body["payload"]["entries"] = serde_json::json!([]);
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "wholesale entry deletion against a report proving the authority is ahead must be \
         rejected, never read as UpToDate, got {outcome:?}"
    );
}

/// N2 rework, fix 2 (part c) -- the variant NO response-integrity mechanism
/// can ever catch: the on-path party never touches the response at all, only
/// the OUTBOUND request's `from`. The authority answers completely
/// honestly -- an empty entry set (nothing new past the huge `from`) plus its
/// genuine signature over its genuine current tip. Only comparing that
/// signed tip against the witness's own local state (never advanced) can
/// close this.
#[tokio::test]
async fn request_side_from_rewrite_withholding_rejected() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    // The authority's own current tip PR digest -- a legitimately resolving
    // anchor, so its honest response's entries are genuinely EMPTY (nothing
    // new past its own tip). This is the digest-anchor era's equivalent of
    // the pre-N4 fixture's `from=999999` (an innocuous huge sequence past
    // the tip): both make the on-path `from` rewrite produce an honestly
    // "already caught up" response, which is exactly what this test needs
    // K10's post-apply reconciliation (not the response body) to catch.
    let (tip_status, tip_json) = get_json(
        authority.instance.router.clone(),
        &format!("/tip?pr={principal}"),
    )
    .await;
    assert_eq!(tip_status, StatusCode::OK, "authority /tip: {tip_json:?}");
    // Read the `payload` directly, not via `common::envelope_payload` --
    // this authority is attestor-keyed, so its `/tip` is genuinely SIGNED,
    // and that helper asserts the envelope is unsigned.
    let current_tip_pr = tip_json["payload"]["pr"]
        .as_str()
        .expect("authority tip pr")
        .to_string();

    let (proxy_url, _proxy) = spawn_query_rewriting_proxy(
        authority.url.clone(),
        Arc::new(move |q: Option<String>| {
            let q = q.unwrap_or_default();
            let pr = q
                .split('&')
                .find(|kv| kv.starts_with("pr="))
                .unwrap_or("")
                .to_string();
            Some(format!("{pr}&from={current_tip_pr}"))
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "a request-side `from` rewrite must not withhold every entry behind a fully genuine \
         response, got {outcome:?}"
    );
}

/// Spawn an on-path proxy that forwards the FIRST `/patch` request to
/// `upstream` untouched, caches that genuine response, and replays the SAME
/// cached response for every later request regardless of the query --
/// models an on-path party that holds one genuine response and rebroadcasts
/// it after the witness has moved past it, rather than forwarding a fresh
/// one.
async fn spawn_replay_proxy(upstream: String) -> (String, tokio::task::JoinHandle<()>) {
    let cache: Arc<tokio::sync::Mutex<Option<serde_json::Value>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let cache = cache.clone();
            async move {
                let mut cached = cache.lock().await;
                if let Some(body) = cached.clone() {
                    return axum::Json(body);
                }
                let url = match raw.0 {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                *cached = Some(body.clone());
                axum::Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Diagnostic fix: a non-empty response every one of whose entries the
/// `seq < from_seq` guard skips -- because the witness already holds them,
/// exactly what a replayed-but-stale genuine response looks like once the
/// witness has since caught up further -- must not be reported as
/// `Failed { RejectedEntry }`. Nothing in such a response is rejected
/// (`rejected` stays 0); reporting a rejection would tell the operator every
/// entry failed verification when in fact none was even attempted.
///
/// The proxy forwards the witness's first request to a real two-commit
/// authority untouched and caches that genuine catch-up response (entries
/// for sequence 0 and 1, a signed report attesting the final tip), then
/// replays that identical cached response on every later request regardless
/// of the `from` it is asked for. The first sync legitimately applies both
/// entries; on the second sync both entries are now below the witness's
/// (advanced) `from_seq` and are skipped, not rejected, while the post-apply
/// check trivially agrees with local state because the replayed report
/// attests exactly the tip the witness already reached.
#[tokio::test]
async fn stale_replay_with_no_new_entries_reports_up_to_date_not_rejected() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_replay_proxy(authority.url.clone()).await;
    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    let first = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            first,
            cyphr_server::sync::SyncOutcome::Synced {
                applied: 2,
                rejected: 0
            }
        ),
        "the first sync must genuinely catch the witness up to both commits: {first:?}"
    );

    let second = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    match second {
        cyphr_server::sync::SyncOutcome::UpToDate => {},
        cyphr_server::sync::SyncOutcome::Failed {
            reason: cyphr_server::sync::SyncFailure::RejectedEntry,
        } => panic!(
            "a stale-but-genuine response whose entries are all already applied must not be \
             reported as RejectedEntry -- nothing in it was rejected, both entries were merely \
             already held"
        ),
        other => panic!("expected UpToDate, got {other:?}"),
    }
}

/// GUARD (regression protection, already-correct behavior): a CONFIGURED
/// witness fails closed when the statement is stripped entirely -- the
/// `/patch` unsigned-on-signing-failure degradation (a liveness affordance
/// for an UNCONFIGURED witness) must never be usable to downgrade a
/// configured one's channel.
#[tokio::test]
async fn stripped_statement_fails_closed_when_configured() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            body["statement"] = serde_json::json!({ "kind": "unsigned" });
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EnvelopeUnsignedOrMisSigned
            }
        ),
        "a configured witness must fail closed on a stripped statement, applying nothing, got \
         {outcome:?}"
    );
}

// ========================================================================
// Node N4: content-addressed resync anchor (#140)
// ========================================================================
//
// Evaluates the test-shaped acceptance criteria N4.1, N4.2, N4.4, N4.5:
// - `sync_resumes_from_digest_anchor` (N4.1): a witness resumes sync from a content-digest anchor.
// - `fork_shares_sequence_rejected_by_digest_anchor` (N4.2): a fork reaching the same sequence as
//   the canonical chain is NOT accepted via the digest anchor.
// - `sequence_only_anchor_does_not_resume` (N4.4): a request whose ONLY anchor is a sequence does
//   not resume.
// - `anchor_digest_rejects_malformed` (N4.5): the anchor rejects malformed input.
//
// RED against the current code: `PatchQuery.from` is `Option<u64>` and
// `sync.rs` builds `from={from_seq}` from `commit_count` (sync.rs:39-47,
// routes.rs:35-37). Every positive assertion below sends a TAGGED DIGEST
// STRING (e.g. `SHA-256:...`) as `from` -- that fails to parse as a `u64` at
// all today, so each test's own positive control is what fails for the
// right reason, not merely a checked-but-vacuous negative. See Zami #140
// ("Content addressed digest for everything... Sequence is metadata") for
// why N4.2 constructs a genuine two-branch equivocation rather than
// asserting the property abstractly.

/// Build a genuinely CHAINING sequence of push bodies for one principal: its
/// genesis commit (SPEC 5.1), in which golden creates itself and
/// `key_names[0]` (so its id is `common::genesis_push_id(pool, "golden",
/// key_names[0]).await`), then one chained `key/create` push body per remaining
/// name in `key_names`, each signed by golden onto the state left by the
/// previous entry via the SAME `principal` object (the `append_key_create`
/// doc comment explains why a shared object, not a fresh one per commit, is
/// what makes the chain genuine).
///
/// Serves every multi-commit fixture here -- the two-commit authority, an
/// honest 3-commit authority, a split two-step chain, and a forked branch --
/// from one construction.
async fn build_chained_push_bodies(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    now: i64,
    key_names: &[&str],
) -> Vec<String> {
    assert!(!key_names.is_empty(), "at least a genesis key is required");
    let key = |name: &str| {
        pool.get(name)
            .expect("key in pool")
            .key()
            .expect("pool key")
    };
    let mut principal = cyphr::Principal::implicit(key("golden"))
        .await
        .expect("genesis");
    let c0 = test_fixtures::bundle::genesis_bundle(
        &mut principal,
        pool.get("golden").expect("golden key"),
        &[key(key_names[0])],
        now,
    )
    .await
    .expect("genesis commit");

    let body = |blobs: &[Vec<u8>]| common::push_blobs(principal_id, blobs);

    let mut bodies = vec![common::push_body(principal_id, &c0)];
    for (i, name) in key_names.iter().enumerate().skip(1) {
        let c = append_key_create(&mut principal, pool, "golden", name, now + i as i64).await;
        bodies.push(body(&c));
    }
    bodies
}

/// Spawn a passthrough proxy in front of `upstream` for `GET /patch`: records
/// every request's raw query string, in arrival order, into `captured`, then
/// forwards the request unmodified and relays the upstream's JSON body
/// verbatim. Unlike `spawn_patch_proxy` (which MUTATES the body to model an
/// on-path attacker), this proxy changes nothing -- it exists only to let
/// the test observe what `sync_from_authority` actually places on the wire,
/// which the client itself gives no other hook into.
async fn spawn_observing_patch_proxy(
    upstream: String,
    captured: Arc<std::sync::Mutex<Vec<String>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let captured = captured.clone();
            async move {
                let query = raw.0.unwrap_or_default();
                captured.lock().unwrap().push(query.clone());
                let url = if query.is_empty() {
                    format!("{upstream}/patch")
                } else {
                    format!("{upstream}/patch?{query}")
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                axum::Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observing proxy listener");
    let addr = listener.local_addr().expect("observing proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// N4.1: `sync_resumes_from_digest_anchor`
///
/// A witness that already synced a genesis commit, then resumes after the
/// authority gains a second commit, MUST anchor its resync request on the
/// CONTENT DIGEST of its own current tip's PR (S0.1 -- the specification
/// owner's ruling that PR is the anchor root), not on a bare sequence
/// number. Pinned two ways: functionally, the witness must actually apply
/// exactly the one new commit (`applied: 1`, not a full resync and not
/// zero); and on the wire, an observing proxy in front of the authority
/// records the outbound `/patch` request's `from` value, which MUST equal
/// the witness's own previously-synced tip PR digest. The wire check is
/// what makes this differ from merely checking that *a* resync happened --
/// the legacy path also resumes correctly, just by sequence.
#[tokio::test]
async fn sync_resumes_from_digest_anchor() {
    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    let now = 1_700_100_000;
    let bodies = build_chained_push_bodies(&pool, principal_id, now, &["key_a", "key_b"]).await;

    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");
    let mut auth_instance = common::multi::Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let (s0, b0) = post_json(auth_app.clone(), "/push", bodies[0].clone()).await;
    assert_eq!(s0, StatusCode::CREATED, "genesis push: {b0:?}");

    let captured: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (proxy_url, _proxy) = spawn_observing_patch_proxy(auth_url, captured.clone()).await;
    let (witness_state, _witness_app) = witness_for(&proxy_url, None).await;

    let first = sync_from_authority(&witness_state, principal_id).await;
    assert!(
        matches!(
            first,
            SyncOutcome::Synced {
                applied: 1,
                rejected: 0
            }
        ),
        "first sync must apply exactly the genesis commit: {first:?}"
    );
    let witness_tip_pr = witness_state
        .engine
        .get_tip(principal_id)
        .await
        .expect("witness get_tip")
        .expect("witness holds a tip after the first sync")
        .pr;

    let (s1, b1) = post_json(auth_app.clone(), "/push", bodies[1].clone()).await;
    assert_eq!(s1, StatusCode::CREATED, "second commit push: {b1:?}");

    let second = sync_from_authority(&witness_state, principal_id).await;
    assert!(
        matches!(
            second,
            SyncOutcome::Synced {
                applied: 1,
                rejected: 0
            }
        ),
        "second sync must resume and apply EXACTLY the new commit, not a full resync: {second:?}"
    );

    let queries = captured.lock().unwrap().clone();
    assert_eq!(
        queries.len(),
        2,
        "expected exactly two outbound /patch requests, one per sync: {queries:?}"
    );
    let decoded_from = reqwest::Url::parse(&format!("http://capture/?{}", queries[1]))
        .expect("parse captured query")
        .query_pairs()
        .find(|(k, _)| k == "from")
        .map(|(_, v)| v.into_owned());
    assert_eq!(
        decoded_from.as_deref(),
        Some(witness_tip_pr.as_str()),
        "the resync anchor MUST be the witness's own tip PR content digest, not a sequence number \
         -- captured second outbound query: {:?}",
        queries[1]
    );
}

/// An authority that does not hold the witness's anchor answers 404 to an
/// anchored `/patch`; the witness must then ask again from genesis (a witness
/// may always do so) rather than fail the sync. Backs `sync_from_authority`'s
/// retry: red if the 404 fails the sync, or if the retry is also anchored.
#[tokio::test]
async fn sync_asks_again_from_genesis_when_the_authority_lacks_the_anchor() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;

    let captured: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let refuse_anchor = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upstream = authority.url.clone();
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get({
            let (captured, refuse_anchor) = (captured.clone(), refuse_anchor.clone());
            move |raw: axum::extract::RawQuery| {
                let (upstream, captured, refuse_anchor) =
                    (upstream.clone(), captured.clone(), refuse_anchor.clone());
                async move {
                    let query = raw.0.unwrap_or_default();
                    captured.lock().unwrap().push(query.clone());
                    if refuse_anchor.load(std::sync::atomic::Ordering::SeqCst)
                        && query.contains("from=")
                    {
                        return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({})))
                            .into_response();
                    }
                    let body: serde_json::Value = reqwest::Client::new()
                        .get(format!("{upstream}/patch?{query}"))
                        .header("accept", "application/json")
                        .send()
                        .await
                        .expect("upstream")
                        .json()
                        .await
                        .expect("upstream json");
                    axum::Json(body).into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let proxy_url = format!("http://{}", listener.local_addr().expect("addr"));
    let _proxy = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let (witness_state, _witness_app) = witness_for(&proxy_url, None).await;

    let first = sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(first, SyncOutcome::Synced { applied: 2, rejected: 0 }),
        "{first:?}"
    );

    refuse_anchor.store(true, std::sync::atomic::Ordering::SeqCst);
    captured.lock().unwrap().clear();
    let second = sync_from_authority(&witness_state, &principal).await;
    assert!(matches!(second, SyncOutcome::UpToDate), "{second:?}");
    let queries = captured.lock().unwrap().clone();
    assert_eq!(queries.len(), 2, "anchored ask, then one retry: {queries:?}");
    assert!(queries[0].contains("from="), "{queries:?}");
    assert!(!queries[1].contains("from="), "the retry is unanchored: {queries:?}");
}

/// N4.2: `fork_shares_sequence_rejected_by_digest_anchor`
///
/// The point of #140: a sequence number cannot bind a specific history, a
/// content digest can. Constructs a genuine equivocation -- two
/// INDEPENDENTLY built, individually valid commit chains for the same
/// principal that both claim "sequence 1", but with different content and
/// therefore different PR digests -- the split-view shape, where an anchor
/// that cannot distinguish two records fails silently. The canonical
/// authority never held the fork's commit, so the fork's digest must not
/// resolve to the canonical chain's own sequence-1 position merely because
/// the two share a sequence number.
///
/// Differential, not a bare assertion (per the composer's note that a prior
/// suite in this campaign asserted a property no fixture could exercise):
/// the HONEST digest anchor's resume tail is the POSITIVE control (this
/// alone is RED against the current `u64` anchor -- a tagged digest string
/// never parses as a sequence number), and the FORK's digest -- despite
/// claiming the identical position -- MUST NOT resolve to that same tail.
#[tokio::test]
async fn fork_shares_sequence_rejected_by_digest_anchor() {
    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    // The fork lives on a SEPARATE authority and shares the canonical genesis
    // (hence the genesis-derived id); it diverges only at sequence 1.
    let fork_principal_id = principal_id;
    let now = 1_700_200_000;

    // Canonical authority: three genuinely chained commits.
    let bodies =
        build_chained_push_bodies(&pool, principal_id, now, &["key_a", "key_b", "alice"]).await;
    let (auth_state, _identity, _auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");
    for body in &bodies {
        let (status, resp) = post_json(auth_app.clone(), "/push", body.clone()).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "canonical chain push: {resp:?}"
        );
    }

    // The honest position-1 PR digest, read back from the canonical chain's
    // own `/patch` entries -- exactly what a witness anchored there holds.
    let (_, canonical_patch) =
        get_json(auth_app.clone(), &format!("/patch?pr={principal_id}")).await;
    let canonical_entries = canonical_patch["payload"]["entries"]
        .as_array()
        .cloned()
        .expect("canonical patch entries array");
    assert_eq!(
        canonical_entries.len(),
        3,
        "canonical chain must hold 3 entries"
    );
    let honest_seq1_pr = canonical_entries[1]["pr"]
        .as_str()
        .expect("entry[1] carries pr digest")
        .to_string();

    // A SEPARATE, independent authority holding a fork: the SAME genesis
    // shape (key_a, signed by golden) but a DIFFERENT, genuinely valid
    // "sequence 1" commit (introducing "bob" rather than "key_b") -- a real
    // equivocation, not a corrupted/forged fixture.
    let fork_bodies =
        build_chained_push_bodies(&pool, fork_principal_id, now, &["key_a", "bob"]).await;
    let (fork_state, _fork_identity, _fork_dir) = attestor_server().await;
    let fork_app = build_app_router(fork_state.clone()).expect("fork router");
    for body in &fork_bodies {
        let (status, resp) = post_json(fork_app.clone(), "/push", body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "fork chain push: {resp:?}");
    }
    let (_, fork_patch) =
        get_json(fork_app.clone(), &format!("/patch?pr={fork_principal_id}")).await;
    let fork_entries = fork_patch["payload"]["entries"]
        .as_array()
        .cloned()
        .expect("fork patch entries array");
    assert_eq!(fork_entries.len(), 2, "fork chain must hold 2 entries");
    let fork_seq1_pr = fork_entries[1]["pr"]
        .as_str()
        .expect("fork entry[1] carries pr digest")
        .to_string();
    assert_ne!(
        honest_seq1_pr, fork_seq1_pr,
        "fixture bug: the fork must genuinely diverge from the canonical chain at the shared \
         sequence position"
    );

    // POSITIVE CONTROL: the honest digest anchor resumes correctly.
    let (honest_status, honest_resp) = get_json(
        auth_app.clone(),
        &format!("/patch?pr={principal_id}&from={honest_seq1_pr}"),
    )
    .await;
    assert_eq!(
        honest_status,
        StatusCode::OK,
        "resuming from the canonical chain's own digest MUST succeed: {honest_resp:?}"
    );
    let honest_tail = honest_resp["payload"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        honest_tail.len(),
        1,
        "the honest digest anchor MUST resume to exactly the one entry after it: {honest_resp:?}"
    );

    // THE FORK: querying the CANONICAL authority with the fork's digest
    // (same claimed position, different content) MUST NOT be accepted as
    // the same resume point.
    let (fork_anchor_status, fork_anchor_resp) = get_json(
        auth_app.clone(),
        &format!("/patch?pr={principal_id}&from={fork_seq1_pr}"),
    )
    .await;
    let fork_anchor_tail = if fork_anchor_status == StatusCode::OK {
        fork_anchor_resp["payload"]["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    assert_ne!(
        fork_anchor_tail, honest_tail,
        "a digest that shares the canonical chain's sequence position but not its content MUST \
         NOT resolve to the same resume tail as the genuine anchor -- fork response: \
         {fork_anchor_resp:?}"
    );
}

/// N4.4: `sequence_only_anchor_does_not_resume`
///
/// A request whose ONLY anchor is a raw sequence number -- exactly what the
/// legacy `from={from_seq}` path sent -- MUST NOT resume the same way the
/// genuine digest anchor does; sequence becomes metadata (S3), never a de
/// facto anchor, including under a THIRD spelling the N4.3 grep for the two
/// known literal forms cannot catch. Paired with the same positive control
/// as the fork test: the digest anchor resuming correctly to exactly one
/// entry is what's actually RED against the current `u64`-typed `from`,
/// since a tagged digest string fails to parse there today.
#[tokio::test]
async fn sequence_only_anchor_does_not_resume() {
    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    let now = 1_700_300_000;

    let bodies =
        build_chained_push_bodies(&pool, principal_id, now, &["key_a", "key_b", "alice"]).await;
    let (auth_state, _identity, _auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");
    for body in &bodies {
        let (status, resp) = post_json(auth_app.clone(), "/push", body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "chain push: {resp:?}");
    }

    let (_, patch_resp) = get_json(auth_app.clone(), &format!("/patch?pr={principal_id}")).await;
    let entries = patch_resp["payload"]["entries"]
        .as_array()
        .cloned()
        .expect("patch entries array");
    assert_eq!(entries.len(), 3, "canonical chain must hold 3 entries");
    let seq1_pr = entries[1]["pr"].as_str().expect("entry[1] pr").to_string();
    let seq1_number = entries[1]["sequence"].as_u64().expect("entry[1] sequence");

    // Digest anchor: MUST resume to exactly the one entry after position 1.
    let (digest_status, digest_resp) = get_json(
        auth_app.clone(),
        &format!("/patch?pr={principal_id}&from={seq1_pr}"),
    )
    .await;
    assert_eq!(digest_status, StatusCode::OK, "{digest_resp:?}");
    let digest_tail = digest_resp["payload"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(digest_tail.len(), 1, "{digest_resp:?}");

    // Bare sequence number, same numeric position: MUST NOT reach the same
    // resume outcome.
    let (seq_status, seq_resp) = get_json(
        auth_app.clone(),
        &format!("/patch?pr={principal_id}&from={seq1_number}"),
    )
    .await;
    let seq_tail = if seq_status == StatusCode::OK {
        seq_resp["payload"]["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    assert_ne!(
        seq_tail, digest_tail,
        "a bare sequence number MUST NOT function as a de facto resync anchor once the digest \
         anchor is in place -- sequence-only response: {seq_resp:?}"
    );
}

/// N4.5: `anchor_digest_rejects_malformed`
///
/// A malformed `from` anchor MUST be refused with the app's structured JSON
/// error envelope -- the same `AppError::bad_request` pattern the existing
/// `GET /e/{digest}` handler already uses for a malformed digest path
/// parameter (routes.rs's `entity` handler) -- not silently treated as
/// absent. Checking ONLY the status code would be vacuous: today, ANY
/// non-numeric `from` value already 400s via axum's generic `Option<u64>`
/// query-rejection, coincidentally at the same status code, but with
/// axum's default plain-text body rather than the app's JSON envelope.
/// Requiring the JSON envelope shape is what's actually RED today.
#[tokio::test]
async fn anchor_digest_rejects_malformed() {
    let pool = load_pool();
    let principal_id_owned = common::golden_principal_id(&load_pool()).await;
    let principal_id = principal_id_owned.as_str();
    let now = 1_700_400_000;

    let bodies = build_chained_push_bodies(&pool, principal_id, now, &["key_a", "key_b"]).await;
    let (auth_state, _identity, _auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");
    for body in &bodies {
        let (status, resp) = post_json(auth_app.clone(), "/push", body.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "chain push: {resp:?}");
    }

    // Digest-shaped (right "ALG:" prefix) but the wrong byte length for
    // SHA-256 -- the exact `DigestLengthMismatch` case
    // `cyphr::state::TaggedDigest`'s own unit tests already pin
    // (rs/cyphr/src/state.rs's `tagged_digest_length_mismatch`).
    let malformed = "SHA-256:AAAAAAAAAAAAAAAAAAAAAA";
    let (status, resp) = get_json(
        auth_app.clone(),
        &format!("/patch?pr={principal_id}&from={malformed}"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed digest anchor MUST be refused with 400: {resp:?}"
    );
    let payload = common::envelope_payload(&resp);
    let message = payload["error"].as_str().expect(
        "a malformed-anchor refusal MUST carry the app's JSON error envelope, not axum's default \
         plain-text query rejection",
    );
    assert!(
        message.to_lowercase().contains("digest"),
        "refusal message should name the digest as the problem, got: {message:?}"
    );
}

/// Merge-gate C1 (F1): the bounded-`to` unsigned guard in `routes.rs`'s
/// `patch` handler is a deliberate, security-relevant refusal-to-sign --
/// signing the authority's CURRENT tip attestation over a response that may
/// stop short of it (a bounded `to`) would misdescribe what was actually
/// served. Before this test, NOTHING in the suite could distinguish that
/// guard existing from it being deleted outright: `e2e.rs`'s only bounded
/// caller (`patch_with_range`) runs against a KEYLESS server, so its
/// response is unsigned regardless of the guard, and it asserts nothing
/// about `statement` at all.
///
/// Paired with a positive control on the SAME authority and principal: an
/// UNBOUNDED request IS signed. Without the control, "unsigned" here could
/// be misread as "this server never signs" rather than "this specific
/// response was refused a signature" -- exactly the vacuity class this
/// campaign's earlier suites (N4 included) were built to close.
#[tokio::test]
async fn patch_bounded_to_is_unsigned_on_attestor() {
    let now = 1_700_500_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;

    let (unbounded_status, unbounded) = get_json(
        authority.instance.router.clone(),
        &format!("/patch?pr={principal}"),
    )
    .await;
    assert_eq!(unbounded_status, StatusCode::OK, "{unbounded:?}");
    assert_eq!(
        unbounded["statement"]["kind"], "signed",
        "positive control: an UNBOUNDED patch on a signing-capable authority must be signed -- \
         {unbounded:?}"
    );

    let (bounded_status, bounded) = get_json(
        authority.instance.router.clone(),
        &format!("/patch?pr={principal}&to=0"),
    )
    .await;
    assert_eq!(bounded_status, StatusCode::OK, "{bounded:?}");
    assert_eq!(
        bounded["statement"]["kind"], "unsigned",
        "a bounded `to` response MUST be served unsigned -- signing the authority's CURRENT tip \
         over a response that stops short of it would misdescribe what was actually served: \
         {bounded:?}"
    );
    let entries = bounded["payload"]["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        entries.len(),
        1,
        "to=0 should bound the response to exactly commit 0: {bounded:?}"
    );
}

// ========================================================================
// Extraction net: behaviour the pull-sync extraction must preserve
// ========================================================================

/// Claim: witness pull sync of a MULTI-commit principal converges to the
/// authority's tip, and the authenticated channel refuses both a
/// body altered after signing and a body signed by a different key,
/// leaving the witness holding nothing. End-to-end scenario: yes (real
/// authority over TCP, on-path proxy, real witness engine).
///
/// Turns red if a refactor of the sync path: applies entries without
/// reconciling to the signed report (the tamper cases then end `Synced`);
/// verifies the envelope against the wrong key or skips the algorithm
/// check (the mis-signed case then applies); or stops advancing past the
/// first commit (the convergence case then stops at count 1). Existing
/// tests pin each of these on genesis-only or single-field fixtures; this
/// pins them together on a chained principal against the engine's
/// resulting tip, which is what a relocated sync loop must still produce.
#[tokio::test]
async fn sync_converges_and_refuses_tampered_or_missigned() {
    let now = 1_700_000_000;
    let principal = common::golden_principal_id(&load_pool()).await;
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_tip = authority
        .instance
        .state
        .engine
        .get_tip(&principal)
        .await
        .expect("authority tip lookup")
        .expect("authority holds the principal");
    assert_eq!(
        authority_tip.commit_count, 2,
        "fixture is a two-commit chain"
    );

    // 1. Convergence: both commits applied, every root equal to the authority's.
    let (w, _app) = witness_for(&authority.url, Some(authority.identity())).await;
    let outcome = sync_from_authority(&w, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Synced {
                applied: 2,
                rejected: 0
            }
        ),
        "an untampered two-commit sync must apply both commits: {outcome:?}"
    );
    let tip = w
        .engine
        .get_tip(&principal)
        .await
        .expect("witness tip lookup")
        .expect("witness holds the principal after sync");
    assert_eq!(tip.commit_count, 2);
    assert_eq!(tip.commit_id, authority_tip.commit_id);
    assert_eq!(
        (&tip.pr, &tip.sr, &tip.ar, &tip.cr),
        (
            &authority_tip.pr,
            &authority_tip.sr,
            &authority_tip.ar,
            &authority_tip.cr
        ),
        "witness roots must equal the authority's"
    );

    // 2. Statement altered after signing: signature no longer verifies.
    let (proxy_url, _p1) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            body["statement"]["coz"]["pay"]["sequence"] = serde_json::json!(0);
            body
        }),
    )
    .await;
    let (w, _app) = witness_for(&proxy_url, Some(authority.identity())).await;
    let outcome = sync_from_authority(&w, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EnvelopeUnsignedOrMisSigned
            }
        ),
        "a statement altered after signing must be refused as mis-signed: {outcome:?}"
    );
    assert!(
        w.engine.get_tip(&principal).await.unwrap().is_none(),
        "a refused sync must leave the witness unchanged"
    );

    // 3. Every entry's blob signature corrupted under an intact envelope.
    let (proxy_url, _p2) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            let entries = body["payload"]["entries"]
                .as_array_mut()
                .expect("authority serves entries");
            for entry in entries {
                let blob = Base64UrlUnpadded::decode_vec(entry["txs"][0][0].as_str().unwrap())
                    .expect("entry blob decodes");
                let mut coz: serde_json::Value = serde_json::from_slice(&blob).unwrap();
                let sig = coz["sig"].as_str().unwrap().to_string();
                let flipped = if sig.starts_with('A') { "B" } else { "A" };
                coz["sig"] = format!("{flipped}{}", &sig[1..]).into();
                entry["txs"][0][0] =
                    Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).unwrap()).into();
            }
            body
        }),
    )
    .await;
    let (w, _app) = witness_for(&proxy_url, Some(authority.identity())).await;
    let outcome = sync_from_authority(&w, &principal).await;
    assert!(
        matches!(outcome, SyncOutcome::Failed { .. }),
        "entries failing signature verification must not end Synced: {outcome:?}"
    );
    assert!(
        w.engine.get_tip(&principal).await.unwrap().is_none(),
        "forged entries must leave the witness unchanged"
    );

    // 4. Signed by a key other than the configured authority identity.
    let other = coz::Alg::Ed25519.generate_keypair();
    let wrong = AuthorityIdentity {
        alg: other.alg.name().to_string(),
        pub_key: other.pub_bytes.clone(),
    };
    let (w, _app) = witness_for(&authority.url, Some(wrong)).await;
    let outcome = sync_from_authority(&w, &principal).await;
    assert!(
        matches!(
            outcome,
            SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EnvelopeUnsignedOrMisSigned
            }
        ),
        "a patch signed by another key must be refused as mis-signed: {outcome:?}"
    );
    assert!(
        w.engine.get_tip(&principal).await.unwrap().is_none(),
        "a mis-signed sync must leave the witness unchanged"
    );
}

/// Claim: an unauthenticated read cannot grow server memory without bound;
/// once syncs for N attacker-chosen principal ids have finished, the
/// per-principal lock map holds no entry for them. End-to-end scenario: no
/// (it inspects `AppState::sync_locks`, which has no HTTP surface; a
/// memory-growth property is not observable through responses).
///
/// Turns red if a lock entry is kept per requested id after its sync
/// completes -- today `sync_from_authority` inserts and never removes.
/// The assertion is "nothing retained once idle", the strongest bound a
/// fix can honour; a mere cap above the probe count would not satisfy it.
#[tokio::test]
async fn sync_locks_bounded() {
    let (authority_url, _auth) = spawn_fixed_authority(serde_json::json!({})).await;
    let (witness_state, witness_app) = witness_for(&authority_url, None).await;

    const PROBES: usize = 32;
    for i in 0..PROBES {
        let (status, _) = get_json(
            witness_app.clone(),
            &format!("/tip?pr=SHA-256:unknown-principal-{i}"),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "an unknown principal must not exist"
        );
    }

    let retained = witness_state.sync_locks.lock().await.len();
    assert_eq!(
        retained, 0,
        "{PROBES} finished syncs for distinct unknown ids left {retained} lock entries"
    );
}

/// Backs key death at admission on the witness path (SPEC 6.4): the
/// authority holds a principal whose genesis keys are `golden` and `eve`,
/// a `golden` commit, then `eve`'s commit at the tip dated a minute ahead
/// of the wall clock, then `eve`'s naked revoke. A witness syncing from it
/// learns the authority's revokes before it submits the delta; the
/// witness's own receipt time, now, is `eve`'s cutoff (#203), so it admits
/// the history dated before it and refuses `eve`'s commit dated after it.
/// Turns red if the witness admits a dead key's commit dated after its
/// cutoff.
#[tokio::test]
async fn witness_refuses_a_dead_keys_tip_commit() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let eve = pool.get("eve_ed25519").expect("eve");
    let t = 1_700_000_000;
    let ahead = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        + 60;
    let mut p = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut p, g, &[eve.key().expect("eve")], t)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let live = common::key_commit_by(&mut p, "golden", "key_a", t + 1).await;
    let dead = common::key_commit_by(&mut p, "eve_ed25519", "key_b", ahead).await;

    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let mut authority = common::multi::Instance {
        name: "authority".to_string(),
        state,
        identity: Some(identity),
        dir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    authority.bind_tcp().await.expect("bind authority TCP");
    let url = authority.url().expect("authority TCP URL");
    for bundle in [&genesis, &live, &dead] {
        let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, bundle)).await;
        assert_eq!(status, StatusCode::CREATED, "authority push: {body:?}");
    }
    let (status, body) = post_json(
        app.clone(),
        "/revoke",
        common::eve_revoke(t + 2).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");

    let (witness, _) = witness_for(&url, None).await;
    let _ = sync_from_authority(&witness, &id).await;
    let tip = witness
        .engine
        .get_tip(&id)
        .await
        .expect("tip")
        .expect("the witness holds the live history");
    assert_eq!(
        tip.commit_count, 2,
        "the witness admitted eve's commit after its death"
    );
}
