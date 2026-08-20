//! Acceptance suite for S2's storage-layering-by-authority regroup
//! (`docs/adr/0002-storage-layering-by-authority.md`).
//!
//! The proposal (`docs/proposals/storage-layering.md`) and the ADR ask one
//! question an operator must be able to answer without reading code: which
//! directory is safe to `rm -rf`? The corrected layout (ADR-0002 Decision 1,
//! 6) answers it by construction --
//!
//! ```text
//! data_dir/
//! ├── record/                 what the server was told
//! │   ├── blobs/                  (+ every principal's EML commit-tree
//! │   │                            keyspaces -- record, not derived: see
//! │   │                            Decision 6)
//! │   ├── observations/
//! │   ├── admission/
//! │   └── server-principal.json
//! └── index/                  what the server works out; the sole
//!                             derived-class member; the only directory an
//!                             operator may ever `rm -rf`
//! ```
//!
//! Three tests, each closing a distinct facet of that promise:
//!
//! - [`fresh_boot_creates_exact_record_and_index_tree`] -- the tree itself:
//!   nothing extra, nothing missing, at either level.
//! - [`eml_commit_tree_lives_under_record_blobs_not_index`] -- the trap the
//!   layout invites: the EML commit tree is *reconstructible* from the blob
//!   store like anything in `index/`, but reconstructibility is not the
//!   authority test (ADR-0002 Decision 3, 6) -- attestation is. A test that
//!   only checked "does `rm -rf index/` + rebuild recover the same answers?"
//!   would still pass even if the commit tree's bytes physically lived
//!   inside `index/`, because replay from the blob store reconstructs the
//!   EML tree regardless of where its keyspaces currently sit (see the
//!   S1 baseline, `cyphr-storage/tests/eml_keyspace_recovery.rs`). This test
//!   checks placement directly instead: it opens the two physical fjall
//!   databases by path and asserts which one actually holds the keyspaces,
//!   so a commit tree filed under the disposable half fails here even
//!   though it would still "recover" under the other test.
//! - [`index_deletion_and_rebuild_restores_identical_answers`] -- the
//!   behavioral promise for the side that *is* disposable: deleting
//!   `index/` and rebuilding must not be observable from outside.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cyphr_server::config::{AdmissionConfig, ServerConfig};
use cyphr_server::{AppState, build_app_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

// ========================================================================
// Shared boot helper
// ========================================================================

/// Construct an `AppState` and run it through the same startup sequence
/// `serve()` runs (`lib.rs`'s `serve` function): open storage, run
/// incremental reindex, and -- when keyed and asked for -- bootstrap the
/// server's own principal (the `record/server-principal.json` sidecar).
///
/// `bootstrap_own_principal` is a separate knob from "keyed" because two of
/// the three tests below deliberately skip it: bootstrapping makes the
/// server an attestor (principal + identity both present), which signs
/// `/tip` envelopes and complicates response comparison for no benefit to
/// those tests. Login needs only `state.identity`, never `state.principal`
/// (`auth/login.rs`'s `login` handler reads `state.identity` alone), so
/// skipping the bootstrap does not weaken the login-path assertions.
async fn boot(config: ServerConfig, bootstrap_own_principal: bool) -> Arc<AppState> {
    let mut state = AppState::new(config).expect("failed to open AppState");
    state
        .engine
        .reindex(&[], false)
        .await
        .expect("incremental reindex on boot failed");

    if bootstrap_own_principal {
        if let (Some(identity), Some(key_path)) = (
            state.identity.clone(),
            state.config.signing_key_path.clone(),
        ) {
            let sp = cyphr_server::auth::principal::ServerPrincipal::bootstrap(
                &state.engine,
                identity,
                &key_path,
                &state.config.data_dir,
            )
            .await
            .expect("bootstrap server principal failed");
            state.principal = Some(Arc::new(sp));
        }
    }

    Arc::new(state)
}

/// The set of a directory's immediate entry names, panicking (with the
/// directory path) rather than silently reporting an empty set if the
/// directory does not exist -- an absent directory is a distinct finding
/// from an empty one for every assertion below.
fn read_dir_names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({dir:?}) failed: {e}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("read_dir({dir:?}) entry failed: {e}"))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// GET `uri` against `app` and return the raw response bytes, unparsed.
///
/// Deliberately distinct from `common::get_json`: that helper collapses a
/// non-JSON or empty body to `Value::Null`, which would make two
/// differently-corrupted `/e/{digest}` responses compare equal to each
/// other. `/e/{digest}` serves raw `application/octet-stream` content, so
/// the comparison this suite needs is over the exact bytes.
async fn get_bytes(app: axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

// ========================================================================
// Test 1 -- ac-layout / c-layout-exact
// ========================================================================

/// A fresh keyed boot under `policy = "invite"` must create exactly
/// `record/{blobs,observations,admission,server-principal.json}` plus
/// `index/`, and nothing else, at either level of the data directory.
///
/// Every one of the four stores under `record/` is only created by a
/// distinct construction site (`AppState::new` for `blobs`/`observations`;
/// `admission::layer`, wired only inside `build_app_router`, for
/// `admission` -- and only under the invite policy; `ServerPrincipal::
/// bootstrap` for `server-principal.json`), so this test exercises the
/// full startup sequence, not just `AppState::new`.
///
/// Currently RED: today's construction sites open `blobs/`, `observations/`,
/// `admission/`, and `server-principal.json` directly as siblings under
/// `data_dir`, so the actual top-level set is `{blobs, index, observations,
/// admission, server-principal.json}` -- five entries, no `record/` at all.
#[tokio::test]
async fn fresh_boot_creates_exact_record_and_index_tree() {
    let root = tempfile::tempdir().expect("tempdir");
    let data_dir = root.path().join("data");
    let key_path = common::write_signing_key(root.path());
    let tokens_path = root.path().join("invite-tokens.txt");
    std::fs::write(&tokens_path, "").expect("write empty invite-tokens file");

    let config = ServerConfig {
        data_dir: data_dir.clone(),
        signing_key_path: Some(key_path),
        admission: AdmissionConfig::Invite { tokens_path },
        ..Default::default()
    };

    let state = boot(config, true).await;
    // `admission::layer` (and therefore `record/admission`, under the
    // invite policy) is composed only here, never in `AppState::new`.
    let _app = build_app_router(state.clone()).expect("failed to build app router");

    let top_level = read_dir_names(&data_dir);
    let expected_top_level: BTreeSet<String> =
        ["record", "index"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        top_level, expected_top_level,
        "a fresh keyed boot under policy=invite must create exactly record/ and index/ at the \
         top level of the data directory (ADR-0002 Decision 1), got: {top_level:?}"
    );

    let record_dir = data_dir.join("record");
    let record_entries = read_dir_names(&record_dir);
    let expected_record_entries: BTreeSet<String> = [
        "blobs",
        "observations",
        "admission",
        "server-principal.json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        record_entries, expected_record_entries,
        "record/ must hold exactly the four told stores (ADR-0002 Decision 1), got: \
         {record_entries:?}"
    );

    for name in ["blobs", "observations", "admission"] {
        let p = record_dir.join(name);
        assert!(
            p.is_dir(),
            "record/{name} must be a directory (its own fjall database), got {p:?}"
        );
    }
    assert!(
        record_dir.join("server-principal.json").is_file(),
        "record/server-principal.json must be a plain file, matching the genesis-record sidecar \
         `ServerPrincipal::bootstrap` writes"
    );
    assert!(
        data_dir.join("index").is_dir(),
        "index/ must be a directory (the sole derived-class member, ADR-0002 Decision 6)"
    );
}

// ========================================================================
// Test 2 -- the reconstructibility trap (grounds ADR-0002 Decision 6)
// ========================================================================

/// The EML commit-tree keyspaces backing a principal's chain must live
/// inside the physical fjall database at `record/blobs`, never inside the
/// one at `index/` -- checked directly by opening both databases at their
/// expected final paths and probing keyspace presence, not inferred from
/// whether the tree can be reconstructed (it always can: see the module
/// doc's trap explanation and the S1 baseline,
/// `cyphr-storage/tests/eml_keyspace_recovery.rs`).
///
/// Currently RED: `record/blobs` does not exist yet at all (today's blob
/// store opens at the top-level `blobs/`), so opening it fresh finds none
/// of the expected keyspaces.
#[tokio::test]
async fn eml_commit_tree_lives_under_record_blobs_not_index() {
    let root = tempfile::tempdir().expect("tempdir");
    let data_dir = root.path().join("data");
    let config = ServerConfig {
        data_dir: data_dir.clone(),
        ..Default::default()
    };

    let state = boot(config, false).await;
    let fixture = common::load_golden("mutations", "key_add_changes_state");
    let principal_id = "s2-eml-placement-check";
    common::bootstrap_principal(&state, principal_id, &fixture).await;

    // Drop every handle onto the physical databases (the engine, the blob
    // store, the indexer, all reachable only through `state`) before
    // reopening them independently below -- fjall databases are exclusive
    // per open handle, mirroring the S1 baseline's own
    // populate-then-drop-then-reopen structure.
    drop(state);

    // Mirrors the fixed keyspace-name suffixes
    // `storage_fjall::FjallStorage::with_database_scoped` opens (see the S1
    // baseline's `delete_principal_eml_keyspaces`). `principal_id` here uses
    // only characters already inside `sanitize_fjall_prefix`'s passthrough
    // charset, so the sanitized name is the identifier itself.
    let eml_keyspaces = [
        format!("{principal_id}_eml_leaves"),
        format!("{principal_id}_eml_nodes"),
        format!("{principal_id}_eml_metadata"),
    ];

    let record_blobs_db = fjall::Database::builder(data_dir.join("record").join("blobs"))
        .open()
        .expect("open record/blobs db");
    for name in &eml_keyspaces {
        assert!(
            record_blobs_db.keyspace_exists(name),
            "principal {principal_id}'s EML keyspace {name} must live inside record/blobs -- \
             ADR-0002 Decision 6: the commit tree is record data (its root is signed into every \
             commit's Arrow, SPEC.md:114,333-339,587-588), not a derived projection, so it \
             belongs in the record/ tree the same as any other told store. Found no such \
             keyspace there."
        );
    }

    let index_db = fjall::Database::builder(data_dir.join("index"))
        .open()
        .expect("open index db");
    for name in &eml_keyspaces {
        assert!(
            !index_db.keyspace_exists(name),
            "principal {principal_id}'s EML keyspace {name} must NOT live inside index/ -- \
             finding it there means record data (attested by every commit's Arrow) has been \
             filed under the one directory the layout tells an operator is safe to `rm -rf`: \
             data loss waiting for someone to act on the layout's own promise."
        );
    }
}

// ========================================================================
// Test 3 -- ac-rebuild / c-index-disposable
// ========================================================================

/// `rm -rf <data_dir>/index` followed by a full rebuild must restore
/// identical answers on `/tip`, `/e/{digest}`, and login -- the disposal
/// side of the promise Test 1 states structurally: `index/` is the one
/// directory an operator may delete, and nothing served through it may be
/// observably different afterward.
///
/// `/tip`'s `now` field is wall-clock at request time (`auth::server_now()`
/// in `routes.rs`), not reconstructed record state, so it is excluded from
/// the comparison; every other `/tip` field, the raw `/e/{digest}` bytes,
/// and the login-issued token's decoded `pr` claim are compared directly.
/// The literal bearer-token string is not compared (`issue_token` mints a
/// fresh token bound to the real call-time `now`), but the same signed
/// login request body is replayed against both boots and must succeed
/// both times and authenticate the same principal both times -- which is
/// the property that would break if `resolve_genesis`/`load_principal`
/// (both index-served, `routes.rs`/`engine/mod.rs`) failed to recover
/// after the index rebuild.
///
/// This is `index/`'s literal, top-level path unchanged by this node
/// (ADR-0002 Decision 1: `index/` is regrouped, not moved -- `rm -rf
/// data/index` stays correct, `docs/guides/operating-a-server.md:327-333`),
/// so unlike Tests 1-2 this property does not depend on the record/
/// regroup landing first; it independently pins the disposability
/// guarantee this node's rewiring must not regress.
#[tokio::test]
async fn index_deletion_and_rebuild_restores_identical_answers() {
    const AUDIENCE: &str = "cyphr.me";

    let root = tempfile::tempdir().expect("tempdir");
    let data_dir = root.path().join("data");
    let key_path = common::write_signing_key(root.path());

    let config = ServerConfig {
        data_dir: data_dir.clone(),
        signing_key_path: Some(key_path),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };

    let state = boot(config.clone(), false).await;
    let app = build_app_router(state.clone()).expect("failed to build app router");

    let pool = common::load_pool();
    let principal_id = "s2-index-rebuild-check";
    let push_now = 1_700_000_000;
    let push_body = common::build_genesis_push_body(&pool, principal_id, push_now);
    let (push_status, push_json) = common::post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "genesis push must succeed to set up the fixture: {push_json:?}"
    );

    // -- before: snapshot /tip, /e/{commit_id}, and a login attempt --

    let (tip_status_before, tip_before) =
        common::get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status_before, StatusCode::OK, "{tip_before:?}");
    let tip_payload_before = common::envelope_payload(&tip_before).clone();
    let commit_id = tip_payload_before["commit_id"]
        .as_str()
        .expect("tip payload carries commit_id")
        .to_string();

    let (entity_status_before, entity_bytes_before) =
        get_bytes(app.clone(), &format!("/e/{commit_id}")).await;
    assert_eq!(
        entity_status_before,
        StatusCode::OK,
        "GET /e/{{commit_id}} must resolve before deletion (status {entity_status_before})"
    );
    assert!(
        !entity_bytes_before.is_empty(),
        "entity bytes must be non-empty before deletion, or the comparison below proves nothing"
    );

    let login_now = now_secs();
    let login_request_body = login_body(&pool, "golden", AUDIENCE, Some(principal_id), None, login_now);
    let (login_status_before, login_before) =
        common::post_json(app.clone(), "/auth/login", login_request_body.clone()).await;
    assert_eq!(login_status_before, StatusCode::OK, "{login_before:?}");
    let token_before = common::envelope_payload(&login_before)["token"]
        .as_str()
        .expect("login payload carries token")
        .to_string();
    let identity_before = state.identity.clone().expect("keyed server has identity");
    let claims_before = identity_before
        .verify_token(&token_before, now_secs())
        .expect("token issued before deletion must verify");
    assert_eq!(claims_before.pr, principal_id);

    // Drop every handle onto the physical databases before touching
    // index/ on disk.
    drop(app);
    drop(state);

    let index_path = data_dir.join("index");
    assert!(
        index_path.exists(),
        "index/ must exist before deletion, or this test is not exercising c-index-disposable"
    );
    std::fs::remove_dir_all(&index_path).expect("remove index directory");

    // -- rebuild: reopen storage at the same data_dir, then a full reindex --

    let state = boot(config, false).await;
    state
        .engine
        .reindex(&[], true)
        .await
        .expect("full reindex after index deletion failed");
    let app = build_app_router(state.clone()).expect("failed to build app router (post-rebuild)");

    // -- after: re-issue the same three requests and compare --

    let (tip_status_after, tip_after) =
        common::get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status_after, StatusCode::OK, "{tip_after:?}");
    let mut tip_payload_after = common::envelope_payload(&tip_after).clone();
    let mut tip_payload_before_cmp = tip_payload_before.clone();
    for payload in [&mut tip_payload_after, &mut tip_payload_before_cmp] {
        payload
            .as_object_mut()
            .expect("tip payload is a JSON object")
            .remove("now");
    }
    assert_eq!(
        tip_payload_after, tip_payload_before_cmp,
        "every reconstructed /tip field but wall-clock `now` must be identical after the index \
         rebuild"
    );

    let (entity_status_after, entity_bytes_after) =
        get_bytes(app.clone(), &format!("/e/{commit_id}")).await;
    assert_eq!(
        entity_status_after,
        StatusCode::OK,
        "GET /e/{{commit_id}} must resolve identically after the index rebuild (status \
         {entity_status_after})"
    );
    assert_eq!(
        entity_bytes_after, entity_bytes_before,
        "entity bytes must be byte-for-byte identical after the index rebuild"
    );

    let (login_status_after, login_after) =
        common::post_json(app.clone(), "/auth/login", login_request_body).await;
    assert_eq!(login_status_after, StatusCode::OK, "{login_after:?}");
    let token_after = common::envelope_payload(&login_after)["token"]
        .as_str()
        .expect("login payload carries token")
        .to_string();
    let identity_after = state.identity.clone().expect("keyed server has identity");
    let claims_after = identity_after
        .verify_token(&token_after, now_secs())
        .expect("token issued after the index rebuild must verify");
    assert_eq!(
        claims_after.pr, claims_before.pr,
        "login must authenticate the same principal before and after the index rebuild"
    );
}

// ------------------------------------------------------------------------
// Login body construction, mirrored from `tests/login.rs` (a separate
// integration-test crate this one cannot import from).
// ------------------------------------------------------------------------

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Sign a login envelope with a pool key, returning the JSON request body.
/// `claimed_pr` is the principal the signer claims; `challenge` selects the
/// challenge-response flow when present (unused by this suite, which only
/// exercises the timestamp flow).
fn login_body(
    pool: &test_fixtures::Pool,
    signer_name: &str,
    audience: &str,
    claimed_pr: Option<&str>,
    challenge: Option<&str>,
    now: i64,
) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let signer = pool.get(signer_name).expect("signer in pool");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("signer prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub b64");
    let tmb = signer.compute_tmb().expect("signer tmb");

    let mut pay = coz::Pay::new();
    pay.alg = Some(signer.alg.clone());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(format!("{audience}/cyphr/auth/login"));
    if let Some(pr) = claimed_pr {
        pay.extra
            .insert("pr".to_string(), serde_json::Value::String(pr.into()));
    }
    if let Some(c) = challenge {
        pay.extra
            .insert("challenge".to_string(), serde_json::Value::String(c.into()));
    }

    let pay_bytes = serde_json::to_vec(&pay).unwrap();
    let (sig, _cad) = coz::sign_json(&pay_bytes, &signer.alg, &prv, &pub_key).expect("sign login");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).unwrap(),
        sig,
    })
    .unwrap()
}
