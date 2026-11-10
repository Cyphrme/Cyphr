//! Shared integration-test harness for the cyphr-server MSS API.
//!
//! Integration tests are separate crates, so each suite hand-rolled the same
//! server-construction and fixture boilerplate. This module consolidates that
//! seam behind a small builder API, shared via the standard `mod common;`
//! submodule pattern -- the mechanism for reusing code across integration-test
//! crates, which cannot `use` one another.
//!
//! Each integration crate compiles this module independently and uses only the
//! subset of helpers it needs, so per-crate `dead_code` is inherent to the
//! pattern rather than a defect; it is allowed here once instead of annotated
//! item by item.
#![allow(dead_code)]

pub mod multi;

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::AppState;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

// ========================================================================
// Capability 1 -- build a server (keyless, keyed, and keyed+bootstrapped)
// ========================================================================

/// Build a keyless `AppState` over a fresh temporary data directory.
///
/// Returns the state alongside the `TempDir` guard: hold it for the test's
/// lifetime (dropping it removes the on-disk store).
pub fn keyless_server() -> (Arc<AppState>, TempDir) {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let config = ServerConfig {
        data_dir: temp_dir.path().to_path_buf(),
        ..Default::default()
    };
    let state = Arc::new(AppState::new(config).expect("failed to open keyless AppState"));
    (state, temp_dir)
}

/// Write a fresh Ed25519 signing key file into `dir` and return its path.
pub fn write_signing_key(dir: &Path) -> std::path::PathBuf {
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

/// A keyed `AppState` whose signing key is `key_path`, keyed but not yet
/// bootstrapped. Mirrors what `serve` constructs before it bootstraps the
/// principal, so callers can observe the keyed-but-unbootstrapped state.
pub fn keyed_appstate(data_dir: &Path, key_path: &Path) -> AppState {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    AppState::new(config).expect("keyed AppState opens")
}

/// A keyed, bootstrapped `AppState` -- the attestor condition -- plus the
/// live identity handle used to check receipt claims against, and the
/// `TempDir` guard backing its store. Hold the guard for the test's
/// lifetime.
pub async fn attestor_server() -> (Arc<AppState>, Arc<ServerIdentity>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
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

    (Arc::new(state), identity, dir)
}

// ========================================================================
// Capability 2 -- golden fixtures, and push / bootstrap a principal
// ========================================================================

/// Load a golden fixture from the shared workspace test vectors.
pub fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

/// Convert a golden fixture's key JSON to a domain `cyphr::Key`.
pub fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();

    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();

    cyphr::Key::new(
        alg.to_string(),
        Thumbprint::from_bytes(tmb_bytes),
        pub_bytes,
    )
    .expect("key binds its tmb")
}

/// Build genesis from a golden fixture's `genesis_keys` array.
pub fn make_genesis(genesis_keys: &[serde_json::Value]) -> cyphr_storage::Genesis {
    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    if keys.len() == 1 {
        cyphr_storage::Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        cyphr_storage::Genesis::Explicit(keys)
    }
}

/// Build raw coz blobs from a golden fixture's commit, embedding key material.
pub fn build_raw_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    let mut blobs = Vec::new();

    for coz_value in cozies {
        let mut coz = coz_value.clone();

        let typ = coz["pay"]["typ"].as_str().unwrap_or("");
        let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(typ);

        if is_key_introducing {
            if let Some(ks) = keys {
                if key_idx < ks.len() {
                    coz.as_object_mut()
                        .unwrap()
                        .insert("key".to_string(), ks[key_idx].clone());
                    key_idx += 1;
                }
            }
        }

        blobs.push(serde_json::to_vec(&coz).unwrap());
    }

    blobs
}

/// The id the fixture's genesis derives, i.e. the only `principal_id`
/// `bootstrap_principal` may use for it: the PG its genesis commit names
/// (SPEC 5.1), or for a fixture with none its genesis key's PR (SPEC 3.1).
pub fn fixture_principal_id(fixture: &serde_json::Value) -> String {
    let named = fixture["commits"]
        .as_array()
        .and_then(|commits| commits.first())
        .and_then(|first| first["txs"].as_array())
        .and_then(|txs| {
            let blobs: Vec<Vec<u8>> = txs
                .iter()
                .filter_map(|tx| serde_json::to_vec(tx).ok())
                .collect();
            test_fixtures::bundle::genesis_id(&blobs)
        });
    named.unwrap_or_else(|| {
        let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
        cyphr_storage::engine::genesis_principal_id(&make_genesis(genesis_keys))
            .expect("fixture genesis derives an id")
    })
}

/// Bootstrap a principal into the engine via the validated write path, using
/// the fixture's explicit genesis.
pub async fn bootstrap_principal(
    state: &AppState,
    principal_id: &str,
    fixture: &serde_json::Value,
) {
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        state
            .engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("bootstrap submit_commit failed");
    }
}

/// Load the shared cryptographic key pool backing the golden fixtures.
pub fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

/// Sign a fresh "add `new_key_name`" commit onto `principal`, signed by
/// `signer_name` (must have a known private key in `pool`). Returns the new
/// commit's raw coz blob bytes, wire-ready for `submit_commit`.
///
/// Takes `principal` by value rather than `&Principal` + internal `.clone()`
/// deliberately: `Principal::clone()` shares the underlying `CloneableLog`'s
/// `Arc<Mutex<Log<S>>>>`, not a deep copy, so cloning one shared starting
/// principal for N variants would have all N append to the SAME commit tree.
/// Each call site must instead build its own independent `Principal` (e.g. via
/// a fresh `load_principal_from_commits` call) to get genuinely independent,
/// mutually-exclusive alternative "next commits".
pub fn sign_key_create_commit(
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

    // Field order is alphabetical, matching `canonicalize_value`'s
    // `sort_keys()` byte-for-byte -- the server re-canonicalizes before
    // computing czd/verifying, so signing over any other order would make
    // the signature mismatch what the server re-derives.
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
        .expect("key/create should verify against the starting principal state");

    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&signer.alg, &signer_prv, &signer_pub, &signer_tmb),
            now,
            "cyphr.me",
        )
        .expect("commit should finalize");

    let entries = cyphr_storage::export_commits(&principal).expect("export the new commit");
    let new_commit = entries.last().expect("at least one commit after finalize");

    // `export_commits` deliberately doesn't embed "key" into the cozy JSON
    // (it carries key material separately, at the commit level, for the
    // internal CommitEntry storage format) -- but the wire format
    // `submit_commit` parses from raw client blobs expects "key" embedded
    // directly on the key-introducing cozy itself. Embed it here for the one
    // key/create cozy.
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

/// The id a principal with an implicit genesis on pool key `name` derives
/// (SPEC 3.1): that key's thumbprint, base64url. A principal that commits
/// is keyed by its PG instead ([`genesis_push_id`]).
pub fn implicit_principal_id(pool: &test_fixtures::Pool, name: &str) -> String {
    pool.get(name)
        .expect("key in pool")
        .compute_tmb_b64()
        .expect("pool key tmb")
}

/// The principal [`build_genesis_push_body_with`] pushes and its genesis
/// commit's blobs: `genesis_name` creates itself, then `new_key_name`.
fn genesis_push(
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    new_key_name: &str,
    now: i64,
) -> (cyphr::Principal, Vec<Vec<u8>>) {
    let key = |name: &str| {
        pool.get(name)
            .expect("key in pool")
            .key()
            .expect("pool key")
    };
    let mut principal = cyphr::Principal::implicit(key(genesis_name)).expect("genesis");
    let blobs = test_fixtures::bundle::genesis_bundle(
        &mut principal,
        pool.get(genesis_name).expect("genesis key in pool"),
        &[key(new_key_name)],
        now,
    )
    .expect("genesis commit");
    (principal, blobs)
}

/// The id (the PG) of the principal whose genesis commit
/// [`build_genesis_push_body_with`] builds for `genesis_name` and
/// `new_key_name`. The PG is the state the genesis keys root, whatever
/// the commit's time.
pub fn genesis_push_id(
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    new_key_name: &str,
) -> String {
    let (_, blobs) = genesis_push(pool, genesis_name, new_key_name, 1);
    test_fixtures::bundle::genesis_id(&blobs).expect("genesis PG")
}

/// The id of the standard test principal, the one `build_genesis_push_body`
/// builds: `golden` with `key_a`.
pub fn golden_principal_id(pool: &test_fixtures::Pool) -> String {
    genesis_push_id(pool, "golden", "key_a")
}

/// The principal [`build_genesis_push_body_with`] pushes, after its genesis
/// commit: the state a test signs its next commit on.
pub fn genesis_pushed_principal(
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    new_key_name: &str,
    now: i64,
) -> cyphr::Principal {
    genesis_push(pool, genesis_name, new_key_name, now).0
}

/// Build a brand-new principal's genesis push HTTP body: its genesis
/// commit (SPEC 5.1, 5.3), in which `genesis_name` creates itself and
/// `new_key_name`, then signs the `principal/create` and `commit/create`.
/// Every `key/create` discloses its key, so the principal reads from the
/// blobs alone. Its id is [`genesis_push_id`]; pass that as
/// `principal_id` unless the test deliberately pushes under another one.
pub fn build_genesis_push_body_with(
    pool: &test_fixtures::Pool,
    genesis_name: &str,
    new_key_name: &str,
    principal_id: &str,
    now: i64,
) -> String {
    let (_, blobs) = genesis_push(pool, genesis_name, new_key_name, now);
    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// The standard genesis push: `golden` with `key_a`.
pub fn build_genesis_push_body(pool: &test_fixtures::Pool, principal_id: &str, now: i64) -> String {
    build_genesis_push_body_with(pool, "golden", "key_a", principal_id, now)
}

/// Build a second commit push HTTP body for the standard principal
/// ([`build_genesis_push_body`] pushed at `genesis_now`), introducing
/// `key_b`, signed by `golden`.
pub fn build_second_commit_push_body(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    genesis_now: i64,
    now: i64,
) -> String {
    let principal = genesis_pushed_principal(pool, "golden", "key_a", genesis_now);
    let blobs = sign_key_create_commit(principal, pool, "golden", "key_b", now);

    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

// ========================================================================
// Capability 3 -- issue HTTP requests (unauthed oneshot against build_router)
// ========================================================================
//
// The two adopting suites only issue unauthed requests; a bearer-authed
// variant is deliberately omitted (no adopting suite needs one yet -- see the
// harness node's report). Add it at the layer whose suite first requires it.

/// Send an unauthed `GET` against the router via `oneshot`, returning the
/// status and the parsed JSON body (`Null` when the body is empty or not
/// JSON, e.g. an empty error response).
pub async fn get_json(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
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

/// Send an unauthed `POST` of a JSON `body` against the router via `oneshot`,
/// returning the status and the parsed JSON body (`Null` when empty or not
/// JSON).
pub async fn post_json(app: Router, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
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

// ========================================================================
// Capability 4 -- inspect responses
// ========================================================================

/// Assert `body` is a well-formed unsigned envelope
/// (`docs/specs/http-envelope.md`) and return its `payload` for further
/// field assertions -- migrated suites read `payload.*`, never top-level
/// fields.
pub fn envelope_payload(body: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(
        body["v"],
        serde_json::json!(1),
        "response must carry envelope v=1: {body:?}"
    );
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("unsigned"),
        "an unattested response must be explicitly unsigned, not merely missing a signature: \
         {body:?}"
    );
    &body["payload"]
}
