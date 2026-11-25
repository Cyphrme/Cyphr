//! Peer-exposure bounds: what unauthenticated input (a config typo, a
//! garbage `pr`, repeated reads) may cost or change.
//!
//! Every RED test names, in its doc comment, the claim it backs, the lying
//! or no-op implementation that stays red, and whether it is an end-to-end
//! scenario. `--ignored` runs the reds; the rest are green characterization
//! tests of behaviour the fixes must keep.
//!
//! Not covered here, by construction: a committed push never answering 500
//! after `submit_commit` (the internal exits in `routes::push`). No fault
//! reachable through the public surface lands AFTER a durable commit --
//! every corruption this suite could inject (index poisoning, key swaps,
//! every pool algorithm) fails the commit itself or succeeds -- so forcing
//! those exits needs a production seam. See the node report.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use clap::Parser;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::{AdmissionConfig, Cli, ConfigError, ServerConfig, ServerMode};
use cyphr_server::{AppState, build_app_router, build_router};

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, golden_principal_id, load_pool, post_json,
    sign_key_create_commit,
};

// ========================================================================
// Config: a misspelled key must not silently fall back to a default
// ========================================================================

fn load_toml(toml: &str) -> Result<ServerConfig, ConfigError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cyphr-server.toml");
    std::fs::write(&path, toml).expect("write config");
    let cli = Cli::try_parse_from(["cyphr-server", "--config", path.to_str().unwrap(), "serve"])
        .expect("valid CLI args");
    cyphr_server::config::resolve_config(&cli)
}

/// The config must be refused AND the error must name the offending key, so
/// a refusal for some unrelated reason cannot pass.
fn assert_refused_naming(toml: &str, key: &str) {
    match load_toml(toml) {
        Ok(cfg) => panic!("config with unknown key `{key}` was accepted: {cfg:?}"),
        Err(e) => assert!(
            e.to_string().contains(key),
            "refusal must name `{key}`, got: {e}"
        ),
    }
}

/// Backs: a misspelled security setting cannot fall back to a default; the
/// config is refused and the error names the typo. One case per table, since
/// `deny_unknown_fields` is easy to forget on any single struct (admission
/// tag enum, top level, `[limits]`, inline `RateBucket`, `[gossip]`).
/// Unit: the config loader runs before any server exists, so no HTTP surface
/// reaches it.
#[test]
fn unknown_keys_are_refused_in_every_config_table() {
    assert_refused_naming(
        "[admission]\npolcy = \"invite\"\ntokens_path = \"/x\"\n",
        "polcy",
    );
    assert_refused_naming(
        "[admission]\npolicy = \"invite\"\ntokens_path = \"/x\"\ntokens_pth = \"/y\"\n",
        "tokens_pth",
    );
    assert_refused_naming("listn = \"127.0.0.1:1\"\n", "listn");
    assert_refused_naming("[limits]\nmax_body_byte = 1\n", "max_body_byte");
    assert_refused_naming(
        "[limits]\npush = { per_second = 1, burst = 1, bursts = 2 }\n",
        "bursts",
    );
    assert_refused_naming("[gossip]\nintervall_secs = 5\n", "intervall_secs");
}

/// GREEN characterization: every shipped and every valid key still loads
/// (catches an over-eager deny, e.g. one that rejects the example config,
/// the `pub` rename, or the admission tag). E2E: load path.
#[test]
fn known_keys_still_load() {
    let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/cyphr-server.example.toml");
    let cfg = load_toml(&std::fs::read_to_string(example).expect("example config"))
        .expect("the shipped example config loads");
    assert!(matches!(cfg.admission, AdmissionConfig::Open));

    let cfg = load_toml(
        "mode = \"witness\"\n[gossip]\npeers = [\"https://a\", { url = \"https://b\", pg = \
         \"SHA-512:AAAA\" }]\n[admission]\npolicy = \"invite\"\ntokens_path = \
         \"/t\"\n[limits]\npush = { per_second = 3, burst = 4 }\n",
    )
    .expect("every valid key loads");
    assert!(matches!(cfg.admission, AdmissionConfig::Invite { .. }));
    assert_eq!(cfg.mode, ServerMode::Witness);
    assert_eq!(cfg.limits.push.burst, 4);
    assert_eq!(cfg.gossip.peers[1].pg(), Some("SHA-512:AAAA"));
}

// ========================================================================
// Witness: a malformed `pr` must not cost an outbound request
// ========================================================================

/// A mock authority counting every `/patch` it is asked for.
async fn counting_authority() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NOT_FOUND
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock authority");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, hits, handle)
}

async fn witness_against(url: &str) -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: dir.path().join("data"),
        gossip: cyphr_server::config::GossipConfig {
            peers: vec![cyphr_server::config::PeerEntry::Url(url.to_string())],
            ..Default::default()
        },
        ..Default::default()
    };
    let state = Arc::new(AppState::new(config).expect("witness AppState"));
    (build_app_router(state).expect("witness router"), dir)
}

/// A well-formed (43-char base64url) principal id nobody has created.
const WELL_FORMED_UNKNOWN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Claim: unauthenticated input cannot trigger outbound work. Red if a
/// witness asks its authority about a `pr` that is not even a digest. Lying
/// impl it catches: validating only on `/tip` (the loop covers `/patch`),
/// or only emptiness/length. E2E: HTTP in, counted outbound request.
#[tokio::test]
async fn malformed_pr_triggers_no_outbound_sync() {
    let (url, hits, _authority) = counting_authority().await;
    let (app, _dir) = witness_against(&url).await;

    let garbage = [
        "x",
        "AAAA",
        "not%20base64%21%21",
        "..%2F..%2Fetc%2Fpasswd",
        "SHA-256:",
        "SHA-256:%25%25",
        "SHA-999:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &"A".repeat(4096),
    ];
    let mut leaked = Vec::new();
    for route in ["/tip", "/patch"] {
        for pr in garbage {
            let before = hits.load(Ordering::SeqCst);
            let (status, _) = get_json(app.clone(), &format!("{route}?pg={pr}")).await;
            assert!(!status.is_server_error(), "{route} pr={pr:.20}: {status}");
            if hits.load(Ordering::SeqCst) != before {
                leaked.push(format!("{route}?pg={pr:.20}"));
            }
        }
    }
    assert!(
        leaked.is_empty(),
        "outbound sync for malformed pr: {leaked:?}"
    );
}

/// GREEN characterization: a well-formed unknown `pr` still syncs, exactly
/// once per request. Catches the no-op fix that disables witness sync (or
/// rejects every pr) to satisfy the red above.
#[tokio::test]
async fn well_formed_unknown_pr_still_syncs_once_per_request() {
    let (url, hits, _authority) = counting_authority().await;
    let (app, _dir) = witness_against(&url).await;
    for _ in 0..2 {
        let before = hits.load(Ordering::SeqCst);
        let (status, _) = get_json(app.clone(), &format!("/tip?pg={WELL_FORMED_UNKNOWN}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(hits.load(Ordering::SeqCst), before + 1);
    }
}

// ========================================================================
// Keyed /tip: an unchanged pre-PG tip must not replay history per GET
// ========================================================================

/// Claim: repeated unauthenticated reads cannot trigger unbounded work, and
/// a read of the tip the server itself admitted costs no replay at all: the
/// engine holds the roots of every commit it admitted, by the commit that
/// names them (U3). Red if a GET of an UNCHANGED keyed tip replays any
/// stored commit. Lying impl it catches: roots re-derived from the whole
/// chain on each read (base: the first read replayed, and so did every one
/// that missed a cache keyed by the request). The control is the engine's
/// own cold derivation, which the same counter must see. E2E: HTTP reads,
/// counted engine replays.
#[tokio::test]
async fn repeated_tip_get_does_not_replay_history() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let pid = golden_principal_id(&pool).await;
    let (s, b) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &pid, 1_700_000_000).await,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b:?}");

    let uri = format!("/tip?pg={pid}");
    let before = state.engine.commits_replayed();
    for _ in 0..10 {
        let (s, _) = get_json(app.clone(), &uri).await;
        assert_eq!(s, StatusCode::OK);
    }
    let extra = state.engine.commits_replayed() - before;
    assert_eq!(
        extra, 0,
        "10 unchanged reads replayed {extra} stored commits"
    );

    state.engine.rederive_roots(&pid).await.expect("rederive");
    assert!(
        state.engine.commits_replayed() > before,
        "control: the counter sees a cold derivation"
    );
}

/// GREEN characterization (metamorphic): the signed tip always reflects the
/// current chain -- after a new commit the tip's commit_count advances and
/// its signed roots equal the payload's and the engine's fresh derivation.
/// Catches a replay cache that serves stale roots after a commit. E2E.
#[tokio::test]
async fn tip_after_new_commit_is_never_stale() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let pid = golden_principal_id(&pool).await;
    let uri = format!("/tip?pg={pid}");
    let (s, b) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &pid, 1_700_000_000).await,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b:?}");
    let (_, first) = get_json(app.clone(), &uri).await;
    assert_eq!(first["payload"]["commit_count"], 1);

    let golden = pool.get("golden").unwrap();
    let genesis = || {
        cyphr_storage::Genesis::Implicit(
            cyphr::Key::new(
                golden.alg.clone(),
                golden.compute_tmb().unwrap(),
                Base64UrlUnpadded::decode_vec(&golden.pub_key).unwrap(),
            )
            .unwrap(),
        )
    };
    let stored = state
        .engine
        .load_principal(&pid, genesis())
        .await
        .expect("load");
    let entries = cyphr_storage::export_commits(&stored).expect("export");
    let principal = cyphr_storage::load_principal_from_commits(genesis(), &entries)
        .await
        .expect("replay");
    let blobs = sign_key_create_commit(principal, &pool, "golden", "key_b", 1_700_000_100).await;
    let body = common::push_body(&pid, &blobs);
    let (s, b) = post_json(app.clone(), "/push", body).await;
    assert_eq!(s, StatusCode::CREATED, "second commit: {b:?}");

    let (s, second) = get_json(app, &uri).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(second["payload"]["commit_count"], 2, "tip must advance");
    let derived = state.engine.rederive_roots(&pid).await.expect("rederive");
    let claims = &second["statement"]["coz"]["pay"]["roots"];
    assert_eq!(
        claims["sr"],
        serde_json::json!(derived.sr),
        "signed sr is the current chain's"
    );
    assert_ne!(
        first["payload"]["sr"], second["payload"]["sr"],
        "state changed"
    );
    assert_eq!(second["payload"]["sr"], serde_json::json!(derived.sr));
}
