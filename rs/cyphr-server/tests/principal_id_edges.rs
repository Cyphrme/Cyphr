//! The server's text edges take a principal id in one spelling, the
//! labelled `ALG:digest` (CLOSE-DECISIONS D5 and Q1). Two edges here: the
//! config file's pinned peer genesis, and the HTTP query `pg`. (The login
//! edge is in `login.rs`.)
//!
//! Properties, for every supported hash and arbitrary digest bytes of its
//! width:
//! - config: a pinned `pg` in the labelled spelling loads and keeps that spelling; the same digest
//!   bare, a wrong-width digest under a label, and an unknown label each fail at load, before any
//!   server starts, and the bare one's error shows the labelled form;
//! - HTTP: a labelled `pg` is read as an id (an unknown principal is not a malformed request), a
//!   bare one is a 400 whose error shows the labelled form. No width is guessed.
//!
//! Red before ID: the config keeps `pg` as an unchecked `String`, so a
//! malformed pin loads; and every query handler normalizes a bare id
//! instead of refusing it.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::{HASH_ALGS, HashAlg};
use cyphr_server::config::{Cli, ServerConfig, resolve_config};
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use proptest::prelude::*;
use tower::ServiceExt;

mod common;

use clap::Parser;

const UNLABELLED: &str = "unlabelled principal id";

fn id_parts() -> impl Strategy<Value = (HashAlg, Vec<u8>)> {
    proptest::sample::select(HASH_ALGS.to_vec()).prop_flat_map(|a| {
        (
            Just(a),
            proptest::collection::vec(any::<u8>(), a.digest_size()),
        )
    })
}

// ---------------------------------------------------------------- config

fn load(dir: &Path, pg: &str) -> Result<ServerConfig, String> {
    let file = dir.join("cyphr-server.toml");
    std::fs::write(
        &file,
        format!("[gossip]\npeers = [{{ url = \"http://127.0.0.1:2\", pg = \"{pg}\" }}]\n"),
    )
    .expect("write config");
    let cli = Cli::try_parse_from([
        "cyphr-server".as_ref(),
        "--config".as_ref(),
        file.as_os_str(),
        "serve".as_ref(),
    ])
    .expect("valid args");
    resolve_config(&cli).map_err(|e| e.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn a_labelled_pinned_genesis_loads_and_keeps_its_spelling((alg, bytes) in id_parts()) {
        let dir = tempfile::tempdir().expect("tempdir");
        let labelled = format!("{alg}:{}", Base64UrlUnpadded::encode_string(&bytes));
        let config = load(dir.path(), &labelled).map_err(TestCaseError::fail)?;
        let peer = serde_json::to_value(&config.gossip.peers[0]).expect("peer serializes");
        prop_assert_eq!(peer["pg"].as_str(), Some(labelled.as_str()));
    }

    #[test]
    fn a_malformed_pinned_genesis_fails_the_config_load(
        (alg, bytes) in id_parts(),
        other in proptest::sample::select(HASH_ALGS.to_vec()),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let b64 = Base64UrlUnpadded::encode_string(&bytes);

        let bare = load(dir.path(), &b64).expect_err("a bare pinned genesis must not load");
        prop_assert!(bare.contains(UNLABELLED), "bare: {bare}");

        let unknown = format!("NOPE-1:{b64}");
        prop_assert!(load(dir.path(), &unknown).is_err(), "unknown label loaded");

        let empty = format!("{alg}:");
        prop_assert!(load(dir.path(), &empty).is_err(), "empty digest loaded");

        if other.digest_size() != alg.digest_size() {
            let wrong = format!("{other}:{b64}");
            prop_assert!(load(dir.path(), &wrong).is_err(), "wrong width loaded");
        }
    }
}

// ------------------------------------------------------------ HTTP query

async fn get_text(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("infallible router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The id-taking GET routes: `/tip`, `/patch`, `/resync`, `/proof`.
fn queries(pg: &str) -> [String; 4] {
    [
        format!("/tip?pg={pg}"),
        format!("/patch?pg={pg}"),
        format!("/resync?pg={pg}"),
        format!("/proof?pg={pg}&size=1&claim=member:0"),
    ]
}

/// One runtime and one store for every case: opening a store costs more
/// than a request.
fn shared() -> (&'static tokio::runtime::Runtime, &'static Arc<AppState>) {
    static SHARED: OnceLock<(tokio::runtime::Runtime, Arc<AppState>, tempfile::TempDir)> =
        OnceLock::new();
    let (rt, state, _dir) = SHARED.get_or_init(|| {
        let (state, dir) = common::keyless_server();
        (tokio::runtime::Runtime::new().expect("runtime"), state, dir)
    });
    (rt, state)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn a_query_id_is_read_labelled_and_a_bare_one_is_refused((alg, bytes) in id_parts()) {
        let (rt, state) = shared();
        let b64 = Base64UrlUnpadded::encode_string(&bytes);
        let labelled = format!("{alg}:{b64}");
        rt.block_on(async {
            for uri in queries(&labelled) {
                let (status, body) = get_text(build_router(Arc::clone(state)), &uri).await;
                assert_ne!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
            }
            for uri in queries(&b64) {
                let (status, body) = get_text(build_router(Arc::clone(state)), &uri).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
                assert!(body.contains(UNLABELLED), "{uri}: error must show the labelled form: {body}");
            }
        });
    }
}

/// A held principal is found under its labelled id and under no bare
/// spelling of it (a regression guard: refusing the bare form must not
/// cost the labelled one).
#[tokio::test]
async fn a_held_principal_is_served_by_its_labelled_id_only() {
    let (state, _guard) = common::keyless_server();
    let (id, first, _) = common::ops::golden_chain().await;
    let id = id.to_string();
    let (status, resp) = common::post_json(build_router(Arc::clone(&state)), "/push", first).await;
    assert_eq!(status, StatusCode::CREATED, "{resp:?}");

    for uri in queries(&id) {
        let (status, body) = get_text(build_router(Arc::clone(&state)), &uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
    }
    let bare = id.split_once(':').expect("labelled id").1;
    for uri in queries(bare) {
        let (status, body) = get_text(build_router(Arc::clone(&state)), &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
    }
}
