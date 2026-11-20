//! The record database holds every principal's commit log in a fixed set
//! of keyspaces: creating a fjall keyspace costs about fourteen fsyncs under
//! a database-wide lock, so a keyspace per principal makes a new
//! principal's first push slow and stalls every concurrent write.
//!
//! The test counts keyspaces by reopening the record database after the
//! server is dropped (fjall databases are exclusive per open handle). It
//! runs end to end because the property is a consequence of the whole push
//! path (route, engine, log factory), not of any one layer.

use std::path::Path;

use axum::http::StatusCode;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};

mod common;

use common::{build_genesis_push_body_with, genesis_push_id, load_pool, post_json};

/// Distinct pool keys that can each be the genesis of their own principal.
const GENESIS_KEYS: [&str; 6] = [
    "golden",
    "alice",
    "bob",
    "carol",
    "eve_ed25519",
    "diana_es384",
];

/// A fresh server over `data_dir` with the first `principals` of
/// [`GENESIS_KEYS`] pushed, then dropped.
async fn serve_and_push(data_dir: &Path, principals: usize) {
    let pool = load_pool();
    let state = std::sync::Arc::new(
        AppState::new(ServerConfig {
            data_dir: data_dir.to_path_buf(),
            ..Default::default()
        })
        .expect("open server state"),
    );
    let app = build_router(state.clone());
    for name in &GENESIS_KEYS[..principals] {
        let id = genesis_push_id(&pool, name, "key_a").await;
        let body = build_genesis_push_body_with(&pool, name, "key_a", &id, 1_700_000_000).await;
        let (status, _) = post_json(app.clone(), "/push", body).await;
        assert_eq!(status, StatusCode::CREATED, "push of principal {name}");
    }
}

/// The sorted keyspace names of the record database under `data_dir`.
fn record_keyspaces(data_dir: &Path) -> Vec<String> {
    let db = fjall::Database::builder(data_dir.join("record").join("blobs"))
        .open()
        .expect("open record database");
    let mut names: Vec<String> = db
        .list_keyspace_names()
        .into_iter()
        .map(|n| n.to_string())
        .collect();
    names.sort();
    names
}

/// Behaviour: the keyspace set of the record database does not depend on
/// how many principals it holds, from none (so a first push of a
/// never-seen principal creates none) to several. Red at base: three
/// keyspaces per principal.
#[tokio::test]
async fn record_keyspace_set_is_fixed_across_principal_counts() {
    let mut sets = Vec::new();
    for principals in [0, 1, 3, 6] {
        let dir = tempfile::tempdir().expect("tempdir");
        serve_and_push(dir.path(), principals).await;
        sets.push((principals, record_keyspaces(dir.path())));
    }
    for (principals, names) in &sets[1..] {
        assert_eq!(
            names, &sets[0].1,
            "{principals} principals must leave the keyspace set an empty database has"
        );
    }
}
