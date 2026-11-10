//! Helpers for the offline-operator suites: a keyless data directory, pushes
//! through the real router, and the real binary.

use std::path::{Path, PathBuf};
use std::process::Output;

use axum::http::StatusCode;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};

use super::{
    build_genesis_push_body, build_genesis_push_body_with, build_second_commit_push_body,
    genesis_push_id, golden_principal_id, load_pool, post_json,
};

pub fn config_at(data: &Path) -> ServerConfig {
    ServerConfig {
        data_dir: data.to_path_buf(),
        ..Default::default()
    }
}

/// Open the store at `data` and POST each body to `/push`; the store is
/// closed again on return so the binary can open it.
pub async fn push_all(data: &Path, bodies: Vec<String>) {
    let state = std::sync::Arc::new(AppState::new(config_at(data)).expect("open store"));
    let app = build_router(state);
    for body in bodies {
        let (status, resp) = post_json(app.clone(), "/push", body).await;
        assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    }
}

/// The standard principal's id and its two push bodies.
pub async fn golden_chain() -> (String, String, String) {
    let pool = load_pool();
    let pr = golden_principal_id(&pool).await;
    let first = build_genesis_push_body(&pool, &pr, 1_700_000_000).await;
    let second = build_second_commit_push_body(&pool, &pr, 1_700_000_000, 1_700_000_100).await;
    (pr, first, second)
}

/// A second principal's id and its genesis push body.
pub async fn alice_chain() -> (String, String) {
    let pool = load_pool();
    let id = genesis_push_id(&pool, "alice", "bob").await;
    let body = build_genesis_push_body_with(&pool, "alice", "bob", &id, 1_700_000_000).await;
    (id, body)
}

/// Run `cyphr-server <args>` on `data` and return its output.
pub fn server(data: &Path, args: &[&str], tail: &[&str]) -> Output {
    let none: PathBuf = data.join("no-server.toml");
    std::process::Command::new(env!("CARGO_BIN_EXE_cyphr-server"))
        .arg("--config")
        .arg(none)
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .args(tail)
        .output()
        .expect("spawn cyphr-server")
}

/// `(commit_count, pr)` of every principal in the store at `data`.
pub async fn tips(data: &Path) -> Vec<(String, u64, String)> {
    use cyphr_storage::index::Indexer;
    let state = AppState::new(config_at(data)).expect("open store");
    state
        .engine
        .rebuild_index_from_manifests()
        .await
        .expect("heal");
    let mut out: Vec<_> = state
        .engine
        .indexer()
        .list_principals()
        .await
        .expect("list")
        .into_iter()
        .map(|p| (p.principal_id, p.commit_count, p.pr))
        .collect();
    out.sort();
    out
}
