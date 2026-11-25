//! The operator's storage ceiling (`[limits] max_stored_bytes`): a write
//! that would pass it is refused `507` with nothing stored, and the bytes
//! the engine counts are the bytes a fresh engine finds on disk.

use std::sync::Arc;

use axum::http::StatusCode;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_app_router};

mod common;

use common::{build_genesis_push_body, golden_principal_id, load_pool, post_json};

const NOW: i64 = 1_700_000_000;

fn state_over(dir: &std::path::Path, ceiling: Option<u64>) -> Arc<AppState> {
    let mut config = ServerConfig {
        data_dir: dir.join("data"),
        ..Default::default()
    };
    config.limits.max_stored_bytes = ceiling.and_then(std::num::NonZeroU64::new);
    Arc::new(AppState::new(config).expect("state"))
}

/// Claim: over a ceiling a push is refused 507 and adds nothing; with no
/// ceiling the same push is accepted, and the count the engine kept equals
/// what a fresh engine over the same directory counts after its rebuild
/// scan. Turns red if the ceiling is not enforced, a refusal leaves bytes
/// behind, or the live count drifts from the stored bytes.
/// End-to-end scenario: yes (the real router and a reopened store).
#[tokio::test]
async fn a_write_over_the_ceiling_is_refused_and_the_count_matches_the_disk() {
    let pool = load_pool();
    let pid = golden_principal_id(&pool).await;
    let body = build_genesis_push_body(&pool, &pid, NOW).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let tight = state_over(&dir.path().join("tight"), Some(1));
    let app = build_app_router(tight.clone()).expect("router");
    let (status, json) = post_json(app, "/push", body.clone()).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{json:?}");
    assert_eq!(tight.engine.stored_bytes(), 0, "a refusal stores nothing");

    let open = state_over(&dir.path().join("open"), None);
    let app = build_app_router(open.clone()).expect("router");
    let (status, json) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "{json:?}");
    let live = open.engine.stored_bytes();
    assert!(live > 0);
    drop(open);

    let reopened = state_over(&dir.path().join("open"), None);
    reopened
        .engine
        .rebuild_index_from_manifests()
        .await
        .expect("rebuild");
    assert_eq!(reopened.engine.stored_bytes(), live);
}
