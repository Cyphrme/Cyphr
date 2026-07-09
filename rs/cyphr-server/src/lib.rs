//! # Cyphr Server
//!
//! Authority server for the Cyphr Protocol, exposing the MSS API
//! over HTTP.
//!
//! The server is structured as a library + binary crate:
//! - Library (`lib.rs`) owns the application state, route wiring, and the `serve()` entry point.
//! - Binary (`main.rs`) handles CLI parsing and process lifecycle.

pub mod config;
pub mod error;
pub mod logging;
pub mod routes;

use std::sync::Arc;

use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::engine::StorageEngine;

// ========================================================================
// Application state
// ========================================================================

/// Shared application state accessible from all route handlers.
///
/// Wrapped in `Arc` and passed via axum's `State` extractor.
///
/// ## Backend note
///
/// The blob store, each principal's Commit Tree, and the index are all
/// durable. The blob store and Commit Trees share one physical `Database`
/// (`FjallBlobStore::from_database` plus
/// `cyphr_blob_fjall::open_eml_storage_scoped`, per
/// `docs/specs/blob-store-fjall.md`'s `[fjall-single-keyspace]` mandate --
/// which is scoped to blobs+EML, not the index), with each principal's
/// Commit Tree keyed to its own scoped keyspace by `principal_id` so
/// multiple principals safely share the one database. The index opens
/// its own, separate `Database`: the index is a derived, rebuildable
/// projection of the blob store (root `AGENTS.md` I1), and keeping its
/// storage independent preserves that a blob-store-only failure (lost or
/// corrupted blob content with the index otherwise intact) surfaces as a
/// real, loud lookup failure rather than silently disappearing along with
/// the index that would otherwise share its fate.
pub struct AppState {
    /// Resolved server configuration.
    pub config: config::ServerConfig,

    /// Protocol-aware storage engine.
    pub engine:
        StorageEngine<FjallBlobStore, FjallIndexer, cyphr_blob_fjall::storage_fjall::FjallStorage>,
}

impl AppState {
    /// Construct application state from resolved configuration.
    pub fn new(config: config::ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let db = fjall::Database::builder(config.data_dir.join("blobs")).open()?;
        let blob_store = FjallBlobStore::from_database(db.clone())?;
        let indexer = FjallIndexer::open(&config.data_dir.join("index"))?;
        let engine =
            StorageEngine::with_storage_factory(blob_store, indexer, move |principal_id: &str| {
                cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), principal_id)
                    .map_err(|e| e.to_string())
            });
        Ok(Self { config, engine })
    }
}

// ========================================================================
// Server lifecycle
// ========================================================================

/// Build the application router with all routes and middleware.
///
/// Separated from [`serve`] to enable integration testing without
/// binding a TCP listener.
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/tip", axum::routing::get(routes::tip))
        .route("/patch", axum::routing::get(routes::patch))
        .route("/push", axum::routing::post(routes::push))
        .route("/e/{digest}", axum::routing::get(routes::entity))
        .with_state(state)
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                |request: &axum::http::Request<_>| {
                    let request_id = uuid::Uuid::new_v4().to_string();
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        uri = %request.uri(),
                        request_id = %request_id,
                    )
                },
            ),
        )
}

/// Start the HTTP server with graceful shutdown.
///
/// Binds to `config.listen`, wires routes, and blocks until
/// SIGTERM/SIGINT.
pub async fn serve(config: config::ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = config.listen.clone();
    let state = Arc::new(AppState::new(config)?);

    // Run incremental reindexing on startup
    state.engine.reindex(&[], false).await?;

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(listen = %listen_addr, "server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server stopped");
    Ok(())
}

/// Wait for a shutdown signal (Ctrl-C / SIGTERM).
///
/// `axum::serve(..).with_graceful_shutdown(..)` requires a
/// `Future<Output = ()>`, so there is no `Result` to propagate here even in
/// principle. `ctrl_c()` only errs if the OS refuses to let the process
/// install a signal handler at all -- a process-level failure unrelated to
/// any request or its input, and one this process cannot meaningfully
/// recover from (it would run with no way to shut down gracefully).
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for shutdown signal");
    tracing::info!("shutdown signal received, draining connections");
}
