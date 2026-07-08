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
/// The blob store, index, and each principal's Commit Tree are all
/// durable and share one physical `Database` (`FjallBlobStore::from_database`,
/// `FjallIndexer::from_database`, and
/// `cyphr_blob_fjall::open_eml_storage_scoped`, per
/// `docs/specs/blob-store-fjall.md`'s `[fjall-single-keyspace]` mandate),
/// with each principal's Commit Tree keyed to its own scoped keyspace by
/// `principal_id` so multiple principals safely share the one database.
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
        let indexer = FjallIndexer::from_database(db.clone())?;
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
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for shutdown signal");
    tracing::info!("shutdown signal received, draining connections");
}
