//! # Cyphr Server
//!
//! Authority server for the Cyphr Protocol, exposing the MSS API
//! over HTTP.
//!
//! The server is structured as a library + binary crate:
//! - Library (`lib.rs`) owns the application state, route wiring,
//!   and the `serve()` entry point.
//! - Binary (`main.rs`) handles CLI parsing and process lifecycle.

pub mod config;
pub mod error;
pub mod logging;
pub mod routes;

use std::sync::Arc;

use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;

// ========================================================================
// Application state
// ========================================================================

/// Shared application state accessible from all route handlers.
///
/// Wrapped in `Arc` and passed via axum's `State` extractor.
///
/// ## Backend note
///
/// Currently uses `MemoryBlobStore` + `MemoryIndexer` — state is lost
/// on restart. Production backends (fjall + SQLite) will be wired
/// once the SQLite indexer lands (Phase 2b).
pub struct AppState {
    /// Resolved server configuration.
    pub config: config::ServerConfig,

    /// Protocol-aware storage engine.
    pub engine: StorageEngine<MemoryBlobStore, MemoryIndexer>,
}

impl AppState {
    /// Construct application state from resolved configuration.
    pub fn new(config: config::ServerConfig) -> Self {
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        Self { config, engine }
    }
}

// ========================================================================
// Server lifecycle
// ========================================================================

/// Start the HTTP server with graceful shutdown.
///
/// Binds to `config.listen`, wires routes, and blocks until
/// SIGTERM/SIGINT.
pub async fn serve(config: config::ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = config.listen.clone();
    let state = Arc::new(AppState::new(config));

    let app = axum::Router::new()
        .route("/tip", axum::routing::get(routes::tip))
        .route("/patch", axum::routing::get(routes::patch))
        .route("/push", axum::routing::post(routes::push))
        .route("/e/{digest}", axum::routing::get(routes::entity))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

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
