//! # Cyphr Server
//!
//! Authority server for the Cyphr Protocol, exposing the MSS API
//! over HTTP.
//!
//! The server is structured as a library + binary crate:
//! - Library (`lib.rs`) owns the application state, route wiring, and the `serve()` entry point.
//! - Binary (`main.rs`) handles CLI parsing and process lifecycle.

pub mod auth;
pub mod config;
pub mod envelope;
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

    /// The server's own signing identity, if `config.signing_key_path` is
    /// set. `None` means the server holds no signing key -- callers that
    /// require one (e.g. bearer-token issuance) must handle that case
    /// explicitly rather than assume presence.
    pub identity: Option<Arc<auth::ServerIdentity>>,

    /// The server's own Cyphr principal, established on a keyed boot from
    /// the same signing key as `identity`. `None` in keyless mode, and also
    /// `None` until [`serve`] has bootstrapped it (construction via
    /// [`AppState::new`] stays synchronous; the chain is created or loaded
    /// in the async startup path).
    pub principal: Option<Arc<auth::principal::ServerPrincipal>>,

    /// Single-use challenge store backing the challenge-response login
    /// flow. In-memory and per-process (ruling R8's spirit: no durable
    /// auth state beyond short expiry).
    pub challenges: auth::login::ChallengeStore,
}

impl AppState {
    /// Construct application state from resolved configuration.
    ///
    /// If `config.signing_key_path` is set, the signing key must load
    /// successfully or construction fails -- a configured-but-broken key
    /// is a startup error, not a silent fallback to no identity.
    pub fn new(config: config::ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let db = fjall::Database::builder(config.data_dir.join("blobs")).open()?;
        let blob_store = FjallBlobStore::from_database(db.clone())?;
        let indexer = FjallIndexer::open(&config.data_dir.join("index"))?;
        let engine =
            StorageEngine::with_storage_factory(blob_store, indexer, move |principal_id: &str| {
                cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), principal_id)
                    .map_err(|e| e.to_string())
            });

        let identity = match &config.signing_key_path {
            Some(path) => Some(Arc::new(auth::ServerIdentity::load_from_path(path)?)),
            None => None,
        };

        Ok(Self {
            config,
            engine,
            identity,
            principal: None,
            challenges: auth::login::ChallengeStore::new(),
        })
    }

    /// Rotate the server's signing key.
    ///
    /// Extends the server principal's own chain and rewrites its key file
    /// (via [`auth::principal::ServerPrincipal::rotate`]), then refreshes the
    /// live signing identity so token issuance, login, and push admission —
    /// which read `AppState.identity` — sign and verify with the rotated-in
    /// key rather than the retired one. Requires the principal to have been
    /// bootstrapped (a keyed boot) and a configured key path.
    ///
    /// Taking `&mut self` is deliberate: the swap must be visible to the
    /// identity's consumers, so rotation is only possible where the identity
    /// can actually be updated, never on a shared `Arc<AppState>` behind the
    /// running router.
    pub async fn rotate_signing_key(
        &mut self,
        new_keypair: &coz::KeyPair,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let principal = self
            .principal
            .clone()
            .ok_or("server has no principal to rotate (keyless or not yet bootstrapped)")?;
        principal.rotate(&self.engine, new_keypair).await?;

        // Refresh the live signing identity from the rewritten key file, so
        // the token/login/push-admission consumers of `AppState.identity`
        // pick up the new key instead of signing with the retired one.
        let key_path = self
            .config
            .signing_key_path
            .clone()
            .ok_or("server has no signing key path to rewrite")?;
        self.identity = Some(Arc::new(auth::ServerIdentity::load_from_path(&key_path)?));
        Ok(())
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
        .route(
            "/auth/challenge",
            axum::routing::post(auth::login::challenge),
        )
        .route("/auth/login", axum::routing::post(auth::login::login))
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
    let mut state = AppState::new(config)?;

    // Run incremental reindexing on startup
    state.engine.reindex(&[], false).await?;

    // On a keyed boot, establish (or load) the server's own principal so
    // its genesis chain exists and is served like any other principal. The
    // key path is retained so a later rotation can rewrite the key file;
    // an identity is present exactly when a signing key path is configured.
    if let (Some(identity), Some(key_path)) = (
        state.identity.clone(),
        state.config.signing_key_path.clone(),
    ) {
        let principal = auth::principal::ServerPrincipal::bootstrap(
            &state.engine,
            identity,
            &key_path,
            &state.config.data_dir,
        )
        .await?;
        tracing::info!(pg = %principal.pg(), "server principal established");
        state.principal = Some(Arc::new(principal));
    }

    let state = Arc::new(state);
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

#[cfg(test)]
mod tests {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;

    fn write_signing_key_file(dir: &std::path::Path) -> std::path::PathBuf {
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

    #[test]
    fn app_state_with_configured_signing_key_loads_identity() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let key_path = write_signing_key_file(temp_dir.path());
        let config = config::ServerConfig {
            data_dir: temp_dir.path().join("data"),
            signing_key_path: Some(key_path),
            ..Default::default()
        };

        let state = AppState::new(config).expect("AppState::new with a valid key succeeds");
        assert!(
            state.identity.is_some(),
            "a configured signing key must be loaded into AppState.identity"
        );
    }

    #[test]
    fn app_state_without_signing_key_has_no_identity() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config = config::ServerConfig {
            data_dir: temp_dir.path().join("data"),
            ..Default::default()
        };

        let state = AppState::new(config).expect("AppState::new without a key still succeeds");
        assert!(
            state.identity.is_none(),
            "no signing_key_path configured must leave identity unset"
        );
    }

    #[test]
    fn app_state_with_broken_signing_key_path_fails_clearly() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config = config::ServerConfig {
            data_dir: temp_dir.path().join("data"),
            signing_key_path: Some(std::path::PathBuf::from("/nonexistent/signing-key.json")),
            ..Default::default()
        };

        let result = AppState::new(config);
        assert!(
            result.is_err(),
            "a configured-but-missing signing key must fail construction, not panic or \
             silently disable the identity"
        );
    }
}
