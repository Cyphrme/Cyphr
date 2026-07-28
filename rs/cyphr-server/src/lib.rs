//! # Cyphr Server
//!
//! Authority server for the Cyphr Protocol, exposing the MSS API
//! over HTTP.
//!
//! The server is structured as a library + binary crate:
//! - Library (`lib.rs`) owns the application state, route wiring, and the `serve()` entry point.
//! - Binary (`main.rs`) handles CLI parsing and process lifecycle.

pub mod admission;
pub mod auth;
pub mod config;
pub mod consistency;
pub mod envelope;
pub mod error;
pub mod fanout;
pub mod logging;
pub mod observation;
pub mod rate_limit;
pub mod receipt;
pub mod registration;
pub mod revoke;
pub mod routes;
pub mod sync;

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

    /// Durable, server-local naked-revoke observations (SPEC §6.4). Its
    /// own store, distinct from the rebuildable index: a naked revoke
    /// mutates no chain and must survive a reindex, so it cannot live in
    /// the index that a reindex rebuilds.
    pub observations: observation::ObservationStore,

    /// In-memory witness registration store (SPEC §13.5.1).
    pub registration: registration::RegistrationStore,

    /// Reusable HTTP client for witness state sync and upstream calls.
    pub http_client: reqwest::Client,

    /// Per-principal locks for synchronizing witness state sync execution.
    pub sync_locks: std::sync::Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
        >,
    >,

    /// Background fanout delivery tracker (SPEC §13.5).
    pub fanout: fanout::FanoutTracker,
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

        let observations =
            observation::ObservationStore::open(&config.data_dir.join("observations"))?;

        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build http client");

        let sync_locks =
            std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        Ok(Self {
            config,
            engine,
            identity,
            principal: None,
            challenges: auth::login::ChallengeStore::new(),
            observations,
            registration: registration::RegistrationStore::new(),
            http_client,
            sync_locks,
            fanout: fanout::FanoutTracker::new(),
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

    /// This server's attestor capability -- the principal and signing
    /// identity together, present if and only if both a bootstrapped
    /// principal AND a live signing identity are present.
    ///
    /// This is the single implementation of that spec-level rule (a
    /// bootstrapped principal without a signing key, or vice versa, is not
    /// an attestor); every call site that decides whether to sign a
    /// response goes through this or [`AppState::attestor_identity`] rather
    /// than re-matching the two fields, so the rule can never drift out of
    /// sync between call sites.
    pub fn attestor(
        &self,
    ) -> Option<(
        &Arc<auth::principal::ServerPrincipal>,
        &Arc<auth::ServerIdentity>,
    )> {
        match (&self.principal, &self.identity) {
            (Some(principal), Some(identity)) => Some((principal, identity)),
            _ => None,
        }
    }

    /// The signing identity alone, for attestor-only callers that don't
    /// need the principal itself. Delegates to [`AppState::attestor`] so
    /// there remains exactly one place implementing the check.
    pub fn attestor_identity(&self) -> Option<&Arc<auth::ServerIdentity>> {
        self.attestor().map(|(_, identity)| identity)
    }
}

// ========================================================================
// Server lifecycle
// ========================================================================

async fn witness_write_refusal_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, error::AppError> {
    match *req.method() {
        axum::http::Method::POST
        | axum::http::Method::PUT
        | axum::http::Method::DELETE
        | axum::http::Method::PATCH => Err(error::AppError::forbidden(
            "write operations disabled in witness mode",
        )),
        _ => Ok(next.run(req).await),
    }
}

/// Build the application router with all routes and middleware.
///
/// Separated from [`serve`] to enable integration testing without
/// binding a TCP listener.
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    let mut router = axum::Router::new()
        .route("/tip", axum::routing::get(routes::tip))
        .route("/patch", axum::routing::get(routes::patch))
        .route("/push", axum::routing::post(routes::push))
        .route("/revoke", axum::routing::post(routes::revoke))
        .route(
            "/witness/register",
            axum::routing::post(routes::witness_register_post)
                .get(routes::witness_register_get)
                .delete(routes::witness_register_delete),
        )
        .route("/e/{digest}", axum::routing::get(routes::entity))
        .route("/server", axum::routing::get(routes::identity))
        .route(
            "/auth/challenge",
            axum::routing::post(auth::login::challenge),
        )
        .route("/auth/login", axum::routing::post(auth::login::login))
        .fallback(async || error::AppError::not_found("route not found"));

    if state.config.mode == config::ServerMode::Witness {
        router = router.layer(axum::middleware::from_fn(witness_write_refusal_middleware));
    }

    router.with_state(state).layer(
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

/// Build the full application router with all routes, admission layer, rate-limiting layer, and
/// body limit layer.
pub fn build_app_router(state: Arc<AppState>) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let admission_config = state.config.admission.clone();
    let admission_data_dir = state.config.data_dir.clone();
    let probe_state = state.clone();
    let resident: admission::ResidentProbe = Arc::new(move |id: String| {
        let state = probe_state.clone();
        Box::pin(async move {
            state
                .engine
                .get_tip(&id)
                .await
                .map(|tip| tip.is_some())
                .unwrap_or(false)
        })
    });

    let limits = state.config.limits.clone();
    let count_state = state.clone();
    let count_probe: rate_limit::CountProbe = Arc::new(move |id: String| {
        let state = count_state.clone();
        Box::pin(async move {
            state
                .engine
                .get_tip(&id)
                .await
                .map(|tip| tip.map(|t| t.commit_count).unwrap_or(0))
                .unwrap_or(0)
        })
    });

    let mut app = build_router(state);
    if let Some(gate) = admission::layer(
        &admission_config,
        &admission_data_dir,
        resident,
        limits.max_body_bytes as usize,
    )? {
        app = app.layer(gate);
    }
    app = app.layer(rate_limit::layer(&limits, count_probe));
    app = app.layer(axum::extract::DefaultBodyLimit::max(
        limits.max_body_bytes as usize,
    ));

    Ok(app)
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
    let app = build_app_router(state)?;

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let local_addr = listener.local_addr()?;

    // Report the resolved bind address on stdout (all logs go to stderr) so a
    // caller that requests an ephemeral port with `:0` learns the real port
    // the OS assigned, without ever choosing a port itself. Flush explicitly:
    // piped stdout is block-buffered, and a reader blocks until this lands.
    println!("listening on {local_addr}");
    std::io::Write::flush(&mut std::io::stdout())?;
    tracing::info!(listen = %local_addr, "server started");

    // Serve with per-connection peer info so the per-IP fence can key on the
    // real peer address the kernel reports.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
            "a configured-but-missing signing key must fail construction, not panic or silently \
             disable the identity"
        );
    }

    #[tokio::test]
    async fn attestor_reflects_all_four_principal_identity_combinations() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let key_path = write_signing_key_file(temp_dir.path());
        let config = config::ServerConfig {
            data_dir: temp_dir.path().join("data"),
            signing_key_path: Some(key_path),
            ..Default::default()
        };
        let mut state = AppState::new(config).expect("AppState::new with a valid key");
        state.engine.reindex(&[], false).await.expect("reindex");

        let identity = state
            .identity
            .clone()
            .expect("configured signing key loads identity");
        let principal = Arc::new(
            auth::principal::ServerPrincipal::bootstrap(
                &state.engine,
                identity.clone(),
                state
                    .config
                    .signing_key_path
                    .as_ref()
                    .expect("key path set"),
                &state.config.data_dir,
            )
            .await
            .expect("bootstrap succeeds"),
        );

        // (None, None) -- keyless, unbootstrapped.
        state.identity = None;
        state.principal = None;
        assert!(state.attestor().is_none());
        assert!(state.attestor_identity().is_none());

        // (None, Some) -- keyed but not yet bootstrapped.
        state.identity = Some(identity.clone());
        state.principal = None;
        assert!(state.attestor().is_none());
        assert!(state.attestor_identity().is_none());

        // (Some, None) -- would not arise from real startup (bootstrap
        // itself requires an identity), but the predicate must still
        // require both fields rather than being satisfiable by either alone.
        state.identity = None;
        state.principal = Some(principal.clone());
        assert!(state.attestor().is_none());
        assert!(state.attestor_identity().is_none());

        // (Some, Some) -- attestor.
        state.identity = Some(identity.clone());
        state.principal = Some(principal.clone());
        let (p, i) = state.attestor().expect("both present -> attestor");
        assert!(Arc::ptr_eq(p, &principal));
        assert!(Arc::ptr_eq(i, &identity));
        assert!(Arc::ptr_eq(
            state.attestor_identity().expect("both present -> attestor"),
            &identity
        ));
    }
}
