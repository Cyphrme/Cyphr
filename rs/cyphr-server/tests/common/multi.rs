//! Multi-server harness helpers (`rs/cyphr-server/tests/common/multi.rs`).
//!
//! Provides support for instantiating and managing multiple independent
//! `cyphr-server` instances to test instance isolation, multitenancy,
//! cross-instance signature verification failure, and independent storage engines.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::{AppState, build_router};
use tempfile::TempDir;

use super::{attestor_server, get_json, keyless_server, post_json};

/// An isolated server instance within a multi-server setup.
pub struct Instance {
    pub name: String,
    pub state: Arc<AppState>,
    pub identity: Option<Arc<ServerIdentity>>,
    pub dir: TempDir,
    pub router: Router,
}

impl Instance {
    /// Send an unauthed GET request to this instance's router.
    pub async fn get(&self, uri: &str) -> (StatusCode, serde_json::Value) {
        get_json(self.router.clone(), uri).await
    }

    /// Send an unauthed POST request of a JSON body to this instance's router.
    pub async fn post(&self, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
        post_json(self.router.clone(), uri, body).await
    }
}

/// Container holding multiple isolated server instances.
pub struct MultiServer {
    pub instances: Vec<Instance>,
}

impl MultiServer {
    /// Construct `count` independent attestor server instances.
    pub async fn new_attestors(count: usize) -> Self {
        let mut instances = Vec::with_capacity(count);
        for i in 0..count {
            let (state, identity, dir) = attestor_server().await;
            let router = build_router(state.clone());
            instances.push(Instance {
                name: format!("attestor-{i}"),
                state,
                identity: Some(identity),
                dir,
                router,
            });
        }
        Self { instances }
    }

    /// Construct `count` independent keyless server instances.
    pub async fn new_keyless(count: usize) -> Self {
        let mut instances = Vec::with_capacity(count);
        for i in 0..count {
            let (state, dir) = keyless_server();
            let router = build_router(state.clone());
            instances.push(Instance {
                name: format!("keyless-{i}"),
                state,
                identity: None,
                dir,
                router,
            });
        }
        Self { instances }
    }

    /// Get reference to instance at index `i`.
    pub fn get(&self, i: usize) -> &Instance {
        &self.instances[i]
    }
}
