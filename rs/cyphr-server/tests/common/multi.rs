//! Multi-server harness helpers (`rs/cyphr-server/tests/common/multi.rs`).
//!
//! Provides support for instantiating and managing multiple independent
//! `cyphr-server` instances to test instance isolation, multitenancy,
//! cross-instance signature verification failure, and independent storage engines.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_app_router};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

use super::{attestor_server, keyless_server};

/// A parsed HTTP response: status code plus the raw body string and parsed JSON.
#[derive(Debug, Clone)]
pub struct TestResponse {
    pub status: StatusCode,
    pub body: String,
    pub json: serde_json::Value,
}

impl TestResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

/// An isolated server instance within a multi-server setup.
pub struct Instance {
    pub name: String,
    pub state: Arc<AppState>,
    pub identity: Option<Arc<ServerIdentity>>,
    pub dir: TempDir,
    pub router: Router,
    pub listener_addr: Option<std::net::SocketAddr>,
    pub tcp_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Instance {
    fn drop(&mut self) {
        if let Some(handle) = self.tcp_handle.take() {
            handle.abort();
        }
    }
}

impl Instance {
    /// Construct an isolated instance from a given `ServerConfig` and `TempDir` guard.
    pub async fn from_config(config: ServerConfig, dir: TempDir) -> Self {
        let mut state = AppState::new(config).expect("failed to open AppState");
        state
            .engine
            .reindex(&[], false)
            .await
            .expect("reindex failed");

        let identity = if let (Some(id), Some(key_path)) = (
            state.identity.clone(),
            state.config.signing_key_path.clone(),
        ) {
            let sp = cyphr_server::auth::principal::ServerPrincipal::bootstrap(
                &state.engine,
                id.clone(),
                &key_path,
                &state.config.data_dir,
            )
            .await
            .expect("bootstrap server principal");
            state.principal = Some(Arc::new(sp));
            Some(id)
        } else {
            None
        };

        let state = Arc::new(state);
        let router = build_app_router(state.clone()).expect("failed to build app router");

        Self {
            name: "instance".to_string(),
            state,
            identity,
            dir,
            router,
            listener_addr: None,
            tcp_handle: None,
        }
    }

    /// Construct an isolated instance from a TOML configuration file path and `TempDir` guard.
    pub async fn from_config_file(config_path: &Path, dir: TempDir) -> Self {
        use figment::Figment;
        use figment::providers::{Format, Serialized, Toml};

        let figment = Figment::new()
            .merge(Serialized::defaults(ServerConfig::default()))
            .merge(Toml::file(config_path));
        let config: ServerConfig = figment
            .extract()
            .expect("failed to parse ServerConfig TOML");
        Self::from_config(config, dir).await
    }

    /// Bind an ephemeral TCP listener on `127.0.0.1:0` and spawn `axum::serve` in the background.
    ///
    /// Extends this instance to support real network socket transport testing capabilities
    /// alongside in-process dispatch.
    pub async fn bind_tcp(
        &mut self,
    ) -> Result<std::net::SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(addr) = self.listener_addr {
            return Ok(addr);
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = self.router.clone();

        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
        });

        self.listener_addr = Some(addr);
        self.tcp_handle = Some(handle);
        Ok(addr)
    }

    /// Returns the bound TCP socket address, if `bind_tcp` has been called.
    pub fn tcp_addr(&self) -> Option<std::net::SocketAddr> {
        self.listener_addr
    }

    /// Returns the HTTP base URL string (e.g. `http://127.0.0.1:12345`), if `bind_tcp` has been called.
    pub fn url(&self) -> Option<String> {
        self.listener_addr.map(|addr| format!("http://{addr}"))
    }

    /// Send an HTTP request against this instance's router.
    pub async fn request(
        &self,
        method: &str,
        uri: &str,
        body: Option<String>,
        headers: &[(&str, &str)],
        ip: Option<&str>,
    ) -> TestResponse {
        request_raw(self.router.clone(), method, uri, body, headers, ip).await
    }

    /// Send an unauthed GET request returning `(StatusCode, serde_json::Value)` for backward
    /// compatibility.
    pub async fn get(&self, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = self.request("GET", uri, None, &[], None).await;
        (resp.status, resp.json)
    }

    /// Send an unauthed POST request returning `(StatusCode, serde_json::Value)` for backward
    /// compatibility.
    pub async fn post(&self, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
        let resp = self.request("POST", uri, Some(body), &[], None).await;
        (resp.status, resp.json)
    }

    /// Send a GET request returning full `TestResponse`.
    pub async fn get_resp(&self, uri: &str) -> TestResponse {
        self.request("GET", uri, None, &[], None).await
    }

    /// Send a GET request from a specific source IP returning full `TestResponse`.
    pub async fn get_from_ip(&self, uri: &str, ip: &str) -> TestResponse {
        self.request("GET", uri, None, &[], Some(ip)).await
    }

    /// Send a POST request returning full `TestResponse`.
    pub async fn post_resp(&self, uri: &str, body: impl Into<String>) -> TestResponse {
        self.request("POST", uri, Some(body.into()), &[], None)
            .await
    }

    /// Send a POST request with headers returning full `TestResponse`.
    pub async fn post_with_headers(
        &self,
        uri: &str,
        body: impl Into<String>,
        headers: &[(&str, &str)],
    ) -> TestResponse {
        self.request("POST", uri, Some(body.into()), headers, None)
            .await
    }

    /// Send a POST request from a specific source IP returning full `TestResponse`.
    pub async fn post_from_ip(&self, uri: &str, body: impl Into<String>, ip: &str) -> TestResponse {
        self.request("POST", uri, Some(body.into()), &[], Some(ip))
            .await
    }
}

/// Execute an in-process HTTP request against an axum `Router` using `oneshot`.
pub async fn request_raw(
    app: Router,
    method: &str,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
    ip: Option<&str>,
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    let mut has_content_type = false;
    for (k, v) in headers {
        builder = builder.header(*k, *v);
        if k.eq_ignore_ascii_case("content-type") {
            has_content_type = true;
        }
    }
    let body_str = body.unwrap_or_default();
    if !has_content_type && (method == "POST" || !body_str.is_empty()) {
        builder = builder.header("content-type", "application/json");
    }

    let mut req = builder.body(Body::from(body_str)).unwrap();

    let peer_addr: std::net::SocketAddr = if let Some(ip_str) = ip {
        let ip_addr: std::net::IpAddr = ip_str
            .parse()
            .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
        std::net::SocketAddr::new(ip_addr, 12345)
    } else {
        "127.0.0.1:12345".parse().unwrap()
    };
    req.extensions_mut().insert(ConnectInfo(peer_addr));

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8_lossy(&bytes).to_string();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };

    TestResponse {
        status,
        body: body_text,
        json,
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
            let router = build_app_router(state.clone()).expect("failed to build app router");
            instances.push(Instance {
                name: format!("attestor-{i}"),
                state,
                identity: Some(identity),
                dir,
                router,
                listener_addr: None,
                tcp_handle: None,
            });
        }
        Self { instances }
    }

    /// Construct `count` independent keyless server instances.
    pub async fn new_keyless(count: usize) -> Self {
        let mut instances = Vec::with_capacity(count);
        for i in 0..count {
            let (state, dir) = keyless_server();
            let router = build_app_router(state.clone()).expect("failed to build app router");
            instances.push(Instance {
                name: format!("keyless-{i}"),
                state,
                identity: None,
                dir,
                router,
                listener_addr: None,
                tcp_handle: None,
            });
        }
        Self { instances }
    }

    /// Bind ephemeral TCP socket listeners for all instances in this container.
    pub async fn bind_tcp(
        &mut self,
    ) -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
        let mut addrs = Vec::with_capacity(self.instances.len());
        for inst in &mut self.instances {
            addrs.push(inst.bind_tcp().await?);
        }
        Ok(addrs)
    }

    /// Get reference to instance at index `i`.
    pub fn get(&self, i: usize) -> &Instance {
        &self.instances[i]
    }
}
