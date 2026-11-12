//! The HTTP carrier: each request target is a `GET` or `POST` against a
//! base URL.

use std::net::IpAddr;
use std::time::Duration;

use crate::connector::{ChannelBinding, ConnectError, Connector, Method, Request};

/// Largest response body the carrier reads. A peer is untrusted, so an
/// answer is read as a capped stream instead of being buffered whole.
pub const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// How [`HttpConnector::connect`] builds its client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpOptions {
    /// Total time a request may take, connect through last byte.
    pub timeout: Duration,
    /// Permit plain `http://` to a host that is not loopback. Off by
    /// default: `https://` and loopback `http://` need no opt-in.
    pub allow_cleartext: bool,
    /// DER certificates trusted in addition to the bundled web roots, for a
    /// peer behind a private CA.
    pub trust_root_der: Vec<Vec<u8>>,
}

impl HttpOptions {
    /// Defaults (no cleartext, no extra roots) with a total `timeout`.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            allow_cleartext: false,
            trust_root_der: Vec::new(),
        }
    }
}

/// A [`Connector`] over HTTP. It exposes no channel binding.
pub struct HttpConnector {
    client: reqwest::Client,
    base_url: String,
}

impl HttpConnector {
    /// Carry requests to `base_url` over `client`. The caller owns the
    /// client's bounds; the response-size cap still applies.
    #[must_use]
    pub fn new(client: reqwest::Client, base_url: &str) -> Self {
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Whether `base_url` is a URL the carrier would use: the scheme check
    /// of [`HttpConnector::connect`], without building a client.
    ///
    /// # Errors
    ///
    /// As [`HttpConnector::with_client`].
    pub fn check_url(base_url: &str, allow_cleartext: bool) -> Result<(), ConnectError> {
        check_scheme(base_url, allow_cleartext)
    }

    /// [`HttpConnector::new`] over the caller's `client`, after the scheme
    /// check [`HttpConnector::connect`] applies: for a caller that owns a
    /// shared client but still must not send plain `http://` to a
    /// non-loopback host.
    ///
    /// # Errors
    ///
    /// [`ConnectError::CleartextRefused`] for `http://` to a non-loopback
    /// host without `allow_cleartext`; [`ConnectError::Unreachable`] for a
    /// URL that is not `http(s)://host`.
    pub fn with_client(
        client: reqwest::Client,
        base_url: &str,
        allow_cleartext: bool,
    ) -> Result<Self, ConnectError> {
        check_scheme(base_url, allow_cleartext)?;
        Ok(Self::new(client, base_url))
    }

    /// Carry requests to `base_url` over a client built for an untrusted
    /// peer: TLS verified against the bundled web roots, a total timeout,
    /// and no redirect (one could leave the peer the caller chose,
    /// including for a plaintext host).
    ///
    /// # Errors
    ///
    /// [`ConnectError::CleartextRefused`] for `http://` to a non-loopback
    /// host without [`HttpOptions::allow_cleartext`];
    /// [`ConnectError::Unreachable`] for a URL that is not `http(s)://host`
    /// or a client that cannot be built.
    pub fn connect(base_url: &str, options: &HttpOptions) -> Result<Self, ConnectError> {
        check_scheme(base_url, options.allow_cleartext)?;
        let unusable = |why: String| ConnectError::Unreachable(why);
        let mut builder = reqwest::Client::builder()
            .timeout(options.timeout)
            .redirect(reqwest::redirect::Policy::none());
        for der in &options.trust_root_der {
            let root = reqwest::Certificate::from_der(der)
                .map_err(|e| unusable(format!("trusted root is not a DER certificate: {e}")))?;
            builder = builder.add_root_certificate(root);
        }
        let client = builder
            .build()
            .map_err(|e| unusable(format!("cannot build the HTTP client: {e}")))?;
        Ok(Self::new(client, base_url))
    }
}

/// Refuse a URL the carrier must not use: not `http(s)://host`, or plain
/// `http://` to a non-loopback host without `allow_cleartext`.
fn check_scheme(base_url: &str, allow_cleartext: bool) -> Result<(), ConnectError> {
    let unusable = |why: String| ConnectError::Unreachable(why);
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| unusable(format!("peer URL `{base_url}`: {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url
                .host_str()
                .ok_or_else(|| unusable(format!("peer URL `{base_url}` has no host")))?;
            if !allow_cleartext && !is_loopback(host) {
                return Err(ConnectError::CleartextRefused {
                    host: host.to_string(),
                });
            }
            Ok(())
        },
        other => Err(unusable(format!(
            "peer URL scheme `{other}` is not http(s)"
        ))),
    }
}

/// Whether `host` (as `Url::host_str` spells it: IPv6 stays bracketed)
/// names this machine. A mapped IPv4 address is judged as the IPv4 it wraps.
fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical().is_loopback(),
        Err(_) => bare.eq_ignore_ascii_case("localhost"),
    }
}

impl Connector for HttpConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let url = format!("{}{}", self.base_url, request.target);
        let builder = match request.method {
            Method::Get => self.client.get(url),
            Method::Post => self
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(request.body.clone()),
        };
        let unreachable = |err: reqwest::Error| ConnectError::Unreachable(err.to_string());
        let mut res = builder
            .header("accept", "application/json")
            .send()
            .await
            .map_err(unreachable)?;
        let status = res.status();
        if matches!(status.as_u16(), 401 | 403 | 422) {
            // A refusal (422, or 401/403 for a key the peer will not take) says why in its envelope; the reason is
            // read bounded, and a body that is not an envelope leaves the
            // bare status.
            let mut body = Vec::new();
            while let Some(chunk) = res.chunk().await.ok().flatten() {
                if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            let message = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["payload"]["error"].as_str().map(str::to_owned));
            return Err(match message {
                Some(message) => ConnectError::Refused {
                    status: status.as_u16(),
                    message,
                },
                None => ConnectError::NonSuccess(status.as_u16()),
            });
        }
        if !status.is_success() {
            return Err(ConnectError::NonSuccess(status.as_u16()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(unreachable)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ConnectError::TooLarge {
                    limit: MAX_RESPONSE_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
