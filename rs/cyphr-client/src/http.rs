//! The HTTP carrier: each request target is a `GET` against a base URL.

use crate::connector::{ChannelBinding, ConnectError, Connector, Request};

/// A [`Connector`] over HTTP `GET`. It exposes no channel binding.
pub struct HttpConnector {
    client: reqwest::Client,
    base_url: String,
}

impl HttpConnector {
    /// Carry requests to `base_url` over `client`.
    #[must_use]
    pub fn new(client: reqwest::Client, base_url: &str) -> Self {
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

impl Connector for HttpConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let target = &request.target;
        let res = self
            .client
            .get(format!("{}{target}", self.base_url))
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|err| ConnectError::Unreachable(err.to_string()))?;
        let status = res.status();
        if !status.is_success() {
            return Err(ConnectError::NonSuccess(status.as_u16()));
        }
        res.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|err| ConnectError::Unreachable(err.to_string()))
    }
}
