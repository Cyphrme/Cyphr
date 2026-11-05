//! The HTTP carrier.

use crate::connector::{ChannelBinding, ConnectError, Connector};

/// A [`Connector`] over HTTP `GET`.
pub struct HttpConnector {
    _client: reqwest::Client,
    _base_url: String,
}

impl HttpConnector {
    /// Carry requests to `base_url` over `client`.
    #[must_use]
    pub fn new(client: reqwest::Client, base_url: &str) -> Self {
        Self {
            _client: client,
            _base_url: base_url.to_string(),
        }
    }
}

impl Connector for HttpConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, _request: &[u8]) -> Result<Vec<u8>, ConnectError> {
        Err(ConnectError::Unreachable("not implemented".into()))
    }
}
