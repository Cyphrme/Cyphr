//! The carrier seam: a byte-in, byte-out [`Connector`] and the typed
//! [`ChannelBinding`] it exposes once its handshake is done.

use std::future::Future;

/// What a [`ChannelBinding`]'s bytes are a binding *to*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindingKind {
    /// The Noise handshake hash `h` (Noise Protocol Framework, section
    /// 11.2): unique to one handshake and identical on both peers.
    NoiseHandshakeHash,
}

/// A value that ties application-layer signatures to one carrier session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBinding {
    kind: BindingKind,
    bytes: Vec<u8>,
}

impl ChannelBinding {
    /// A binding of `kind` carrying `bytes`.
    #[must_use]
    pub fn new(kind: BindingKind, bytes: Vec<u8>) -> Self {
        Self { kind, bytes }
    }

    /// What the bytes bind to.
    #[must_use]
    pub fn kind(&self) -> BindingKind {
        self.kind
    }

    /// The binding value.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Whether a caller needs the carrier to expose a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingPolicy {
    /// Any carrier is acceptable; a binding is passed through if present.
    NotRequired,
    /// The carrier must expose a binding of exactly this kind.
    Required(BindingKind),
}

/// Why a carrier fell short of a [`BindingPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The carrier exposes no channel binding.
    #[error("carrier exposes no channel binding but {required:?} is required")]
    Missing { required: BindingKind },
    /// The carrier's binding is of a different kind than required.
    #[error("carrier binding is {found:?} but {required:?} is required")]
    WrongKind {
        required: BindingKind,
        found: BindingKind,
    },
}

/// A carrier-level failure, before any protocol bytes are interpreted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// The peer could not be reached or the exchange broke off.
    #[error("peer unreachable: {0}")]
    Unreachable(String),
    /// The peer answered with a non-success status.
    #[error("peer answered with status {0}")]
    NonSuccess(u16),
    /// The peer refused the request as a protocol violation (HTTP 422);
    /// `message` is the error text of its answer envelope.
    #[error("peer refused with status {status}: {message}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The peer's own error text.
        message: String,
    },
    /// The peer's answer is longer than the carrier will read.
    #[error("peer answered with more than {limit} bytes")]
    TooLarge {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// The carrier refuses plain `http://` to a host that is not loopback:
    /// every byte would cross the network readable and forgeable.
    #[error(
        "cleartext http to non-loopback host `{host}` is refused; use https, or opt in with \
         `HttpOptions::allow_cleartext`"
    )]
    CleartextRefused {
        /// The host the URL names.
        host: String,
    },
}

/// The HTTP-shaped verbs a request can carry. Push, evidence and gossip
/// run over the same seam as sync, so a request is a whole message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read: no body.
    Get,
    /// Write: the body carries the payload.
    Post,
}

/// One request to the peer: method, target and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// What to do with the target.
    pub method: Method,
    /// The request target, e.g. `/patch?pr=...`.
    pub target: String,
    /// The payload; empty for a `Get`.
    pub body: Vec<u8>,
}

impl Request {
    /// A body-less read of `target`.
    #[must_use]
    pub fn get(target: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            target: target.into(),
            body: Vec::new(),
        }
    }

    /// A write of `body` to `target`.
    #[must_use]
    pub fn post(target: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            method: Method::Post,
            target: target.into(),
            body,
        }
    }
}

/// A carrier that moves one request to the peer and the response back.
pub trait Connector {
    /// The binding established by this carrier's handshake, if any.
    fn channel_binding(&self) -> Option<&ChannelBinding>;

    /// Send `request` and return the response body bytes.
    fn exchange(
        &self,
        request: &Request,
    ) -> impl Future<Output = Result<Vec<u8>, ConnectError>> + Send;
}
