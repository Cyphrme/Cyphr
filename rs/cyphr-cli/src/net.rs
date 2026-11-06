//! The CLI's view of a peer: one HTTP carrier behind
//! [`cyphr_client::Connector`], and the typed ways an exchange can fail.
//!
//! The carrier is local rather than [`cyphr_client::HttpConnector`] because
//! that connector sends a `POST` body without a `content-type`, which the
//! server refuses for `/push`. Everything else (the patch fetch and its
//! envelope checks) goes through `cyphr-client` unchanged.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{
    BindingPolicy, ChannelBinding, ConnectError, Connector, Method, PatchFailure, PatchRequest,
    Request, fetch_patch,
};
use serde_json::Value;

/// Why an exchange with a peer failed.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// The peer could not be reached.
    #[error("peer {peer} unreachable: {reason}")]
    Unreachable {
        /// The peer's base URL.
        peer: String,
        /// The carrier's cause.
        reason: String,
    },
    /// The peer answered with a status the command has no finer reading of.
    #[error("peer {peer} answered with status {status}")]
    Status {
        /// The peer's base URL.
        peer: String,
        /// The HTTP status.
        status: u16,
    },
    /// The peer holds a tip the sender's history does not contain.
    #[error("peer {peer} holds a newer or different tip ({detail}); rebase onto it first")]
    Stale {
        /// The peer's base URL.
        peer: String,
        /// What the comparison found.
        detail: String,
    },
    /// The peer's answer is not the expected shape.
    #[error("peer {peer} sent a malformed answer: {reason}")]
    Malformed {
        /// The peer's base URL.
        peer: String,
        /// What was wrong.
        reason: String,
    },
    /// The peer's envelope states a wire version this build does not read.
    #[error("peer {peer} speaks envelope version {found}, not the supported {supported}")]
    UnknownVersion {
        /// The peer's base URL.
        peer: String,
        /// The version the peer stated.
        found: u64,
        /// The version this build reads.
        supported: u64,
    },
    /// The peer's history disagrees with the local history below the tip.
    #[error("peer {peer} history diverges from the local history at commit {height}")]
    Diverged {
        /// The peer's base URL.
        peer: String,
        /// 0-based index of the first differing commit.
        height: usize,
    },
}

impl PeerError {
    /// The refusal kind this error reports under `--output json`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unreachable { .. } => "unreachable",
            Self::Stale { .. } => "stale",
            Self::Malformed { .. } => "malformed",
            Self::UnknownVersion { .. } => "unknownversion",
            Self::Diverged { .. } => "forked",
            Self::Status {
                status: 401 | 403, ..
            } => "unauthorized",
            Self::Status { status: 413, .. } => "toolarge",
            Self::Status {
                status: 400 | 422, ..
            } => "malformed",
            Self::Status { .. } => "other",
        }
    }

    fn from_connect(peer: &str, err: ConnectError) -> Self {
        match err {
            ConnectError::Unreachable(reason) => Self::Unreachable {
                peer: peer.to_owned(),
                reason,
            },
            ConnectError::NonSuccess(status) => Self::Status {
                peer: peer.to_owned(),
                status,
            },
        }
    }

    fn from_patch(peer: &str, err: PatchFailure) -> Self {
        match err {
            PatchFailure::Unreachable(reason) => Self::Unreachable {
                peer: peer.to_owned(),
                reason,
            },
            PatchFailure::NonSuccess(status) => Self::Status {
                peer: peer.to_owned(),
                status,
            },
            PatchFailure::UnsupportedVersion { found, supported } => Self::UnknownVersion {
                peer: peer.to_owned(),
                found,
                supported,
            },
            other => Self::Malformed {
                peer: peer.to_owned(),
                reason: other.to_string(),
            },
        }
    }
}

/// One peer reached over HTTP.
pub struct Peer {
    client: reqwest::Client,
    url: String,
}

impl Peer {
    /// A peer at `url` (a base URL such as `http://127.0.0.1:8080`).
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_owned(),
        }
    }

    /// The peer's base URL, as named by the caller.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The tip commit id the peer holds for `principal`, `None` when the
    /// peer holds nothing for it.
    ///
    /// # Errors
    ///
    /// [`PeerError`] when the peer is unreachable or answers outside the
    /// contract. The answer is the peer's claim: the server validates any
    /// commit it is later sent, so this is only used to choose what to send.
    pub async fn tip_commit_id(&self, principal: &str) -> Result<Option<String>, PeerError> {
        let target = format!("/tip?pr={principal}");
        match self.exchange(&Request::get(target)).await {
            Ok(body) => {
                let doc: Value =
                    serde_json::from_slice(&body).map_err(|e| self.malformed(e.to_string()))?;
                doc["payload"]["commit_id"]
                    .as_str()
                    .map(|s| Some(s.to_owned()))
                    .ok_or_else(|| self.malformed("payload.commit_id missing".into()))
            },
            Err(ConnectError::NonSuccess(404)) => Ok(None),
            Err(e) => Err(PeerError::from_connect(&self.url, e)),
        }
    }

    /// The peer's whole history for `principal`: one blob list per commit,
    /// empty when the peer holds nothing for it.
    ///
    /// # Errors
    ///
    /// [`PeerError`] for a carrier failure, a refusal, or an answer that is
    /// not a well-formed patch.
    pub async fn chain(&self, principal: &str) -> Result<Vec<Vec<Vec<u8>>>, PeerError> {
        let request = PatchRequest {
            principal_id: principal,
            anchor: None,
        };
        match fetch_patch(self, &request, BindingPolicy::NotRequired, None).await {
            Ok(patch) => patch
                .entries
                .into_iter()
                .map(|e| {
                    e.blobs.map_err(|defect| {
                        self.malformed(format!("entry {}: {defect:?}", e.sequence))
                    })
                })
                .collect(),
            Err(PatchFailure::NonSuccess(404)) => Ok(Vec::new()),
            Err(e) => Err(PeerError::from_patch(&self.url, e)),
        }
    }

    /// Send one commit's blobs to the peer.
    ///
    /// # Errors
    ///
    /// [`PeerError::Stale`] when the peer answers 409 (its tip has moved
    /// past the commit's predecessor); other [`PeerError`]s otherwise.
    pub async fn push_commit(&self, principal: &str, blobs: &[Vec<u8>]) -> Result<(), PeerError> {
        let body = serde_json::json!({
            "principal_id": principal,
            "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
        });
        let bytes = serde_json::to_vec(&body).map_err(|e| self.malformed(e.to_string()))?;
        match self.exchange(&Request::post("/push", bytes)).await {
            Ok(_) => Ok(()),
            Err(ConnectError::NonSuccess(409)) => Err(PeerError::Stale {
                peer: self.url.clone(),
                detail: "the peer refused the commit's predecessor (409)".into(),
            }),
            Err(e) => Err(PeerError::from_connect(&self.url, e)),
        }
    }

    fn malformed(&self, reason: String) -> PeerError {
        PeerError::Malformed {
            peer: self.url.clone(),
            reason,
        }
    }
}

impl Connector for Peer {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let url = format!("{}{}", self.url, request.target);
        let builder = match request.method {
            Method::Get => self.client.get(url),
            Method::Post => self
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(request.body.clone()),
        };
        let res = builder
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
        let status = res.status();
        if !status.is_success() {
            return Err(ConnectError::NonSuccess(status.as_u16()));
        }
        res.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| ConnectError::Unreachable(e.to_string()))
    }
}
