//! The CLI's view of a peer: one [`cyphr_client::HttpConnector`] with the
//! bounds a peer deserves, and the typed ways an exchange can fail.

use std::time::Duration;

use cyphr::replay::WireBundle;
use cyphr_client::{
    ConnectError, Connector, HttpConnector, HttpOptions, PatchFailure, Request, TipAnswer,
    verify_patch_body,
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
    /// The peer refused the request as a protocol violation, and said why.
    #[error("peer {peer} refused: {message}")]
    Refused {
        /// The peer's base URL.
        peer: String,
        /// The HTTP status: 422, or 401/403 for a key the peer will not take.
        status: u16,
        /// The peer's own error text.
        message: String,
    },
    /// The peer holds a tip the sender's history does not contain.
    #[error("peer {peer} holds a newer or different tip ({detail}); rebase onto it first")]
    Stale {
        /// The peer's base URL.
        peer: String,
        /// What the comparison found.
        detail: String,
    },
    /// The peer's answer exceeds the size the client will read.
    #[error("peer {peer} sent more than {limit} bytes")]
    TooLarge {
        /// The peer's base URL.
        peer: String,
        /// The cap that was exceeded.
        limit: usize,
    },
    /// The peer URL is plain `http://` to a host that is not loopback.
    #[error(
        "peer {peer} is cleartext http to a non-loopback host; use https, or pass \
         --allow-cleartext to send it in the clear"
    )]
    CleartextRefused {
        /// The peer's base URL.
        peer: String,
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
            Self::CleartextRefused { .. } => "other",
            Self::Refused { status: 422, .. } => "protocol",
            Self::Refused { .. } => "unauthorized",
            Self::Stale { .. } => "stale",
            Self::Malformed { .. } => "malformed",
            Self::TooLarge { .. } => "toolarge",
            Self::UnknownVersion { .. } => "unknownversion",
            Self::Diverged { .. } => "forked",
            Self::Status {
                status: 401 | 403, ..
            } => "unauthorized",
            Self::Status { status: 413, .. } => "toolarge",
            Self::Status { status: 400, .. } => "malformed",
            Self::Status { .. } => "other",
        }
    }
}

/// A peer's history: its commits' bundles, and its action-only bundles,
/// which hold no chain position (SPEC 4.8.1).
#[derive(Debug, Default)]
pub struct PeerHistory {
    /// One bundle per commit, oldest first.
    pub commits: Vec<WireBundle>,
    /// The blobs of each action-only bundle, as served.
    pub actions: Vec<Vec<Vec<u8>>>,
}

/// One peer reached over HTTP(S). The carrier bounds every request (total
/// timeout, no redirect, at most [`cyphr_client::MAX_RESPONSE_BYTES`] read) and refuses
/// cleartext to a non-loopback host unless the user allowed it.
pub struct Peer {
    connector: HttpConnector,
    url: String,
}

impl Peer {
    /// A peer at `url` (a base URL such as `https://peer.example`) whose
    /// requests give up after `timeout_secs`; `allow_cleartext` permits
    /// plain `http://` to a non-loopback host.
    ///
    /// # Errors
    ///
    /// [`PeerError::CleartextRefused`] for cleartext the user has not
    /// allowed; [`PeerError::Unreachable`] when the HTTP client cannot be
    /// built. The bounds are never silently dropped.
    pub fn new(url: &str, timeout_secs: u64, allow_cleartext: bool) -> Result<Self, PeerError> {
        let url = url.trim_end_matches('/').to_owned();
        let mut options = HttpOptions::new(Duration::from_secs(timeout_secs));
        options.allow_cleartext = allow_cleartext;
        let connector =
            HttpConnector::connect(&url, &options).map_err(|e| Self::carrier_error(&url, e))?;
        Ok(Self { connector, url })
    }

    /// The peer's base URL, as named by the caller.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// What the peer says its tip is for `principal`: one commit while the
    /// principal is Active, the fork point and heads in Error (SPEC
    /// 15.5); `None` when the peer holds nothing for it.
    ///
    /// # Errors
    ///
    /// [`PeerError`] when the peer is unreachable or answers outside the
    /// contract. The answer is the peer's claim: the server validates any
    /// commit it is later sent, so this is only used to choose what to send.
    pub async fn tip(&self, principal: &str) -> Result<Option<TipAnswer>, PeerError> {
        match self
            .send(&Request::get(format!("/tip?pr={principal}")))
            .await
        {
            Ok(body) => {
                let doc: Value =
                    serde_json::from_slice(&body).map_err(|e| self.malformed(e.to_string()))?;
                TipAnswer::parse(&doc)
                    .map(Some)
                    .map_err(|e| self.malformed(e.to_string()))
            },
            Err(PeerError::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The peer's whole history for `principal`: one blob list per commit,
    /// and the action-only bundles between them. Both are empty when the
    /// peer holds nothing for it.
    ///
    /// # Errors
    ///
    /// [`PeerError`] for a carrier failure, a refusal, or an answer that is
    /// not a well-formed patch.
    pub async fn chain(&self, principal: &str) -> Result<PeerHistory, PeerError> {
        let target = cyphr_client::PatchRequest {
            principal_id: principal,
            anchor: None,
        }
        .target();
        let body = match self.send(&Request::get(target)).await {
            Ok(body) => body,
            Err(PeerError::Status { status: 404, .. }) => return Ok(PeerHistory::default()),
            Err(e) => return Err(e),
        };
        let patch = verify_patch_body(&body, principal, None).map_err(|e| self.patch_error(e))?;
        let commits = patch
            .entries
            .into_iter()
            .map(|e| {
                e.bundle
                    .map_err(|defect| self.malformed(format!("entry {}: {defect:?}", e.sequence)))
            })
            .collect::<Result<_, _>>()?;
        let actions = patch
            .actions
            .into_iter()
            .enumerate()
            .map(|(i, a)| {
                a.blobs
                    .map_err(|defect| self.malformed(format!("action bundle {i}: {defect:?}")))
            })
            .collect::<Result<_, PeerError>>()?;
        Ok(PeerHistory { commits, actions })
    }

    /// Send one bundle to the peer: a commit's, or an action-only one.
    ///
    /// # Errors
    ///
    /// [`PeerError::Stale`] when the peer answers 409 (its tip has moved
    /// past the commit's predecessor); other [`PeerError`]s otherwise.
    pub async fn push_commit(&self, principal: &str, bundle: &WireBundle) -> Result<(), PeerError> {
        self.push_commit_with_parent(principal, bundle, None).await
    }

    /// [`push_commit`](Self::push_commit), with the commit `bundle` extends
    /// as the request's `parent` when the peer's caps refused it alone: the
    /// two are one offer there.
    ///
    /// # Errors
    ///
    /// As [`push_commit`](Self::push_commit).
    pub async fn push_commit_with_parent(
        &self,
        principal: &str,
        bundle: &WireBundle,
        parent: Option<&WireBundle>,
    ) -> Result<(), PeerError> {
        let mut body = serde_json::to_value(bundle).map_err(|e| self.malformed(e.to_string()))?;
        body["principal_id"] = principal.into();
        if let Some(parent) = parent {
            body["parent"] =
                serde_json::to_value(parent).map_err(|e| self.malformed(e.to_string()))?;
        }
        let bytes = serde_json::to_vec(&body).map_err(|e| self.malformed(e.to_string()))?;
        match self.send(&Request::post("/push", bytes)).await {
            Ok(_) => Ok(()),
            Err(PeerError::Status { status: 409, .. }) => Err(PeerError::Stale {
                peer: self.url.clone(),
                detail: "the peer answered 409: a tip this history does not extend, or a state it \
                         refuses; the transport does not carry the peer's message"
                    .into(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Send a naked revoke envelope (`{pay, sig, key}`, SPEC 6.4) to the peer.
    ///
    /// # Errors
    ///
    /// [`PeerError`] when the peer is unreachable or refuses the revoke.
    pub async fn post_revoke(&self, envelope: &Value) -> Result<(), PeerError> {
        let bytes = serde_json::to_vec(envelope).map_err(|e| self.malformed(e.to_string()))?;
        self.send(&Request::post("/revoke", bytes)).await.map(drop)
    }

    fn malformed(&self, reason: String) -> PeerError {
        PeerError::Malformed {
            peer: self.url.clone(),
            reason,
        }
    }

    fn patch_error(&self, err: PatchFailure) -> PeerError {
        match err {
            PatchFailure::UnsupportedVersion { found, supported } => PeerError::UnknownVersion {
                peer: self.url.clone(),
                found,
                supported,
            },
            other => self.malformed(other.to_string()),
        }
    }

    /// One request/response exchange, with every bound applied.
    async fn send(&self, request: &Request) -> Result<Vec<u8>, PeerError> {
        self.connector
            .exchange(request)
            .await
            .map_err(|e| Self::carrier_error(&self.url, e))
    }

    fn carrier_error(peer: &str, err: ConnectError) -> PeerError {
        let peer = peer.to_owned();
        match err {
            ConnectError::NonSuccess(status) => PeerError::Status { peer, status },
            ConnectError::Refused { status, message } => PeerError::Refused {
                peer,
                status,
                message,
            },
            ConnectError::TooLarge { limit } => PeerError::TooLarge { peer, limit },
            ConnectError::CleartextRefused { .. } => PeerError::CleartextRefused { peer },
            ConnectError::Unreachable(reason) => PeerError::Unreachable { peer, reason },
        }
    }
}
