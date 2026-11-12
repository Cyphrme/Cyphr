//! Application error type with axum `IntoResponse` integration.
//!
//! Maps internal engine and configuration errors into structured
//! JSON error responses with appropriate HTTP status codes.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Application-level error returned from route handlers.
#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
    /// A stable, machine-readable refusal kind (snake_case) a client may
    /// match on instead of the message; `None` where the status says it all.
    kind: Option<&'static str>,
}

impl AppError {
    /// 500 Internal Server Error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
            kind: None,
        }
    }

    /// 404 Not Found.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
            kind: None,
        }
    }

    /// 400 Bad Request.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
            kind: None,
        }
    }

    /// 409 Conflict.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
            kind: None,
        }
    }

    /// 401 Unauthorized.
    ///
    /// For failed authentication: a rejected login (bad signature,
    /// mismatched audience, inactive key, non-Active principal, replayed
    /// or stale request). Route-level 401 enforcement on existing
    /// endpoints is a later concern; this constructor gives the login
    /// handlers a single, correctly-shaped rejection.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
            kind: None,
        }
    }

    /// 403 Forbidden.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
            kind: None,
        }
    }

    /// 501 Not Implemented.
    ///
    /// For a capability the server genuinely does not offer under its
    /// current configuration (e.g. login/challenge on a server with no
    /// signing identity) -- distinct from 500, which implies a fault the
    /// server should not have hit. A declared capability absence must
    /// never read as a transient server fault.
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            message: msg.into(),
            kind: None,
        }
    }

    /// Map an observation-store failure to a 500. The store is durable
    /// server infrastructure, so a failure to read or write it is a server
    /// fault, never a client error. The specific cause is logged, not
    /// leaked to the client.
    ///
    /// The one exception is a full death set: the operator's ceiling
    /// refusing a new record is storage pressure relieved by refusal (507),
    /// logged as a warning, not a fault.
    pub fn observation(err: crate::observation::ObservationError) -> Self {
        if let crate::observation::ObservationError::Full { .. } = err {
            tracing::warn!(error = %err, "naked revoke refused: death set at its ceiling");
            return Self {
                status: StatusCode::INSUFFICIENT_STORAGE,
                message: err.to_string(),
                kind: None,
            };
        }
        tracing::error!(error = %err, "naked-revoke observation store error");
        Self::internal("observation store error")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let now = crate::auth::server_now();
        let mut payload = serde_json::json!({
            "error": self.message,
            "now": now,
        });
        if let Some(kind) = self.kind {
            payload["kind"] = kind.into();
        }
        let body = crate::envelope::Envelope::unsigned(payload);
        (self.status, axum::Json(body)).into_response()
    }
}

/// Custom JSON extractor that maps JSON deserialization / body parsing errors into
/// `AppError::bad_request`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for AppJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let status = rejection.status();
                let msg = rejection.body_text();
                if status == StatusCode::PAYLOAD_TOO_LARGE || msg.contains("length limit exceeded")
                {
                    Err(AppError {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        message: msg,
                        kind: Some("too_large"),
                    })
                } else {
                    Err(AppError {
                        kind: Some("malformed_body"),
                        ..AppError::bad_request(msg)
                    })
                }
            },
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for AppError {}

// ========================================================================
// EngineError → AppError mapping
// ========================================================================

impl AppError {
    /// Map a [`cyphr_storage::engine::EngineError`] to an HTTP response.
    ///
    /// Variant mapping:
    /// - `NotFound` → 404
    /// - `InvalidInput`, `MalformedBlob` → 400
    /// - `Ambiguous` → 409 Conflict (the key names several principals)
    /// - `Protocol(cyphr::Error::StateMismatch | cyphr::Error::CommitMismatch)` → 409 Conflict (the
    ///   submitted commit's claimed predecessor state no longer matches the principal's actual
    ///   current state — the signature that a concurrent writer already claimed this principal's
    ///   next write, not that this submission is itself malformed)
    /// - `Protocol(cyphr::Error::Storage(_))` → 500 (infrastructure failure that happened to
    ///   surface through the protocol layer, not a genuine protocol violation)
    /// - `Protocol` (any other wrapped [`cyphr::Error`]) → 422 Unprocessable Entity (valid JSON,
    ///   invalid protocol)
    /// - `Errored` → 423 Locked (the principal is in Error, SPEC 15.5: nothing but a fork
    ///   resolution is processed until it is resolved)
    /// - `EmbeddedUnsupported` → 501 Not Implemented (the server resolves no embedded principal, so
    ///   it cannot judge a coz an embedded member may have signed)
    /// - `BlobStore`, `Indexer`, `Load`, `LegacyManifest`, `Storage` → 500
    pub fn engine(err: cyphr_storage::engine::EngineError) -> Self {
        use cyphr_storage::engine::EngineError;

        let kind = Self::engine_kind(&err);
        let mapped = match &err {
            EngineError::NotFound(_) => Self::not_found(err.to_string()),
            EngineError::Ambiguous(_) => Self::conflict(err.to_string()),
            EngineError::InvalidInput(_) | EngineError::MalformedBlob(_) => {
                Self::bad_request(err.to_string())
            },
            EngineError::Protocol(cyphr::Error::StateMismatch | cyphr::Error::CommitMismatch) => {
                Self::conflict(err.to_string())
            },
            EngineError::Protocol(cyphr::Error::Storage(_)) => {
                tracing::error!(error = %err, "internal engine error");
                Self::internal("internal storage error")
            },
            EngineError::BranchLimit { .. } => Self::conflict(err.to_string()),
            EngineError::Errored { .. } => Self {
                status: StatusCode::LOCKED,
                message: err.to_string(),
                kind: None,
            },
            EngineError::EmbeddedUnsupported { .. } => Self::not_implemented(err.to_string()),
            EngineError::Protocol(_) => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: err.to_string(),
                kind: None,
            },
            // `BlobStore`, `Indexer`, `Load`, `LegacyManifest`, `Storage`, and any
            // variant added later (the enum is non-exhaustive): an unclassified
            // engine failure is the server's, never the caller's.
            _ => {
                tracing::error!(error = %err, "internal engine error");
                Self::internal("internal storage error")
            },
        };
        Self { kind, ..mapped }
    }

    /// The machine-readable kind of a refusal the caller can act on, so a
    /// client tells a state mismatch from a reused coz or a malformed one
    /// without reading the message. `None` for a server fault: its cause
    /// is the server's, not the caller's to branch on.
    fn engine_kind(err: &cyphr_storage::engine::EngineError) -> Option<&'static str> {
        use cyphr_storage::engine::EngineError;

        match err {
            EngineError::NotFound(_) => Some("not_found"),
            EngineError::Ambiguous(_) => Some("ambiguous"),
            EngineError::InvalidInput(_) => Some("invalid_input"),
            EngineError::MalformedBlob(_) => Some("malformed_blob"),
            EngineError::BranchLimit { .. } => Some("branch_limit"),
            EngineError::Errored { .. } => Some("errored"),
            EngineError::EmbeddedUnsupported { .. } => Some("embedded_unsupported"),
            EngineError::Protocol(cyphr::Error::Storage(_)) => None,
            EngineError::Protocol(cyphr::Error::StateMismatch) => Some("state_mismatch"),
            EngineError::Protocol(cyphr::Error::CommitMismatch) => Some("commit_mismatch"),
            EngineError::Protocol(cyphr::Error::CozReuse) => Some("coz_reuse"),
            EngineError::Protocol(cyphr::Error::GenesisIncomplete) => Some("genesis_incomplete"),
            EngineError::Protocol(_) => Some("protocol"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use cyphr_storage::engine::EngineError;

    use super::*;

    /// Backs: a stale-`pre` push is a 409 on the wire (SPEC 2.3.2).
    /// Unit: the HTTP path is `s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put`; this
    /// pins the status mapping alone.
    #[test]
    fn state_mismatch_maps_to_conflict() {
        let resp =
            AppError::engine(EngineError::Protocol(cyphr::Error::StateMismatch)).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
