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
}

impl AppError {
    /// 500 Internal Server Error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }

    /// 404 Not Found.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }

    /// 400 Bad Request.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    /// 409 Conflict.
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: msg.into(),
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
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, axum::Json(body)).into_response()
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
    /// - `Protocol(cyphr::Error::StateMismatch | cyphr::Error::CommitMismatch)` → 409 Conflict (the
    ///   submitted commit's claimed predecessor state no longer matches the principal's actual
    ///   current state — the signature that a concurrent writer already claimed this principal's
    ///   next write, not that this submission is itself malformed)
    /// - `Protocol(cyphr::Error::Storage(_))` → 500 (infrastructure failure that happened to
    ///   surface through the protocol layer, not a genuine protocol violation)
    /// - `Protocol` (any other wrapped [`cyphr::Error`]) → 422 Unprocessable Entity (valid JSON,
    ///   invalid protocol)
    /// - `BlobStore`, `Indexer`, `Load`, `Storage` → 500
    pub fn engine(err: cyphr_storage::engine::EngineError) -> Self {
        use cyphr_storage::engine::EngineError;

        match &err {
            EngineError::NotFound(_) => Self::not_found(err.to_string()),
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
            EngineError::Protocol(_) => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: err.to_string(),
            },
            EngineError::BlobStore(_)
            | EngineError::Indexer(_)
            | EngineError::Load(_)
            | EngineError::Storage(_) => {
                tracing::error!(error = %err, "internal engine error");
                Self::internal("internal storage error")
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use cyphr_storage::engine::EngineError;

    use super::*;

    #[test]
    fn state_mismatch_maps_to_conflict() {
        let resp =
            AppError::engine(EngineError::Protocol(cyphr::Error::StateMismatch)).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn commit_mismatch_maps_to_conflict() {
        let resp =
            AppError::engine(EngineError::Protocol(cyphr::Error::CommitMismatch)).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn other_protocol_errors_remain_unprocessable_entity() {
        let resp =
            AppError::engine(EngineError::Protocol(cyphr::Error::InvalidSignature)).into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
