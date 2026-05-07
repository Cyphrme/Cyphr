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

    /// 501 Not Implemented.
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
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
    /// - `Protocol` → 422 Unprocessable Entity (valid JSON, invalid protocol)
    /// - `BlobStore`, `Indexer`, `Load` → 500
    pub fn engine(err: cyphr_storage::engine::EngineError) -> Self {
        use cyphr_storage::engine::EngineError;

        match &err {
            EngineError::NotFound(_) => Self::not_found(err.to_string()),
            EngineError::InvalidInput(_) | EngineError::MalformedBlob(_) => {
                Self::bad_request(err.to_string())
            },
            EngineError::Protocol(_) => Self {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: err.to_string(),
            },
            EngineError::BlobStore(_) | EngineError::Indexer(_) | EngineError::Load(_) => {
                tracing::error!(error = %err, "internal engine error");
                Self::internal("internal storage error")
            },
        }
    }
}
