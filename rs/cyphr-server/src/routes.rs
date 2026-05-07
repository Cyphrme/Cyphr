//! MSS API route handlers.
//!
//! Stub implementations returning 501 Not Implemented. Step 2 of
//! this CORE session will wire these to [`StorageEngine`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::AppState;

/// `GET /tip` — current principal state.
pub async fn tip(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

/// `GET /patch` — commit chain delta.
pub async fn patch(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

/// `POST /push` — accept and validate a signed commit bundle.
pub async fn push(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

/// `GET /e/{digest}` — content-addressed entity lookup.
pub async fn entity(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}
