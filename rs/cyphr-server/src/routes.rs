//! MSS API route handlers.
//!
//! Each handler extracts request parameters, delegates to the
//! [`StorageEngine`], and converts the result into an HTTP response.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::error::AppError;

// ========================================================================
// Request types
// ========================================================================

/// Query parameters for `GET /tip`.
#[derive(Debug, Deserialize)]
pub struct TipQuery {
    /// Principal genesis identifier (tagged digest).
    pub pr: String,
}

/// Query parameters for `GET /patch`.
#[derive(Debug, Deserialize)]
pub struct PatchQuery {
    /// Principal genesis identifier.
    pub pr: String,
    /// Start sequence (inclusive). Omit for genesis.
    pub from: Option<u64>,
    /// End sequence (inclusive). Omit for tip.
    pub to: Option<u64>,
}

/// Request body for `POST /push`.
#[derive(Debug, Deserialize)]
pub struct PushRequest {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Raw coz JSON envelopes, base64url-encoded.
    ///
    /// Each element is a complete `{pay, sig, key?}` coz envelope
    /// encoded as a base64url string for JSON transport.
    pub blobs: Vec<String>,
}

// ========================================================================
// Response types
// ========================================================================

/// Response for `GET /tip`.
#[derive(Debug, Serialize)]
pub struct TipResponse {
    pub principal_id: String,
    pub pr: String,
    pub sr: String,
    pub ar: String,
    pub commit_id: String,
    pub commit_count: u64,
    pub last_updated: i64,
}

/// A single commit entry in a patch response.
#[derive(Debug, Serialize)]
pub struct PatchEntryResponse {
    pub commit_id: String,
    pub sequence: u64,
    pub pr: String,
    /// Raw coz blobs as base64url strings.
    pub blobs: Vec<String>,
}

/// Response for `GET /patch`.
#[derive(Debug, Serialize)]
pub struct PatchResponseBody {
    pub principal_id: String,
    pub entries: Vec<PatchEntryResponse>,
}

/// Response for `POST /push`.
#[derive(Debug, Serialize)]
pub struct PushResponse {
    /// BLAKE3 hashes of stored blobs (hex-encoded).
    pub blob_hashes: Vec<String>,
}

// ========================================================================
// Handlers
// ========================================================================

/// `GET /tip?pr=<PG>` — current principal state.
pub async fn tip(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    let tip = state.engine.get_tip(&query.pr).map_err(AppError::engine)?;

    match tip {
        Some(t) => Ok(Json(TipResponse {
            principal_id: t.principal_id,
            pr: t.pr,
            sr: t.sr,
            ar: t.ar,
            commit_id: t.commit_id,
            commit_count: t.commit_count,
            last_updated: t.last_updated,
        })),
        None => Err(AppError::not_found(format!(
            "principal {} not found",
            query.pr
        ))),
    }
}

/// `GET /patch?pr=<PG>&from=<n>&to=<n>` — commit chain delta.
pub async fn patch(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PatchQuery>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let response = state
        .engine
        .get_patch(&query.pr, query.from, query.to)
        .map_err(AppError::engine)?;

    let entries = response
        .entries
        .into_iter()
        .map(|entry| PatchEntryResponse {
            commit_id: entry.commit.commit_id,
            sequence: entry.commit.sequence,
            pr: entry.commit.pr,
            blobs: entry
                .blobs
                .iter()
                .map(|b| Base64UrlUnpadded::encode_string(b))
                .collect(),
        })
        .collect();

    Ok(Json(PatchResponseBody {
        principal_id: response.principal_id,
        entries,
    }))
}

/// `POST /push` — accept and validate a signed commit bundle.
pub async fn push(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PushRequest>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    if request.blobs.is_empty() {
        return Err(AppError::bad_request("empty commit bundle"));
    }

    // Decode base64url blobs back to raw bytes.
    let raw_blobs: Vec<Vec<u8>> = request
        .blobs
        .iter()
        .enumerate()
        .map(|(i, b)| {
            Base64UrlUnpadded::decode_vec(b)
                .map_err(|e| AppError::bad_request(format!("blob[{i}]: invalid base64url: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let blob_refs: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

    // Genesis auto-detection: the engine resolves genesis from stored
    // state (existing principal) or from the submitted blobs (new principal).
    let result = state
        .engine
        .submit_commit(&request.principal_id, None, &blob_refs)
        .map_err(AppError::engine)?;

    Ok((
        StatusCode::CREATED,
        Json(PushResponse {
            blob_hashes: result.blob_hashes.iter().map(|h| h.to_string()).collect(),
        }),
    ))
}

/// `GET /e/{digest}` — content-addressed entity lookup.
pub async fn entity(
    State(state): State<Arc<AppState>>,
    Path(digest_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let digest: cyphr::state::TaggedDigest = digest_str
        .parse()
        .map_err(|e| AppError::bad_request(format!("invalid digest: {e}")))?;

    let data = state.engine.get_entity(&digest).map_err(AppError::engine)?;

    match data {
        Some(bytes) => Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )),
        None => Err(AppError::not_found(format!(
            "entity {digest_str} not found"
        ))),
    }
}
