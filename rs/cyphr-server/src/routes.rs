//! MSS API route handlers.
//!
//! Each handler extracts request parameters, delegates to the
//! [`StorageEngine`], and converts the result into an HTTP response.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::envelope::Envelope;
use crate::error::AppError;
use crate::{AppState, receipt};

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
    /// Current Commit Root (empty string if no commit has populated the
    /// EML log yet). `docs/specs/http-envelope.md` `[envelope-r-cr]`.
    pub cr: String,
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
    /// The accepted commit's id -- a push client previously had no way to
    /// learn this without a follow-up `/tip` read.
    pub commit_id: String,
    /// The accepted commit's 0-indexed position (post-state
    /// `commit_count - 1`).
    pub sequence: u64,
    /// The post-state roots, nested to mirror the same shape a signed
    /// commit receipt's `roots` claim carries (`docs/specs/receipts.md`),
    /// so an attestor's push claims can be compared against this payload
    /// claim-by-claim.
    pub roots: PushRoots,
}

/// Post-commit roots on a push response, mirroring
/// [`crate::receipt::Roots`]'s wire shape.
#[derive(Debug, Serialize)]
pub struct PushRoots {
    pub pr: String,
    pub sr: String,
    pub ar: String,
    pub cr: String,
}

/// The server's genesis key, published as a trustless HINT for offline
/// verification (`docs/specs/server-identity.md`'s TOFU story): a client
/// reconstructs `Genesis::Explicit` from it and re-derives the PG,
/// trusting the hint only once that derivation matches the pinned `pg` --
/// never on discovery's say-so alone. Nested under `genesis` so these
/// fields are unambiguously distinct from [`IdentityResponse::Attestor`]'s
/// CURRENT-key fields, which describe whichever key is active right now
/// and may differ from the genesis key after a rotation.
#[derive(Debug, Serialize)]
pub struct GenesisKeyInfo {
    pub alg: String,
    #[serde(rename = "pub")]
    pub pub_key: String,
    pub tmb: String,
    pub first_seen: i64,
}

/// Response for `GET /server` — the server's identity/capability
/// discovery payload (`docs/specs/server-identity.md`).
///
/// Internally tagged by `tier` so a client reads capability level
/// structurally, the same discipline the envelope's `statement.kind`
/// uses: `repository` carries no identity-shaped fields at all rather
/// than empty strings a client could mis-parse as attestation.
#[derive(Debug, Serialize)]
#[serde(tag = "tier", rename_all = "lowercase")]
pub enum IdentityResponse {
    /// A keyed, bootstrapped server: the stable Principal Genesis, the
    /// CURRENT signing key's algorithm, public key, and thumbprint (all
    /// base64url except `alg`), and the GENESIS key hint offline
    /// verification replays the chain from.
    Attestor {
        pg: String,
        alg: String,
        #[serde(rename = "pub")]
        pub_key: String,
        tmb: String,
        genesis: GenesisKeyInfo,
    },
    /// No established, servable chain to pin: no signing key configured,
    /// or a keyed process whose principal has not been bootstrapped.
    Repository,
}

// ========================================================================
// Handlers
// ========================================================================

/// `GET /tip?pr=<PG>` — current principal state.
#[tracing::instrument(skip(state))]
pub async fn tip(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    let tip = state
        .engine
        .get_tip(&query.pr)
        .await
        .map_err(AppError::engine)?;

    let t = tip.ok_or_else(|| AppError::not_found(format!("principal {} not found", query.pr)))?;

    let payload = TipResponse {
        principal_id: t.principal_id.clone(),
        pr: t.pr.clone(),
        sr: t.sr.clone(),
        ar: t.ar.clone(),
        cr: t.cr.clone(),
        commit_id: t.commit_id.clone(),
        commit_count: t.commit_count,
        last_updated: t.last_updated,
    };

    match (&state.principal, &state.identity) {
        (Some(_), Some(identity)) => {
            let roots = receipt::Roots {
                pr: t.pr,
                sr: t.sr,
                ar: t.ar,
                cr: t.cr,
            };
            let coz = receipt::tip_report(
                identity,
                crate::auth::server_now(),
                t.principal_id,
                t.commit_count - 1,
                t.commit_id,
                &roots,
                t.commit_count,
                t.last_updated,
            )
            .ok_or_else(|| AppError::internal("tip report signing unavailable"))?;
            Ok(Json(Envelope::signed(payload, coz)))
        },
        _ => Ok(Json(Envelope::unsigned(payload))),
    }
}

/// `GET /patch?pr=<PG>&from=<n>&to=<n>` — commit chain delta.
#[tracing::instrument(skip(state))]
pub async fn patch(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PatchQuery>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let response = state
        .engine
        .get_patch(&query.pr, query.from, query.to)
        .await
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

    Ok(Json(Envelope::unsigned(PatchResponseBody {
        principal_id: response.principal_id,
        entries,
    })))
}

/// `POST /push` — accept and validate a signed commit bundle.
///
/// Authorization is the payload's own signatures (ARCHITECT RULING R7):
/// no bearer token is required, including for a brand-new principal's
/// genesis (which cannot have logged in yet). A bearer token is an
/// OPTIONAL admission/anti-abuse knob -- if one IS presented, it must
/// name this same principal.
#[tracing::instrument(
    skip(state, headers, request),
    fields(
        principal_id = %request.principal_id,
        blob_count = request.blobs.len()
    )
)]
pub async fn push(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<PushRequest>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    if request.blobs.is_empty() {
        return Err(AppError::bad_request("empty commit bundle"));
    }

    crate::auth::middleware::check_push_admission(
        &headers,
        state.identity.as_deref(),
        &request.principal_id,
        crate::auth::server_now(),
    )?;

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
        .await
        .map_err(AppError::engine)?;

    // The response attests the state that RESULTED from this accepted
    // commit -- read back via the same post-submit tip any other client
    // would see. A push client previously had no way to learn the
    // accepted commit_id/sequence/roots without a follow-up /tip read.
    let t = state
        .engine
        .get_tip(&request.principal_id)
        .await
        .map_err(AppError::engine)?
        .ok_or_else(|| AppError::internal("accepted commit has no tip"))?;

    let payload = PushResponse {
        blob_hashes: result.blob_hashes.iter().map(|h| h.to_string()).collect(),
        commit_id: t.commit_id.clone(),
        sequence: t.commit_count - 1,
        roots: PushRoots {
            pr: t.pr.clone(),
            sr: t.sr.clone(),
            ar: t.ar.clone(),
            cr: t.cr.clone(),
        },
    };

    match (&state.principal, &state.identity) {
        (Some(_), Some(identity)) => {
            let roots = receipt::Roots {
                pr: t.pr,
                sr: t.sr,
                ar: t.ar,
                cr: t.cr,
            };
            let coz = receipt::commit_receipt(
                identity,
                crate::auth::server_now(),
                t.principal_id,
                t.commit_count - 1,
                t.commit_id,
                &roots,
            )
            .ok_or_else(|| AppError::internal("commit receipt signing unavailable"))?;
            Ok((StatusCode::CREATED, Json(Envelope::signed(payload, coz))))
        },
        _ => Ok((StatusCode::CREATED, Json(Envelope::unsigned(payload)))),
    }
}

/// `GET /server` — the server's identity/capability discovery endpoint
/// (`docs/specs/server-identity.md`).
///
/// Declares `attestor` if and only if a bootstrapped principal AND a live
/// signing identity are both present, publishing the PG from the former
/// and the CURRENT key material from the latter -- never the on-disk
/// genesis record or key file, so there is exactly one source of truth
/// per fact. Any other combination declares `repository`: no established
/// chain means nothing honest to pin.
#[tracing::instrument(skip(state))]
pub async fn identity(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let payload = match (&state.principal, &state.identity) {
        (Some(principal), Some(identity)) => {
            let tmb = identity
                .alg()
                .compute_thumbprint(identity.pub_key())
                .ok_or_else(|| AppError::internal("signing identity thumbprint unavailable"))?;
            let genesis_key = principal.genesis_key();
            IdentityResponse::Attestor {
                pg: principal.pg().to_string(),
                alg: identity.alg().name().to_string(),
                pub_key: Base64UrlUnpadded::encode_string(identity.pub_key()),
                tmb: Base64UrlUnpadded::encode_string(tmb.as_bytes()),
                genesis: GenesisKeyInfo {
                    alg: genesis_key.alg.clone(),
                    pub_key: Base64UrlUnpadded::encode_string(&genesis_key.pub_key),
                    tmb: Base64UrlUnpadded::encode_string(genesis_key.tmb.as_bytes()),
                    first_seen: genesis_key.first_seen,
                },
            }
        },
        _ => IdentityResponse::Repository,
    };

    Ok(Json(Envelope::unsigned(payload)))
}

/// `GET /e/{digest}` — content-addressed entity lookup.
#[tracing::instrument(skip(state))]
pub async fn entity(
    State(state): State<Arc<AppState>>,
    Path(digest_str): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let digest: cyphr::state::TaggedDigest = digest_str
        .parse()
        .map_err(|e| AppError::bad_request(format!("invalid digest: {e}")))?;

    let data = state
        .engine
        .get_entity(&digest)
        .await
        .map_err(AppError::engine)?;

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
