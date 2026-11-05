//! MSS API route handlers.
//!
//! Each handler extracts request parameters, delegates to the
//! [`StorageEngine`], and converts the result into an HTTP response.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use cyphr_storage::index::types::TipState;
use serde::{Deserialize, Serialize};

use crate::envelope::Envelope;
use crate::error::{AppError, AppJson};
use crate::sync::SyncOutcome;
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
    /// Resync anchor: a tagged content digest (Zami #140; the anchor root
    /// is PR). Raw string here -- the `patch` handler parses it into a
    /// [`cyphr::state::TaggedDigest`] and refuses a malformed value with the
    /// app's JSON error envelope, matching the `GET /e/{digest}` handler's
    /// precedent. Omit to resync from genesis. Sequence is never accepted
    /// here (S3: sequence is metadata, not a trust anchor).
    pub from: Option<String>,
    /// End sequence (inclusive). Omit for tip.
    pub to: Option<u64>,
}

/// Request body for `POST /push`.
#[derive(Debug, Serialize, Deserialize)]
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
    pub now: i64,
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
    /// The accepted commit's 0-indexed position (the
    /// post-state commit count minus one).
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

/// Response for `POST /revoke` -- acknowledgement that a self-signed naked
/// revoke was accepted and the key recorded dead (SPEC §6.4). The death
/// record is server-local truth, not a trust object a client replays, so the
/// acknowledgement is unsigned regardless of attestor status (see the
/// handler).
#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    /// The revoked key's thumbprint, base64url -- now dead globally.
    pub revoked_tmb: String,
    /// Always true on a 2xx: the revoked key was durably recorded dead.
    pub recorded: bool,
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
    /// A read-only witness server syncing from an authority.
    Witness { mode: String, now: i64 },
    /// No established, servable chain to pin: no signing key configured,
    /// or a keyed process whose principal has not been bootstrapped.
    Repository,
}

// ========================================================================
// Handlers
// ========================================================================

/// Whether `raw` is shaped like a principal identifier: an `ALG:digest`
/// tagged digest or a bare canonical base64url digest of a supported
/// length. Peer input, so checked before it can reach an outbound request.
fn is_principal_ref(raw: &str) -> bool {
    if raw.contains(':') {
        raw.parse::<cyphr::state::TaggedDigest>().is_ok()
    } else {
        receipt::parse_genesis_id_str(raw).is_ok()
    }
}

/// Witness mode only: sync `pr` from the authority before the local read.
///
/// A `pr` that is not shaped like a principal identifier is never forwarded:
/// the local lookup alone answers (not found), so unauthenticated garbage
/// costs the witness no outbound request. Authority mode is unchanged.
async fn witness_sync(state: &Arc<AppState>, pr: &str) {
    if state.config.mode != crate::config::ServerMode::Witness {
        return;
    }
    if !is_principal_ref(pr) {
        tracing::debug!("witness sync skipped: pr is not a principal identifier");
        return;
    }
    match crate::sync::sync_from_authority(state, pr).await {
        SyncOutcome::Synced { applied, rejected } => {
            tracing::debug!(principal = %pr, applied, rejected, "witness sync applied entries");
        },
        SyncOutcome::UpToDate => {},
        SyncOutcome::Failed { reason } => {
            tracing::warn!(principal = %pr, ?reason, "witness sync failed");
        },
    }
}

/// `GET /tip?pr=<PG>` — current principal state.
#[tracing::instrument(skip(state))]
pub async fn tip(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    witness_sync(&state, &query.pr).await;

    let tip = state
        .engine
        .get_tip(&query.pr)
        .await
        .map_err(AppError::engine)?;

    let t = tip.ok_or_else(|| AppError::not_found(format!("principal {} not found", query.pr)))?;

    let payload = TipResponse {
        principal_id: cyphr_storage::engine::bare_digest(&t.principal_id).to_string(),
        pr: t.pr.clone(),
        sr: t.sr.clone(),
        ar: t.ar.clone(),
        cr: t.cr.clone(),
        commit_id: t.commit_id.clone(),
        commit_count: t.commit_count,
        last_updated: t.last_updated,
        now: crate::auth::server_now(),
    };

    match sign_tip_attestation(&state, &t).await? {
        Some(coz) => Ok(Json(Envelope::signed(payload, coz))),
        None => Ok(Json(Envelope::unsigned(payload))),
    }
}

/// The accepted commit's 0-indexed sequence position: `commit_count`'s
/// checked predecessor (#98/#156). `commit_count == 0` can only mean a
/// desynchronized or corrupted tip -- `MemoryIndexer::index_commit`
/// computes `commit_count` as the chain's own length, so `get_tip` never
/// returns `0` for an existing principal today -- but nothing in the TYPE
/// enforces that invariant, so a caller-reachable zero is treated as an
/// internal error rather than trusted to never wrap a plain subtraction.
fn commit_sequence(commit_count: u64) -> Result<u64, AppError> {
    commit_count
        .checked_sub(1)
        .ok_or_else(|| AppError::internal("tip commit_count is zero: cannot derive sequence"))
}

/// Sign a tip-report attestation over an already-fetched tip state `t` --
/// the claim set `/tip` and `/patch` both need (identity, entry/root
/// binding, `now`), factored out so `/patch`'s envelope signing (K10) reuses
/// exactly `/tip`'s signing path rather than a second one. Returns `Ok(None)`
/// when the server holds no signing identity (the legacy unsigned path).
async fn sign_tip_attestation(
    state: &Arc<AppState>,
    t: &TipState,
) -> Result<Option<coz::CozJson>, AppError> {
    let Some(identity) = state.attestor_identity() else {
        return Ok(None);
    };

    let derived = state
        .engine
        .rederive_roots(&t.principal_id)
        .await
        .map_err(|e| AppError::internal(format!("attestation root re-derivation failed: {e}")))?;

    if derived.pr != t.pr || derived.sr != t.sr || derived.ar != t.ar || derived.cr != t.cr {
        return Err(AppError::internal(
            "attestation root desynchronized with index",
        ));
    }

    let roots = receipt::Roots {
        pr: derived.pr,
        sr: derived.sr,
        ar: derived.ar,
        // Storage's own re-derivation still reports "no commit root yet"
        // as an empty string (cyphr-storage, out of this node's surface)
        // -- this is the boundary where that sentinel becomes the
        // receipt's typed absence (#147).
        cr: (!derived.cr.is_empty()).then_some(derived.cr),
    };
    let coz = receipt::tip_report(
        identity,
        crate::auth::server_now(),
        cyphr_storage::engine::bare_digest(&t.principal_id).to_string(),
        commit_sequence(t.commit_count)?,
        t.commit_id.clone(),
        &roots,
        t.commit_count,
        t.last_updated,
    )
    .ok_or_else(|| AppError::internal("tip attestation signing unavailable"))?;
    Ok(Some(coz))
}

/// `GET /patch?pr=<PG>&from=<n>&to=<n>` — commit chain delta.
#[tracing::instrument(skip(state))]
pub async fn patch(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PatchQuery>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    witness_sync(&state, &query.pr).await;

    // Retyped from a bare sequence to a content digest (Zami #140; S0.1: the
    // anchor root is PR). Parsed here, once, at the same boundary the
    // existing `GET /e/{digest}` handler (`entity`, below) parses a digest
    // path parameter -- a malformed anchor is refused with the app's JSON
    // error envelope, not axum's generic query-rejection, matching that
    // precedent exactly (parse-don't-validate, eng-frame §2).
    let anchor: Option<cyphr::state::TaggedDigest> = match &query.from {
        Some(raw) => Some(
            raw.parse()
                .map_err(|e| AppError::bad_request(format!("invalid resync anchor digest: {e}")))?,
        ),
        None => None,
    };

    let response = state
        .engine
        .get_patch(&query.pr, anchor.as_ref(), query.to)
        .await
        .map_err(AppError::engine)?;

    // Fetched unconditionally (not just when entries are empty, as before):
    // the not-found check below still needs it, and the signing step after
    // now needs it too -- one fetch serves both instead of two call sites
    // each deciding independently whether a tip lookup is warranted.
    let tip = state
        .engine
        .get_tip(&query.pr)
        .await
        .map_err(AppError::engine)?;

    if response.entries.is_empty() && tip.is_none() {
        return Err(AppError::not_found(format!(
            "principal {} not found",
            query.pr
        )));
    }

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

    let payload = PatchResponseBody {
        principal_id: cyphr_storage::engine::bare_digest(&response.principal_id).to_string(),
        entries,
    };

    // Signed via the same tip-attestation path `/tip` uses (K10): the
    // envelope attests the AUTHORITY's current tip, accurate ONLY when a
    // request is served through to that tip. A bounded `to` can stop short
    // of the tip -- signing the current-tip attestation over a response
    // that does not actually reach it would misdescribe what was served
    // (flagged at this node's dispatch as the bounded-`to` attestation
    // edge). Resolved here by refusing to sign a bounded response rather
    // than attesting a state later than what was actually served -- the
    // simpler of S3's two sanctioned resolutions, since re-deriving roots
    // AT an arbitrary bounded position is a materially larger change than
    // this node's digest-anchor surface calls for. `to=None` (every
    // existing caller and test) is unaffected.
    //
    // Unlike `/tip`, a failure to sign is NOT otherwise propagated as a
    // hard error: `/patch`'s entries are independently re-verified by every
    // witness that applies them (`submit_commit`), so an authority whose
    // own re-derived roots momentarily disagree with its index (the same
    // desync guard `/tip` enforces strictly) is safer serving them
    // unsigned than refusing to serve at all.
    let coz = match tip {
        Some(_) if query.to.is_some() => {
            tracing::debug!(
                principal = %query.pr,
                to = ?query.to,
                "patch response bounded by `to`; serving unsigned to avoid attesting a later \
                 state than what was actually served"
            );
            None
        },
        Some(t) => match sign_tip_attestation(&state, &t).await {
            Ok(coz) => coz,
            Err(err) => {
                tracing::warn!(
                    principal = %query.pr,
                    error = %err,
                    "patch envelope signing unavailable; serving unsigned"
                );
                None
            },
        },
        None => None,
    };

    match coz {
        Some(coz) => Ok(Json(Envelope::signed(payload, coz))),
        None => Ok(Json(Envelope::unsigned(payload))),
    }
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
    AppJson(request): AppJson<PushRequest>,
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

    // #168: an attestor server refuses to sign a post-commit receipt for a
    // non-canonical `principal_id` (`receipt::commit_receipt`'s own
    // `parse_genesis_id_str` gate) -- refusing HERE, before any durable
    // write, keeps that refusal from being discovered only after
    // `submit_commit` (below) has already landed the commit, which
    // previously left a durable write standing behind a reported `500`.
    // Scoped to attestor mode: a keyless or keyed-but-unbootstrapped
    // server never attempts to sign a receipt, so it stays free to accept
    // any storage-key-shaped `principal_id`, exactly as before.
    if state.attestor_identity().is_some()
        && receipt::parse_genesis_id_str(cyphr_storage::engine::bare_digest(&request.principal_id))
            .is_err()
    {
        return Err(AppError::bad_request(format!(
            "principal_id is not a canonical genesis identifier: {}",
            request.principal_id
        )));
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

    // Global key-death gate (SPEC §6.4): a naked-revoked key is refused for
    // every capability, push included. Refuse the bundle if any signing key
    // (`pay.tmb`) is dead. Runs before submit_commit so a dead key is an auth
    // refusal, never a stale-predecessor 409. A blob whose shape submit_commit
    // will itself reject (unparseable, no tmb, non-b64url tmb) is left for
    // that authoritative validation rather than pre-judged here.
    //
    // INVARIANT (refusal-only): this fence consults an UNVERIFIED,
    // client-declared `pay.tmb` -- the signature is not checked until
    // submit_commit below. It is compliant ONLY because its outcome is pure
    // refusal: a forged `pay.tmb` naming a dead key can at worst refuse a push
    // the forger was making anyway. It must NEVER be extended to admit,
    // authorize, or otherwise act on this unverified `tmb`; any such use would
    // trust a value the client fully controls.
    for raw in &raw_blobs {
        let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(raw) else {
            continue;
        };
        let Some(tmb_b64) = parsed["pay"]["tmb"].as_str() else {
            continue;
        };
        let Ok(tmb_bytes) = Base64UrlUnpadded::decode_vec(tmb_b64) else {
            continue;
        };
        let tmb = coz::Thumbprint::from_bytes(tmb_bytes);
        if state
            .observations
            .is_dead(&tmb)
            .await
            .map_err(AppError::observation)?
        {
            return Err(AppError::unauthorized("push signing key was revoked"));
        }
    }

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
    // Read back under the canonical id the engine stored under: the
    // submitted spelling can stop resolving once this commit moves the PR.
    let t = state
        .engine
        .get_tip(&result.principal_id)
        .await
        .map_err(AppError::engine)?
        .ok_or_else(|| AppError::internal("accepted commit has no tip"))?;

    let payload = PushResponse {
        blob_hashes: result.blob_hashes.iter().map(|h| h.to_string()).collect(),
        commit_id: t.commit_id.clone(),
        sequence: commit_sequence(t.commit_count)?,
        roots: PushRoots {
            pr: t.pr.clone(),
            sr: t.sr.clone(),
            ar: t.ar.clone(),
            cr: t.cr.clone(),
        },
    };

    match state.attestor_identity() {
        Some(identity) => {
            let derived = state
                .engine
                .rederive_roots(&result.principal_id)
                .await
                .map_err(|e| {
                    AppError::internal(format!("attestation root re-derivation failed: {e}"))
                })?;

            if derived.pr != t.pr || derived.sr != t.sr || derived.ar != t.ar || derived.cr != t.cr
            {
                return Err(AppError::internal(
                    "attestation root desynchronized with index",
                ));
            }

            let roots = receipt::Roots {
                pr: derived.pr,
                sr: derived.sr,
                ar: derived.ar,
                // See `sign_tip_attestation`'s identical conversion: the
                // empty-string sentinel becomes the receipt's typed
                // absence at this boundary (#147).
                cr: (!derived.cr.is_empty()).then_some(derived.cr),
            };
            let coz = receipt::commit_receipt(
                identity,
                crate::auth::server_now(),
                cyphr_storage::engine::bare_digest(&t.principal_id).to_string(),
                commit_sequence(t.commit_count)?,
                t.commit_id,
                &roots,
            )
            .ok_or_else(|| AppError::internal("commit receipt signing unavailable"))?;
            Ok((StatusCode::CREATED, Json(Envelope::signed(payload, coz))))
        },
        None => Ok((StatusCode::CREATED, Json(Envelope::unsigned(payload)))),
    }
}

/// `POST /revoke` — accept, verify, and record a self-signed naked revoke
/// (SPEC §6.4).
///
/// A naked revoke is an uncommitted, self-signed `key/revoke` coz: the key
/// named by the coz's `tmb` signs its own revoke. The request body is the
/// signed coz PLUS its disclosed public key (`{pay, sig, key}`), naming no
/// principal. This handler verifies it replay-free against the DISCLOSED key
/// (via [`crate::revoke::interpret`]) -- no principal load, no chain replay,
/// and never reading the index's content -- and records the full self-signing
/// envelope in the durable global death-set as independently re-verifiable
/// evidence. It never touches any principal's chain (a naked revoke mutates no
/// PR). Thereafter the key is refused GLOBALLY, for every capability and every
/// principal that holds it (see [`crate::auth::login`] and [`push`]).
#[tracing::instrument(skip(state, envelope))]
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    AppJson(envelope): AppJson<crate::revoke::NakedRevokeEnvelope>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let verified = crate::revoke::interpret(&envelope, state.engine.indexer()).await?;

    // Store the full `{pay, sig, key}` envelope: self-contained evidence any
    // later reader can re-verify with no index.
    state
        .observations
        .record(&verified.revoked_tmb, verified.evidence)
        .await
        .map_err(AppError::observation)?;

    let payload = RevokeResponse {
        revoked_tmb: Base64UrlUnpadded::encode_string(verified.revoked_tmb.as_bytes()),
        recorded: true,
    };
    Ok((StatusCode::OK, Json(Envelope::unsigned(payload))))
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

    let payload = if state.config.mode == crate::config::ServerMode::Witness {
        IdentityResponse::Witness {
            mode: "witness".to_string(),
            now: crate::auth::server_now(),
        }
    } else {
        match state.attestor() {
            Some((principal, identity)) => {
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
                        alg: genesis_key.alg().to_owned(),
                        pub_key: Base64UrlUnpadded::encode_string(genesis_key.pub_key()),
                        tmb: Base64UrlUnpadded::encode_string(genesis_key.tmb().as_bytes()),
                        first_seen: genesis_key.first_seen(),
                    },
                }
            },
            None => IdentityResponse::Repository,
        }
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

// ========================================================================
// #98/#156: the receipt `sequence` must never silently wrap
// ========================================================================

/// White-box coverage for #98/#156: a receipt/response `sequence` is the
/// post-state commit count minus one, which wraps on a zero count. The
/// zero count is unreachable via ordinary commit ingestion (a `TipState`
/// is only recorded after indexing at least one commit), but nothing in
/// the type enforces that, so this drives `sign_tip_attestation` with a
/// hand-constructed [`TipState`] -- no HTTP path can feed it one.
#[cfg(test)]
mod commit_count_underflow_tests {
    use std::sync::Arc;

    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use tempfile::TempDir;

    use super::*;
    use crate::auth::principal::ServerPrincipal;
    use crate::config::ServerConfig;

    /// A keyed, bootstrapped [`AppState`] -- mirrors
    /// `tests/common/mod.rs::attestor_server()`, duplicated here (rather
    /// than reused) because that helper lives in a separate
    /// integration-test crate and cannot see `sign_tip_attestation`,
    /// which is private to this module.
    async fn attestor_state() -> (Arc<AppState>, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("signing-key.json");
        let kp = coz::Alg::Ed25519.generate_keypair();
        let file = serde_json::json!({
            "alg": kp.alg.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
            "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
        });
        std::fs::write(&key_path, serde_json::to_vec(&file).unwrap()).unwrap();

        let config = ServerConfig {
            data_dir: dir.path().join("data"),
            signing_key_path: Some(key_path.clone()),
            ..Default::default()
        };
        let mut state = AppState::new(config).expect("keyed AppState opens");
        let identity = state.identity.clone().expect("keyed state has identity");

        // `state.attestor_identity()` (what `sign_tip_attestation` gates
        // on) requires BOTH `identity` and `principal` to be `Some` --
        // bootstrap the server's own principal purely to satisfy that
        // gate. The fixture tip each test below actually signs comes from
        // a SEPARATE, purpose-built genesis push (`push_test_genesis`),
        // not the server's own chain: `rederive_roots`'s auto-detection
        // (`resolve_genesis` -> `genesis_from_raw_blobs`) requires the
        // genesis key embedded on the CLOSING `commit/create` cozy, a wire
        // shape `build_genesis` (used here) does not produce -- it hands
        // `submit_commit` an already-resolved `Genesis::Explicit`
        // directly, bypassing that auto-detection entirely. A test push
        // must go through the same auto-detecting shape a real client
        // request does.
        let sp =
            ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
                .await
                .expect("bootstrap the server principal");
        state.principal = Some(Arc::new(sp));

        (Arc::new(state), dir)
    }

    /// Push a minimal, data-free genesis commit for `principal_id` through
    /// the engine directly -- an implicit-genesis key closed by a
    /// `commit/create` introducing one further key, the genesis key
    /// embedded on the CLOSING cozy exactly as `submit_commit`'s
    /// auto-detection (`genesis_from_raw_blobs`) requires. Mirrors
    /// `tests/common/mod.rs::build_genesis_push_body` +
    /// `sign_key_create_commit`'s wire shape, duplicated here (with a
    /// freshly generated keypair rather than the shared `test_fixtures`
    /// pool) because that helper lives in the separate integration-test
    /// crate this unit-test module cannot depend on.
    ///
    /// Returns the principal id the genesis derives (SPEC §3.1), the only
    /// id the engine accepts for this commit.
    async fn push_test_genesis(state: &AppState, now: i64) -> String {
        let golden_kp = coz::Alg::Ed25519.generate_keypair();
        let golden_tmb = golden_kp
            .alg
            .compute_thumbprint(&golden_kp.pub_bytes)
            .expect("golden thumbprint");
        let golden_key = cyphr::Key::new(
            golden_kp.alg.name().to_string(),
            golden_tmb.clone(),
            golden_kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb");

        let new_kp = coz::Alg::Ed25519.generate_keypair();
        let new_tmb = new_kp
            .alg
            .compute_thumbprint(&new_kp.pub_bytes)
            .expect("new-key thumbprint");
        let new_tmb_b64 = Base64UrlUnpadded::encode_string(new_tmb.as_bytes());
        let golden_tmb_b64 = Base64UrlUnpadded::encode_string(golden_tmb.as_bytes());

        let pay_value = serde_json::json!({
            "alg": golden_kp.alg.name(),
            "id": new_tmb_b64,
            "now": now,
            "tmb": golden_tmb_b64,
            "typ": "cyphr.me/cyphr/key/create",
        });
        let mut pay_obj = pay_value.clone();
        pay_obj.as_object_mut().unwrap().sort_keys();
        let pay_vec = serde_json::to_vec(&pay_obj).unwrap();

        let (sig_bytes, cad) = coz::sign_json(
            &pay_vec,
            golden_kp.alg.name(),
            &golden_kp.prv_bytes,
            &golden_kp.pub_bytes,
        )
        .expect("signing supported for Ed25519");
        let czd =
            coz::czd_for_alg(&cad, &sig_bytes, golden_kp.alg.name()).expect("czd for Ed25519");

        let new_key = cyphr::Key::new(
            new_kp.alg.name().to_string(),
            new_tmb,
            new_kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(now);

        let mut principal =
            cyphr::Principal::implicit(golden_key.clone()).expect("implicit genesis");
        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_key))
            .expect("key/create verifies against the starting principal state");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    golden_kp.alg.name(),
                    &golden_kp.prv_bytes,
                    &golden_kp.pub_bytes,
                    &golden_tmb,
                ),
                now,
                "cyphr.me",
            )
            .expect("commit finalizes");

        let entries = cyphr_storage::export_commits(&principal).expect("export the new commit");
        let commit = entries.last().expect("at least one commit after finalize");

        let mut key_idx = 0;
        let blobs: Vec<Vec<u8>> = commit
            .cozies
            .iter()
            .map(|v| {
                let mut coz = v.clone();
                let typ = coz["pay"]["typ"].as_str().unwrap_or("");
                if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < commit.keys.len() {
                    let key = &commit.keys[key_idx];
                    coz.as_object_mut().unwrap().insert(
                        "key".to_string(),
                        serde_json::json!({
                            "alg": key.alg,
                            "pub": key.pub_key,
                            "tmb": key.tmb,
                        }),
                    );
                    key_idx += 1;
                }
                serde_json::to_vec(&coz).expect("cozy serializes")
            })
            .collect();

        // The genesis key is embedded on the CLOSING `commit/create` cozy
        // (`resolve_genesis`'s auto-detection wire contract for a
        // never-before-seen principal), not on the `key/create` cozy above.
        let closing_idx = blobs.len() - 1;
        let mut closing: serde_json::Value = serde_json::from_slice(&blobs[closing_idx]).unwrap();
        closing.as_object_mut().unwrap().insert(
            "key".to_string(),
            serde_json::json!({
                "alg": golden_key.alg(),
                "pub": Base64UrlUnpadded::encode_string(golden_key.pub_key()),
                "tmb": golden_tmb_b64,
            }),
        );
        let closing_blob = serde_json::to_vec(&closing).unwrap();

        let mut all_blobs = blobs;
        let last = all_blobs.len() - 1;
        all_blobs[last] = closing_blob;

        let principal_id = cyphr_storage::engine::genesis_principal_id(
            &cyphr_storage::Genesis::Implicit(golden_key.clone()),
        )
        .expect("genesis-derived principal id");
        let blob_refs: Vec<&[u8]> = all_blobs.iter().map(Vec::as_slice).collect();
        state
            .engine
            .submit_commit(&principal_id, None, &blob_refs)
            .await
            .expect("genesis push succeeds");
        principal_id
    }

    /// Positive control: proves this suite's harness genuinely exercises
    /// `sign_tip_attestation`'s real signing path. A *legitimate*
    /// `commit_count == 1` tip must sign a receipt whose `sequence` claim
    /// is `0`. If this control fails, the red test below is not
    /// trustworthy -- it could be "failing" for an unrelated harness
    /// reason rather than the zero-commit-count defect.
    #[tokio::test]
    async fn sign_tip_attestation_legitimate_tip_signs_correct_sequence() {
        let (state, _dir) = attestor_state().await;
        let principal_id = push_test_genesis(&state, 1_700_200_000).await;

        let tip = state
            .engine
            .get_tip(&principal_id)
            .await
            .expect("get_tip")
            .expect("a real tip exists after the genesis push");
        assert_eq!(
            tip.commit_count, 1,
            "sanity: a fresh genesis push has exactly one commit"
        );

        let coz = sign_tip_attestation(&state, &tip)
            .await
            .expect("legitimate commit_count must sign without error")
            .expect("a keyed, bootstrapped server must sign");
        assert_eq!(
            coz.pay["sequence"],
            serde_json::json!(0),
            "commit_count=1 must yield sequence=0: {:?}",
            coz.pay
        );
    }

    /// RED: a [`TipState`] reporting `commit_count == 0` -- unreachable
    /// via the real commit-ingestion path today, but nothing in the TYPE
    /// enforces that, which is exactly #98/#156's complaint -- must never
    /// let `sign_tip_attestation` sign a receipt at all, and must never
    /// panic doing so.
    ///
    /// Once the subtraction is checked, this test passes either
    /// because the call returns an explicit error or because it falls
    /// back to unsigned (`Ok(None)`) -- either is an acceptable "typed
    /// absence" per this node's IBC, which leaves the exact
    /// representation delegated; only signing a receipt at all is
    /// disallowed.
    ///
    /// Driven through `tokio::spawn` (not an in-place `.await`) so a
    /// debug-mode overflow panic is CAUGHT as a `JoinError` rather than
    /// aborting the test process outright -- this must fail loudly under
    /// plain `cargo test` (the debug profile most contributors run), not
    /// only under `--release`, binding both consequences the issues name
    /// (a debug panic and a release-mode `u64::MAX` wrap) under one
    /// property.
    #[tokio::test]
    async fn sign_tip_attestation_zero_commit_count_never_wraps_or_panics() {
        let (state, _dir) = attestor_state().await;
        let principal_id = push_test_genesis(&state, 1_700_200_100).await;

        let real_tip = state
            .engine
            .get_tip(&principal_id)
            .await
            .expect("get_tip")
            .expect("a real tip exists after the genesis push");

        // A hand-corrupted copy of a REAL, otherwise-consistent tip: every
        // root still matches what `rederive_roots` independently
        // recomputes (so the desync guard at the top of
        // `sign_tip_attestation` does not short-circuit before the
        // subtraction runs), with only `commit_count` forced to the
        // claimed-unreachable value.
        let mut corrupted = real_tip.clone();
        corrupted.commit_count = 0;

        let state_for_task = Arc::clone(&state);
        let outcome =
            tokio::spawn(async move { sign_tip_attestation(&state_for_task, &corrupted).await })
                .await;

        match outcome {
            Err(join_err) => panic!(
                "commit_count == 0 must not panic (a debug-mode u64 underflow trap): {join_err}"
            ),
            Ok(Ok(Some(coz))) => {
                let sequence = coz.pay["sequence"].clone();
                panic!(
                    "commit_count == 0 must never produce a signed receipt at all (a typed \
                     absence is required, not a value) -- got a signed sequence claim: {sequence}"
                );
            },
            Ok(Ok(None)) | Ok(Err(_)) => {
                // Acceptable: refused to sign, one way or the other -- the
                // exact representation is this node's delegated call.
            },
        }
    }
}
