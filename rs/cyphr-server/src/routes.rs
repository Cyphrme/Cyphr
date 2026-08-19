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
use crate::registration::RegistrationAuthority;
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

/// `GET /tip?pr=<PG>` — current principal state.
#[tracing::instrument(skip(state))]
pub async fn tip(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    if state.config.mode == crate::config::ServerMode::Witness {
        match crate::sync::sync_from_authority(&state, &query.pr).await {
            SyncOutcome::Synced { applied, rejected } => {
                tracing::debug!(
                    principal = %query.pr,
                    applied,
                    rejected,
                    "witness sync applied entries"
                );
            },
            SyncOutcome::UpToDate => {},
            SyncOutcome::Failed { reason } => {
                tracing::warn!(principal = %query.pr, ?reason, "witness sync failed");
            },
        }
    }

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
        now: crate::auth::server_now(),
    };

    match sign_tip_attestation(&state, &t).await? {
        Some(coz) => Ok(Json(Envelope::signed(payload, coz))),
        None => Ok(Json(Envelope::unsigned(payload))),
    }
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
        cr: derived.cr,
    };
    let coz = receipt::tip_report(
        identity,
        crate::auth::server_now(),
        t.principal_id.clone(),
        t.commit_count - 1,
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

    if state.config.mode == crate::config::ServerMode::Witness {
        match crate::sync::sync_from_authority(&state, &query.pr).await {
            SyncOutcome::Synced { applied, rejected } => {
                tracing::debug!(
                    principal = %query.pr,
                    applied,
                    rejected,
                    "witness sync applied entries"
                );
            },
            SyncOutcome::UpToDate => {},
            SyncOutcome::Failed { reason } => {
                tracing::warn!(principal = %query.pr, ?reason, "witness sync failed");
            },
        }
    }

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
        principal_id: response.principal_id,
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
    let t = state
        .engine
        .get_tip(&request.principal_id)
        .await
        .map_err(AppError::engine)?
        .ok_or_else(|| AppError::internal("accepted commit has no tip"))?;

    crate::fanout::spawn_fanout(
        state.clone(),
        request.principal_id.clone(),
        request.blobs.clone(),
    );

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

    match state.attestor_identity() {
        Some(identity) => {
            let derived = state
                .engine
                .rederive_roots(&request.principal_id)
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
                cr: derived.cr,
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
                        alg: genesis_key.alg.clone(),
                        pub_key: Base64UrlUnpadded::encode_string(&genesis_key.pub_key),
                        tmb: Base64UrlUnpadded::encode_string(genesis_key.tmb.as_bytes()),
                        first_seen: genesis_key.first_seen,
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
// Witness registration routes (SPEC §13.5.1)
// ========================================================================

/// Request envelope for POST /witness/register and DELETE /witness/register.
#[derive(Debug, Deserialize)]
pub struct WitnessRegisterEnvelope {
    pub pay: serde_json::Value,
    #[serde(with = "coz::b64")]
    pub sig: Vec<u8>,
    pub key: Option<crate::revoke::DisclosedKey>,
}

/// Parsed and cryptographically verified witness registration details.
pub struct VerifiedWitnessRegister {
    pub principal_id: String,
    pub witness_id: String,
    pub signer_tmb: String,
    pub now: i64,
    pub verb: String,
    pub raw_blob: Vec<u8>,
}

/// Verify envelope structure, key thumbprint bind, and signature.
pub fn verify_witness_register_envelope(
    envelope: &WitnessRegisterEnvelope,
) -> Result<VerifiedWitnessRegister, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let key = envelope
        .key
        .as_ref()
        .ok_or_else(|| AppError::bad_request("witness register envelope missing disclosed key"))?;

    let pay_bytes = serde_json::to_vec(&envelope.pay)
        .map_err(|e| AppError::bad_request(format!("invalid JSON pay: {e}")))?;

    let id = envelope
        .pay
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing id in pay"))?;

    let tmb = envelope
        .pay
        .get("tmb")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing tmb in pay"))?;

    let typ = envelope
        .pay
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing typ in pay"))?;

    let principal_id = envelope
        .pay
        .get("principal_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("missing principal_id in pay"))?;

    let now = envelope
        .pay
        .get("now")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::bad_request("missing now in pay"))?;

    // Thumbprint bind verification
    let computed_tmb = coz::compute_thumbprint_for_alg(&key.alg, &key.pub_key)
        .ok_or_else(|| AppError::unauthorized("unsupported algorithm for key thumbprint"))?;

    let computed_tmb_b64 = Base64UrlUnpadded::encode_string(computed_tmb.as_bytes());
    if computed_tmb_b64 != tmb {
        return Err(AppError::unauthorized("signer thumbprint mismatch"));
    }

    // Signature verification
    let valid =
        coz::verify_json(&pay_bytes, &envelope.sig, &key.alg, &key.pub_key).unwrap_or(false);
    if !valid {
        return Err(AppError::unauthorized(
            "invalid signature on witness register envelope",
        ));
    }

    let verb = if typ.ends_with("/witness/register/create") {
        "create".to_string()
    } else if typ.ends_with("/witness/register/delete") {
        "delete".to_string()
    } else {
        return Err(AppError::bad_request(format!("invalid typ: {typ}")));
    };

    let coz_obj = serde_json::json!({
        "pay": envelope.pay,
        "sig": Base64UrlUnpadded::encode_string(&envelope.sig),
        "key": {
            "alg": key.alg,
            "pub": Base64UrlUnpadded::encode_string(&key.pub_key),
            "tmb": tmb,
        }
    });
    let raw_blob = serde_json::to_vec(&coz_obj).unwrap_or_default();

    Ok(VerifiedWitnessRegister {
        principal_id: principal_id.to_string(),
        witness_id: id.to_string(),
        signer_tmb: tmb.to_string(),
        now,
        verb,
        raw_blob,
    })
}

/// Parse the registration authorization context into a typed
/// [`RegistrationAuthority`] proof: a resident principal is managed by its
/// active keys; a not-yet-resident principal only by itself (SPEC §13.5.1:
/// the principal signs its witness registrations). `witness_id` plays no
/// part — a `witness_id` naming the signer's own key was never evidence
/// that the signer may register for the principal.
async fn check_registration_authorization(
    state: &AppState,
    principal_id: &str,
    signer_tmb: &str,
) -> Result<RegistrationAuthority, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    // A residency lookup failure propagates: falling through to the
    // non-resident branch on an engine fault would decide authorization
    // against absent evidence.
    let tip = state
        .engine
        .get_tip(principal_id)
        .await
        .map_err(AppError::engine)?;
    if tip.is_some() {
        let genesis = state
            .engine
            .resolve_genesis(principal_id, &[])
            .await
            .map_err(AppError::engine)?;
        let principal = state
            .engine
            .load_principal(principal_id, genesis)
            .await
            .map_err(AppError::engine)?;

        let signer_tmb_bytes = Base64UrlUnpadded::decode_vec(signer_tmb)
            .map_err(|_| AppError::unauthorized("invalid signer thumbprint base64"))?;
        let signer_tmb_obj = coz::Thumbprint::from_bytes(signer_tmb_bytes);

        return RegistrationAuthority::active_key(&principal, &signer_tmb_obj)
            .ok_or_else(|| AppError::unauthorized("signer key is not active for principal"));
    }

    RegistrationAuthority::self_signer(principal_id, signer_tmb)
        .ok_or_else(|| AppError::unauthorized("unauthorized third-party witness registration"))
}

/// `POST /witness/register` — register an external witness for a principal.
#[tracing::instrument(skip(state, envelope))]
pub async fn witness_register_post(
    State(state): State<Arc<AppState>>,
    AppJson(envelope): AppJson<WitnessRegisterEnvelope>,
) -> Result<impl IntoResponse, AppError> {
    let verified = verify_witness_register_envelope(&envelope)?;
    if verified.verb != "create" {
        return Err(AppError::bad_request(
            "invalid verb for POST witness register",
        ));
    }

    let authority =
        check_registration_authorization(&state, &verified.principal_id, &verified.signer_tmb)
            .await?;

    let (current_witnesses, _) = state.registration.get_witnesses(&verified.principal_id);
    if current_witnesses.len() >= crate::registration::MAX_WITNESSES_PER_PRINCIPAL
        && !current_witnesses.iter().any(|w| w == &verified.witness_id)
    {
        return Err(AppError::bad_request("capacity limit reached"));
    }

    let _ = state
        .engine
        .submit_commit(&verified.principal_id, None, &[&verified.raw_blob])
        .await;

    state.registration.register_witness(
        authority,
        &verified.principal_id,
        &verified.witness_id,
        verified.now,
    )?;

    let payload = serde_json::json!({
        "principal_id": verified.principal_id,
        "witness_id": verified.witness_id,
        "last_updated": verified.now,
        "now": verified.now,
    });

    let env = crate::envelope::Envelope::unsigned(payload);

    Ok((StatusCode::CREATED, Json(env)))
}

/// `DELETE /witness/register` — revoke (mark inactive) a registered witness.
#[tracing::instrument(skip(state, envelope))]
pub async fn witness_register_delete(
    State(state): State<Arc<AppState>>,
    AppJson(envelope): AppJson<WitnessRegisterEnvelope>,
) -> Result<impl IntoResponse, AppError> {
    let verified = verify_witness_register_envelope(&envelope)?;
    if verified.verb != "delete" {
        return Err(AppError::bad_request(
            "invalid verb for DELETE witness register",
        ));
    }

    let authority =
        check_registration_authorization(&state, &verified.principal_id, &verified.signer_tmb)
            .await?;

    let _ = state
        .engine
        .submit_commit(&verified.principal_id, None, &[&verified.raw_blob])
        .await;

    state.registration.revoke_witness(
        authority,
        &verified.principal_id,
        &verified.witness_id,
        verified.now,
    )?;

    let (active_witnesses, last_updated) = state.registration.get_witnesses(&verified.principal_id);

    let payload = serde_json::json!({
        "principal_id": verified.principal_id,
        "witnesses": active_witnesses,
        "last_updated": last_updated,
    });

    let env = crate::envelope::Envelope::unsigned(payload);

    Ok((StatusCode::OK, Json(env)))
}

/// `GET /witness/register` — query active witnesses for a principal.
#[tracing::instrument(skip(state, query))]
pub async fn witness_register_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    let (active_witnesses, last_updated) = state.registration.get_witnesses(&query.pr);
    let deliveries = state.fanout.get_deliveries(&query.pr, &active_witnesses);

    let payload = serde_json::json!({
        "principal_id": query.pr,
        "witnesses": active_witnesses,
        "last_updated": last_updated,
        "deliveries": deliveries,
    });

    let env = crate::envelope::Envelope::unsigned(payload);

    Ok((StatusCode::OK, Json(env)))
}

// ========================================================================
// #98/#156: `commit_count - 1` must never silently wrap
// ========================================================================

/// White-box coverage for #98/#156: three sites in this file compute a
/// receipt/response `sequence` as `t.commit_count - 1` on a plain `u64`,
/// with no check. Issue #98's own text: "It's safe today ... the safety
/// rests on that invariant holding at every call site indefinitely, with
/// no compiler or runtime signal if a future change ... ever violated
/// it." Issue #156 confirms the invariant is genuinely unreachable via
/// the ordinary commit-ingestion path today (a `TipState` is only ever
/// recorded after indexing at least one commit -- `MemoryIndexer`'s own
/// `commit_count` is a freshly-computed chain length, never a caller
/// -supplied value), so this suite exercises the vulnerable call sites
/// directly with a hand-constructed [`TipState`] rather than via HTTP --
/// the same white-box pattern `sync.rs`'s own
/// `resulting_tip_matches_report_accepts_legitimate_empty_commit_root`
/// test already uses.
///
/// Only `sign_tip_attestation` (this file's :272, shared by `/tip` and
/// `/patch`) is independently callable this way; `push`'s own two sites
/// (:521 payload, :557 receipt) fetch their `TipState` from the live,
/// concretely-typed `FjallIndexer`-backed engine inline and cannot be fed
/// a corrupted value without either refactoring production code (out of
/// this role's scope) or a storage-layer corruption this crate's test
/// surface has no API to perform -- see
/// `no_unchecked_commit_count_arithmetic_remains_in_routes` below, which
/// covers all three sites structurally instead.
#[cfg(test)]
mod commit_count_underflow_tests {
    use std::path::Path;
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
        let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
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
    async fn push_test_genesis(state: &AppState, principal_id: &str, now: i64) {
        let golden_kp = coz::Alg::Ed25519.generate_keypair();
        let golden_tmb = golden_kp
            .alg
            .compute_thumbprint(&golden_kp.pub_bytes)
            .expect("golden thumbprint");
        let golden_key = cyphr::Key {
            alg: golden_kp.alg.name().to_string(),
            tmb: golden_tmb.clone(),
            pub_key: golden_kp.pub_bytes.clone(),
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: None,
        };

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
        let czd = coz::czd_for_alg(&cad, &sig_bytes, golden_kp.alg.name()).expect("czd for Ed25519");

        let new_key = cyphr::Key {
            alg: new_kp.alg.name().to_string(),
            tmb: new_tmb,
            pub_key: new_kp.pub_bytes.clone(),
            first_seen: now,
            last_used: None,
            revocation: None,
            tag: None,
        };

        let mut principal =
            cyphr::Principal::implicit(golden_key.clone()).expect("implicit genesis");
        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_key))
            .expect("key/create verifies against the starting principal state");
        scope
            .finalize_with_arrow(
                golden_kp.alg.name(),
                &golden_kp.prv_bytes,
                &golden_kp.pub_bytes,
                &golden_tmb,
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
                "alg": golden_key.alg,
                "pub": Base64UrlUnpadded::encode_string(&golden_key.pub_key),
                "tmb": golden_tmb_b64,
            }),
        );
        let closing_blob = serde_json::to_vec(&closing).unwrap();

        let mut all_blobs = blobs;
        let last = all_blobs.len() - 1;
        all_blobs[last] = closing_blob;

        let blob_refs: Vec<&[u8]> = all_blobs.iter().map(Vec::as_slice).collect();
        state
            .engine
            .submit_commit(principal_id, None, &blob_refs)
            .await
            .expect("genesis push succeeds");
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
        let principal_id = Base64UrlUnpadded::encode_string(&[0x61u8; 32]);
        push_test_genesis(&state, &principal_id, 1_700_200_000).await;

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
    /// Mutation this binds: today's bare `t.commit_count - 1` at :272.
    /// Once fixed with a checked computation, this test passes either
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
        let principal_id = Base64UrlUnpadded::encode_string(&[0x62u8; 32]);
        push_test_genesis(&state, &principal_id, 1_700_200_100).await;

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
        let outcome = tokio::spawn(async move {
            sign_tip_attestation(&state_for_task, &corrupted).await
        })
        .await;

        match outcome {
            Err(join_err) => panic!(
                "commit_count == 0 must not panic (a debug-mode u64 underflow trap): {join_err}"
            ),
            Ok(Ok(Some(coz))) => {
                let sequence = coz.pay["sequence"].clone();
                panic!(
                    "commit_count == 0 must never produce a signed receipt at all (a typed \
                     absence is required, not a value) -- got a signed sequence claim: \
                     {sequence}"
                );
            },
            Ok(Ok(None)) | Ok(Err(_)) => {
                // Acceptable: refused to sign, one way or the other -- the
                // exact representation is this node's delegated call.
            },
        }
    }

    /// Structural companion to the behavioral test above: this file's
    /// three call sites (`sign_tip_attestation`'s :272, `push`'s payload
    /// :521, `push`'s receipt :557) must ALL move off the bare
    /// `commit_count - 1` expression, not just the one the test above can
    /// reach behaviorally (`c-no-wrap`).
    ///
    /// Scoped to code lines only -- the doc comment on
    /// `PushResponse::sequence` that describes the relationship in prose
    /// is not arithmetic and is not this constraint's target. Scoped to
    /// THIS file only -- `sync.rs:479`'s own `commit_count - 1` is already
    /// guarded by an explicit `tip.commit_count == 0 ||` short-circuit
    /// before it runs (the "codebase already contains the correct pattern
    /// once" the IBC cites), a different file, and out of this check's
    /// scope by construction; a whole-crate literal-text grep would flag
    /// it too despite it already being safe.
    #[test]
    fn no_unchecked_commit_count_arithmetic_remains_in_routes() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes.rs");
        let src = std::fs::read_to_string(&path).expect("read routes.rs");
        // Scan only the PRODUCTION portion of the file, up to this test
        // module's own opening line -- this test module's source text
        // necessarily quotes the literal pattern it is checking for (in
        // doc comments, filter closures, and the assertion message
        // itself), which would otherwise self-match.
        let module_marker = "mod commit_count_underflow_tests {";
        let production_src = src
            .split_once(module_marker)
            .map(|(before, _)| before)
            .unwrap_or(&src);
        let offenders: Vec<(usize, &str)> = production_src
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .filter(|(_, line)| line.contains("commit_count - 1"))
            .map(|(i, line)| (i + 1, line))
            .collect();
        assert!(
            offenders.is_empty(),
            "unchecked `commit_count - 1` arithmetic remains in routes.rs (c-no-wrap): \
             {offenders:?}"
        );
    }
}
