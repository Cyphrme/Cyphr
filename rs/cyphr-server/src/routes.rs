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
    /// Start sequence (inclusive). Omit for genesis.
    pub from: Option<u64>,
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

    let response = state
        .engine
        .get_patch(&query.pr, query.from, query.to)
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
    // envelope attests the AUTHORITY's current tip, accurate whenever a
    // request is served through to that tip (the `to=None` case every
    // existing caller and test uses). A bounded `to` older than the
    // current tip would make this attestation describe a later state than
    // what was actually served -- `PatchQuery`/the resync anchor are a
    // separate node's surface, so that combination is a known, undecided
    // edge left for that node's owner rather than silently patched over
    // here.
    //
    // Unlike `/tip`, a failure to sign is NOT propagated as a hard error:
    // `/patch`'s entries are independently re-verified by every witness
    // that applies them (`submit_commit`), so an authority whose own
    // re-derived roots momentarily disagree with its index (the same
    // desync guard `/tip` enforces strictly) is safer serving them
    // unsigned than refusing to serve at all.
    let coz = match tip {
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
