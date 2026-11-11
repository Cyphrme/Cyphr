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

/// Query parameters for `GET /revoked`.
#[derive(Debug, Deserialize)]
pub struct RevokedQuery {
    /// Comma-separated base64url thumbprints.
    pub tmbs: String,
}

/// Response for `GET /revoked`.
#[derive(Debug, Serialize)]
pub struct RevokedResponse {
    /// The self-signed revoke envelope (`{pay, sig, key}`) of each asked
    /// key this server holds one for; keys it holds none for are absent.
    pub revoked: Vec<serde_json::Value>,
}

/// Most keys one `GET /revoked` may name.
const MAX_REVOKED_ASKS: usize = 128;

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

/// Request body for `POST /push`: the principal and one bundle in the
/// SPEC 4.6.2 wire form, `{principal_id, txs, keys, actions}`.
///
/// `txs` holds the commit's transactions, each an array of `{pay, sig}`
/// coz envelopes (base64url strings for JSON transport), the commit
/// transaction last; `keys` the public keys its key-introducing cozies
/// name; `actions` data actions recorded before the transactions. A bundle
/// of `actions` alone records them and forms no commit.
#[derive(Debug, Serialize, Deserialize)]
pub struct PushRequest {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// The session's bearer token, for a request that cannot carry an
    /// `Authorization` header (the Noise transport has none). A header, if
    /// both are present, wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The bundle.
    #[serde(flatten)]
    pub bundle: cyphr::replay::WireBundle,
}

// ========================================================================
// Response types
// ========================================================================

/// Response for `GET /tip`.
#[derive(Debug, Serialize)]
pub struct TipResponse {
    pub principal_id: String,
    pub pr: String,
    /// `null` for a Dead principal that holds no data.
    pub sr: Option<String>,
    /// `null` for a Dead principal.
    pub ar: Option<String>,
    /// Current Commit Root (empty string if no commit has populated the
    /// EML log yet). `docs/specs/http-envelope.md` `[envelope-r-cr]`.
    pub cr: String,
    pub commit_id: String,
    pub commit_count: u64,
    pub last_updated: i64,
    pub now: i64,
}

/// Response for `GET /branches`.
#[derive(Debug, Serialize)]
pub struct BranchesResponse {
    pub branches: Vec<cyphr_storage::engine::BranchTip>,
}

/// Response for `GET /evidence`.
#[derive(Debug, Serialize)]
pub struct EvidenceResponse {
    pub items: Vec<serde_json::Value>,
}

/// A single commit entry in a patch response: its metadata and its bundle
/// in the push wire form (`txs`, `keys`, `actions`).
#[derive(Debug, Serialize)]
pub struct PatchEntryResponse {
    pub commit_id: String,
    pub sequence: u64,
    pub pr: String,
    /// The commit's bundle, grouped by transaction as accepted.
    #[serde(flatten)]
    pub bundle: cyphr::replay::WireBundle,
}

/// Response for `GET /patch`.
#[derive(Debug, Serialize)]
pub struct PatchResponseBody {
    pub principal_id: String,
    pub entries: Vec<PatchEntryResponse>,
    /// Action-only bundles (SPEC 4.8.1), each preceding the commit at
    /// `after`; a `ds/create` includes exactly the actions before it.
    pub actions: Vec<PatchActionsResponse>,
}

/// One action-only bundle in a patch response.
#[derive(Debug, Serialize)]
pub struct PatchActionsResponse {
    pub after: u64,
    /// Raw coz blobs as base64url strings.
    pub blobs: Vec<String>,
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
    pub sr: Option<String>,
    pub ar: Option<String>,
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

/// `GET /branches?pr=<PG>` -- every branch head the store holds for the
/// principal: its canonical tip and each retained rival, a commit that
/// verified at its `pre` but took a position the chain already held.
///
/// A fork is evidence the store keeps, never a state it merges (I2): the
/// push that produced a rival was refused (409), and `/tip` still reports
/// the canonical chain alone. Exactly one entry is `canonical`.
#[tracing::instrument(skip(state))]
pub async fn branches(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    witness_sync(&state, &query.pr).await;

    let branches = state
        .engine
        .list_branches(&query.pr)
        .await
        .map_err(AppError::engine)?;
    Ok(Json(Envelope::unsigned(BranchesResponse { branches })))
}

/// `GET /evidence?pr=<PG>` -- every principal fork the store holds
/// evidence of, each item self-describing and checkable offline.
///
/// An item is `{kind: "principal-fork", pg, height, pre, a, b}`: two
/// distinct commits (`a`, `b`, each a bundle in the push wire form) that both
/// verify against the principal's state at `pre`, the Principal Root after
/// commit `height - 1` (`null` at height 0). One of the two is the
/// canonical commit at `height`. A verifier replays the principal's chain
/// to `height`, checks its root is `pre`, and replays each commit from
/// there (`cyphr_client::evidence`); no server signature takes part, so
/// nothing here asks to be believed (arch-evidence-is-portable).
///
/// Only forks of principals are served: the server keeps no peer
/// equivocation evidence, which a client assembles from signed statements
/// it collected itself. A principal never forked answers an empty list.
#[tracing::instrument(skip(state))]
pub async fn evidence(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    // A malformed id is the caller's error (400), not an unknown principal
    // (404): the harness probes for this route with an id that is not one.
    if query.pr.parse::<cyphr::state::TaggedDigest>().is_err()
        && receipt::parse_genesis_id_str(&query.pr).is_err()
    {
        return Err(AppError::bad_request(format!(
            "pr is not a principal identifier: {}",
            query.pr
        )));
    }
    witness_sync(&state, &query.pr).await;

    let (principal, forks) = state
        .engine
        .fork_evidence(&query.pr)
        .await
        .map_err(AppError::engine)?;
    let pg = cyphr_storage::engine::bare_digest(&principal).to_string();
    let items = forks
        .iter()
        .map(|f| {
            serde_json::json!({
                "kind": "principal-fork",
                "pg": pg,
                "height": f.sequence,
                "pre": f.pre,
                "a": f.canonical,
                "b": f.rival,
            })
        })
        .collect();
    Ok(Json(Envelope::unsigned(EvidenceResponse { items })))
}

/// `GET /revoked?tmbs=<tmb>,<tmb>...` -- the naked revokes this peer holds
/// for the named keys (SPEC 6.4).
///
/// A naked revoke mutates no chain, so a verifier that replays commits can
/// never learn of one from `/patch`; it asks here, for the keys its own
/// record holds. Each answer is the stored self-signed envelope, which the
/// reader re-verifies (`cyphr_client::verify_naked_revoke`): the peer is a
/// mirror of the revoke, not its authority.
#[tracing::instrument(skip(state))]
pub async fn revoked(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RevokedQuery>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let asked: Vec<&str> = query.tmbs.split(',').filter(|s| !s.is_empty()).collect();
    if asked.len() > MAX_REVOKED_ASKS {
        return Err(AppError::bad_request(format!(
            "at most {MAX_REVOKED_ASKS} keys per request, got {}",
            asked.len()
        )));
    }
    let mut revoked = Vec::new();
    for raw in asked {
        let bytes = Base64UrlUnpadded::decode_vec(raw)
            .map_err(|_| AppError::bad_request(format!("`{raw}` is not a base64url thumbprint")))?;
        if let Some(envelope) = state
            .observations
            .revoke_of(&coz::Thumbprint::from_bytes(bytes))
            .await
            .map_err(AppError::observation)?
        {
            revoked.push(envelope);
        }
    }
    Ok(Json(Envelope::unsigned(RevokedResponse { revoked })))
}

/// `GET /view?pr=<PG>` -- this peer's signed claim "I hold `pr` at this
/// tree size and index" (GOSSIP.md section 3), the self-claim a client
/// verifies against the peer's chain
/// ([`cyphr_client::verify_view_statement`]).
///
/// Shares `/tip`'s attestation path: same re-derived roots, same
/// desynchronization guard, same degrade-to-unsigned on a signer failure.
/// The payload is the tip, so an unsigned answer is still a usable read.
#[tracing::instrument(skip(state))]
pub async fn view(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TipQuery>,
) -> Result<impl IntoResponse, AppError> {
    witness_sync(&state, &query.pr).await;

    let t = state
        .engine
        .get_tip(&query.pr)
        .await
        .map_err(AppError::engine)?
        .ok_or_else(|| AppError::not_found(format!("principal {} not found", query.pr)))?;

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

    let Some(signer) = state.attestor_signer() else {
        return Ok(Json(Envelope::unsigned(payload)));
    };
    let roots = attested_roots(&state, &t).await?;
    match receipt::view_statement(
        signer.as_ref(),
        crate::auth::server_now(),
        cyphr_storage::engine::bare_digest(&t.principal_id).to_string(),
        t.commit_count,
        t.commit_id.clone(),
        &roots,
    )
    .await
    {
        Ok(coz) => Ok(Json(Envelope::signed(payload, coz))),
        Err(reason) => {
            tracing::warn!(
                principal = %t.principal_id,
                %reason,
                "view statement could not be signed; answering unsigned"
            );
            Ok(Json(Envelope::unsigned(payload)))
        },
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

/// The roots re-derived from the blob store for tip `t`, memoized per
/// (principal, commit id): the replay is a pure function of the chain up to
/// that commit, so a hit is exact and the next commit misses by construction.
/// The caller still compares the result against the index's roots, so a
/// diverging index is caught on every request, cached or not.
async fn derived_roots(
    state: &Arc<AppState>,
    t: &TipState,
) -> Result<cyphr_storage::engine::DerivedRoots, AppError> {
    let key = (t.principal_id.clone(), t.commit_id.clone());
    if let Some(hit) = state.derived_roots.get(&key) {
        return Ok(hit);
    }
    // The server's own principal has an explicit genesis, which its blobs
    // cannot express, so its genesis is supplied rather than read back.
    let own = state
        .principal
        .as_ref()
        .filter(|p| p.pg() == t.principal_id);
    let derived = match own {
        Some(p) => {
            state
                .engine
                .rederive_roots_with_genesis(
                    &t.principal_id,
                    cyphr_storage::Genesis::Explicit(vec![p.genesis_key().clone()]),
                )
                .await
        },
        None => state.engine.rederive_roots(&t.principal_id).await,
    }
    .map_err(|e| AppError::internal(format!("attestation root re-derivation failed: {e}")))?;
    state.derived_roots.insert(key, derived.clone());
    Ok(derived)
}

/// The roots every attestation of tip `t` signs: re-derived from the blob
/// store and required to agree with the index, so no statement attests a
/// state the chain does not hold.
async fn attested_roots(state: &Arc<AppState>, t: &TipState) -> Result<receipt::Roots, AppError> {
    let derived = derived_roots(state, t).await?;

    if derived.pr != t.pr || derived.sr != t.sr || derived.ar != t.ar || derived.cr != t.cr {
        return Err(AppError::internal(
            "attestation root desynchronized with index",
        ));
    }

    Ok(receipt::Roots {
        pr: derived.pr,
        sr: derived.sr,
        ar: derived.ar,
        // Storage's own re-derivation still reports "no commit root yet"
        // as an empty string (cyphr-storage, out of this node's surface)
        // -- this is the boundary where that sentinel becomes the
        // receipt's typed absence (#147).
        cr: (!derived.cr.is_empty()).then_some(derived.cr),
    })
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
    let Some(signer) = state.attestor_signer() else {
        return Ok(None);
    };

    let roots = attested_roots(state, t).await?;
    let sequence = commit_sequence(t.commit_count)?;
    // The tip is true whether or not the server could attest it: a signer
    // that cannot sign degrades the answer to unsigned, with the typed
    // reason in the log (it is not a wire field -- an unsigned statement
    // is unauthenticated, so a client cannot act on a reason it carries).
    match receipt::tip_report(
        signer.as_ref(),
        crate::auth::server_now(),
        cyphr_storage::engine::bare_digest(&t.principal_id).to_string(),
        sequence,
        t.commit_id.clone(),
        &roots,
        t.commit_count,
        t.last_updated,
    )
    .await
    {
        Ok(coz) => Ok(Some(coz)),
        Err(reason) => {
            tracing::warn!(
                principal = %t.principal_id,
                %reason,
                "tip attestation could not be signed; answering unsigned"
            );
            Ok(None)
        },
    }
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
            bundle: entry.bundle,
        })
        .collect();

    let actions = response
        .actions
        .into_iter()
        .map(|a| PatchActionsResponse {
            after: a.after,
            blobs: a
                .blobs
                .iter()
                .map(|b| Base64UrlUnpadded::encode_string(b))
                .collect(),
        })
        .collect();

    let payload = PatchResponseBody {
        principal_id: cyphr_storage::engine::bare_digest(&response.principal_id).to_string(),
        entries,
        actions,
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
    skip(state, headers, peer, request),
    fields(
        principal_id = %request.principal_id,
        blob_count = request.bundle.cozies().count()
    )
)]
pub async fn push(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<axum::Extension<crate::transport::AuthenticatedPeer>>,
    AppJson(request): AppJson<PushRequest>,
) -> Result<impl IntoResponse, AppError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    if request.bundle.is_empty() {
        return Err(AppError::bad_request("empty commit bundle"));
    }

    crate::auth::middleware::check_push_admission(
        // A header wins over the body's token (the Noise transport has no
        // headers).
        crate::auth::middleware::bearer_token(&headers).or(request.token.as_deref()),
        state.identity.as_deref(),
        &state.engine,
        &state.observations,
        &request.principal_id,
        crate::auth::server_now(),
        peer.as_ref().map(|p| p.0.handshake_hash.as_slice()),
    )
    .await?;

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
    for raw in request.bundle.cozies() {
        let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(raw) else {
            continue;
        };
        // SPEC §6.4: a dead key is not re-added to any principal either.
        if state
            .observations
            .introduces_dead_key(&parsed)
            .await
            .map_err(AppError::observation)?
        {
            return Err(AppError::forbidden("push introduces a revoked key"));
        }
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
        .submit_commit(&request.principal_id, None, &request.bundle)
        .await
        .map_err(AppError::engine)?;

    let tip = result.tip.as_ref().ok_or_else(|| {
        AppError::bad_request("bundle formed no commit and the principal has no committed state")
    })?;
    let signer = state.attestor_signer();
    let (envelope, receipt_unavailable) =
        push_response(&result, tip, crate::auth::server_now(), signer.as_deref()).await;
    if let Some(reason) = receipt_unavailable {
        tracing::error!(
            principal = %result.principal_id,
            %reason,
            "commit is durable but its receipt could not be signed; answering unsigned"
        );
    }
    Ok((StatusCode::CREATED, Json(envelope)))
}

/// Build the `201` body from data already in hand after the commit: the
/// tip the engine computed while ingesting. Nothing here re-reads the index
/// or re-derives roots (the ingest replay is the authority; an index that
/// disagrees is a reindex concern, not a push response).
async fn push_response(
    result: &cyphr_storage::engine::IngestResult,
    tip: &cyphr_storage::engine::CommittedTip,
    now: i64,
    signer: Option<&dyn receipt::ReceiptSigner>,
) -> (Envelope<PushResponse>, Option<receipt::ReceiptError>) {
    let payload = PushResponse {
        blob_hashes: result.blob_hashes.iter().map(|h| h.to_string()).collect(),
        commit_id: tip.commit_id.clone(),
        sequence: tip.sequence,
        roots: PushRoots {
            pr: tip.pr.clone(),
            sr: tip.sr.clone(),
            ar: tip.ar.clone(),
            cr: tip.cr.clone(),
        },
    };
    let Some(signer) = signer else {
        return (Envelope::unsigned(payload), None);
    };
    let roots = receipt::Roots {
        pr: tip.pr.clone(),
        sr: tip.sr.clone(),
        ar: tip.ar.clone(),
        cr: (!tip.cr.is_empty()).then(|| tip.cr.clone()),
    };
    // The commit is durable: a receipt that cannot be signed degrades the
    // envelope to unsigned, it does not turn the answer into an error.
    match receipt::commit_receipt(
        signer,
        now,
        cyphr_storage::engine::bare_digest(&result.principal_id).to_string(),
        tip.sequence,
        tip.commit_id.clone(),
        &roots,
    )
    .await
    {
        Ok(coz) => (Envelope::signed(payload, coz), None),
        Err(reason) => (Envelope::unsigned(payload), Some(reason)),
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
    use cyphr_storage::index::Indexer;

    let verified = crate::revoke::interpret(&envelope).await?;

    // Store the full `{pay, sig, key}` envelope: self-contained evidence any
    // later reader can re-verify with no index. Once the death set is at its
    // ceiling, only a key some stored principal holds is still recorded: the
    // ceiling bounds junk revokes of keys nobody here holds, and must never
    // deny the emergency revoke of a held key (SPEC 6.4). The index is read
    // for presence only, never content.
    match state
        .observations
        .record(&verified.revoked_tmb, verified.evidence.clone())
        .await
    {
        Ok(()) => {},
        Err(full @ crate::observation::ObservationError::Full { .. }) => {
            let tmb_b64 = Base64UrlUnpadded::encode_string(verified.revoked_tmb.as_bytes());
            let held = state
                .engine
                .indexer()
                .get_key(&tmb_b64)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "naked-revoke presence lookup failed");
                    AppError::internal("key index lookup failed")
                })?
                .is_some();
            if !held {
                return Err(AppError::observation(full));
            }
            state
                .observations
                .record_seen(&verified.revoked_tmb, verified.evidence)
                .await
                .map_err(AppError::observation)?;
        },
        Err(e) => return Err(AppError::observation(e)),
    }

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
///
/// A digest may name several holders (SPEC 7.6 lets principals that share
/// keys reuse a coz). A czd or blob-hash digest still names one blob: the
/// store keeps a coz's unsigned `key` member only on key-introducing cozes,
/// so every holder shares one canonical blob. A state or auth root digest
/// can differ between holders; the first holder in canonical order is
/// served. SR and AR are root digests, not hashes of the served bytes: a
/// client verifies them by verifying the commit that contains them. The response is not
/// authenticated by the server: clients verify what they fetch. The bytes are signed, so that is
/// always possible.
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
        // not the server's own chain, so it goes through the same
        // blob-only genesis read (`submit_commit` with no `Genesis`) a
        // real client request does.
        let sp =
            ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
                .await
                .expect("bootstrap the server principal");
        state.principal = Some(Arc::new(sp));

        (Arc::new(state), dir)
    }

    /// Push a minimal, data-free genesis commit for a fresh principal
    /// through the engine directly -- a genesis key that creates itself and
    /// one further key, then signs the `principal/create` and
    /// `commit/create` (SPEC 5.1), every `key/create` disclosing its key
    /// so `submit_commit` reads the genesis from the blobs alone. Mirrors
    /// `tests/common/mod.rs::build_genesis_push_body`'s wire shape,
    /// duplicated here (with freshly generated keypairs rather than the
    /// shared `test_fixtures` pool) because that helper lives in the
    /// separate integration-test crate this unit-test module cannot depend
    /// on.
    ///
    /// Returns the principal id the genesis derives (its PG, SPEC 5.1), the
    /// only id the engine accepts for this commit.
    async fn push_test_genesis(state: &AppState, now: i64) -> String {
        push_test_genesis_ingest(state, now).await.0
    }

    /// [`push_test_genesis`], also returning the engine's ingest result.
    async fn push_test_genesis_ingest(
        state: &AppState,
        now: i64,
    ) -> (String, cyphr_storage::engine::IngestResult) {
        let key_of = |kp: &coz::KeyPair| {
            let tmb = kp
                .alg
                .compute_thumbprint(&kp.pub_bytes)
                .expect("thumbprint");
            let key = cyphr::Key::new(kp.alg.name().to_string(), tmb.clone(), kp.pub_bytes.clone())
                .expect("key binds its tmb");
            (key, tmb)
        };
        let golden_kp = coz::Alg::Ed25519.generate_keypair();
        let (golden_key, golden_tmb) = key_of(&golden_kp);
        let (new_key, _) = key_of(&coz::Alg::Ed25519.generate_keypair());

        let mut principal = cyphr::Principal::implicit(golden_key)
            .await
            .expect("genesis");
        principal
            .commit_genesis(
                &cyphr::signer::SoftwareSigner::new(
                    golden_kp.alg.name(),
                    &golden_kp.prv_bytes,
                    &golden_kp.pub_bytes,
                    &golden_tmb,
                ),
                &[new_key],
                now,
                "cyphr.me",
            )
            .await
            .expect("genesis commits");
        let bundle = test_fixtures::bundle::last_commit_bundle(&principal).expect("bundle");
        let principal_id = test_fixtures::bundle::genesis_id(&bundle).expect("genesis PG");

        let ingest = state
            .engine
            .submit_commit(&principal_id, None, &bundle)
            .await
            .expect("genesis push succeeds");
        (principal_id, ingest)
    }

    /// Claim: the tip `submit_commit` returns is exactly the tip the index
    /// then serves, so a push answer built from it cannot disagree with
    /// `GET /tip`. Red if ingest and the indexer pick different digest
    /// variants, or the sequence is off by one.
    #[tokio::test]
    async fn push_response_tip_equals_the_indexed_tip() {
        let (state, _dir) = attestor_state().await;
        let (principal_id, ingest) = push_test_genesis_ingest(&state, 1_700_200_200).await;
        let committed = ingest.tip.expect("a commit forms a tip");
        let indexed = state
            .engine
            .get_tip(&principal_id)
            .await
            .expect("get_tip")
            .expect("indexed");
        assert_eq!(committed.sequence, indexed.commit_count - 1);
        assert_eq!(committed.commit_id, indexed.commit_id);
        assert_eq!(
            (committed.pr, committed.sr, committed.ar, committed.cr),
            (indexed.pr, indexed.sr, indexed.ar, indexed.cr)
        );
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

// ========================================================================
// A committed push is always reported as committed
// ========================================================================

/// Claim: once a commit is durable, the push answer is `201` carrying that
/// commit's tip -- a receipt that cannot be signed degrades to an unsigned
/// envelope, never to an error. Red if `push_response` fails (the route
/// would answer 500 for a write that landed).
///
/// Pure-function tests, because no fault reachable over HTTP lands after a
/// durable commit (see `tests/peer_bounds.rs`). The failure is injected
/// through `receipt::commit_receipt`'s own refusal of a value that is not a
/// digest. A failing signer is covered end to end in
/// `tests/receipt_signer.rs`.
#[cfg(test)]
mod push_response_tests {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr_storage::engine::{CommittedTip, IngestResult};

    use super::*;
    use crate::envelope::Statement;

    fn digest(fill: u8) -> String {
        format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[fill; 32]))
    }

    fn identity() -> (crate::auth::ServerIdentity, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let kp = coz::Alg::Ed25519.generate_keypair();
        let path = dir.path().join("key.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "alg": kp.alg.name(),
                "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
                "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
            }))
            .unwrap(),
        )
        .unwrap();
        (
            crate::auth::ServerIdentity::load_from_path(&path).expect("load key"),
            dir,
        )
    }

    fn committed(commit_id: String) -> (IngestResult, CommittedTip) {
        let tip = CommittedTip {
            sequence: 4,
            commit_id,
            pr: digest(1),
            sr: Some(digest(2)),
            ar: Some(digest(3)),
            cr: digest(4),
        };
        let result = IngestResult {
            principal_id: digest(9),
            blob_hashes: Vec::new(),
            manifest_hash: None,
            tip: Some(tip.clone()),
        };
        (result, tip)
    }

    /// Backs: a receipt-signing failure never turns a committed push into an error; the commit is
    /// reported unsigned. Unit: a non-digest `commit_id` is unreachable through real ingest.
    #[tokio::test]
    async fn push_response_receipt_failure_is_still_a_committed_answer() {
        let (identity, _dir) = identity();
        // Not a digest: `commit_receipt` refuses to sign it.
        let (result, tip) = committed("not-a-digest".to_string());
        let (env, unavailable) = push_response(
            &result,
            &tip,
            1_700_000_000,
            Some(&identity as &dyn receipt::ReceiptSigner),
        )
        .await;
        assert!(matches!(
            unavailable,
            Some(receipt::ReceiptError::Field { .. })
        ));
        assert!(matches!(env.statement, Statement::Unsigned));
        assert_eq!(env.payload.sequence, 4, "the commit is still reported");
        assert_eq!(env.payload.commit_id, "not-a-digest");
    }
}

// ========================================================================
// Operability
// ========================================================================

/// `GET /healthz` -- can this peer serve? Unauthenticated; the body names
/// no principal, path, or error text (causes go to the log, not the wire).
pub async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.health.storage_writable().await {
        (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "unavailable",
                "error": "storage unavailable",
            })),
        )
    }
}

/// `GET /metrics` -- Prometheus text exposition of the request, refusal and
/// accepted-push counters.
pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
}
