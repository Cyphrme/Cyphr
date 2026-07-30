//! Witness mode state synchronization client (`docs/specs/witness-mode.md`).
//!
//! Fetches state deltas (`GET /patch`) from a configured upstream authority
//! node, validates every commit signature and root in memory using storage
//! engine rules before persisting, and rejects unverified deltas without
//! partial application.
//!
//! When [`crate::config::ServerConfig::authority_identity`] is configured,
//! the channel is additionally authenticated (K10): the response's signed
//! statement must verify against that identity AND its claims must bind the
//! entries actually received (entry-commitment), not merely carry a valid
//! signature over an unrelated `pay` -- see [`verify_authenticated_envelope`].
//! Without it, sync runs the legacy unauthenticated path unchanged.

use std::sync::Arc;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use tracing::{error, warn};

use crate::AppState;
use crate::config::AuthorityIdentity;
use crate::envelope::Statement;
use crate::receipt::{self, TipReport};

/// The result of one [`sync_from_authority`] attempt.
///
/// `#[must_use]`: the type this replaces (`Result<(), AppError>`) returned
/// `Ok(())` on every failure path and both call sites discarded it with
/// `let _ =`, so a stalled or attacked sync was silently invisible. A
/// caller MUST destructure every arm.
#[derive(Debug)]
#[must_use = "a discarded sync outcome hides upstream and verification failures silently"]
pub enum SyncOutcome {
    /// At least one entry was applied to local storage.
    Synced { applied: usize },
    /// Not in witness mode, no authority configured, or the authority had
    /// nothing new to serve.
    UpToDate,
    /// The sync attempt failed. Local storage is untouched -- every failure
    /// path fails closed, never a partial apply.
    Failed { reason: SyncFailure },
}

/// Why a [`SyncOutcome::Failed`] happened.
#[derive(Debug)]
pub enum SyncFailure {
    /// The witness's own local tip lookup failed before any network call.
    LocalStorageError(String),
    /// The upstream authority could not be reached (network/transport
    /// error).
    UpstreamUnreachable(String),
    /// The upstream authority answered with a non-success HTTP status.
    UpstreamNonSuccess(u16),
    /// The response body did not decode as the expected patch JSON shape.
    MalformedResponse(String),
    /// An expected authority identity is configured (K10), but the response
    /// carried no signed statement, or its signature does not verify
    /// against that identity.
    EnvelopeUnsignedOrMisSigned,
    /// The response carried a validly-signed statement, but it does not
    /// canonicalize via [`TipReport::parse`] -- a report the ingestion gate
    /// refuses to act on. This closes the cross-node equivocation-evasion
    /// path: a typed comparison of an unparseable report reads as "no
    /// claim," so a malformed report must never become a retained
    /// attestation in the first place.
    MalformedReport,
    /// The signed report's `(sequence, commit_id)` does not match the
    /// highest-sequence entry actually received -- an on-path party altered
    /// what was served after signing (e.g. truncation). The signature alone
    /// proves the report is genuine; this proves the entries are what the
    /// report attests to.
    EntryCommitmentMismatch,
    /// Every entry in a non-empty response was individually rejected
    /// (decode or verification failure); nothing applied.
    RejectedEntry,
}

/// Sync state for `principal_id` from upstream authority URL if in Witness
/// mode.
pub async fn sync_from_authority(state: &Arc<AppState>, principal_id: &str) -> SyncOutcome {
    if state.config.mode != crate::config::ServerMode::Witness {
        return SyncOutcome::UpToDate;
    }

    let Some(authority_url) = &state.config.authority_url else {
        return SyncOutcome::UpToDate;
    };

    let principal_lock = {
        let mut map = state.sync_locks.lock().await;
        map.entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = principal_lock.lock().await;

    let base_url = authority_url.trim_end_matches('/');

    let from_seq = match state.engine.get_tip(principal_id).await {
        Ok(tip) => tip.map(|t| t.commit_count).unwrap_or(0),
        Err(err) => {
            error!(
                principal = %principal_id,
                error = %err,
                "witness sync: local tip lookup failed"
            );
            return SyncOutcome::Failed {
                reason: SyncFailure::LocalStorageError(err.to_string()),
            };
        },
    };

    let patch_url = format!("{base_url}/patch?pr={principal_id}&from={from_seq}");

    let res = match state
        .http_client
        .get(&patch_url)
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!(
                principal = %principal_id,
                error = %err,
                "witness sync HTTP request failed"
            );
            return SyncOutcome::Failed {
                reason: SyncFailure::UpstreamUnreachable(err.to_string()),
            };
        },
    };

    if !res.status().is_success() {
        let status = res.status();
        warn!(
            principal = %principal_id,
            %status,
            "witness sync upstream non-success status"
        );
        return SyncOutcome::Failed {
            reason: SyncFailure::UpstreamNonSuccess(status.as_u16()),
        };
    }

    let body: Value = match res.json().await {
        Ok(v) => v,
        Err(err) => {
            warn!(
                principal = %principal_id,
                error = %err,
                "witness sync payload decode failed"
            );
            return SyncOutcome::Failed {
                reason: SyncFailure::MalformedResponse(err.to_string()),
            };
        },
    };

    let entries = match body
        .get("payload")
        .and_then(|p| p.get("entries"))
        .and_then(|e| e.as_array())
    {
        Some(e) => e,
        None => {
            warn!(principal = %principal_id, "witness sync payload missing entries array");
            return SyncOutcome::Failed {
                reason: SyncFailure::MalformedResponse(
                    "payload.entries missing or not an array".to_string(),
                ),
            };
        },
    };

    // Authenticated channel (K10). When the witness knows the expected
    // authority identity, the signature AND the entry-binding are checked
    // here, strictly before the per-entry apply loop below -- a mismatch
    // must leave local storage completely untouched (fail closed), and the
    // only way to guarantee that with no undo path is to gate before the
    // first `submit_commit`, not after.
    if let Some(expected) = &state.config.authority_identity {
        if let Err(reason) = verify_authenticated_envelope(&body, entries, expected) {
            warn!(
                principal = %principal_id,
                ?reason,
                "witness sync authenticated-channel check failed"
            );
            return SyncOutcome::Failed { reason };
        }
    }

    let mut applied = 0usize;
    for entry in entries {
        let seq = entry.get("sequence").and_then(|s| s.as_u64()).unwrap_or(0);
        if seq < from_seq {
            continue;
        }

        let blob_strs = match entry.get("blobs").and_then(|b| b.as_array()) {
            Some(b) => b,
            None => {
                warn!(principal_id = %principal_id, "patch entry carries no blobs array; skipping");
                continue;
            },
        };

        let mut raw_blobs = Vec::with_capacity(blob_strs.len());
        let mut decode_error = false;
        for b_val in blob_strs {
            let Some(b_str) = b_val.as_str() else {
                decode_error = true;
                break;
            };
            let Ok(decoded) = Base64UrlUnpadded::decode_vec(b_str) else {
                decode_error = true;
                break;
            };
            raw_blobs.push(decoded);
        }

        if decode_error || raw_blobs.is_empty() {
            // Wedge fix, site 1 (decode failure): a malformed entry must
            // never make a later, genuine entry unreachable -- skip and
            // record, don't abort the whole sync. `from_seq` is
            // recomputed fresh from local state on every call with no
            // persisted progress marker, so aborting here would refetch
            // and re-abort on this same entry forever.
            warn!(principal_id = %principal_id, "patch entry blob decode failed; skipping");
            continue;
        }

        let blob_refs: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

        // Submit commit to storage engine which verifies commit signatures & roots in memory
        // before persisting. If validation fails, skip this entry and continue: an
        // unverifiable entry (wedge fix, site 2) must not block a later genuine one, for
        // the identical reason as the decode failure above.
        if let Err(err) = state
            .engine
            .submit_commit(principal_id, None, &blob_refs)
            .await
        {
            warn!(
                principal_id = %principal_id,
                error = %err,
                "witness node rejected unverifiable delta from authority; skipping"
            );
            continue;
        }

        applied += 1;
    }

    if entries.is_empty() {
        SyncOutcome::UpToDate
    } else if applied > 0 {
        SyncOutcome::Synced { applied }
    } else {
        SyncOutcome::Failed {
            reason: SyncFailure::RejectedEntry,
        }
    }
}

/// Verify the authenticated channel (K10) for one `/patch` response: the
/// statement must be a signature by `expected`, it must canonicalize via
/// [`TipReport::parse`], and its claimed `(sequence, commit_id)` must match
/// the highest-sequence entry actually present in `entries`.
///
/// The last check is the load-bearing correction over "the signature
/// verifies": a signature over `pay` says nothing about a *separate*
/// plaintext `entries` array, so an on-path attacker who truncates
/// `entries` after signing produces a response whose signature still
/// verifies. Binding `(sequence, commit_id)` of the highest-sequence entry
/// closes that gap without needing engine state: a commit's identity is
/// only reachable by genuinely possessing the full chain up to it, so a
/// truncated array's highest surviving entry can never carry the same
/// `(sequence, commit_id)` the authority actually signed for its true
/// final entry.
fn verify_authenticated_envelope(
    body: &Value,
    entries: &[Value],
    expected: &AuthorityIdentity,
) -> Result<(), SyncFailure> {
    let statement: Option<Statement> = body
        .get("statement")
        .and_then(|s| serde_json::from_value(s.clone()).ok());

    let Some(Statement::Signed(coz)) = statement else {
        return Err(SyncFailure::EnvelopeUnsignedOrMisSigned);
    };

    if coz.pay["alg"].as_str() != Some(expected.alg.as_str())
        || !receipt::receipt_signature_verifies(&coz, &expected.pub_key)
    {
        return Err(SyncFailure::EnvelopeUnsignedOrMisSigned);
    }

    let report = TipReport::parse(&coz).map_err(|_| SyncFailure::MalformedReport)?;

    if entries.is_empty() {
        return Ok(());
    }

    // The highest CLAIMED sequence, not merely the last array element: an
    // attacker controlling entry order should not be able to dodge this
    // check by reordering rather than truncating.
    let Some(highest) = entries
        .iter()
        .max_by_key(|e| e.get("sequence").and_then(Value::as_u64).unwrap_or(0))
    else {
        return Ok(());
    };
    let highest_seq = highest.get("sequence").and_then(Value::as_u64).unwrap_or(0);
    let highest_commit_id = highest
        .get("commit_id")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if highest_seq != report.sequence || highest_commit_id != report.commit_id.to_string() {
        return Err(SyncFailure::EntryCommitmentMismatch);
    }

    Ok(())
}
