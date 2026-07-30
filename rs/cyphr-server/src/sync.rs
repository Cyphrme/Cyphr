//! Witness mode state synchronization client (`docs/specs/witness-mode.md`).
//!
//! Fetches state deltas (`GET /patch`) from a configured upstream authority
//! node, validates every commit signature and root in memory using storage
//! engine rules before persisting, and rejects unverified deltas without
//! partial application.
//!
//! When [`crate::config::ServerConfig::authority_identity`] is configured,
//! the channel is additionally authenticated (K10) in two parts:
//!
//! 1. Before any entry is applied, the response's signed statement must verify against the expected
//!    identity, canonicalize via [`TipReport::parse`], and attest to the SAME principal being
//!    synced -- see [`verify_authenticated_envelope`]. A genuine, validly-signed report for a
//!    *different* principal (an on-path party rewrote only the outbound query) is refused here,
//!    before it ever reaches storage.
//! 2. After the apply loop runs, the witness's own resulting local tip must equal what the signed
//!    report attests -- see [`resulting_tip_matches_report`]. This is the load-bearing check: a
//!    signature over `pay` says nothing about a *separate* plaintext `entries` array, so no
//!    per-entry label comparison against that same array can ever be sound (a decoy entry that
//!    copies its victim's declared `sequence`/`commit_id` passes any such check while carrying junk
//!    `blobs`). Comparing against what the witness's own storage engine independently verified and
//!    produced is not defeatable by altering the wire body, because it never trusts the wire body's
//!    self-consistency in the first place.
//!
//! Without a configured identity, sync runs the legacy unauthenticated path
//! unchanged.

use std::sync::Arc;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::index::types::TipState;
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
    /// At least one entry was applied to local storage. `rejected` counts
    /// entries in the SAME response that were individually skipped (decode
    /// or verification failure) -- a caller that only reads `applied` cannot
    /// tell a clean sync from one where some entries were poisoned, exactly
    /// the signal a future staleness adapter needs.
    Synced { applied: usize, rejected: usize },
    /// Not in witness mode, no authority configured, or the authority had
    /// nothing new to serve.
    UpToDate,
    /// The sync attempt failed. Local storage is untouched by THIS call's
    /// failure path -- a failure detected after the apply loop (the
    /// post-apply reconciliation) may still follow a partial, but fully
    /// chain-verified, apply from entries earlier in the same response; see
    /// [`resulting_tip_matches_report`].
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
    /// The signed report attests a DIFFERENT principal than the one being
    /// synced -- an on-path party rewrote the outbound query's `pr`, and the
    /// authority answered honestly for whichever principal it was actually
    /// asked about. The response is entirely genuine; it simply is not a
    /// claim about this principal. Caught before any entry is applied.
    PrincipalMismatch,
    /// After the apply loop ran, the witness's own resulting local tip does
    /// not equal what the signed report attests -- see
    /// [`resulting_tip_matches_report`]. This is the general withholding
    /// closure: it catches a decoy entry that preserves its victim's
    /// declared labels, a dropped middle or trailing entry, and a wholesale
    /// emptied or request-rewritten response identically, because none of
    /// them change what the witness's own storage engine actually produced.
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

    // Authenticated channel (K10), part 1. When the witness knows the
    // expected authority identity, the signature, the report's canonical
    // shape, AND the report's principal are checked here, strictly before
    // the per-entry apply loop below -- a mismatch must leave local storage
    // completely untouched (fail closed), and the only way to guarantee
    // that with no undo path is to gate before the first `submit_commit`,
    // not after. Entry-binding is NOT checked here (see part 2, after the
    // loop): no comparison of the wire body against itself can be sound.
    let authenticated_report: Option<TipReport> =
        if let Some(expected) = &state.config.authority_identity {
            match verify_authenticated_envelope(&body, expected, principal_id) {
                Ok(report) => Some(report),
                Err(reason) => {
                    warn!(
                        principal = %principal_id,
                        ?reason,
                        "witness sync authenticated-channel check failed"
                    );
                    return SyncOutcome::Failed { reason };
                },
            }
        } else {
            None
        };

    let mut applied = 0usize;
    let mut rejected = 0usize;
    for entry in entries {
        let seq = entry.get("sequence").and_then(|s| s.as_u64()).unwrap_or(0);
        if seq < from_seq {
            continue;
        }

        let blob_strs = match entry.get("blobs").and_then(|b| b.as_array()) {
            Some(b) => b,
            None => {
                warn!(
                    principal_id = %principal_id,
                    sequence = seq,
                    "patch entry carries no blobs array; skipping"
                );
                rejected += 1;
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
            warn!(
                principal_id = %principal_id,
                sequence = seq,
                "patch entry blob decode failed; skipping"
            );
            rejected += 1;
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
                sequence = seq,
                error = %err,
                "witness node rejected unverifiable delta from authority; skipping"
            );
            rejected += 1;
            continue;
        }

        applied += 1;
    }

    // Authenticated channel (K10), part 2: the post-apply reconciliation.
    // Independent of anything the wire body claims about itself, compare
    // what the witness's OWN storage engine now holds against what the
    // signed report attests. This is the check that actually closes
    // withholding: a decoy entry, a dropped middle or trailing entry, and a
    // wholesale emptied or request-rewritten response all leave local state
    // short of (or divergent from) the attested tip, and none of them can
    // be dressed up to avoid that -- there is no wire field left to falsify
    // that this comparison reads.
    if let Some(report) = &authenticated_report {
        let resulting = match state.engine.get_tip(principal_id).await {
            Ok(tip) => tip,
            Err(err) => {
                error!(
                    principal = %principal_id,
                    error = %err,
                    "witness sync: post-apply local tip lookup failed"
                );
                return SyncOutcome::Failed {
                    reason: SyncFailure::LocalStorageError(err.to_string()),
                };
            },
        };

        if !resulting_tip_matches_report(resulting.as_ref(), report) {
            warn!(
                principal = %principal_id,
                applied,
                rejected,
                "witness sync: resulting local state does not match the authority's signed \
                 attestation -- entries were withheld or substituted"
            );
            return SyncOutcome::Failed {
                reason: SyncFailure::EntryCommitmentMismatch,
            };
        }
    }

    if entries.is_empty() {
        SyncOutcome::UpToDate
    } else if applied > 0 {
        SyncOutcome::Synced { applied, rejected }
    } else {
        SyncOutcome::Failed {
            reason: SyncFailure::RejectedEntry,
        }
    }
}

/// Verify the authenticated channel (K10), part 1, for one `/patch`
/// response: the statement must be a signature by `expected`, it must
/// canonicalize via [`TipReport::parse`], and it must attest to
/// `principal_id` -- the principal actually being synced, not merely SOME
/// principal the authority happens to hold.
///
/// The principal check is load-bearing, not defense in depth: the storage
/// engine's `resolve_genesis` derives a new principal's genesis from
/// whatever blobs are submitted under `principal_id` and never compares it
/// against the identifier itself, so an on-path party who rewrites only the
/// outbound query's `pr` gets back a fully genuine, genuinely-signed
/// response for a *different* principal -- every other check here passes,
/// because the response really is what it claims to be, just not an answer
/// about the principal the witness asked. This is the only place that can
/// be stopped.
///
/// Entry-binding is NOT decided here -- see [`resulting_tip_matches_report`],
/// which runs after the apply loop against the witness's own resulting
/// state rather than against anything the wire body carries about itself.
fn verify_authenticated_envelope(
    body: &Value,
    expected: &AuthorityIdentity,
    principal_id: &str,
) -> Result<TipReport, SyncFailure> {
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

    // `report.pr` (a bare b64ut genesis identifier, SPEC §2.2.3's DEFAULT
    // form) and `principal_id` share the identical wire form -- a direct
    // string comparison, no re-encoding needed.
    if report.pr.to_string() != principal_id {
        return Err(SyncFailure::PrincipalMismatch);
    }

    Ok(report)
}

/// Authenticated channel (K10), part 2: does the witness's own resulting
/// local tip -- freshly re-read from the storage engine after the apply loop
/// ran, so every applied entry has already passed full cryptographic
/// verification -- equal what the signed report attests?
///
/// `report.sequence` is the attested commit's 0-indexed position;
/// `TipState::commit_count` is that position plus one (the same relationship
/// `sign_tip_attestation` uses when composing the report). `resulting` is
/// `None` exactly when the witness holds nothing for this principal, which
/// can never equal a report that attests a real committed tip (the
/// `commit_count == 0` case is unreachable for a signed report in the first
/// place -- a `TipState` is only ever recorded after indexing a commit).
fn resulting_tip_matches_report(resulting: Option<&TipState>, report: &TipReport) -> bool {
    let Some(tip) = resulting else {
        return false;
    };
    if tip.commit_count == 0 || tip.commit_count - 1 != report.sequence {
        return false;
    }
    if tip.commit_id != report.commit_id.to_string() {
        return false;
    }
    if tip.pr != report.roots.pr.to_string()
        || tip.sr != report.roots.sr.to_string()
        || tip.ar != report.roots.ar.to_string()
    {
        return false;
    }
    let report_cr = report
        .roots
        .cr
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    tip.cr == report_cr
}
