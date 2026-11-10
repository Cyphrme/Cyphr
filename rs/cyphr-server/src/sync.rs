//! Witness mode state synchronization client (`docs/guides/operating-a-server.md`, "Witness mode").
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
//!    synced -- see [`cyphr_client::verify_authenticated_envelope`]. A genuine, validly-signed
//!    report for a *different* principal (an on-path party rewrote only the outbound query) is
//!    refused here, before it ever reaches storage.
//! 2. After the apply loop runs, the witness's own resulting local tip must equal what the signed
//!    report attests -- see [`resulting_tip_matches_report`]. A signature over `pay` says nothing
//!    about a *separate* plaintext `entries` array, so no per-entry label comparison against that
//!    same array can ever be sound (a decoy entry that copies its victim's declared
//!    `sequence`/`commit_id` passes any such check while carrying junk cozies). Comparing against
//!    what the witness's own storage engine independently verified and produced instead of reading
//!    the wire body against itself catches every MODIFICATION of a response -- truncation,
//!    per-principal substitution, and wholesale emptying all leave local state short of, or
//!    divergent from, the attested tip, whether the response or only the outbound request was
//!    altered.
//!
//! **What this does not close: replay of a genuine response.** The check authenticates the
//! *pairing* of local state and signed report, not the report's *currency*. A response the
//! authority genuinely signed at a moment when its tip equalled the witness's own state matches
//! that state by construction, forever -- an on-path party can hold such a response and keep
//! serving it on every later poll, and the witness reads [`SyncOutcome::UpToDate`] indefinitely
//! while the authority advances without limit. Nothing is forged or altered, so no comparison of
//! wire fields against each other or against local state can distinguish it from a live response.
//! Closing it needs a freshness or monotonicity property this channel does not provide; that is an
//! open protocol question upstream of this module, not a defect in this comparison -- tracked as
//! issue #152, gated on the open specification question of what an attestation asserts about
//! currency.
//!
//! Without a configured identity, sync runs the legacy unauthenticated path
//! unchanged.

use std::sync::Arc;

use cyphr_client::{
    AuthorityKey, BindingPolicy, HttpConnector, PatchFailure, PatchRequest, TipReport, fetch_patch,
};
use cyphr_storage::index::types::TipState;
use tracing::{error, warn};

use crate::AppState;
use crate::config::AuthorityIdentity;

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
    /// The carrier fell short of the channel binding the witness requires;
    /// no request was sent.
    ChannelBindingRefused(cyphr_client::BindingError),
    /// The upstream authority could not be reached (network/transport
    /// error).
    UpstreamUnreachable(String),
    /// The upstream authority answered with a non-success HTTP status.
    UpstreamNonSuccess(u16),
    /// The response body did not decode as the expected patch JSON shape.
    MalformedResponse(String),
    /// The upstream's response envelope states a wire version this build
    /// does not read; nothing was applied.
    UnsupportedEnvelopeVersion { found: u64, supported: u64 },
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
    /// [`resulting_tip_matches_report`]. Catches every MODIFICATION of the
    /// response: a decoy entry that preserves its victim's declared labels, a
    /// dropped middle or trailing entry, and a wholesale emptied or
    /// request-rewritten response are all caught identically, because none
    /// of them change what the witness's own storage engine actually
    /// produced. Does NOT catch a *replay* of a genuine, unmodified response
    /// captured while the authority's tip matched the witness's own state --
    /// see the module documentation's "What this does not close" section.
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
        // Drop idle entries (held only by the map). Every holder clones
        // under this same map lock, so a count of 1 means nobody holds or
        // awaits the lock. Pruning here, as well as on completion below,
        // bounds the map even when a request future is cancelled between
        // acquiring a lock and releasing it.
        map.retain(|_, lock| Arc::strong_count(lock) > 1);
        map.entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };

    let outcome = {
        let _guard = principal_lock.lock().await;
        sync_locked(state, principal_id, authority_url).await
    };

    // Release the entry once idle. Unconditionally keeping it would grow
    // the map by one lock per principal id an unauthenticated reader asks
    // about. Two holders -- this clone and the map's -- means no other
    // sync is queued behind it.
    let mut map = state.sync_locks.lock().await;
    if Arc::strong_count(&principal_lock) == 2 {
        map.remove(principal_id);
    }
    outcome
}

/// One sync attempt, run while holding `principal_id`'s lock.
async fn sync_locked(
    state: &Arc<AppState>,
    principal_id: &str,
    authority_url: &str,
) -> SyncOutcome {
    let local_tip = match state.engine.get_tip(principal_id).await {
        Ok(tip) => tip,
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

    // The resync anchor (Zami #140; S0.1: the anchor root is PR) is the
    // witness's own current tip PR content digest, not a sequence number --
    // a digest binds the SPECIFIC history it was produced from, where a
    // sequence number is shared by any equivocating fork at the same
    // position. Absent entirely (rather than an anchor to some sentinel
    // position) when the witness holds nothing yet for this principal, so
    // the authority serves a full resync from genesis, matching legacy
    // bootstrapping behavior.
    //
    // `from_seq` is retained ONLY as a local, defensive re-application
    // guard on the entries this call itself receives below (`seq <
    // from_seq`) -- it is never placed on the wire and never what the
    // authority resumes from, so it stays exactly the metadata S3 permits,
    // not a second de facto anchor.
    let from_seq = local_tip.as_ref().map_or(0, |t| t.commit_count);
    let anchor_pr = local_tip.as_ref().map(|t| t.pr.clone());

    let connector = HttpConnector::new(state.http_client.clone(), authority_url);
    let request = PatchRequest {
        principal_id,
        anchor: anchor_pr.as_deref(),
    };
    // Authenticated channel (K10), part 1. When the witness knows the
    // expected authority identity, the signature, the report's canonical
    // shape, AND the report's principal are checked inside `fetch_patch`,
    // strictly before any entry is handed back -- a mismatch must leave
    // local storage completely untouched (fail closed), and the only way
    // to guarantee that with no undo path is to gate before the first
    // `submit_commit`, not after. Entry-binding is NOT checked there (see
    // part 2, after the loop): no comparison of the wire body against
    // itself can be sound.
    let expected = state.config.authority_identity.as_ref().map(authority_key);
    let patch = match fetch_patch(
        &connector,
        &request,
        BindingPolicy::NotRequired,
        expected.as_ref(),
    )
    .await
    {
        Ok(patch) => patch,
        Err(err) => {
            warn!(
                principal = %principal_id,
                error = %err,
                "witness sync: patch fetch or verification failed"
            );
            return SyncOutcome::Failed { reason: err.into() };
        },
    };
    let authenticated_report: Option<TipReport> = patch.report;

    let mut applied = 0usize;
    let mut rejected = 0usize;
    for entry in &patch.entries {
        let seq = entry.sequence;
        if seq < from_seq {
            continue;
        }

        let bundle = match &entry.bundle {
            Ok(bundle) => bundle,
            Err(defect) => {
                // Wedge fix, site 1 (decode failure): a malformed entry
                // must never make a later, genuine entry unreachable --
                // skip and record, don't abort the whole sync. `from_seq`
                // is recomputed fresh from local state on every call with
                // no persisted progress marker, so aborting here would
                // refetch and re-abort on this same entry forever.
                warn!(
                    principal_id = %principal_id,
                    sequence = seq,
                    ?defect,
                    "patch entry undecodable; skipping"
                );
                rejected += 1;
                continue;
            },
        };

        // Submit commit to storage engine which verifies commit signatures & roots in memory
        // before persisting. If validation fails, skip this entry and continue: an
        // unverifiable entry (wedge fix, site 2) must not block a later genuine one, for
        // the identical reason as the decode failure above.
        if let Err(err) = state.engine.submit_commit(principal_id, None, bundle).await {
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

    if applied > 0 {
        SyncOutcome::Synced { applied, rejected }
    } else if rejected > 0 {
        SyncOutcome::Failed {
            reason: SyncFailure::RejectedEntry,
        }
    } else {
        // Nothing applied and nothing rejected: either the response carried
        // no entries at all, or every entry present was skipped by the
        // `seq < from_seq` guard above because the witness already holds it
        // (e.g. a stale response that predates the witness's last sync).
        // Neither case is a rejection -- `rejected` counts entries this call
        // actually attempted and failed, and reporting `RejectedEntry` here
        // would tell the operator every entry was rejected when none was.
        SyncOutcome::UpToDate
    }
}

fn authority_key(identity: &AuthorityIdentity) -> AuthorityKey {
    AuthorityKey {
        alg: identity.alg.clone(),
        pub_key: identity.pub_key.clone(),
    }
}

impl From<PatchFailure> for SyncFailure {
    fn from(err: PatchFailure) -> Self {
        match err {
            PatchFailure::Unreachable(m) => Self::UpstreamUnreachable(m),
            PatchFailure::NonSuccess(status) => Self::UpstreamNonSuccess(status),
            PatchFailure::MalformedResponse(m) => Self::MalformedResponse(m),
            PatchFailure::EnvelopeUnsignedOrMisSigned => Self::EnvelopeUnsignedOrMisSigned,
            PatchFailure::MalformedReport => Self::MalformedReport,
            PatchFailure::UnsupportedVersion { found, supported } => {
                Self::UnsupportedEnvelopeVersion { found, supported }
            },
            PatchFailure::PrincipalMismatch => Self::PrincipalMismatch,
            PatchFailure::Binding(refusal) => Self::ChannelBindingRefused(refusal),
        }
    }
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
        || tip.sr != report.roots.sr.as_ref().map(ToString::to_string)
        || tip.ar != report.roots.ar.as_ref().map(ToString::to_string)
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

#[cfg(test)]
mod tests {
    use cyphr::HashAlg;
    use cyphr::state::TaggedDigest;
    use cyphr_client::TipReportRoots;

    use super::*;

    /// C2: the empty-commit-root invariant, pinned where it is actually
    /// constructible. A principal legitimately in the no-commit-root state
    /// (a key-established-but-uncommitted principal, or a reindexed
    /// implicit-genesis principal with `crs: Vec::new()` -- see the module
    /// doc's discussion of storage's `""` sentinel) must not be
    /// over-rejected: a report whose `cr` is ABSENT matches a local tip
    /// whose `cr` is EMPTY.
    ///
    /// The integration-level sibling this pinned before
    /// (`witness_accepts_genesis_report_at_ingestion`) could not hold: no
    /// push path on this authority produces a witness-resulting tip whose
    /// OWN `cr` is empty (`finalize_commit` writes a real CR on every
    /// finalized commit), so a wire fixture built by doctoring the *report*
    /// alone was fixture-vs-entries incoherent -- a `cr`-mismatch is the
    /// entries' true, correct verdict. This unit test asserts the same
    /// property directly against the pure comparison, with no fixture
    /// contortion.
    #[test]
    fn resulting_tip_matches_report_accepts_legitimate_empty_commit_root() {
        let pr = TaggedDigest::new(HashAlg::Sha256, vec![0x01; 32]).unwrap();
        let sr = TaggedDigest::new(HashAlg::Sha256, vec![0x02; 32]).unwrap();
        let ar = TaggedDigest::new(HashAlg::Sha256, vec![0x03; 32]).unwrap();
        let commit_id = TaggedDigest::new(HashAlg::Sha256, vec![0x04; 32]).unwrap();

        let tip = TipState {
            principal_id: "test-principal".to_string(),
            pr: pr.to_string(),
            sr: Some(sr.to_string()),
            ar: Some(ar.to_string()),
            cr: String::new(),
            commit_id: commit_id.to_string(),
            commit_count: 1,
            last_updated: 0,
        };
        let report = TipReport {
            pr: coz::Thumbprint::from_bytes(vec![0xffu8; 32]),
            sequence: 0,
            commit_id,
            roots: TipReportRoots {
                pr,
                sr: Some(sr),
                ar: Some(ar),
                cr: None,
            },
        };

        assert!(
            resulting_tip_matches_report(Some(&tip), &report),
            "a report with an ABSENT commit root must match a local tip with an EMPTY commit \
             root, not be rejected as a mismatch"
        );
    }

    /// Claim: a refused channel binding surfaces as its own failure, not as
    /// a connectivity problem an operator would chase on the network. Unit
    /// level by exception: the witness requires no binding today, so no
    /// scenario can provoke the refusal end to end.
    #[test]
    fn binding_refusal_maps_to_its_own_failure() {
        let refusal = PatchFailure::Binding(cyphr_client::BindingError::Missing {
            required: cyphr_client::BindingKind::NoiseHandshakeHash,
        });
        assert!(
            matches!(
                SyncFailure::from(refusal),
                SyncFailure::ChannelBindingRefused(_)
            ),
            "a binding refusal must not be reported as an unreachable upstream"
        );
    }
}
