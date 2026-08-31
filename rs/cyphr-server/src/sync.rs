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
//!    synced -- see [`verify_authenticated_envelope`]. A genuine, validly-signed report for a
//!    *different* principal (an on-path party rewrote only the outbound query) is refused here,
//!    before it ever reaches storage.
//! 2. After the apply loop runs, the witness's own resulting local tip must equal what the signed
//!    report attests -- see [`resulting_tip_matches_report`]. A signature over `pay` says nothing
//!    about a *separate* plaintext `entries` array, so no per-entry label comparison against that
//!    same array can ever be sound (a decoy entry that copies its victim's declared
//!    `sequence`/`commit_id` passes any such check while carrying junk `blobs`). Comparing against
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

use std::fmt::Write as _;
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
        map.entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = principal_lock.lock().await;

    let base_url = authority_url.trim_end_matches('/');

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

    // Percent-encode `principal_id` (client-supplied) and the anchor before
    // they are interpolated into the outbound URL, so a value containing
    // `&`/`=`/`#` cannot inject extra query parameters into the witness's
    // own outbound request. Currently redundant with the pre-apply principal
    // comparison below (any such value already fails to match the report's
    // attested principal) and with the anchor's own tagged-digest charset
    // (algorithm name plus base64url, which excludes those bytes), but the
    // safety should not depend on either being the only guard.
    let encoded_principal = percent_encode_query_value(principal_id);
    let patch_url = match &anchor_pr {
        Some(pr) => {
            let encoded_anchor = percent_encode_query_value(pr);
            format!("{base_url}/patch?pr={encoded_principal}&from={encoded_anchor}")
        },
        None => format!("{base_url}/patch?pr={encoded_principal}"),
    };

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

/// Percent-encode `value` for use as one query-string component, escaping
/// every byte outside RFC 3986's `unreserved` set (`ALPHA` / `DIGIT` / `-` /
/// `.` / `_` / `~`) as `%XX`. A minimal, dependency-free encoder scoped to
/// this module's one call site: `principal_id` is client-supplied and
/// interpolated into the outbound `/patch` URL, so a value containing
/// `&`/`=`/`#` must not be able to inject extra query parameters into the
/// witness's own outbound request.
fn percent_encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            },
            _ => {
                out.push('%');
                write!(out, "{byte:02X}").expect("write to String never fails");
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use cyphr::HashAlg;
    use cyphr::state::TaggedDigest;

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
            sr: sr.to_string(),
            ar: ar.to_string(),
            cr: String::new(),
            commit_id: commit_id.to_string(),
            commit_count: 1,
            last_updated: 0,
        };
        let report = TipReport {
            pr: coz::Thumbprint::from_bytes(vec![0xffu8; 32]),
            sequence: 0,
            commit_id,
            roots: receipt::TipReportRoots {
                pr,
                sr,
                ar,
                cr: None,
            },
        };

        assert!(
            resulting_tip_matches_report(Some(&tip), &report),
            "a report with an ABSENT commit root must match a local tip with an EMPTY commit \
             root, not be rejected as a mismatch"
        );
    }

    #[test]
    fn percent_encode_query_value_leaves_unreserved_bytes_alone() {
        assert_eq!(percent_encode_query_value("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode_query_value(""), "");
    }

    #[test]
    fn percent_encode_query_value_escapes_query_injection_chars() {
        // `&`, `=`, and `#` are exactly the bytes an injected extra query
        // parameter or a fragment marker would need.
        assert_eq!(percent_encode_query_value("a&b=c#d"), "a%26b%3Dc%23d");
    }
}
