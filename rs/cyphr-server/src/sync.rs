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
    AuthorityKey, BindingPolicy, ConnectError, HttpConnector, PatchFailure, PatchRequest,
    TipReport, fetch_patch,
};
use cyphr_storage::index::types::TipState;
use tracing::{error, warn};

use crate::AppState;
use crate::config::AuthorityIdentity;

/// The config switch that allows a cleartext upstream, as the operator
/// spells it.
pub const CLEARTEXT_SWITCH: &str = "allow_cleartext_upstream";

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
    /// The upstream is plain `http://` to a non-loopback `host`; nothing was
    /// sent. The operator opts in with the config `switch`.
    CleartextRefused {
        /// The host the upstream URL names.
        host: String,
        /// The config switch that allows it.
        switch: &'static str,
    },
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

    // The upstream path refuses plain `http://` to a non-loopback host
    // unless the operator opted in, so a tip report cannot be rewritten in
    // transit by default. `resolve_config` already refuses at startup; this
    // is the same rule for a state built any other way.
    let connector = match HttpConnector::with_client(
        state.http_client.clone(),
        authority_url,
        state.config.allow_cleartext_upstream,
    ) {
        Ok(connector) => connector,
        Err(ConnectError::CleartextRefused { host }) => {
            warn!(principal = %principal_id, %host, "witness sync: cleartext upstream refused");
            return SyncOutcome::Failed {
                reason: SyncFailure::CleartextRefused {
                    host,
                    switch: CLEARTEXT_SWITCH,
                },
            };
        },
        Err(other) => {
            return SyncOutcome::Failed {
                reason: SyncFailure::UpstreamUnreachable(other.to_string()),
            };
        },
    };
    let mut request = PatchRequest {
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
    let mut fetched = fetch_patch(
        &connector,
        &request,
        BindingPolicy::NotRequired,
        expected.as_ref(),
    )
    .await;
    // An anchor the authority does not hold (the witness is ahead on a
    // commit the authority lacks, say one resolving a fork it still holds
    // open) is a 404: ask again from genesis, which a witness may always do.
    if matches!(fetched, Err(PatchFailure::NonSuccess(404))) && request.anchor.is_some() {
        request.anchor = None;
        fetched = fetch_patch(
            &connector,
            &request,
            BindingPolicy::NotRequired,
            expected.as_ref(),
        )
        .await;
    }
    let patch = match fetched {
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
    let held_report = patch.held;

    let mut applied = 0usize;
    let mut rejected = 0usize;
    let mut bundles = Vec::new();
    let mut seqs = Vec::new();
    // In Error `entries` ends with the canonical branch; that branch is
    // handled with the others below, past the already-held guard.
    // The counts come off the wire: a peer overstating the canonical branch
    // must not wrap the subtraction.
    let common_len = patch.entries.len().saturating_sub(
        patch
            .fork
            .iter()
            .flat_map(|f| &f.branches)
            .find(|b| b.canonical)
            .map_or(0, |b| b.entries.len()),
    );
    for entry in patch.entries.iter().take(common_len) {
        let seq = entry.sequence;
        if seq < from_seq {
            continue;
        }
        match &entry.bundle {
            Ok(bundle) => {
                bundles.push(bundle.clone());
                seqs.push(seq);
            },
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
            },
        }
    }

    // An authority in Error serves every branch (SPEC 15.7.1). The
    // witness holds them all as evidence of the fork, the canonical one
    // included: a witness ahead of the fork has its own head past them.
    let mut branch_bundles = Vec::new();
    // Each branch's entries as positions among the bundles submitted
    // below: a head the witness's caps refuse is bound to the bytes of its
    // branch's last entry and the answers to those entries.
    let mut branch_at: Vec<(String, Vec<usize>)> = Vec::new();
    let first_branch = bundles.len();
    for branch in patch.fork.iter().flat_map(|f| &f.branches) {
        let mut positions = Vec::new();
        for entry in &branch.entries {
            match &entry.bundle {
                Ok(bundle) => {
                    positions.push(first_branch + branch_bundles.len());
                    branch_bundles.push(bundle.clone());
                },
                Err(defect) => {
                    warn!(principal_id = %principal_id, ?defect, "branch entry undecodable; skipping");
                    rejected += 1;
                },
            }
        }
        branch_at.push((branch.head.clone(), positions));
    }
    bundles.extend(branch_bundles.iter().cloned());
    let mut cap_refused: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // The authority's verified revokes of the keys these commits name go to
    // the engine first, as gossip's do, so its admission refuses what a dead
    // key signed after its death (SPEC 6.4). The keys are named by bundles
    // not yet verified, and they must be asked about before the commits
    // are applied (a dead key's own commits are refused only if its revoke
    // is already held), so the authority can make this node ask about
    // thumbprints it invented. The death-set ceiling bounds what that can
    // store: `record_revokes` refuses a revoke of a key no stored
    // principal holds once the set is full.
    let keys = named_keys(&bundles);
    match cyphr_client::verified_revokes(&connector, "authority", &keys).await {
        Ok((found, _)) => crate::gossip::record_revokes(state, &found).await,
        Err(err) => warn!(principal = %principal_id, %err, "witness sync: revokes not fetched"),
    }

    // The engine verifies each commit in memory before persisting it. An
    // entry it refuses is skipped (wedge fix, site 2): it must not block a
    // later genuine one.
    let main = seqs.len();
    for (i, bundle) in bundles.iter().enumerate() {
        let seq = seqs.get(i).copied().unwrap_or_default();
        match state.engine.submit_commit(principal_id, None, bundle).await {
            Ok(_) => applied += 1,
            // A branch commit the witness already holds is the steady
            // state of polling an authority that stays in Error.
            // A branch commit that does not extend the witness's own head
            // is refused as the tip and kept as evidence of the fork (the
            // same answer a push gets, 409 or 422); whether the witness
            // holds every head is checked after the loop.
            //
            // A branch commit the witness's caps refuse is no wedge either:
            // it may be a line root whose extension changes the verdict, so
            // it is offered again with the next entry; one still refused is
            // recorded, and a head past a cap is bound to its branch's last
            // entry below.
            Err(
                cyphr_storage::engine::EngineError::BranchLimit { .. }
                | cyphr_storage::engine::EngineError::Errored { .. },
            ) if i >= main => {
                let next_in_branch = branch_at
                    .iter()
                    .any(|(_, b)| b.contains(&i) && b.contains(&(i + 1)));
                let paired = match bundles.get(i + 1).filter(|_| next_in_branch) {
                    Some(next) => {
                        state
                            .engine
                            .submit_pair(principal_id, None, bundle, next)
                            .await
                    },
                    None => Err(cyphr_storage::engine::EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    }),
                };
                if matches!(
                    paired,
                    Err(cyphr_storage::engine::EngineError::BranchLimit { .. }
                        | cyphr_storage::engine::EngineError::Errored { .. })
                ) {
                    cap_refused.insert(i);
                }
            },
            Err(cyphr_storage::engine::EngineError::Protocol(_)) if i >= main => {},
            Err(err) => {
                warn!(
                    principal_id = %principal_id,
                    sequence = seq,
                    error = %err,
                    "witness node rejected unverifiable delta from authority; skipping"
                );
                rejected += 1;
            },
        }
    }

    // The authority's resync proofs (SPEC 15.8 item 2): a fork it resolved
    // by proof, which no commit shows, resolves here before the witness's
    // tip is compared with its report below.
    let pops = crate::gossip::fresh_resyncs(state, "authority", &connector, principal_id).await;
    if !pops.is_empty() {
        let chain: Vec<cyphr::replay::WireBundle> = patch
            .entries
            .iter()
            .filter_map(|e| e.bundle.clone().ok())
            .collect();
        crate::gossip::offer_resyncs(state, principal_id, &pops, &chain).await;
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

    // Part 2 for an authority in Error: its statement names heads, not
    // a tip, so the witness must now hold every one of them.
    if let Some(held) = &held_report {
        for head in &held.heads {
            // Every head the authority attests is bound to a branch of its
            // patch: the branch's last entry is that commit,
            // and the entries the witness holds chain. A held head is then
            // the end of a branch the authority served; a head the witness
            // does not hold must also be one its caps cut short.
            let held_now = match state
                .engine
                .holds_commit(principal_id, &head.commit_id.to_string())
                .await
            {
                Ok(held) => held,
                Err(err) => {
                    return SyncOutcome::Failed {
                        reason: SyncFailure::LocalStorageError(err.to_string()),
                    };
                },
            };
            if !head_is_bound(
                state,
                principal_id,
                &head.commit_id,
                held_now,
                &branch_at,
                &bundles,
                &cap_refused,
            )
            .await
            {
                warn!(principal = %principal_id, head = %head.commit_id,
                    "witness sync: a head of the authority is not held");
                return SyncOutcome::Failed {
                    reason: SyncFailure::EntryCommitmentMismatch,
                };
            }
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

/// Every key `bundles` name, as signer (`pay.tmb`) or as introduced
/// (`pay.id` of a key-introducing coz): what a revoke could bear on.
fn named_keys(bundles: &[cyphr::replay::WireBundle]) -> Vec<coz::Thumbprint> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut keys: Vec<coz::Thumbprint> = Vec::new();
    for raw in bundles.iter().flat_map(cyphr::replay::WireBundle::cozies) {
        let Ok(coz) = serde_json::from_slice::<serde_json::Value>(raw) else {
            continue;
        };
        let pay = &coz["pay"];
        let introduced =
            cyphr::parsed_coz::typ::is_key_introducing(pay["typ"].as_str().unwrap_or(""))
                .then(|| pay["id"].as_str())
                .flatten();
        for named in [pay["tmb"].as_str(), introduced].into_iter().flatten() {
            if let Ok(bytes) = Base64UrlUnpadded::decode_vec(named) {
                let tmb = coz::Thumbprint::from_bytes(bytes);
                if !keys.contains(&tmb) {
                    keys.push(tmb);
                }
            }
        }
    }
    keys
}

/// Whether the attested head `head` is bound to a branch of the authority's
/// patch. All of:
/// 1. `head` is the commit id computed from the bytes of the last entry of one branch the authority
///    names it the head of;
/// 2. the entries of that branch the witness holds chain: each held entry extends the held entry
///    before it;
/// 3. if the witness does not hold `head`, it holds the branch to the cap (its first entry off the
///    witness's own chain, and the entry after it if there is one), and every entry past the cap is
///    one it does not hold and answered by the cap (`BranchLimit` or `Errored`, recorded in
///    `cap_refused`).
///
/// What this does not check is that entries the witness does not hold chain
/// to each other: a commit's `pre` is bound only inside its arrow. Its harm
/// is bounded: the witness's own standing and fork point do not depend on
/// it.
async fn head_is_bound(
    state: &Arc<AppState>,
    principal_id: &str,
    head: &cyphr::state::TaggedDigest,
    head_held: bool,
    branch_at: &[(String, Vec<usize>)],
    bundles: &[cyphr::replay::WireBundle],
    cap_refused: &std::collections::HashSet<usize>,
) -> bool {
    let Ok(branches) = state.engine.list_branches(principal_id).await else {
        return false;
    };
    let retained: std::collections::HashSet<&str> = branches
        .iter()
        .filter(|b| !b.canonical)
        .map(|b| b.tip.as_str())
        .collect();
    let named = head.to_string();
    for (declared, positions) in branch_at {
        if *declared != named {
            continue;
        }
        let ids: Vec<Option<String>> = positions
            .iter()
            .map(|&at| {
                bundles
                    .get(at)?
                    .decode()
                    .ok()?
                    .commit_id(head.alg())
                    .map(|d| d.to_string())
            })
            .collect();
        if ids.last().and_then(Option::as_ref) != Some(&named) {
            continue;
        }
        let mut held = Vec::with_capacity(ids.len());
        for id in &ids {
            held.push(match id {
                Some(id) => state
                    .engine
                    .holds_commit(principal_id, id)
                    .await
                    .unwrap_or(false),
                None => false,
            });
        }
        let mut chained = true;
        for i in 1..ids.len() {
            if let (true, true, Some(prev), Some(next)) =
                (held[i - 1], held[i], &ids[i - 1], &ids[i])
                && state
                    .engine
                    .extends(principal_id, prev, next)
                    .await
                    .ok()
                    .flatten()
                    != Some(true)
            {
                chained = false;
            }
        }
        if !chained {
            continue;
        }
        if head_held {
            return true;
        }
        let on_chain =
            |i: usize| held[i] && ids[i].as_deref().is_some_and(|id| !retained.contains(id));
        let Some(first_off) = (0..ids.len()).find(|&i| !on_chain(i)) else {
            continue;
        };
        let cap = cyphr_storage::engine::BRANCH_DEPTH;
        let line_held = held[first_off] && held.get(first_off + 1).is_none_or(|h| *h);
        let past: Vec<usize> = (first_off + cap..ids.len()).collect();
        let past_answered = past
            .iter()
            .all(|&i| !held[i] && cap_refused.contains(&positions[i]));
        if line_held && !past.is_empty() && past_answered {
            return true;
        }
    }
    false
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
    /// OWN `cr` is empty (committing a staged commit writes a real CR on
    /// every finalized commit), so a wire fixture built by doctoring the *report*
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
