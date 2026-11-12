//! Peer-side anti-entropy: a configured timer that runs the verifier's pull
//! step against the peers the operator chose (GOSSIP-MIN section 2).
//!
//! The timer is not a second protocol. Each round, for every principal the
//! server holds, it opens a [`cyphr_client::Record`] from the principal's
//! stored chain and calls the same [`cyphr_client::pull`] a verifying
//! client calls, then stores what verified:
//!
//! - commits past the stored tip replay from the record's anchor (the stored genesis commit) and go
//!   through the engine, which verifies them again before persisting;
//! - a rival branch the pull proved is handed to the engine, which keeps it (G1) so `/branches` and
//!   `/evidence` serve it on;
//! - a naked revoke that verified is recorded in the death set, so it travels on to the peers that
//!   ask this server.
//!
//! Peers are dialled at the address configured, so a deployment (or the
//! scenario proxy) can carry and cut the link.
//!
//! Limits, stated rather than hidden: only principals the server already
//! holds are pulled (a peer learns a new principal from its owner's `/push`;
//! discovery is not part of this), and a round replays each held principal
//! from its stored chain (replay-cost caching is deferred, see
//! `[gossip] interval_secs`).

use std::sync::Arc;
use std::time::Duration;

use cyphr::principal::system_clock;
use cyphr_client::{
    ActionBundle, Anchor, HttpConnector, PatchEntry, PullPeer, Record, branch_bundles, pull,
};
use cyphr_storage::index::Indexer as _;
use tracing::{debug, info, warn};

use crate::AppState;

/// Why one principal's gossip round could not run.
#[derive(Debug, thiserror::Error)]
enum RoundError {
    #[error("reading the stored chain: {0}")]
    Store(#[from] cyphr_storage::engine::EngineError),
    #[error("the stored chain does not replay from its own genesis: {0}")]
    Replay(#[from] cyphr_client::PeerFailure),
    #[error("the principal holds no commits")]
    Empty,
}

/// Start the gossip timer if peers are configured and the server accepts
/// writes. A witness takes its state from its authority, so it never
/// gossips.
///
/// Peer URLs were checked at config resolution; one that still cannot
/// become a connector (a state built without it) is skipped with a warning.
pub fn spawn(state: &Arc<AppState>) -> Option<tokio::task::JoinHandle<()>> {
    let config = &state.config;
    if config.gossip.peers.is_empty() || config.mode != crate::config::ServerMode::Authority {
        return None;
    }
    let peers: Vec<(String, HttpConnector)> = config
        .gossip
        .peers
        .iter()
        .filter_map(|url| {
            match HttpConnector::with_client(
                state.http_client.clone(),
                url,
                config.allow_cleartext_upstream,
            ) {
                Ok(connector) => Some((url.clone(), connector)),
                Err(err) => {
                    warn!(peer = %url, %err, "gossip peer refused; not dialled");
                    None
                },
            }
        })
        .collect();
    let every = Duration::from_secs(config.gossip.interval_secs);
    let state = Arc::clone(state);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        // A slow round must not queue up a burst of rounds behind it.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            round(&state, &peers).await;
        }
    }))
}

/// One gossip round: pull every held principal from every peer.
pub async fn round(state: &Arc<AppState>, peers: &[(String, HttpConnector)]) {
    let principals = match state.engine.indexer().list_principals().await {
        Ok(principals) => principals,
        Err(err) => {
            warn!(%err, "gossip: cannot list principals");
            return;
        },
    };
    for summary in principals {
        if let Err(err) = round_principal(state, peers, &summary.principal_id).await {
            warn!(principal = %summary.principal_id, %err, "gossip: round skipped");
        }
    }
}

async fn round_principal(
    state: &Arc<AppState>,
    peers: &[(String, HttpConnector)],
    principal_id: &str,
) -> Result<(), RoundError> {
    let stored = state.engine.get_patch(principal_id, None, None).await?;
    let genesis = stored.entries.first().ok_or(RoundError::Empty)?;
    let anchor = Anchor::GenesisCommit(genesis.commit.commit_id.clone());
    let entries: Vec<PatchEntry> = stored
        .entries
        .iter()
        .map(|e| PatchEntry {
            sequence: e.commit.sequence,
            bundle: Ok(e.bundle.clone()),
        })
        .collect();
    let actions: Vec<ActionBundle> = stored
        .actions
        .iter()
        .map(|a| ActionBundle {
            after: a.after,
            blobs: Ok(a.blobs.clone()),
        })
        .collect();
    let mut record =
        Record::from_entries(principal_id, anchor, system_clock, &entries, &actions).await?;
    let mark = record.log_len();

    let dialled: Vec<PullPeer<'_, HttpConnector>> = peers
        .iter()
        .map(|(name, connector)| PullPeer { name, connector })
        .collect();
    let report = pull(&mut record, &dialled).await;
    for outcome in &report.peers {
        debug!(principal = %principal_id, peer = %outcome.peer, standing = ?outcome.standing, "gossip: pulled");
    }

    // Verified revokes first, where the engine judges admission and forks
    // by them (SPEC 6.4, 15.7.1), so a dead key's later commits served in
    // this same round are refused.
    record_revokes(state, &report.revoked).await;

    for bundle in record.bundles_since(mark) {
        match state.engine.submit_commit(principal_id, None, bundle).await {
            Ok(_) => info!(principal = %principal_id, "gossip: stored a verified commit"),
            // The principal may have advanced here since the round began
            // (a client's push): the engine refuses what it already holds.
            Err(err) => debug!(principal = %principal_id, %err, "gossip: commit not stored"),
        }
    }
    for fork in &report.forks {
        warn!(principal = %principal_id, height = fork.height, commits = ?fork.commits, "gossip: principal fork");
    }
    // The engine refuses a rival as a tip but retains it as a branch (I2: a
    // fork is evidence, never merged), and accepts a forked peer's later
    // commits only if they verify (SPEC 15.8).
    for bundle in branch_bundles(&record, &report, &dialled).await {
        match state
            .engine
            .submit_commit(principal_id, None, &bundle)
            .await
        {
            Ok(_) => info!(principal = %principal_id, "gossip: a branch commit adopted"),
            Err(err) => debug!(principal = %principal_id, %err, "gossip: branch commit answered"),
        }
    }
    Ok(())
}

/// Record each verified naked revoke where the server keeps deaths (SPEC
/// 6.4): the observations every capability consults, and the engine, which
/// refuses a dead key's commits at admission and judges forks by them.
/// Gossip and a witness's sync both record through this.
pub(crate) async fn record_revokes(state: &AppState, revoked: &[cyphr_client::RevokedKey]) {
    for revoked in revoked {
        if let Err(err) = state
            .observations
            .record_seen(&revoked.tmb, revoked.envelope.clone())
            .await
        {
            warn!(tmb = %revoked.tmb.to_b64(), %err, "naked revoke not recorded");
        }
        if let Err(err) = state.engine.record_revoke(&revoked.envelope).await {
            warn!(tmb = %revoked.tmb.to_b64(), %err, "naked revoke not kept by the engine");
        }
    }
}
