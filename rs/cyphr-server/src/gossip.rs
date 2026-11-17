//! Peer-side anti-entropy: a configured timer that runs the verifier's pull
//! step against the peers the operator chose (GOSSIP-MIN section 2).
//!
//! The timer is not a second protocol. Each round, for every principal the
//! server holds, it opens a [`cyphr_client::Record`] over the engine's
//! kept state of the principal and calls the same [`cyphr_client::pull`] a
//! verifying client calls, then stores what verified:
//!
//! - the record starts from the verified state the engine already keeps, so a round verifies the
//!   commits past that state (a peer's new head), not the chain. A principal the engine keeps no
//!   current state for (evicted, not written since a restart, or one whose history embeds another
//!   principal's pin or Key Tree digest, which are always replayed) is replayed once from its
//!   stored genesis commit. A fork a peer proves needs the commits below it, which the record reads
//!   from the store then;
//! - commits past the stored tip go through the engine, which verifies them again before
//!   persisting;
//! - a rival branch the pull proved is handed to the engine, which keeps it (G1) so `/branches` and
//!   `/evidence` serve it on;
//! - a naked revoke that verified is recorded in the death set, so it travels on to the peers that
//!   ask this server.
//!
//! Peers are dialled at the address configured, so a deployment (or the
//! scenario proxy) can carry and cut the link.
//!
//! A principal whose every peer is idle is not pulled: when each peer lists
//! only heads this server holds (or does not hold the principal at all),
//! there is nothing to fetch and the stored chain is not replayed. The
//! idle test is [`cyphr_client::PeerHeads::idle`], the one the pull step
//! itself uses. The revoke probe is never skipped: a naked revoke moves no
//! head, so each round still asks every peer about the principal's active
//! keys, remembered from the last replay (see [`Gossip`]).
//!
//! Limits, stated rather than hidden: only principals the server already
//! holds are pulled (a peer learns a new principal from its owner's `/push`;
//! discovery is not part of this), and a peer serves every action bundle it
//! holds with each patch, so a pull reads them all (an action already held
//! is not verified again). The gate reads heads only, so it is as
//! blind to data actions that move no head as the pull step is; that is
//! the open action question (GitHub #211), not something the gate adds.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use coz::Thumbprint;
use cyphr::principal::system_clock;
use cyphr_client::{
    ActionBundle, Anchor, ChainSource, HttpConnector, PatchEntry, PullPeer, Record, branch_bundles,
    peer_heads, pull, verified_revokes,
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
        let mut gossip = Gossip::default();
        let mut tick = tokio::time::interval(every);
        // A slow round must not queue up a burst of rounds behind it.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            gossip.round(&state, &peers).await;
        }
    }))
}

/// What the gate keeps between rounds: for each principal, the active keys
/// of the chain at the tip commit last replayed. A naked revoke moves no
/// head, so a skipped round still asks every peer about these keys, and
/// the chain is not replayed to learn them. The set is a function of the
/// tip commit id alone; it only ever lets a round skip work, is never
/// persisted, and a restart costs one replay per principal.
#[derive(Default)]
pub struct Gossip {
    keys: HashMap<String, KeyMemo>,
}

struct KeyMemo {
    tip: String,
    keys: Vec<Thumbprint>,
}

impl Gossip {
    /// One gossip round: pull every held principal from every peer, and
    /// skip the pull (not the revoke probe) of a principal every peer is
    /// idle on.
    pub async fn round(&mut self, state: &Arc<AppState>, peers: &[(String, HttpConnector)]) {
        let principals = match state.engine.indexer().list_principals().await {
            Ok(principals) => principals,
            Err(err) => {
                warn!(%err, "gossip: cannot list principals");
                return;
            },
        };
        for summary in principals {
            let id = &summary.principal_id;
            if let Some(keys) = self.idle_keys(state, peers, id).await {
                probe_revokes(state, peers, &keys).await;
                continue;
            }
            match round_principal(state, peers, id).await {
                Ok(memo) => {
                    self.keys.insert(id.clone(), memo);
                },
                Err(err) => warn!(principal = %id, %err, "gossip: round skipped"),
            }
        }
        state.metrics.gossip_round();
    }

    /// The remembered revoke-probe keys of `principal_id` when the gate
    /// says idle: the engine's tip is the one the keys were read at, and
    /// every peer lists only heads the engine holds (a 404 lists none).
    /// `None` when any of that cannot be shown, which runs the full pull.
    async fn idle_keys(
        &self,
        state: &Arc<AppState>,
        peers: &[(String, HttpConnector)],
        principal_id: &str,
    ) -> Option<Vec<Thumbprint>> {
        let tip = state.engine.get_tip(principal_id).await.ok()??;
        let memo = self
            .keys
            .get(principal_id)
            .filter(|m| m.tip == tip.commit_id)?;
        for (_, connector) in peers {
            let Ok(heads) = peer_heads(connector, principal_id).await else {
                return None;
            };
            let Some(heads) = heads else { continue };
            let mut held = BTreeSet::new();
            for head in heads.tips() {
                if state.engine.holds_commit(principal_id, head).await.ok()? {
                    held.insert(head.to_owned());
                }
            }
            if !heads.idle(|tip| held.contains(tip)) {
                return None;
            }
        }
        Some(memo.keys.clone())
    }
}

/// Ask every peer for the naked revokes of `keys`, as a full pull's last
/// step does, and record what verified.
async fn probe_revokes(
    state: &Arc<AppState>,
    peers: &[(String, HttpConnector)],
    keys: &[Thumbprint],
) {
    let mut seen = BTreeSet::new();
    let mut revoked = Vec::new();
    for (name, connector) in peers {
        match verified_revokes(connector, name, keys).await {
            Ok((found, _rejected)) => {
                revoked.extend(found.into_iter().filter(|r| seen.insert(r.tmb.to_b64())));
            },
            Err(err) => debug!(peer = %name, %err, "gossip: revoke probe failed"),
        }
    }
    record_revokes(state, &revoked).await;
}

/// The chain the engine stores, as a resumed record's store.
struct StoredChain {
    state: Arc<AppState>,
    principal_id: String,
}

impl ChainSource for StoredChain {
    fn first(
        &self,
        count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<PatchEntry>, String>> + Send + '_>> {
        Box::pin(async move {
            let last = u64::try_from(count.saturating_sub(1)).map_err(|e| e.to_string())?;
            let stored = self
                .state
                .engine
                .get_patch(&self.principal_id, None, Some(last))
                .await
                .map_err(|e| e.to_string())?;
            Ok(patch_entries(&stored))
        })
    }
}

/// A record of `principal_id` at the engine's tip: opened over the state
/// the engine keeps, or, when it keeps none that is current, replayed from
/// the stored genesis commit.
async fn open_record(state: &Arc<AppState>, principal_id: &str) -> Result<Record, RoundError> {
    if let Some(kept) = state.engine.kept_principal(principal_id).await {
        let store = Arc::new(StoredChain {
            state: Arc::clone(state),
            principal_id: principal_id.to_owned(),
        });
        if let Ok(record) = Record::resume(principal_id, kept, system_clock, store) {
            return Ok(record);
        }
    }
    let stored = state.engine.get_patch(principal_id, None, None).await?;
    let genesis = stored.entries.first().ok_or(RoundError::Empty)?;
    let anchor = Anchor::GenesisCommit(genesis.commit.commit_id.clone());
    Ok(Record::from_entries(
        principal_id,
        anchor,
        system_clock,
        &patch_entries(&stored),
        &patch_actions(&stored),
    )
    .await?)
}

fn patch_entries(stored: &cyphr_storage::engine::PatchResponse) -> Vec<PatchEntry> {
    stored
        .entries
        .iter()
        .map(|e| PatchEntry {
            sequence: e.commit.sequence,
            bundle: Ok(e.bundle.clone()),
        })
        .collect()
}

fn patch_actions(stored: &cyphr_storage::engine::PatchResponse) -> Vec<ActionBundle> {
    stored
        .actions
        .iter()
        .map(|a| ActionBundle {
            blobs: Ok(a.blobs.clone()),
        })
        .collect()
}

async fn round_principal(
    state: &Arc<AppState>,
    peers: &[(String, HttpConnector)],
    principal_id: &str,
) -> Result<KeyMemo, RoundError> {
    let mut record = open_record(state, principal_id).await?;
    let tip = record.tip().ok_or(RoundError::Empty)?;
    let memo = KeyMemo {
        tip: tip.commit_id,
        keys: record.unrevoked_keys(),
    };
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
    state.metrics.gossip_replayed(record.replayed());
    Ok(memo)
}

/// Record each verified naked revoke where the server keeps deaths (SPEC
/// 6.4), in the one order [`crate::revoke::record_everywhere`] fixes: a
/// revoke the engine refuses reaches neither store. Each is recorded at
/// this node's own receipt time, never the relayer's (#203). Gossip and a
/// witness's sync both record through this.
pub(crate) async fn record_revokes(state: &AppState, revoked: &[cyphr_client::RevokedKey]) {
    for revoked in revoked {
        if let Err(err) =
            crate::revoke::record_everywhere(state, &revoked.tmb, &revoked.envelope).await
        {
            warn!(tmb = %revoked.tmb.to_b64(), %err, "naked revoke not recorded");
        }
    }
}
