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
//!   ask this server;
//! - a resync proof a peer holds (SPEC 15.8 item 2) is offered to the engine with the peer's chain
//!   from the first commit this server lacks, so a fork the principal resolved by proof resolves
//!   here too. A proof moves no head, so a principal in Error here, or that a peer reads in Error
//!   (it lists more heads than this server), is never idle: it takes the full round, which asks for
//!   proofs. A peer that holds a proof selecting a branch this server holds, with no more heads, is
//!   not seen by the gate; the proof reaches this server from its sender or a later full round.
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
//! keys, remembered from the last round (see [`Gossip`]).
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
    BindingPolicy, ChainSource, Connector, HttpConnector, PatchEntry, PatchFailure, PatchRequest,
    PeerKey, PullPeer, Record, TipReport, branch_bundles, fetch_patch, fetch_patch_keyed,
    fetch_resyncs, fetch_tip_body, peer_heads, pull, statement_signer, verified_revokes,
    verify_authenticated_envelope, verify_held_envelope,
};
use cyphr_storage::engine::{PulledOffer, ResyncOffer};
use cyphr_storage::index::Indexer as _;
use tracing::{debug, error, info, warn};

use crate::AppState;

/// Why one principal's gossip round could not run.
#[derive(Debug, thiserror::Error)]
enum RoundError {
    #[error("reading the stored chain: {0}")]
    Store(#[from] cyphr_storage::engine::EngineError),
    #[error("the stored state is not a record of the principal: {0}")]
    Replay(#[from] cyphr_client::PeerFailure),
    #[error("the principal holds no commits")]
    Empty,
}

/// One configured peer: how it is dialled and, when the operator named it,
/// the Principal Genesis of its server principal, whose chain holds the keys
/// its signed tip reports are checked against.
pub struct Peer {
    /// The peer's configured URL, which names it in logs and reports.
    pub name: String,
    /// The carrier to it.
    pub connector: HttpConnector,
    /// The PG of the peer's server principal; `None` means its reports are
    /// not checked (R4: a verifier decides whose claims to accept).
    pub pg: Option<String>,
}

impl Peer {
    /// A peer whose reports are not checked: no server principal named.
    #[must_use]
    pub fn new(name: String, connector: HttpConnector) -> Self {
        Self {
            name,
            connector,
            pg: None,
        }
    }
}

/// The configured peers as connectors. Peer URLs were checked at config
/// resolution; one that still cannot become a connector (a state built
/// without it) is skipped with a warning.
#[must_use]
pub fn peers_of(state: &AppState) -> Vec<Peer> {
    let config = &state.config;
    config
        .gossip
        .peers
        .iter()
        .filter_map(|entry| {
            match HttpConnector::with_client(
                state.http_client.clone(),
                entry.url(),
                config.allow_cleartext_upstream,
            ) {
                Ok(connector) => Some(Peer {
                    name: entry.url().to_owned(),
                    connector,
                    pg: entry.pg().map(str::to_owned),
                }),
                Err(err) => {
                    warn!(peer = %entry.url(), %err, "gossip peer refused; not dialled");
                    None
                },
            }
        })
        .collect()
}

/// Start the gossip timer if peers are configured, in either mode: a
/// service pulls to stay in step with its peers, a witness to follow them.
pub fn spawn(state: &Arc<AppState>) -> Option<tokio::task::JoinHandle<()>> {
    let config = &state.config;
    if config.gossip.peers.is_empty() {
        return None;
    }
    let peers = peers_of(state);
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
/// of the chain at the tip commit last opened. A naked revoke moves no
/// head, so a skipped round still asks every peer about these keys
/// without opening a record to learn them. The set is a function of the
/// tip commit id alone; it only ever lets a round skip work, is never
/// persisted, and after a restart is read again from the engine's state.
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
    pub async fn round(&mut self, state: &Arc<AppState>, peers: &[Peer]) {
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
    /// `None` when any of that cannot be shown, which runs the full pull,
    /// and when this server or a peer reads Error: the exit from Error (a
    /// resync proof) moves no head.
    async fn idle_keys(
        &self,
        state: &Arc<AppState>,
        peers: &[Peer],
        principal_id: &str,
    ) -> Option<Vec<Thumbprint>> {
        let tip = state.engine.get_tip(principal_id).await.ok()??;
        let ours = state.engine.assess(principal_id).await.ok()?;
        if ours.consensus == cyphr_storage::engine::Consensus::Error {
            return None;
        }
        let memo = self
            .keys
            .get(principal_id)
            .filter(|m| m.tip == tip.commit_id)?;
        for Peer { connector, .. } in peers {
            let Ok(heads) = peer_heads(connector, principal_id).await else {
                return None;
            };
            let Some(heads) = heads else { continue };
            // A peer that lists more heads than this server reads Error where it
            // does not: a proof moved its verdict and no head.
            if heads.tips().count() > ours.heads.len() {
                return None;
            }
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
        // A key revoked since the memo was read is no longer worth asking about.
        Some(
            memo.keys
                .iter()
                .filter(|t| !state.engine.is_revoked(&t.to_b64()))
                .cloned()
                .collect(),
        )
    }
}

/// Ask every peer for the naked revokes of `keys`, as a full pull's last
/// step does, and record what verified.
async fn probe_revokes(state: &Arc<AppState>, peers: &[Peer], keys: &[Thumbprint]) {
    let mut seen = BTreeSet::new();
    let mut revoked = Vec::new();
    for Peer {
        name, connector, ..
    } in peers
    {
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

/// A record of `principal_id` at the engine's tip, opened over the
/// engine's verified state of it (`StorageEngine::at_tip`): no commit is
/// replayed here, whether or not a peer answers.
async fn open_record(state: &Arc<AppState>, principal_id: &str) -> Result<Record, RoundError> {
    let at_tip = state
        .engine
        .at_tip(principal_id)
        .await?
        .ok_or(RoundError::Empty)?;
    let store = Arc::new(StoredChain {
        state: Arc::clone(state),
        principal_id: principal_id.to_owned(),
    });
    Ok(Record::resume(
        principal_id,
        at_tip.detach().await?,
        system_clock,
        store,
    )?)
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

async fn round_principal(
    state: &Arc<AppState>,
    peers: &[Peer],
    principal_id: &str,
) -> Result<KeyMemo, RoundError> {
    let mut record = open_record(state, principal_id).await?;
    let tip = record.tip().ok_or(RoundError::Empty)?;
    // The engine's verified revokes are not part of the state the record
    // resumed over: a key it already holds dead is not asked about again.
    let held = record
        .principal()
        .map_or_else(Vec::new, |p| p.ever_held_keys());
    for tmb in held.iter().filter(|t| state.engine.is_revoked(&t.to_b64())) {
        record.note_revoked(tmb);
    }
    let memo = KeyMemo {
        tip: tip.commit_id,
        keys: record.unrevoked_keys(),
    };
    let mark = record.log_len();

    // A peer with a configured server principal is asked for its signed tip
    // report first, and checked against the keys of that principal's chain;
    // one whose report does not verify is refused for the round, and nothing
    // from it is applied.
    let mut attested: Vec<(&Peer, Attested)> = Vec::new();
    let mut usable: Vec<&Peer> = Vec::new();
    for peer in peers {
        match verify_peer_tip(state, peer, principal_id).await {
            Ok(Some(report)) => {
                attested.push((peer, report));
                usable.push(peer);
            },
            Ok(None) => usable.push(peer),
            Err(why) => {
                warn!(principal = %principal_id, peer = %peer.name, %why, "gossip: peer refused");
            },
        }
    }
    let dialled: Vec<PullPeer<'_, HttpConnector>> = usable
        .iter()
        .map(|peer| PullPeer {
            name: &peer.name,
            connector: &peer.connector,
        })
        .collect();
    let report = pull(&mut record, &dialled).await;
    for outcome in &report.peers {
        debug!(principal = %principal_id, peer = %outcome.peer, standing = ?outcome.standing, "gossip: pulled");
    }

    // Verified revokes first, where the engine judges admission and forks
    // by them (SPEC 6.4, 15.7.1), so a dead key's later commits served in
    // this same round are refused.
    record_revokes(state, &report.revoked).await;

    for fork in &report.forks {
        warn!(principal = %principal_id, height = fork.height, commits = ?fork.commits, "gossip: principal fork");
    }
    // The engine refuses a rival as a tip but retains it as a branch (I2: a
    // fork is evidence, never merged), and accepts a forked peer's later
    // commits only if they verify (SPEC 15.8).
    let offered = branch_bundles(&record, &report, &dialled).await;
    let mut served = Vec::new();
    for peer in &usable {
        if let Some(offer) =
            peer_resync_offer(state, &peer.name, &peer.connector, principal_id).await
        {
            served.push(offer);
        }
    }
    let resyncs: Vec<ResyncOffer<'_>> = served
        .iter()
        .map(|(pops, chain)| ResyncOffer { pops, chain })
        .collect();
    let answers = state
        .engine
        .ingest_pulled(
            principal_id,
            &PulledOffer {
                genesis: None,
                commits: record.bundles_since(mark),
                branches: &offered,
                resyncs: &resyncs,
            },
        )
        .await;
    for answer in &answers.commits {
        match &answer.result {
            Ok(_) => info!(principal = %principal_id, "gossip: stored a verified commit"),
            // The principal may have advanced here since the round began
            // (a client's push): the engine refuses what it already holds.
            Err(err) => refused(principal_id, err, "gossip: commit not stored"),
        }
    }
    for answer in &answers.branches {
        match (&answer.result, answer.paired) {
            (Ok(_), false) => info!(principal = %principal_id, "gossip: a branch commit adopted"),
            (Ok(_), true) => info!(principal = %principal_id, "gossip: a branch pair adopted"),
            (Err(err), false) => refused(principal_id, err, "gossip: branch commit answered"),
            (Err(err), true) => refused(principal_id, err, "gossip: branch pair answered"),
        }
    }
    for answer in &answers.resyncs {
        match answer {
            Ok(receipt) if receipt.promoted => {
                info!(principal = %principal_id, "a resync proof made its line the chain");
            },
            Ok(receipt) if receipt.stored => {
                info!(principal = %principal_id, "a resync proof stored")
            },
            Ok(_) => {},
            Err(err) => refused(principal_id, err, "resync proof answered"),
        }
    }
    // The tip check proper: what this node now holds must be what the peer
    // signed. A peer whose report this node does not reach after applying
    // what verified is asked for its branches and evidence, which the engine
    // keeps if they verify (I2: a fork is evidence, never merged).
    for (peer, attestation) in &attested {
        let matches = match attestation {
            Attested::Tip(report) => tip_matches_report(
                state
                    .engine
                    .get_tip(principal_id)
                    .await
                    .ok()
                    .flatten()
                    .as_ref(),
                report,
            ),
            Attested::Held(held) => {
                let mut all = true;
                for head in &held.heads {
                    all &= state
                        .engine
                        .holds_commit(principal_id, &head.commit_id.to_string())
                        .await
                        .unwrap_or(false);
                }
                all
            },
        };
        if matches {
            continue;
        }
        warn!(principal = %principal_id, peer = %peer.name, "gossip: this node does not hold what the peer attests");
        offer_peer_branches(state, peer, principal_id).await;
    }
    state.metrics.gossip_replayed(record.replayed());
    Ok(memo)
}

/// The resync proofs `connector`'s peer holds for `principal_id` that this
/// server does not, each as the `{pay, sig}` coz it was served in.
pub(crate) async fn fresh_resyncs<C: Connector>(
    state: &AppState,
    peer: &str,
    connector: &C,
    principal_id: &str,
) -> Vec<serde_json::Value> {
    let served = match fetch_resyncs(connector, principal_id).await {
        Ok(served) => served,
        Err(err) => {
            debug!(%peer, %err, "resync proofs not fetched");
            return Vec::new();
        },
    };
    let held: BTreeSet<String> = state
        .engine
        .resyncs(principal_id)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|coz| coz["pay"]["id"].as_str().map(str::to_owned))
        .collect();
    served
        .into_iter()
        .filter(|coz| {
            coz["pay"]["id"]
                .as_str()
                .is_some_and(|id| !held.contains(id))
        })
        .collect()
}

/// Fetch `connector`'s peer's resync proofs for `principal_id` and, when it
/// holds any this server lacks, its chain: what the engine is offered
/// ([`StorageEngine::ingest_pulled`](cyphr_storage::engine::StorageEngine::ingest_pulled)).
async fn peer_resync_offer(
    state: &AppState,
    peer: &str,
    connector: &HttpConnector,
    principal_id: &str,
) -> Option<(Vec<serde_json::Value>, Vec<cyphr::replay::WireBundle>)> {
    let pops = fresh_resyncs(state, peer, connector, principal_id).await;
    if pops.is_empty() {
        return None;
    }
    let request = PatchRequest {
        principal_id,
        anchor: None,
    };
    let patch = match fetch_patch(connector, &request, BindingPolicy::NotRequired, None).await {
        Ok(patch) => patch,
        Err(err) => {
            debug!(%peer, %err, "gossip: chain for a resync proof not fetched");
            return None;
        },
    };
    let chain: Vec<cyphr::replay::WireBundle> = patch
        .entries
        .iter()
        .map_while(|e| e.bundle.clone().ok())
        .collect();
    Some((pops, chain))
}

/// Log the engine's answer to a commit gossip handed it. Most answers are
/// refusals of what the node already holds, which are routine; a failed
/// sync is not: the engine refuses every write until restart.
fn refused(principal_id: &str, err: &cyphr_storage::engine::EngineError, what: &str) {
    if matches!(err, cyphr_storage::engine::EngineError::DurabilityLost(_)) {
        error!(principal = %principal_id, %err, "{what}: the record is not durable");
    } else {
        debug!(principal = %principal_id, %err, "{what}");
    }
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

// ========================================================================
// The ingest core's other half: fetch a principal from a peer, check it
// ========================================================================

/// The key of `peer`'s server principal that signed a statement, from the
/// chain this node holds of it.
async fn peer_key(state: &AppState, pg: &str, tmb: &Thumbprint) -> Option<PeerKey> {
    let chain = state.engine.at_tip(pg).await.ok()??;
    chain
        .active_keys()
        .find(|k| k.tmb() == tmb)
        .map(|k| PeerKey {
            alg: k.alg().to_string(),
            pub_key: k.pub_key().to_vec(),
        })
}

/// Make sure this node holds `peer`'s server principal `pg`, fetching it
/// from the peer through the same core as any other principal.
async fn ensure_peer_chain(state: &Arc<AppState>, peer: &Peer, pg: &str) -> Result<(), String> {
    if state
        .engine
        .get_tip(pg)
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(());
    }
    let request = PatchRequest {
        principal_id: pg,
        anchor: None,
    };
    let patch = fetch_patch(&peer.connector, &request, BindingPolicy::NotRequired, None)
        .await
        .map_err(|e| e.to_string())?;
    apply_fetched(state, peer, pg, patch).await?;
    Ok(())
}

/// The peer's signed tip report for `principal_id`, verified against a key
/// active in the held chain of the peer's server principal. `Ok(None)` when
/// the peer has no `pg` (no check), holds nothing for the principal, or is
/// in Error (its statement names heads, not a tip). Until the chain is held,
/// and if the signing key is not in it even after one more fetch (a
/// rotation), the answer is an error: the peer is refused, not trusted.
async fn verify_peer_tip(
    state: &Arc<AppState>,
    peer: &Peer,
    principal_id: &str,
) -> Result<Option<Attested>, String> {
    let Some(pg) = peer.pg.as_deref() else {
        return Ok(None);
    };
    if bare(pg) == bare(principal_id) {
        return Ok(None);
    }
    ensure_peer_chain(state, peer, pg).await?;
    let body = match fetch_tip_body(&peer.connector, principal_id).await {
        Ok(body) => body,
        Err(PatchFailure::NonSuccess(404)) => return Ok(None),
        Err(err) => return Err(err.to_string()),
    };
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let in_error = value["payload"]["state"] == "error";
    let tmb = statement_signer(&body).ok_or("the tip is not signed")?;
    let mut key = peer_key(state, pg, &tmb).await;
    if key.is_none() {
        // The peer may have rotated: follow its chain once more.
        let _ = Box::pin(round_principal(state, std::slice::from_ref(peer), pg)).await;
        key = peer_key(state, pg, &tmb).await;
    }
    let key = key.ok_or("its signing key is not active in its server principal")?;
    if in_error {
        // A peer in Error attests heads, not a tip.
        return verify_held_envelope(&value, &key, principal_id)
            .map(|held| Some(Attested::Held(held)))
            .map_err(|e| e.to_string());
    }
    verify_authenticated_envelope(&value, &key, principal_id)
        .map(|report| Some(Attested::Tip(report)))
        .map_err(|e| e.to_string())
}

/// What a peer's verified signed statement attests: a tip, or, in Error, its
/// heads.
enum Attested {
    Tip(TipReport),
    Held(cyphr_client::HeldReport),
}

fn bare(id: &str) -> &str {
    cyphr_storage::engine::bare_digest(id)
}

/// Whether the tip this node holds is the one `report` attests. `report`'s
/// `sequence` is the attested commit's 0-indexed position, one below the
/// held commit count.
fn tip_matches_report(
    resulting: Option<&cyphr_storage::index::TipState>,
    report: &TipReport,
) -> bool {
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
    let report_cr = report.roots.cr.as_ref().map(ToString::to_string);
    tip.cr == report_cr.unwrap_or_default()
}

/// Ask `peer` for its branches and offer what comes back to the engine.
async fn offer_peer_branches(state: &Arc<AppState>, peer: &Peer, principal_id: &str) {
    let request = PatchRequest {
        principal_id,
        anchor: None,
    };
    let Ok(patch) = fetch_patch(&peer.connector, &request, BindingPolicy::NotRequired, None).await
    else {
        return;
    };
    let branches: Vec<cyphr::replay::WireBundle> = patch
        .fork
        .iter()
        .flat_map(|f| &f.branches)
        .flat_map(|b| &b.entries)
        .filter_map(|e| e.bundle.clone().ok())
        .collect();
    let answers = state
        .engine
        .ingest_pulled(
            principal_id,
            &PulledOffer {
                genesis: None,
                commits: &[],
                branches: &branches,
                resyncs: &[],
            },
        )
        .await;
    for answer in &answers.branches {
        if let Err(err) = &answer.result {
            refused(principal_id, err, "gossip: peer branch answered");
        }
    }
}

/// Fetch `principal_id` from `peer` and apply it: the whole chain from
/// genesis, for a principal this node holds nothing of, so there is no
/// record to resume. The engine binds the id to the genesis the first
/// commit discloses, as it does for a push. With `peer.pg` configured the
/// patch's signed statement must verify under a key of the held chain of
/// that principal, strictly before any entry is decoded, and the tip it
/// attests must be the one this node holds after applying.
///
/// Returns the number of commits applied.
async fn fetch_unheld(
    state: &Arc<AppState>,
    peer: &Peer,
    principal_id: &str,
    check: bool,
) -> Result<usize, String> {
    let request = PatchRequest {
        principal_id,
        anchor: None,
    };
    let patch = match peer
        .pg
        .as_deref()
        .filter(|pg| check && bare(pg) != bare(principal_id))
    {
        None => fetch_patch(&peer.connector, &request, BindingPolicy::NotRequired, None).await,
        Some(pg) => {
            ensure_peer_chain(state, peer, pg).await?;
            let mut chain = state.engine.at_tip(pg).await.map_err(|e| e.to_string())?;
            let mut patch = None;
            for attempt in 0..2 {
                let held = chain.take();
                let lookup = |tmb: &Thumbprint| {
                    held.as_ref().and_then(|c| {
                        c.active_keys().find(|k| k.tmb() == tmb).map(|k| PeerKey {
                            alg: k.alg().to_string(),
                            pub_key: k.pub_key().to_vec(),
                        })
                    })
                };
                match fetch_patch_keyed(
                    &peer.connector,
                    &request,
                    BindingPolicy::NotRequired,
                    lookup,
                )
                .await
                {
                    Err(PatchFailure::EnvelopeUnsignedOrMisSigned) if attempt == 0 => {
                        // The peer may have rotated: follow its chain once more.
                        let _ =
                            Box::pin(round_principal(state, std::slice::from_ref(peer), pg)).await;
                        chain = state.engine.at_tip(pg).await.map_err(|e| e.to_string())?;
                    },
                    other => {
                        patch = Some(other);
                        break;
                    },
                }
            }
            patch.unwrap_or(Err(PatchFailure::EnvelopeUnsignedOrMisSigned))
        },
    }
    .map_err(|e| e.to_string())?;
    apply_fetched(state, peer, principal_id, patch).await
}

/// Apply a verified patch of `principal_id` fetched from `peer`, and check
/// the tip it attests against the one this node then holds.
async fn apply_fetched(
    state: &Arc<AppState>,
    peer: &Peer,
    principal_id: &str,
    patch: cyphr_client::VerifiedPatch,
) -> Result<usize, String> {
    // In Error `entries` ends with the canonical branch, which is handled
    // with the others below. The counts come off the wire: a peer
    // overstating the canonical branch must not wrap the subtraction.
    let common_len = patch.entries.len().saturating_sub(
        patch
            .fork
            .iter()
            .flat_map(|f| &f.branches)
            .find(|b| b.canonical)
            .map_or(0, |b| b.entries.len()),
    );
    let commits: Vec<cyphr::replay::WireBundle> = patch
        .entries
        .iter()
        .take(common_len)
        .filter_map(|e| match &e.bundle {
            Ok(bundle) => Some(bundle.clone()),
            Err(defect) => {
                warn!(principal = %principal_id, sequence = e.sequence, ?defect, "patch entry undecodable; skipping");
                None
            },
        })
        .collect();
    // Each branch's entries as positions among the branch bundles offered
    // below: a head the caps refuse is bound to the bytes of its branch's
    // last entry and to the answers to those entries.
    let mut branches: Vec<cyphr::replay::WireBundle> = Vec::new();
    let mut branch_at: Vec<(String, Vec<usize>)> = Vec::new();
    for branch in patch.fork.iter().flat_map(|f| &f.branches) {
        let mut positions = Vec::new();
        for entry in &branch.entries {
            match &entry.bundle {
                Ok(bundle) => {
                    positions.push(branches.len());
                    branches.push(bundle.clone());
                },
                Err(defect) => {
                    warn!(principal = %principal_id, ?defect, "branch entry undecodable; skipping");
                },
            }
        }
        branch_at.push((branch.head.clone(), positions));
    }

    // The peer's verified revokes of the keys these commits name go to the
    // engine first, so its admission refuses what a dead key signed after
    // its death (SPEC 6.4).
    let mut keys: Vec<Thumbprint> = Vec::new();
    for named in commits
        .iter()
        .chain(&branches)
        .filter_map(|b| b.decode().ok())
        .flat_map(|b| b.named_keys())
    {
        if !keys.contains(&named) {
            keys.push(named);
        }
    }
    match verified_revokes(&peer.connector, &peer.name, &keys).await {
        Ok((found, _)) => record_revokes(state, &found).await,
        Err(err) => debug!(principal = %principal_id, %err, "revokes not fetched"),
    }

    // Resync proofs: a fork the peer resolved by proof, which no commit
    // shows, resolves here before the tip is compared.
    let pops = fresh_resyncs(state, &peer.name, &peer.connector, principal_id).await;
    let chain: Vec<cyphr::replay::WireBundle> = patch
        .entries
        .iter()
        .filter_map(|e| e.bundle.clone().ok())
        .collect();
    let resyncs = [ResyncOffer {
        pops: &pops,
        chain: &chain,
    }];
    let answers = state
        .engine
        .ingest_pulled(
            principal_id,
            &PulledOffer {
                genesis: None,
                commits: &commits,
                branches: &branches,
                resyncs: if pops.is_empty() { &[] } else { &resyncs },
            },
        )
        .await;
    let mut applied = 0;
    for answer in &answers.commits {
        match &answer.result {
            Ok(_) => applied += 1,
            Err(err) => refused(principal_id, err, "fetch: commit not stored"),
        }
    }
    let mut cap_refused: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (j, answer) in answers.branches.iter().enumerate() {
        if let Err(err) = &answer.result {
            refused(principal_id, err, "fetch: branch commit answered");
            if matches!(
                err,
                cyphr_storage::engine::EngineError::BranchLimit { .. }
                    | cyphr_storage::engine::EngineError::Errored { .. }
            ) {
                cap_refused.insert(j);
            }
        }
    }
    // A peer in Error attests heads, not a tip: this node must hold every
    // one, or have the line to it held to the cap, bound to the bytes of
    // its last entry (SPEC 15.7.1).
    if let Some(held) = &patch.held {
        for head in &held.heads {
            let id = head.commit_id.to_string();
            let held_now = state
                .engine
                .holds_commit(principal_id, &id)
                .await
                .map_err(|e| e.to_string())?;
            if !head_is_bound(
                state,
                principal_id,
                &head.commit_id,
                held_now,
                &branch_at,
                &branches,
                &cap_refused,
            )
            .await
            {
                return Err(format!("a head of the peer is not held: {id}"));
            }
        }
    }
    if let Some(report) = &patch.report {
        let resulting = state
            .engine
            .get_tip(principal_id)
            .await
            .map_err(|e| e.to_string())?;
        if !tip_matches_report(resulting.as_ref(), report) {
            return Err(
                "the resulting tip is not the one the peer attests: entries were withheld or \
                 substituted"
                    .into(),
            );
        }
    }
    Ok(applied)
}

/// A read asked for `principal_id`: fetch it from the configured peers when
/// the setting says so (`[gossip] fetch_on_read`, on for a witness). A
/// principal this node holds is pulled as the gossip timer pulls it; one it
/// does not hold is fetched from genesis, from the peers in order, stopping
/// at the first that yields it. A refusal or a failure leaves the local
/// answer as it was.
pub(crate) async fn fetch_on_read(state: &Arc<AppState>, principal_id: &str) {
    if state.config.fetches_on_read() {
        fetch_from_peers(state, principal_id).await;
    }
}

/// The fetch a read triggers, whatever `fetch_on_read` says: bring
/// `principal_id` in step with the configured peers, as one gossip round
/// does for a held principal and a fetch from genesis does for one that is
/// not held.
pub async fn fetch_from_peers(state: &Arc<AppState>, principal_id: &str) {
    if let Err(why) = try_fetch_from_peers(state, principal_id).await {
        warn!(principal = %principal_id, %why, "fetch from peers: refused");
    }
}

/// [`fetch_from_peers`], answering why a peer was refused: the patch of a
/// peer in Error, whose signed held statement attests heads, is applied and
/// each head must be held, or bound to the capped line the peer served
/// (`head_is_bound`); otherwise the peer is refused.
///
/// # Errors
///
/// The reason a peer's answer was refused.
pub async fn try_fetch_from_peers(state: &Arc<AppState>, principal_id: &str) -> Result<(), String> {
    let peers = peers_of(state);
    let mut refusal = None;
    match state.engine.get_tip(principal_id).await {
        Ok(Some(_)) => {
            if let Err(err) = round_principal(state, &peers, principal_id).await {
                debug!(principal = %principal_id, %err, "fetch on read: round skipped");
            }
            for peer in &peers {
                if let Ok(Some(Attested::Held(_))) =
                    verify_peer_tip(state, peer, principal_id).await
                    && let Err(why) = fetch_unheld(state, peer, principal_id, true).await
                {
                    refusal = Some(why);
                }
            }
        },
        Ok(None) => {
            for peer in &peers {
                match fetch_unheld(state, peer, principal_id, true).await {
                    Ok(_) => return Ok(()),
                    Err(why) => {
                        warn!(principal = %principal_id, peer = %peer.name, %why, "fetch on read: refused");
                        refusal = Some(why);
                    },
                }
            }
        },
        Err(err) => return Err(format!("local tip lookup failed: {err}")),
    }
    refusal.map_or(Ok(()), Err)
}

/// Whether the attested head `head` is bound to a branch of the peer's
/// patch. All of:
/// 1. `head` is the commit id computed from the bytes of the last entry of one branch the peer
///    names it the head of;
/// 2. the entries of that branch this node holds chain: each held entry extends the held entry
///    before it;
/// 3. if this node does not hold `head`, it holds the branch to the cap (its first entry off its
///    own chain, and the entry after it if there is one), and every entry past the cap is one it
///    does not hold and answered by the cap (`BranchLimit` or `Errored`, in `cap_refused`).
///
/// What this does not check is that entries this node does not hold chain
/// to each other: a commit's `pre` is bound only inside its arrow. Its harm
/// is bounded: this node's own standing and fork point do not depend on it.
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
        let cap = state.engine.branch_depth();
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
