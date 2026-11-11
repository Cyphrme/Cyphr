//! Embedded-principal tips over gossip: a [`TipSource`] backed by the pull
//! step (SPEC be0663f §10.3, §10.7; GOSSIP-MIN section 2).
//!
//! For each embedded principal it follows, [`GossipTips`] keeps the
//! verifier's own [`Record`] and pulls it from each chosen peer in turn.
//! The tip it hands the core is the record after those pulls, stamped
//! with the verifier's clock at the last pull a peer answered, with the
//! keys the pulls saw naked-revoked, and in `Error` if any pull found a
//! fork. What the pulls saw is kept as a [`FollowReport`]: when each peer
//! was pulled, which peers answered, and B's newest `now`. A followed tip
//! is never reported as current: it is as old as its pull.

use std::collections::BTreeMap;

use cyphr::principal::Clock;
use cyphr::{Tip, TipSource};

use crate::connector::Connector;
use crate::sync::{PeerStanding, PullPeer, Record, pull};

/// One peer's part in a follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPull {
    /// The peer's name.
    pub peer: String,
    /// The verifier's clock when the pull from this peer ended.
    pub pulled_at: i64,
    /// Whether the peer answered (served something the record could be
    /// compared with), rather than failing.
    pub answered: bool,
}

/// What one retrieval of an embedded principal's tip saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowReport {
    /// The embedded digest followed, tagged.
    pub member: String,
    /// Each peer, in the order pulled.
    pub peers: Vec<PeerPull>,
    /// The newest `now` in the record after the pulls; `None` if no chain
    /// is held.
    pub newest_now: Option<i64>,
    /// Whether a pull found a fork (B in `Error`).
    pub forked: bool,
}

impl FollowReport {
    /// How old each answering peer's pull is at `now`, by peer name.
    #[must_use]
    pub fn pull_ages(&self, now: i64) -> Vec<(&str, i64)> {
        self.peers
            .iter()
            .filter(|p| p.answered)
            .map(|p| (p.peer.as_str(), now - p.pulled_at))
            .collect()
    }

    /// How old B's newest `now` is at `now`.
    #[must_use]
    pub fn newest_age(&self, now: i64) -> Option<i64> {
        self.newest_now.map(|n| now - n)
    }
}

/// A [`TipSource`] that pulls each followed principal from `peers`.
pub struct GossipTips<'a, C> {
    peers: &'a [PullPeer<'a, C>],
    clock: Clock,
    records: BTreeMap<String, Record>,
    reports: Vec<FollowReport>,
}

impl<'a, C: Connector> GossipTips<'a, C> {
    /// A source pulling from `peers`, stamping pulls with `clock`.
    #[must_use]
    pub fn new(peers: &'a [PullPeer<'a, C>], clock: Clock) -> Self {
        Self {
            peers,
            clock,
            records: BTreeMap::new(),
            reports: Vec::new(),
        }
    }

    /// Follow the embedded digest `member` (tagged, as A's KT holds it)
    /// through `record`, the verifier's record of that principal.
    #[must_use]
    pub fn follow(mut self, member: &str, record: Record) -> Self {
        self.records.insert(member.to_owned(), record);
        self
    }

    /// What each retrieval saw, oldest first.
    #[must_use]
    pub fn reports(&self) -> &[FollowReport] {
        &self.reports
    }
}

impl<C: Connector> TipSource for GossipTips<'_, C> {
    async fn tip(&mut self, member: &str) -> Option<Tip> {
        let record = self.records.get_mut(member)?;
        let mut report = FollowReport {
            member: member.to_owned(),
            peers: Vec::with_capacity(self.peers.len()),
            newest_now: None,
            forked: false,
        };
        for peer in self.peers {
            let pulled = pull(record, std::slice::from_ref(peer)).await;
            report.forked |= !pulled.forks.is_empty();
            report.peers.push(PeerPull {
                peer: peer.name.to_owned(),
                pulled_at: (self.clock)(),
                answered: pulled
                    .peers
                    .iter()
                    .all(|o| !matches!(o.standing, PeerStanding::Failed(_))),
            });
        }
        let pulled_at = report
            .peers
            .iter()
            .rev()
            .find(|p| p.answered)
            .map(|p| p.pulled_at);
        let tip = record.principal().zip(pulled_at).map(|(b, at)| {
            let tip = Tip::new(b, at).with_revoked(record.dead_keys().map(|(tmb, _)| tmb));
            if report.forked { tip.in_error() } else { tip }
        });
        report.newest_now = tip.as_ref().map(Tip::newest_now);
        self.reports.push(report);
        tip
    }
}
