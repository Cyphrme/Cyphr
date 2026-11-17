//! The abstract model: what each op must leave behind.
//!
//! It has no dependency on `cyphr` core and decides no fork outcome. The
//! honest ops never fork, by construction: every write to a principal goes
//! through one *home* peer (its first holder), so the home's tip is the
//! owner's chain, and the other holders only follow by gossip. Two devices
//! of one principal therefore never push different commits to different
//! peers; the second of two concurrent devices meets the first one's commit
//! at the home and is refused Stale.
//!
//! The two episodes that do fork a principal (a second device forking it,
//! a thief forking it) are built, not raced, and each follows the one flow
//! the hand-written scenarios already pin: two extended branches resolved
//! by the owner's next commit, or a stolen key's branch resolved by the
//! owner's `key/delete`. The model records only the chain the owner is left
//! with; which branch peers hold in between is read from the peers' own
//! evidence by the oracle, never predicted here.
//!
//! The model counts what an observer can read off a peer without trusting
//! the peer: chain height (`commit_count`). It also
//! tracks which peers are stopped or cut off, so the generator and the
//! driver agree on which ops are possible.

use std::collections::{BTreeSet, VecDeque};

use super::plan::Op;

/// A principal created with `--genesis-commit` or `init --keys` starts at
/// one commit.
pub const GENESIS_HEIGHT: u64 = 1;
pub const MAX_DEVICES: usize = 2;

#[derive(Clone, Debug)]
pub struct PrincipalModel {
    /// Peers the principal is published to; `holders[0]` is its home.
    pub holders: Vec<usize>,
    pub devices: usize,
    /// Active keys.
    pub keys: usize,
    /// The device holding each backup key `key add` made, oldest first.
    /// `key delete` or a naked revoke retires the oldest. A multikey
    /// genesis's second key is not counted: the driver is never told its
    /// thumbprint.
    pub backups: VecDeque<usize>,
    /// Commits in the chain.
    pub height: u64,
    /// A theft deleted the second device's key, the only one of its hash
    /// algorithm, and the owner's local store then fails a later commit
    /// (reproduced by `tests/netsim_findings.rs`). No op may commit to the
    /// principal again; reads still apply. Delete this field and its uses
    /// when that test passes.
    pub spent: bool,
}

#[derive(Clone, Debug)]
pub struct Model {
    pub peers: usize,
    pub principals: Vec<PrincipalModel>,
    /// Cut gossip links, as `(a, b)` with `a < b`.
    pub partitioned: BTreeSet<(usize, usize)>,
    /// Links with delay or drops applied.
    pub degraded: BTreeSet<(usize, usize)>,
    pub down: BTreeSet<usize>,
    /// The peer with a backup not yet restored.
    pub backed_up: Option<usize>,
    /// Whether the run's one peer key rollover has happened.
    pub rolled: bool,
}

impl Model {
    pub fn new(peers: usize) -> Model {
        Model {
            peers,
            principals: Vec::new(),
            partitioned: BTreeSet::new(),
            degraded: BTreeSet::new(),
            down: BTreeSet::new(),
            backed_up: None,
            rolled: false,
        }
    }

    fn principal(&mut self, op: &Op, p: usize, d: usize) -> Result<&mut PrincipalModel, String> {
        let peers_down = self.down.clone();
        let pm = self
            .principals
            .get_mut(p)
            .ok_or_else(|| format!("`{op}`: no principal {p}"))?;
        if peers_down.contains(&pm.holders[0]) {
            return Err(format!("`{op}`: home peer {} is stopped", pm.holders[0]));
        }
        if d >= pm.devices {
            return Err(format!("`{op}`: principal {p} has {} devices", pm.devices));
        }
        if pm.spent {
            return Err(format!("`{op}`: principal {p} is spent: its store cannot commit past a deleted paired key"));
        }
        Ok(pm)
    }

    /// An episode needs a principal with two devices and two holders, every
    /// peer running, and starts by healing every link.
    fn episode(&mut self, op: &Op, p: usize) -> Result<(), String> {
        if !self.down.is_empty() {
            return Err(format!("`{op}`: every peer must be running"));
        }
        let pm = self.principal(op, p, 0)?;
        if pm.devices != 2 || pm.holders.len() < 2 {
            return Err(format!("`{op}`: needs two devices and two holders"));
        }
        self.partitioned.clear();
        self.degraded.clear();
        Ok(())
    }

    fn link(&self, op: &Op, a: usize, b: usize) -> Result<(usize, usize), String> {
        if a >= b || b >= self.peers {
            return Err(format!(
                "`{op}`: not a link of {} peers (need a < b)",
                self.peers
            ));
        }
        Ok((a, b))
    }

    /// Advance the model by one op, or say why the op is not valid here.
    pub fn apply(&mut self, op: &Op) -> Result<(), String> {
        match op {
            Op::Create {
                p,
                multikey,
                holders,
            } => {
                if *p != self.principals.len() {
                    return Err(format!(
                        "`{op}`: next principal is {}",
                        self.principals.len()
                    ));
                }
                let distinct: BTreeSet<_> = holders.iter().collect();
                if holders.is_empty()
                    || distinct.len() != holders.len()
                    || holders
                        .iter()
                        .any(|h| *h >= self.peers || self.down.contains(h))
                {
                    return Err(format!("`{op}`: holders must be distinct, running peers"));
                }
                self.principals.push(PrincipalModel {
                    holders: holders.clone(),
                    devices: 1,
                    keys: if *multikey { 2 } else { 1 },
                    backups: VecDeque::new(),
                    height: GENESIS_HEIGHT,
                    spent: false,
                });
            },
            Op::Commit { p, d } => {
                let pm = self.principal(op, *p, *d)?;
                pm.height += 1;
            },
            // An action recorded but not committed moves no height.
            Op::Record { p, d } => {
                self.principal(op, *p, *d)?;
            },
            Op::AddKey { p, d } => {
                let pm = self.principal(op, *p, *d)?;
                pm.height += 1;
                pm.keys += 1;
                pm.backups.push_back(*d);
            },
            Op::Pair { p, d } => {
                let pm = self.principal(op, *p, *d)?;
                if pm.devices >= MAX_DEVICES {
                    return Err(format!(
                        "`{op}`: principal {p} already has {MAX_DEVICES} devices"
                    ));
                }
                pm.height += 1;
                pm.keys += 1;
                pm.devices += 1;
            },
            // The acting device swaps its own key: the key count is kept.
            Op::Replace { p, d } => self.principal(op, *p, *d)?.height += 1,
            Op::DelKey { p, d } => {
                let pm = self.principal(op, *p, *d)?;
                if pm.backups.pop_front().is_none() {
                    return Err(format!("`{op}`: principal {p} has no deletable key"));
                }
                pm.height += 1;
                pm.keys -= 1;
            },
            // The key's own device signs the revoke, then the owner's
            // `key/delete` commit retires it (SPEC 6.4).
            Op::NakedRevoke { p, d } => {
                let peers_down = self.down.clone();
                let pm = self.principal(op, *p, *d)?;
                // The CLI sends the revoke to every peer it knows for the
                // principal, which after publication is every holder; one
                // stopped holder makes the whole send fail.
                if pm.holders.iter().any(|h| peers_down.contains(h)) {
                    return Err(format!("`{op}`: every holder must be running"));
                }
                if pm.backups.front() != Some(d) {
                    return Err(format!("`{op}`: device {d} does not hold the oldest backup"));
                }
                pm.backups.pop_front();
                pm.height += 1;
                pm.keys -= 1;
            },
            // Two devices fork the principal on opposite sides of a cut and
            // the first resolves it: its two commits plus the resolving one.
            // The second device is left holding the abandoned branch.
            Op::Fork { p } => {
                self.episode(op, *p)?;
                let pm = &mut self.principals[*p];
                pm.height += 3;
                pm.devices = 1;
                pm.backups.retain(|d| *d == 0);
            },
            // A thief with the second device's key forks the principal; the
            // owner's first device commits, revokes the key and deletes it.
            Op::Theft { p } => {
                self.episode(op, *p)?;
                let pm = &mut self.principals[*p];
                pm.height += 2;
                pm.keys -= 1;
                pm.devices = 1;
                pm.backups.retain(|d| *d == 0);
                pm.spent = true;
            },
            Op::Concurrent { p } => {
                let pm = self.principal(op, *p, 0)?;
                if pm.devices != 2 {
                    return Err(format!("`{op}`: needs two devices"));
                }
                // Both commits end up in the chain: the second is rebased.
                pm.height += 2;
            },
            Op::Partition { a, b } => {
                let l = self.link(op, *a, *b)?;
                self.partitioned.insert(l);
            },
            Op::Heal { a, b } => {
                let l = self.link(op, *a, *b)?;
                if !self.partitioned.remove(&l) {
                    return Err(format!("`{op}`: link is not cut"));
                }
            },
            Op::Degrade { a, b, .. } => {
                let l = self.link(op, *a, *b)?;
                self.degraded.insert(l);
            },
            Op::Calm { a, b } => {
                let l = self.link(op, *a, *b)?;
                if !self.degraded.remove(&l) {
                    return Err(format!("`{op}`: link is not degraded"));
                }
            },
            Op::Stop { peer } => {
                if *peer >= self.peers || !self.down.is_empty() {
                    return Err(format!("`{op}`: one stopped peer at a time"));
                }
                self.down.insert(*peer);
            },
            Op::Start { peer } => {
                if !self.down.remove(peer) {
                    return Err(format!("`{op}`: peer is not stopped"));
                }
            },
            Op::Backup { peer } => {
                if *peer >= self.peers || self.down.contains(peer) || self.backed_up.is_some() {
                    return Err(format!("`{op}`: needs a running peer and no backup held"));
                }
                self.backed_up = Some(*peer);
            },
            Op::Restore { peer } => {
                if self.backed_up != Some(*peer) || self.down.contains(peer) {
                    return Err(format!("`{op}`: needs the running peer that was backed up"));
                }
                self.backed_up = None;
            },
            Op::RollPeerKey { peer } => {
                if *peer >= self.peers || self.down.contains(peer) || self.rolled {
                    return Err(format!("`{op}`: once per run, on a running peer"));
                }
                self.rolled = true;
            },
            // Checks deferred to the next barrier; they change no state.
            Op::Verdict { p } | Op::SignIn { p } => {
                if *p >= self.principals.len() {
                    return Err(format!("`{op}`: no principal {p}"));
                }
            },
            Op::VerifyAll { peer } => {
                if *peer >= self.peers {
                    return Err(format!("`{op}`: no peer {peer}"));
                }
            },
            Op::Barrier => {
                self.partitioned.clear();
                self.degraded.clear();
                self.down.clear();
            },
        }
        Ok(())
    }
}
