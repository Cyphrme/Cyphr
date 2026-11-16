//! The abstract model: what each op must leave behind.
//!
//! It has no dependency on `cyphr` core and no fork rules: the honest
//! network never forks. That is by construction, not by luck. Every write
//! to a principal goes through one *home* peer (its first holder), so the
//! home's tip is the owner's chain, and the other holders only follow by
//! gossip. Two devices of one principal therefore never push different
//! commits to different peers; the second of two concurrent devices meets
//! the first one's commit at the home and is refused Stale.
//!
//! The model counts what an observer can read off a peer without trusting
//! the peer: chain height (`commit_count`). It also
//! tracks which peers are stopped or cut off, so the generator and the
//! driver agree on which ops are possible.

use std::collections::BTreeSet;

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
    /// Backup keys `key add` made, which `key delete` may retire. A
    /// multikey genesis's second key is not counted: the driver is never
    /// told its thumbprint.
    pub deletable: usize,
    /// Commits in the chain.
    pub height: u64,
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
}

impl Model {
    pub fn new(peers: usize) -> Model {
        Model {
            peers,
            principals: Vec::new(),
            partitioned: BTreeSet::new(),
            degraded: BTreeSet::new(),
            down: BTreeSet::new(),
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
        Ok(pm)
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
                    deletable: 0,
                    height: GENESIS_HEIGHT,
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
                pm.deletable += 1;
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
                if pm.deletable == 0 {
                    return Err(format!("`{op}`: principal {p} has no deletable key"));
                }
                pm.height += 1;
                pm.keys -= 1;
                pm.deletable -= 1;
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
            Op::Barrier => {
                self.partitioned.clear();
                self.degraded.clear();
                self.down.clear();
            },
        }
        Ok(())
    }
}
