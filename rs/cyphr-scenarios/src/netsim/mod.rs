//! NETSIM: a seeded, randomized scenario over a whole gossiping network.
//!
//! A pure generator turns `(seed, Size)` into an op log; an abstract model
//! with no dependency on `cyphr` core says what every op must leave behind;
//! a driver runs the log against real `cyphr-server` processes through the
//! `cyphr` CLI and checks the network invariants at epoch barriers. The
//! processes and the gossip timer are real, so interleaving is not
//! deterministic; the design makes the expected outcome independent of it
//! (see [`model`]).
//!
//! Invariants checked here (NETSIM-1, the honest network):
//! - N1: after quiescence every holder of an unforked principal agrees with the owner's own signed
//!   chain (tip, height, `pr`, `ar`).
//! - N2: an honest op over an unfaulted link is accepted, or is refused Stale and then accepted
//!   after a rebase; nothing else.
//! - N6: no peer ever answered 5xx or 429 (summed over every process lifetime), and no peer log
//!   holds a panic.

use std::time::Duration;

pub mod check;
pub mod model;
pub mod plan;
pub mod run;

/// How big a run is. One generator serves every size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Size {
    pub peers: usize,
    pub principals: usize,
    /// Operations after the setup creates, split into `epochs` by barriers.
    pub ops: usize,
    pub epochs: usize,
    /// Principals acting at once.
    pub concurrency: usize,
    /// Each principal is published to this many peers, inclusive range.
    pub holders: (usize, usize),
    /// How long a barrier waits for convergence before reporting
    /// non-convergence.
    pub converge: Duration,
}

impl Size {
    /// The gating size.
    pub fn ci() -> Size {
        Size {
            peers: 5,
            principals: 12,
            ops: 80,
            epochs: 3,
            concurrency: 4,
            holders: (3, 5),
            converge: Duration::from_secs(120),
        }
    }

    /// The manual size. Every pair of peers shares well over 50 principals'
    /// worth of gossip traffic only here, which is what it measures.
    pub fn large() -> Size {
        Size {
            peers: 9,
            principals: 60,
            ops: 2000,
            epochs: 20,
            concurrency: 8,
            holders: (7, 9),
            converge: Duration::from_secs(600),
        }
    }

    /// `CYPHR_NETSIM_SIZE=large` selects the manual size; anything else
    /// (or nothing) is the gating size.
    pub fn from_env() -> Size {
        match std::env::var("CYPHR_NETSIM_SIZE").as_deref() {
            Ok("large") => Size::large(),
            _ => Size::ci(),
        }
    }

    pub fn peer_names(&self) -> Vec<String> {
        (0..self.peers).map(|i| format!("p{i}")).collect()
    }
}
