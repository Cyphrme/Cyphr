//! Fault vocabulary and seeded schedules.
//!
//! A [`World`] is the pure state of every injected fault; a [`Schedule`]
//! is a seeded, replayable list of timed [`FaultKind`] transitions over
//! it. Keeping both pure means "same seed, same faults" is checkable
//! without any network.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// An undirected connection between two named nodes. Construction
/// normalises the order, so `Link::new(a, b) == Link::new(b, a)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Link(String, String);

impl Link {
    pub fn new(a: &str, b: &str) -> Self {
        if a <= b {
            Self(a.to_owned(), b.to_owned())
        } else {
            Self(b.to_owned(), a.to_owned())
        }
    }

    pub fn touches(&self, node: &str) -> bool {
        self.0 == node || self.1 == node
    }
}

/// Faults currently applied to one link.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LinkFault {
    pub partitioned: bool,
    /// Added before every forwarded chunk.
    pub delay: Duration,
    /// Probability that a new connection is dropped on arrival.
    pub drop: f64,
}

/// One state transition of the fault world.
#[derive(Clone, Debug, PartialEq)]
pub enum FaultKind {
    Partition(Link),
    Heal(Link),
    Delay(Link, Duration),
    Drop(Link, f64),
    Offline(String),
    Online(String),
}

/// Every injected fault, by link and by node.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct World {
    pub links: BTreeMap<Link, LinkFault>,
    pub offline: BTreeSet<String>,
}

impl World {
    pub fn apply(&mut self, fault: &FaultKind) {
        match fault {
            FaultKind::Partition(l) => self.links.entry(l.clone()).or_default().partitioned = true,
            FaultKind::Heal(l) => self.links.entry(l.clone()).or_default().partitioned = false,
            FaultKind::Delay(l, d) => self.links.entry(l.clone()).or_default().delay = *d,
            FaultKind::Drop(l, p) => self.links.entry(l.clone()).or_default().drop = *p,
            FaultKind::Offline(n) => {
                self.offline.insert(n.clone());
            },
            FaultKind::Online(n) => {
                self.offline.remove(n);
            },
        }
    }

    /// Whether traffic on `link` must not flow at all.
    pub fn blocked(&self, link: &Link) -> bool {
        self.links.get(link).is_some_and(|f| f.partitioned)
            || self.offline.iter().any(|n| link.touches(n))
    }

    pub fn fault(&self, link: &Link) -> LinkFault {
        self.links.get(link).cloned().unwrap_or_default()
    }
}

/// A fault applied `at` an offset from the start of a run.
#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub at: Duration,
    pub fault: FaultKind,
}

/// A replayable fault timeline derived entirely from `seed`.
#[derive(Clone, Debug, PartialEq)]
pub struct Schedule {
    pub seed: u64,
    pub events: Vec<Event>,
}

impl Schedule {
    /// Derive `len` (at least one) events over `nodes`. ChaCha8 is a
    /// specified algorithm, so a seed means the same stream on every
    /// platform, unlike `StdRng`, which the rand docs reserve the right
    /// to change between releases.
    pub fn generate(seed: u64, nodes: &[&str], len: usize) -> Self {
        assert!(
            nodes.len() >= 2,
            "a schedule needs two nodes to fault a link"
        );
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut at = Duration::ZERO;
        let events = (0..len.max(1))
            .map(|_| {
                at += Duration::from_millis(rng.gen_range(5..50));
                let a = rng.gen_range(0..nodes.len());
                let b = (a + rng.gen_range(1..nodes.len())) % nodes.len();
                let link = Link::new(nodes[a], nodes[b]);
                let fault = match rng.gen_range(0..6) {
                    0 => FaultKind::Partition(link),
                    1 => FaultKind::Heal(link),
                    2 => FaultKind::Delay(link, Duration::from_millis(rng.gen_range(1..200))),
                    3 => FaultKind::Drop(link, rng.gen_range(0.0..1.0)),
                    4 => FaultKind::Offline(nodes[a].to_owned()),
                    _ => FaultKind::Online(nodes[a].to_owned()),
                };
                Event { at, fault }
            })
            .collect();
        Self { seed, events }
    }

    /// The world after every event has applied.
    pub fn final_world(&self) -> World {
        let mut w = World::default();
        for e in &self.events {
            w.apply(&e.fault);
        }
        w
    }
}
