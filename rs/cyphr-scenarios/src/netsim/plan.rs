//! The op vocabulary and the pure generator `(seed, Size) -> Vec<Op>`.
//!
//! Ops name principals, devices and peers by index; the driver binds them
//! to real keys and processes at run time (keys are fresh every run). The
//! generator folds over the [`Model`], so it only emits ops that are valid
//! at that point of the log (never deleting the last key, never writing
//! through a stopped peer). Everything is drawn from one ChaCha8 stream in
//! order, so the first `n` ops of a log are the same for every `n`.

use std::fmt;
use std::str::FromStr;

use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Size;
use super::model::{MAX_DEVICES, Model};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A new principal, published to every holder. `holders[0]` is its home.
    Create {
        p: usize,
        multikey: bool,
        holders: Vec<usize>,
    },
    /// A data commit, pushed to the home peer.
    Commit {
        p: usize,
        d: usize,
    },
    /// A signed action recorded but not committed, pushed to the home peer.
    Record {
        p: usize,
        d: usize,
    },
    /// `key add`: one more backup key.
    AddKey {
        p: usize,
        d: usize,
    },
    /// Pair a second device into the principal.
    Pair {
        p: usize,
        d: usize,
    },
    /// `key replace`: the acting device swaps its own key.
    Replace {
        p: usize,
        d: usize,
    },
    /// `key delete` of the oldest backup key.
    DelKey {
        p: usize,
        d: usize,
    },
    /// Both devices commit from one tip; the second is refused Stale and
    /// rebases.
    Concurrent {
        p: usize,
    },
    /// Cut the gossip link between two peers.
    Partition {
        a: usize,
        b: usize,
    },
    Heal {
        a: usize,
        b: usize,
    },
    /// Delay every chunk and drop a share of new connections on the link.
    Degrade {
        a: usize,
        b: usize,
        delay_ms: u64,
        drop_pct: u8,
    },
    /// Remove delay and drops from the link.
    Calm {
        a: usize,
        b: usize,
    },
    Stop {
        peer: usize,
    },
    Start {
        peer: usize,
    },
    /// Heal every link, start every peer, wait for quiescence, check N1/N6.
    Barrier,
}

impl Op {
    /// The principal a principal-scoped op acts on. Such ops of different
    /// principals may run at once; every other op is a fence.
    pub fn principal(&self) -> Option<usize> {
        match self {
            Op::Create { p, .. }
            | Op::Commit { p, .. }
            | Op::Record { p, .. }
            | Op::AddKey { p, .. }
            | Op::Pair { p, .. }
            | Op::Replace { p, .. }
            | Op::DelKey { p, .. }
            | Op::Concurrent { p } => Some(*p),
            _ => None,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Create {
                p,
                multikey,
                holders,
            } => {
                let hs: Vec<String> = holders.iter().map(usize::to_string).collect();
                write!(
                    f,
                    "create p={p} multikey={multikey} holders={}",
                    hs.join(",")
                )
            },
            Op::Commit { p, d } => write!(f, "commit p={p} d={d}"),
            Op::Record { p, d } => write!(f, "record p={p} d={d}"),
            Op::AddKey { p, d } => write!(f, "addkey p={p} d={d}"),
            Op::Pair { p, d } => write!(f, "pair p={p} d={d}"),
            Op::Replace { p, d } => write!(f, "replace p={p} d={d}"),
            Op::DelKey { p, d } => write!(f, "delkey p={p} d={d}"),
            Op::Concurrent { p } => write!(f, "concurrent p={p}"),
            Op::Partition { a, b } => write!(f, "partition a={a} b={b}"),
            Op::Heal { a, b } => write!(f, "heal a={a} b={b}"),
            Op::Degrade {
                a,
                b,
                delay_ms,
                drop_pct,
            } => write!(
                f,
                "degrade a={a} b={b} delay_ms={delay_ms} drop_pct={drop_pct}"
            ),
            Op::Calm { a, b } => write!(f, "calm a={a} b={b}"),
            Op::Stop { peer } => write!(f, "stop peer={peer}"),
            Op::Start { peer } => write!(f, "start peer={peer}"),
            Op::Barrier => write!(f, "barrier"),
        }
    }
}

impl FromStr for Op {
    type Err = String;

    fn from_str(line: &str) -> Result<Op, String> {
        let mut words = line.split_whitespace();
        let name = words.next().ok_or("empty op line")?;
        let args: Vec<(&str, &str)> = words
            .map(|w| w.split_once('=').ok_or(format!("`{w}` is not key=value")))
            .collect::<Result<_, _>>()?;
        let get = |key: &str| -> Result<&str, String> {
            args.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .ok_or(format!("`{name}` needs `{key}=`"))
        };
        let num = |key: &str| -> Result<usize, String> {
            get(key)?
                .parse()
                .map_err(|e| format!("`{key}` of `{name}`: {e}"))
        };
        Ok(match name {
            "create" => Op::Create {
                p: num("p")?,
                multikey: get("multikey")?
                    .parse()
                    .map_err(|e| format!("`multikey`: {e}"))?,
                holders: get("holders")?
                    .split(',')
                    .map(|h| h.parse().map_err(|e| format!("`holders`: {e}")))
                    .collect::<Result<_, _>>()?,
            },
            "commit" => Op::Commit {
                p: num("p")?,
                d: num("d")?,
            },
            "record" => Op::Record {
                p: num("p")?,
                d: num("d")?,
            },
            "addkey" => Op::AddKey {
                p: num("p")?,
                d: num("d")?,
            },
            "pair" => Op::Pair {
                p: num("p")?,
                d: num("d")?,
            },
            "replace" => Op::Replace {
                p: num("p")?,
                d: num("d")?,
            },
            "delkey" => Op::DelKey {
                p: num("p")?,
                d: num("d")?,
            },
            "concurrent" => Op::Concurrent { p: num("p")? },
            "partition" => Op::Partition {
                a: num("a")?,
                b: num("b")?,
            },
            "heal" => Op::Heal {
                a: num("a")?,
                b: num("b")?,
            },
            "degrade" => Op::Degrade {
                a: num("a")?,
                b: num("b")?,
                delay_ms: num("delay_ms")? as u64,
                drop_pct: u8::try_from(num("drop_pct")?).map_err(|e| e.to_string())?,
            },
            "calm" => Op::Calm {
                a: num("a")?,
                b: num("b")?,
            },
            "stop" => Op::Stop { peer: num("peer")? },
            "start" => Op::Start { peer: num("peer")? },
            "barrier" => Op::Barrier,
            other => return Err(format!("unknown op `{other}`")),
        })
    }
}

/// An op log as text, one op per line.
pub fn render(ops: &[Op]) -> String {
    ops.iter().map(|o| format!("{o}\n")).collect()
}

/// Parse a rendered op log.
pub fn parse(text: &str) -> Result<Vec<Op>, String> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| l.parse().map_err(|e| format!("line {}: {e}", i + 1)))
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Commit,
    Record,
    AddKey,
    Pair,
    Replace,
    DelKey,
    Concurrent,
    Partition,
    Heal,
    Degrade,
    Calm,
    Stop,
    Start,
}

/// The weights follow the frame's mix, without the adversity ops (NETSIM-2):
/// ordinary writes dominate; link faults and restarts are the minority that
/// the writes must survive.
fn weight(kind: Kind) -> u32 {
    match kind {
        Kind::Commit => 40,
        Kind::Record => 8,
        Kind::AddKey => 7,
        Kind::Pair => 4,
        Kind::Replace => 6,
        Kind::DelKey => 4,
        Kind::Concurrent => 5,
        Kind::Partition => 3,
        Kind::Heal => 3,
        Kind::Degrade => 2,
        Kind::Calm => 2,
        Kind::Stop => 2,
        // A stopped peer should not stay down for long.
        Kind::Start => 6,
    }
}

const KINDS: [Kind; 13] = [
    Kind::Commit,
    Kind::Record,
    Kind::AddKey,
    Kind::Pair,
    Kind::Replace,
    Kind::DelKey,
    Kind::Concurrent,
    Kind::Partition,
    Kind::Heal,
    Kind::Degrade,
    Kind::Calm,
    Kind::Stop,
    Kind::Start,
];

/// Principals created before the mix starts; the rest join mid-run.
fn setup_count(size: &Size) -> usize {
    size.principals - size.principals / 3
}

fn pairs(peers: usize) -> Vec<(usize, usize)> {
    (0..peers)
        .flat_map(|a| ((a + 1)..peers).map(move |b| (a, b)))
        .collect()
}

fn create(rng: &mut ChaCha8Rng, model: &Model, size: &Size, multikey: bool) -> Op {
    let up: Vec<usize> = (0..size.peers)
        .filter(|p| !model.down.contains(p))
        .collect();
    let (lo, hi) = size.holders;
    let want = rng.gen_range(lo..=hi).min(up.len());
    let mut holders = up;
    holders.shuffle(rng);
    holders.truncate(want);
    Op::Create {
        p: model.principals.len(),
        multikey,
        holders,
    }
}

/// The op log for `seed` at `size`: the setup creates, then `size.ops` mixed
/// ops with a barrier after each epoch, then a final barrier.
pub fn generate(seed: u64, size: &Size) -> Vec<Op> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut model = Model::new(size.peers);
    let mut log = Vec::new();
    let push = |model: &mut Model, log: &mut Vec<Op>, op: Op| {
        model
            .apply(&op)
            .unwrap_or_else(|e| panic!("generator produced an invalid op `{op}`: {e}"));
        log.push(op);
    };

    for _ in 0..setup_count(size) {
        let op = create(&mut rng, &model, size, false);
        push(&mut model, &mut log, op);
    }
    let mid = size.principals - setup_count(size);
    let epoch_len = size.ops.div_ceil(size.epochs).max(1);
    let join_every = (size.ops / (mid + 1)).max(1);
    let all_pairs = pairs(size.peers);

    for i in 0..size.ops {
        if i > 0 && i % epoch_len == 0 {
            push(&mut model, &mut log, Op::Barrier);
        }
        if i > 0 && i % join_every == 0 && model.principals.len() < size.principals {
            let op = create(&mut rng, &model, size, true);
            push(&mut model, &mut log, op);
            continue;
        }
        // Principals whose home peer is up; only they can act.
        let live: Vec<usize> = (0..model.principals.len())
            .filter(|&p| !model.down.contains(&model.principals[p].holders[0]))
            .collect();
        let pick = |rng: &mut ChaCha8Rng, ok: &dyn Fn(usize) -> bool| -> Option<usize> {
            let c: Vec<usize> = live.iter().copied().filter(|&p| ok(p)).collect();
            c.choose(rng).copied()
        };
        let open_pairs: Vec<(usize, usize)> = all_pairs
            .iter()
            .copied()
            .filter(|ab| !model.partitioned.contains(ab))
            .collect();
        let cut_pairs: Vec<(usize, usize)> = model.partitioned.iter().copied().collect();
        let bent_pairs: Vec<(usize, usize)> = model.degraded.iter().copied().collect();
        let enabled: Vec<Kind> = KINDS
            .into_iter()
            .filter(|k| match k {
                Kind::Commit | Kind::Record | Kind::AddKey | Kind::Replace => !live.is_empty(),
                Kind::Pair => live
                    .iter()
                    .any(|&p| model.principals[p].devices < MAX_DEVICES),
                Kind::DelKey => live.iter().any(|&p| model.principals[p].deletable > 0),
                Kind::Concurrent => live.iter().any(|&p| model.principals[p].devices == 2),
                Kind::Partition => open_pairs.len() > all_pairs.len() / 2,
                Kind::Heal => !cut_pairs.is_empty(),
                Kind::Degrade => !all_pairs.is_empty(),
                Kind::Calm => !bent_pairs.is_empty(),
                Kind::Stop => model.down.is_empty(),
                Kind::Start => !model.down.is_empty(),
            })
            .collect();
        let total: u32 = enabled.iter().map(|k| weight(*k)).sum();
        let mut roll = rng.gen_range(0..total);
        let kind = *enabled
            .iter()
            .find(|k| {
                let w = weight(**k);
                if roll < w {
                    true
                } else {
                    roll -= w;
                    false
                }
            })
            .expect("roll is below the total weight");

        let op = match kind {
            Kind::Commit | Kind::Record | Kind::AddKey | Kind::Replace => {
                let p = pick(&mut rng, &|_| true).expect("enabled implies a live principal");
                let d = rng.gen_range(0..model.principals[p].devices);
                match kind {
                    Kind::Commit => Op::Commit { p, d },
                    Kind::Record => Op::Record { p, d },
                    Kind::AddKey => Op::AddKey { p, d },
                    _ => Op::Replace { p, d },
                }
            },
            Kind::Pair => {
                let p = pick(&mut rng, &|p| model.principals[p].devices < MAX_DEVICES)
                    .expect("enabled implies one");
                Op::Pair {
                    p,
                    d: rng.gen_range(0..model.principals[p].devices),
                }
            },
            Kind::DelKey => {
                let p = pick(&mut rng, &|p| model.principals[p].deletable > 0)
                    .expect("enabled implies one");
                Op::DelKey {
                    p,
                    d: rng.gen_range(0..model.principals[p].devices),
                }
            },
            Kind::Concurrent => {
                let p = pick(&mut rng, &|p| model.principals[p].devices == 2)
                    .expect("enabled implies one");
                Op::Concurrent { p }
            },
            Kind::Partition => {
                let (a, b) = *open_pairs.choose(&mut rng).expect("enabled implies one");
                Op::Partition { a, b }
            },
            Kind::Heal => {
                let (a, b) = *cut_pairs.choose(&mut rng).expect("enabled implies one");
                Op::Heal { a, b }
            },
            Kind::Degrade => {
                let (a, b) = *all_pairs.choose(&mut rng).expect("enabled implies one");
                Op::Degrade {
                    a,
                    b,
                    delay_ms: rng.gen_range(20..=300),
                    drop_pct: rng.gen_range(5..=30),
                }
            },
            Kind::Calm => {
                let (a, b) = *bent_pairs.choose(&mut rng).expect("enabled implies one");
                Op::Calm { a, b }
            },
            Kind::Stop => Op::Stop {
                peer: rng.gen_range(0..size.peers),
            },
            Kind::Start => Op::Start {
                peer: *model.down.iter().next().expect("enabled implies one"),
            },
        };
        push(&mut model, &mut log, op);
    }
    push(&mut model, &mut log, Op::Barrier);
    log
}
