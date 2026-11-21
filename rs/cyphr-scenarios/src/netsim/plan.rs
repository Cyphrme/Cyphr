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
    /// Device `d`, which holds the principal's oldest backup key, revokes it
    /// by a naked revoke, then the owner's `key/delete` commit retires it.
    NakedRevoke {
        p: usize,
        d: usize,
    },
    /// Fork episode: the home peer is cut off from the rest, the two devices
    /// each extend the chain twice on opposite sides, the cut heals, and the
    /// first device's next commit resolves the fork.
    Fork {
        p: usize,
    },
    /// Lock episode: as a fork episode, but each device extends its branch
    /// twice, so both are extended. No commit leaves that Error, so the
    /// episode ends the principal: every holder must converge on Error with
    /// fork evidence and refuse the owner's further commit, and the model
    /// then retires the principal. Written by hand into op logs; the
    /// generator does not draw it, as no run can go on with the principal.
    Lock {
        p: usize,
    },
    /// Theft episode: a thief copies the second device's key and forks the
    /// principal; the owner revokes the key and resolves by `key/delete`.
    Theft {
        p: usize,
    },
    /// Snapshot a peer with `cyphr-server backup`.
    Backup {
        peer: usize,
    },
    /// Put the backup back with `cyphr-server restore`, then re-push what
    /// the peer holds from each owner.
    Restore {
        peer: usize,
    },
    /// Rotate a peer's signing key, once per run.
    RollPeerKey {
        peer: usize,
    },
    /// At the next barrier, a fresh observer's verdict over every holder.
    Verdict {
        p: usize,
    },
    /// At the next barrier, sign in to a relying party as the principal.
    SignIn {
        p: usize,
    },
    /// At the next barrier, stop the peer, run `cyphr-server verify-all` and
    /// start it again.
    VerifyAll {
        peer: usize,
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
            | Op::NakedRevoke { p, .. }
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
            Op::NakedRevoke { p, d } => write!(f, "nakedrevoke p={p} d={d}"),
            Op::Fork { p } => write!(f, "fork p={p}"),
            Op::Lock { p } => write!(f, "lock p={p}"),
            Op::Theft { p } => write!(f, "theft p={p}"),
            Op::Backup { peer } => write!(f, "backup peer={peer}"),
            Op::Restore { peer } => write!(f, "restore peer={peer}"),
            Op::RollPeerKey { peer } => write!(f, "rollpeerkey peer={peer}"),
            Op::Verdict { p } => write!(f, "verdict p={p}"),
            Op::SignIn { p } => write!(f, "signin p={p}"),
            Op::VerifyAll { peer } => write!(f, "verifyall peer={peer}"),
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
            "nakedrevoke" => Op::NakedRevoke {
                p: num("p")?,
                d: num("d")?,
            },
            "fork" => Op::Fork { p: num("p")? },
            "lock" => Op::Lock { p: num("p")? },
            "theft" => Op::Theft { p: num("p")? },
            "backup" => Op::Backup { peer: num("peer")? },
            "restore" => Op::Restore { peer: num("peer")? },
            "rollpeerkey" => Op::RollPeerKey { peer: num("peer")? },
            "verdict" => Op::Verdict { p: num("p")? },
            "signin" => Op::SignIn { p: num("p")? },
            "verifyall" => Op::VerifyAll { peer: num("peer")? },
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
    NakedRevoke,
    Fork,
    Theft,
    Backup,
    Restore,
    Verdict,
    SignIn,
    Partition,
    Heal,
    Degrade,
    Calm,
    Stop,
    Start,
}

/// Ordinary writes dominate; link faults, restarts and the adversity
/// episodes are the minority that the writes must survive. A peer key
/// rollover happens once per run and a `verify-all` once per epoch, both
/// scheduled rather than drawn, so every run has them.
fn weight(kind: Kind) -> u32 {
    match kind {
        Kind::Commit => 40,
        Kind::Record => 8,
        Kind::AddKey => 7,
        Kind::Pair => 4,
        Kind::Replace => 6,
        Kind::DelKey => 4,
        Kind::Concurrent => 5,
        Kind::NakedRevoke => 3,
        Kind::Fork => 3,
        Kind::Theft => 3,
        Kind::Backup => 1,
        Kind::Restore => 4,
        Kind::Verdict => 2,
        Kind::SignIn => 2,
        Kind::Partition => 3,
        Kind::Heal => 3,
        Kind::Degrade => 2,
        Kind::Calm => 2,
        Kind::Stop => 2,
        // A stopped peer should not stay down for long.
        Kind::Start => 6,
    }
}

const KINDS: [Kind; 20] = [
    Kind::Commit,
    Kind::Record,
    Kind::AddKey,
    Kind::Pair,
    Kind::Replace,
    Kind::DelKey,
    Kind::Concurrent,
    Kind::NakedRevoke,
    Kind::Fork,
    Kind::Theft,
    Kind::Backup,
    Kind::Restore,
    Kind::Verdict,
    Kind::SignIn,
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
/// ops with a barrier after each epoch (each preceded by a `verify-all` of
/// the epoch's peer), then a final barrier.
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
    let roll_at = size.ops * 2 / 5;
    let mut epoch = 0;

    for i in 0..size.ops {
        if i > 0 && i % epoch_len == 0 {
            push(
                &mut model,
                &mut log,
                Op::VerifyAll {
                    peer: epoch % size.peers,
                },
            );
            epoch += 1;
            push(&mut model, &mut log, Op::Barrier);
        }
        if i == roll_at {
            let up: Vec<usize> = (0..size.peers)
                .filter(|p| !model.down.contains(p))
                .collect();
            let peer = *up.choose(&mut rng).expect("at most one peer is stopped");
            push(&mut model, &mut log, Op::RollPeerKey { peer });
            continue;
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
        // An episode needs every peer running and a principal with two
        // devices, which a previous episode or a pairing leaves.
        let episodic = |p: usize| {
            model.down.is_empty()
                && model.principals[p].devices == 2
                && model.principals[p].holders.len() >= 2
        };
        let revocable = |p: usize| !model.principals[p].backups.is_empty();
        let enabled: Vec<Kind> = KINDS
            .into_iter()
            .filter(|k| match k {
                Kind::Commit | Kind::Record | Kind::AddKey | Kind::Replace => !live.is_empty(),
                Kind::Pair => live
                    .iter()
                    .any(|&p| model.principals[p].devices < MAX_DEVICES),
                Kind::DelKey => live
                    .iter()
                    .any(|&p| !model.principals[p].backups.is_empty()),
                Kind::Concurrent => live.iter().any(|&p| model.principals[p].devices == 2),
                Kind::NakedRevoke => live.iter().any(|&p| revocable(p)),
                Kind::Fork | Kind::Theft => live.iter().any(|&p| episodic(p)),
                Kind::Backup => model.backed_up.is_none() && model.down.len() < size.peers,
                Kind::Restore => model
                    .backed_up
                    .is_some_and(|peer| !model.down.contains(&peer)),
                Kind::Verdict | Kind::SignIn => !model.principals.is_empty(),
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
                let p = pick(&mut rng, &|p| !model.principals[p].backups.is_empty())
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
            Kind::NakedRevoke => {
                let p = pick(&mut rng, &revocable).expect("enabled implies one");
                let d = *model.principals[p]
                    .backups
                    .front()
                    .expect("picked for having a backup");
                Op::NakedRevoke { p, d }
            },
            Kind::Fork | Kind::Theft => {
                let p = pick(&mut rng, &episodic).expect("enabled implies one");
                if kind == Kind::Fork {
                    Op::Fork { p }
                } else {
                    Op::Theft { p }
                }
            },
            Kind::Backup => {
                let up: Vec<usize> = (0..size.peers)
                    .filter(|p| !model.down.contains(p))
                    .collect();
                Op::Backup {
                    peer: *up.choose(&mut rng).expect("enabled implies one"),
                }
            },
            Kind::Restore => Op::Restore {
                peer: model.backed_up.expect("enabled implies a backup"),
            },
            Kind::Verdict | Kind::SignIn => {
                let p = rng.gen_range(0..model.principals.len());
                if kind == Kind::Verdict {
                    Op::Verdict { p }
                } else {
                    Op::SignIn { p }
                }
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
    push(
        &mut model,
        &mut log,
        Op::VerifyAll {
            peer: epoch % size.peers,
        },
    );
    push(&mut model, &mut log, Op::Barrier);
    log
}
