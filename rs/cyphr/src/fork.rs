//! Fork resolution (SPEC 15.5-15.8): the one rule every holder of a
//! principal's commits applies, as a pure function of the commits held.
//!
//! A storage engine, a verifier and a relying party each hold some set of
//! a principal's commits; this module is where they all read the same
//! answer from them.

use std::collections::{BTreeSet, HashMap, HashSet};

/// A principal's consensus state (SPEC 15.5), as far as forks decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Consensus {
    /// No unresolved fork.
    Active,
    /// An unresolved fork: nothing that leaves it standing is admitted.
    Error,
}

/// A principal's forks as the protocol reads them (SPEC 15.5-15.8), from
/// the commits a holder keeps: the one rule every holder applies, whether
/// it admits a commit or renders a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Error while the walk cannot choose between the branches at a fork.
    pub consensus: Consensus,
    /// The heads, sorted: the leaf the walk ends at while Active; in Error,
    /// the leaves at or above the contest the walk cannot pass, whatever
    /// their heights.
    pub heads: Vec<String>,
    /// Every position where two or more held commits share a `pre`, in
    /// position order.
    pub forks: Vec<Contest>,
    /// Where the branches part: `Some` exactly in Error.
    pub fork_point: Option<ForkPoint>,
}

/// Where the branches part: the first position the walk cannot choose a
/// commit at, and the Principal Root every branch shares there (SPEC
/// 15.7.1: commits over the same `pre`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForkPoint {
    /// The commit position the branches first differ at; the common chain
    /// is the commits below it.
    pub height: u64,
    /// The common chain's Principal Root; `None` at position 0.
    pub pre: Option<String>,
}

/// Two or more held commits over one `pre`, and how the protocol reads
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contest {
    /// The commit position they take.
    pub sequence: u64,
    /// The Principal Root they share; `None` at sequence 0.
    pub pre: Option<String>,
    /// Their commit ids, sorted.
    pub commits: Vec<String>,
    /// The commit the fork rule's walk follows here; `None` where the walk
    /// stops, or follows none of them.
    pub kept: Option<String>,
    /// The key that settled it: the first signer of the walked commit
    /// extending the kept one. `None` while the fork stands, or when no
    /// commit settled it (a revoke left the kept commit alone).
    pub by: Option<String>,
    /// For each commit here the walk passed over, the tips of its branch:
    /// the held leaves at or above it, sorted. Empty while the fork
    /// stands.
    pub abandoned: std::collections::BTreeMap<String, Vec<String>>,
}

/// A commit a holder keeps, canonical or retained, as [`assessment`] reads
/// it: the protocol data the fork rule needs and nothing of how it is
/// stored.
#[derive(Debug, Clone)]
pub struct Held {
    /// The commit's position.
    pub sequence: u64,
    /// The commit id.
    pub id: String,
    /// The Principal Root the commit was verified against; `None` at
    /// sequence 0.
    pub pre: Option<String>,
    /// The commit's own Principal Root.
    pub pr: String,
    /// The thumbprints that signed the commit's cozies, in coz order: who
    /// settled a fork ([`Contest::by`]).
    pub signed: Vec<String>,
}

/// The forks of a principal as the protocol reads them (SPEC 15.5-15.8).
///
/// A child of a contest (two or more held commits over one `pre`) is
/// *extended* when a held commit names its Principal Root as `pre`. The
/// walk starts from a virtual root whose children are the held commits
/// with no held parent (the genesis commits of a whole record) and, at a
/// contest, follows the one child that is extended. Where none is, or
/// more than one is, the principal is in Error and the walk stops: a fork
/// is an error until the principal resolves it, and it resolves it by
/// extending one branch and not the other (SPEC 15.8; the spec author on
/// #203: "An invalid fork is resolved when the principal unambiguously
/// selects one branch"). Two extended branches are both out of
/// compliance whatever their heights, and no later commit leaves that
/// state. Contests off the walked line do not count.
///
/// While Active the head is the leaf the walk ends at. In Error the heads
/// are the leaves at or above the children of the contest the walk cannot
/// pass, sorted: each is a tip the principal can assert to resolve.
///
/// `asserted` is the Principal Roots of held commits that carry a valid
/// held `resync/create` proof of possession (SPEC 15.8 item 2). At a
/// contest, the children whose subtree holds an asserted commit decide
/// it: one is followed whatever is extended elsewhere, so a later
/// extension of the abandoned branch does not re-open the fork; more
/// than one is Error for good, since no commit or proof leaves it; none
/// is rule E as above. Assertions at or below the fork point, or naming
/// nothing held, select no child and change nothing. The heads in Error
/// stay every leaf at or above the stopping contest's children, asserted
/// or not.
///
/// Every held commit counts: each was admitted when it arrived, a revoke
/// only gates what arrives after it, and a held message is never judged
/// again (SPEC 14.12: "Cyphr does not use reversion"; the spec author on
/// #203: "Retrospection isn't supported"). A signature from a key's
/// active period stands after the key is deleted or replaced too (SPEC
/// 6.2). A key deleted in a commit is state of that branch only; a key
/// revoked, naked or inside a commit, is the node's: it stops what the key
/// dates at or after the receipt, on every branch (SPEC 6.4).
///
/// A pure function of the held commits, so a live engine and one rebuilt
/// from the blobs answer alike (I1): whether a candidate commit would
/// leave Error is this function over the held commits plus the candidate,
/// and a verifier holding the same commits reaches the same verdict,
/// heads and selections as a peer. Held order and duplicates change
/// nothing.
pub fn assessment(held: &[Held], asserted: &[String]) -> Assessment {
    use std::collections::BTreeMap;

    // The distinct held commits over each (position, pre).
    type Over<'a> = (u64, Option<&'a str>);
    let mut over: BTreeMap<Over<'_>, BTreeMap<&str, &Held>> = BTreeMap::new();
    for h in held {
        over.entry((h.sequence, h.pre.as_deref()))
            .or_default()
            .entry(h.id.as_str())
            .or_insert(h);
    }
    let children_of = |sequence: u64, pre: Option<&str>| -> Vec<&Held> {
        over.get(&(sequence, pre))
            .map(|c| c.values().copied().collect())
            .unwrap_or_default()
    };
    let extended = |c: &Held| over.contains_key(&(c.sequence + 1, Some(c.pr.as_str())));

    // The held commits whose subtree holds an asserted commit (the
    // commit itself included): each asserted commit and its held
    // ancestors. Asserted PRs naming nothing held select nothing.
    let by_pr: HashMap<(u64, &str), &Held> = held
        .iter()
        .map(|h| ((h.sequence, h.pr.as_str()), h))
        .collect();
    let asserted: HashSet<&str> = asserted.iter().map(String::as_str).collect();
    let mut asserts: HashSet<&str> = HashSet::new();
    for h in held.iter().filter(|h| asserted.contains(h.pr.as_str())) {
        let mut cur = Some(h);
        while let Some(c) = cur {
            if !asserts.insert(c.id.as_str()) {
                break;
            }
            cur = c
                .pre
                .as_deref()
                .zip(c.sequence.checked_sub(1))
                .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied());
        }
    }

    // The children of the virtual root: the held commits no held commit
    // precedes, at the lowest position that has one. A whole record has
    // only genesis commits there; the engine's window starts at one
    // canonical commit.
    let held_prs: HashSet<(u64, &str)> = held.iter().map(|h| (h.sequence, h.pr.as_str())).collect();
    let root_at = held
        .iter()
        .filter(|h| {
            h.pre
                .as_deref()
                .zip(h.sequence.checked_sub(1))
                .is_none_or(|(pre, below)| !held_prs.contains(&(below, pre)))
        })
        .min_by_key(|h| h.sequence);
    let mut at: Option<&Held> = None;
    let mut children: Vec<&Held> = root_at
        .map(|r| children_of(r.sequence, r.pre.as_deref()))
        .unwrap_or_default();
    let mut walked: HashSet<&str> = HashSet::new();
    let mut stopped: Option<(u64, Option<String>, Vec<&Held>)> = None;
    while !children.is_empty() {
        let next = match children.as_slice() {
            [only] => Some(*only),
            many => {
                let pick = |keep: &dyn Fn(&Held) -> bool| -> Vec<&Held> {
                    many.iter().copied().filter(|c| keep(c)).collect()
                };
                // A PoP decides the contest: one asserted child is
                // followed whatever is extended elsewhere, more than one
                // is Error for good, none leaves the choice to rule E.
                match pick(&|c| asserts.contains(c.id.as_str()))[..] {
                    [only] => Some(only),
                    [] => match pick(&|c| extended(c))[..] {
                        [only] => Some(only),
                        _ => None,
                    },
                    _ => None,
                }
            },
        };
        let Some(next) = next else {
            let first = children[0];
            stopped = Some((first.sequence, first.pre.clone(), children));
            break;
        };
        walked.insert(next.id.as_str());
        at = Some(next);
        children = children_of(next.sequence + 1, Some(next.pr.as_str()));
    }

    // The held leaves at or above `start`, each once.
    let leaves_above = |start: Vec<&Held>| -> BTreeSet<String> {
        let mut leaves: BTreeSet<String> = BTreeSet::new();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut frontier = start;
        while let Some(c) = frontier.pop() {
            if !seen.insert(c.id.as_str()) {
                continue;
            }
            let below = children_of(c.sequence + 1, Some(c.pr.as_str()));
            if below.is_empty() {
                leaves.insert(c.id.clone());
            }
            frontier.extend(below);
        }
        leaves
    };

    let forks = over
        .iter()
        .filter(|(_, c)| c.len() > 1)
        .map(|(&(sequence, pre), commits)| {
            let kept = commits
                .values()
                .copied()
                .find(|h| walked.contains(h.id.as_str()));
            let abandoned = kept
                .map(|k| {
                    commits
                        .values()
                        .filter(|h| h.id != k.id)
                        .map(|h| {
                            let tips = leaves_above(vec![*h]);
                            (h.id.clone(), tips.into_iter().collect())
                        })
                        .collect()
                })
                .unwrap_or_default();
            Contest {
                sequence,
                pre: pre.map(str::to_owned),
                commits: commits.keys().map(|id| (*id).to_owned()).collect(),
                kept: kept.map(|k| k.id.clone()),
                by: kept.and_then(|k| settled_by_extension(held, k, &walked)),
                abandoned,
            }
        })
        .collect();

    let Some((height, pre, rivals)) = stopped else {
        return Assessment {
            consensus: Consensus::Active,
            heads: at.map(|h| h.id.clone()).into_iter().collect(),
            forks,
            fork_point: None,
        };
    };
    Assessment {
        consensus: Consensus::Error,
        heads: leaves_above(rivals).into_iter().collect(),
        forks,
        fork_point: Some(ForkPoint { height, pre }),
    }
}

/// The key that settled a fork by extending `kept`: the first signer of
/// the walked commit whose `pre` is `kept`'s PR.
fn settled_by_extension(held: &[Held], kept: &Held, walked: &HashSet<&str>) -> Option<String> {
    held.iter()
        .find(|c| {
            walked.contains(c.id.as_str())
                && c.sequence == kept.sequence + 1
                && c.pre.as_deref() == Some(kept.pr.as_str())
        })
        .and_then(|c| c.signed.first().cloned())
}

/// The lowest position [`assessment`] must read to answer as it does over
/// every held commit: one below the lowest commit held off the main chain
/// (`lowest_retained`), and the chain's head position `last` alone when
/// none is. The chain below it has one commit at each position and no
/// rival beside or above it, so it holds no head, no fork and no point
/// where two lines part.
#[must_use]
pub fn assessed_from(lowest_retained: Option<u64>, last: u64) -> u64 {
    lowest_retained.map_or(last, |low| low.saturating_sub(1).min(last))
}
