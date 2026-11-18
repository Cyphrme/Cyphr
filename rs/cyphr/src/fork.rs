//! Fork resolution (SPEC 15.5-15.8): the one rule every holder of a
//! principal's commits applies, as a pure function of the commits held.
//!
//! A storage engine, a verifier and a relying party each hold some set of
//! a principal's commits; this module is where they all read the same
//! answer from them.

use std::collections::{HashMap, HashSet};

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
    /// Error while two held commits share the greatest height.
    pub consensus: Consensus,
    /// The heads, sorted: the held commits of the greatest height. One
    /// while Active; in Error, each tied head.
    pub heads: Vec<String>,
    /// Every position where two or more held commits share a `pre`, in
    /// position order.
    pub forks: Vec<Contest>,
    /// Where the tied heads part: `Some` exactly in Error.
    pub fork_point: Option<ForkPoint>,
}

/// Where tied branches part: the first position the walk cannot choose a
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
    /// stops at a tie, or follows none of them.
    pub kept: Option<String>,
    /// The key that settled it: the first signer of the walked commit
    /// extending the kept one. `None` while the fork stands, or when no
    /// commit settled it (a revoke left the kept commit alone).
    pub by: Option<String>,
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

/// The forks of a principal as the protocol reads them (SPEC 15.5-15.8):
/// walk from genesis over the held commits and, where a position has more
/// than one child, follow the child whose
/// subtree is tallest; two equally tall subtrees are Error, and the walk
/// stops there. That is the spec's "the commit resolves the fork" made
/// deterministic: a fork is settled by out-extending the other branch,
/// and a malicious settlement is undone only by recovery (SPEC 14).
///
/// The walk ends at a commit of the greatest height, and two commits of
/// that height tie at the fork where their lines part, so the principal
/// is Active exactly when one held commit is the highest: the heads are
/// the held commits of the greatest height.
///
/// Every held commit counts: each was admitted when it arrived, a
/// revoke only gates what arrives after it , and a held
/// message is never judged again (SPEC 14.12: "Cyphr does not use
/// reversion"; the spec author on #203: "Retrospection isn't
/// supported"). A signature from a key's active period stands after the
/// key is deleted or replaced too (SPEC 6.2), and a revoke inside a commit
/// is state of its own branch only (SPEC 6.4, 15.8).
///
/// A pure function of the held commits, so a live
/// engine and one rebuilt from the blobs answer alike (I1), whether a
/// candidate commit would leave Error is this function over the held
/// commits plus the candidate, and a verifier holding the same commits
/// reaches the same verdict, heads and settlements as a peer. "Tallest"
/// is a statement about what is held now; the forks are what stays true.
pub fn assessment(held: &[Held]) -> Assessment {
    use std::collections::{BTreeMap, BTreeSet};

    let top = held.iter().map(|h| h.sequence).max();
    let heads: Vec<&Held> = held.iter().filter(|h| Some(h.sequence) == top).collect();

    // The walked line: the commits every head descends from (each head's
    // own line while Active).
    let by_pr: HashMap<(u64, &str), &Held> = held
        .iter()
        .map(|h| ((h.sequence, h.pr.as_str()), h))
        .collect();
    fn line_of<'a>(h: &'a Held, by_pr: &HashMap<(u64, &str), &'a Held>) -> HashSet<&'a str> {
        let mut line = HashSet::new();
        let mut at = Some(h);
        while let Some(h) = at {
            line.insert(h.id.as_str());
            at = h
                .pre
                .as_deref()
                .zip(h.sequence.checked_sub(1))
                .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied());
        }
        line
    }
    let mut lines = heads.iter().map(|h| line_of(h, &by_pr));
    let first = lines.next().unwrap_or_default();
    let walked: HashSet<&str> = lines.fold(first, |acc, line| &acc & &line);

    // The distinct held commits over each (position, pre).
    type Over<'a> = (u64, Option<&'a str>);
    let mut over: BTreeMap<Over<'_>, BTreeMap<&str, &Held>> = BTreeMap::new();
    for h in held {
        over.entry((h.sequence, h.pre.as_deref()))
            .or_default()
            .entry(h.id.as_str())
            .or_insert(h);
    }
    let forks = over
        .iter()
        .filter(|(_, c)| c.len() > 1)
        .map(|(&(sequence, pre), commits)| {
            let kept = commits
                .values()
                .copied()
                .find(|h| walked.contains(h.id.as_str()));
            Contest {
                sequence,
                pre: pre.map(str::to_owned),
                commits: commits.keys().map(|id| (*id).to_owned()).collect(),
                kept: kept.map(|k| k.id.clone()),
                by: kept.and_then(|k| settled_by_extension(held, k, &walked)),
            }
        })
        .collect();
    let heads: BTreeSet<String> = heads.iter().map(|h| h.id.clone()).collect();
    let fork_point = (heads.len() > 1).then(|| {
        // The common chain's last commit; the branches part just above it.
        let last = held
            .iter()
            .filter(|h| walked.contains(h.id.as_str()))
            .max_by_key(|h| h.sequence);
        ForkPoint {
            height: last.map_or(0, |h| h.sequence + 1),
            pre: last.map(|h| h.pr.clone()),
        }
    });
    Assessment {
        consensus: if heads.len() > 1 {
            Consensus::Error
        } else {
            Consensus::Active
        },
        heads: heads.into_iter().collect(),
        forks,
        fork_point,
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
