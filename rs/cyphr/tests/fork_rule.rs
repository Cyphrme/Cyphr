//! The fork rule (SPEC 15.7-15.8) as a pure function of the held commits:
//! a contest's child is *extended* when a held commit names its PR as
//! `pre`; the walk from genesis (a contest like any other, between two
//! genesis commits) follows the only extended child, and no extended
//! child, or more than one, is Error. The heads in Error are the leaves at
//! or above the children of the contest the walk cannot pass. Two extended branches are
//! Error at any heights, and no further commit on either leaves it.
//!
//! The reference below is rule E written the plain way, over a generated
//! tree of held commits; `cyphr::fork::assessment` must agree with it.

use cyphr::fork::{Consensus, Held, assessment};
use proptest::prelude::*;

/// A tree of held commits: nodes `0..roots` are genesis commits (position
/// 0, no `pre`); node `roots + i`'s parent is `parents[i]`, always an
/// earlier node.
#[derive(Debug, Clone)]
struct Tree {
    roots: usize,
    parents: Vec<usize>,
}

impl Tree {
    fn held(&self) -> Vec<Held> {
        let mut seqs = vec![0u64; self.roots];
        let mut out: Vec<Held> = (0..self.roots).map(|i| held_of(i, 0, None)).collect();
        for (i, &p) in self.parents.iter().enumerate() {
            let n = self.roots + i;
            seqs.push(seqs[p] + 1);
            out.push(held_of(n, seqs[n], Some(p)));
        }
        out
    }
}

fn held_of(i: usize, sequence: u64, parent: Option<usize>) -> Held {
    Held {
        sequence,
        id: format!("c{i}"),
        pre: parent.map(|p| format!("p{p}")),
        pr: format!("p{i}"),
        signed: vec![format!("k{i}")],
    }
}

/// An arbitrary tree of one or two genesis commits and up to `max` more.
fn tree(max: usize) -> impl Strategy<Value = Tree> {
    (1usize..=2, 0..=max)
        .prop_flat_map(|(roots, n)| {
            (
                Just(roots),
                (0..n).map(|i| 0..roots + i).collect::<Vec<_>>(),
            )
        })
        .prop_map(|(roots, parents)| Tree { roots, parents })
}

/// What the reference reads: the verdict, the one head while Active, and in
/// Error the fork point (height, `pre`) and the heads.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Active {
        head: String,
    },
    Error {
        height: u64,
        pre: Option<String>,
        heads: Vec<String>,
    },
}

/// Rule E, written the plain way: walk from a virtual root whose children
/// are the genesis commits; the heads in Error are the leaves at or above
/// the children of the contest the walk cannot pass.
fn reference(held: &[Held]) -> Verdict {
    let kids = |pr: Option<&str>| -> Vec<&Held> {
        held.iter().filter(|c| c.pre.as_deref() == pr).collect()
    };
    let extended = |c: &Held| held.iter().any(|d| d.pre.as_deref() == Some(c.pr.as_str()));
    let mut at: Option<&Held> = None;
    loop {
        let children = kids(at.map(|a| a.pr.as_str()));
        match children.len() {
            0 => {
                return Verdict::Active {
                    head: at.expect("a commit is held").id.clone(),
                };
            },
            1 => at = Some(children[0]),
            _ => {
                let ext: Vec<&&Held> = children.iter().filter(|c| extended(c)).collect();
                if let [only] = ext.as_slice() {
                    at = Some(**only);
                } else {
                    let mut leaves = Vec::new();
                    let mut frontier = children.clone();
                    while let Some(c) = frontier.pop() {
                        let below = kids(Some(c.pr.as_str()));
                        if below.is_empty() {
                            leaves.push(c.id.clone());
                        }
                        frontier.extend(below);
                    }
                    leaves.sort();
                    leaves.dedup();
                    return Verdict::Error {
                        height: at.map_or(0, |a| a.sequence + 1),
                        pre: at.map(|a| a.pr.clone()),
                        heads: leaves,
                    };
                }
            },
        }
    }
}

fn read(held: &[Held]) -> Verdict {
    let a = assessment(held, &[]);
    match a.consensus {
        Consensus::Active => {
            assert_eq!(a.heads.len(), 1, "Active has one head");
            Verdict::Active {
                head: a.heads[0].clone(),
            }
        },
        Consensus::Error => {
            let fp = a.fork_point.expect("Error has a fork point");
            Verdict::Error {
                height: fp.height,
                pre: fp.pre,
                heads: a.heads,
            }
        },
    }
}

fn is_error(held: &[Held]) -> bool {
    assessment(held, &[]).consensus == Consensus::Error
}

/// Add a commit numbered `i` over the held commit whose PR is `p{parent}`.
fn push(v: &mut Vec<Held>, i: usize, parent: usize) {
    let pre = format!("p{parent}");
    let sequence = v
        .iter()
        .find(|h| h.pr == pre)
        .expect("parent held")
        .sequence
        + 1;
    v.push(held_of(i, sequence, Some(parent)));
}

/// A fork after a chain of `common` commits (genesis included): the left
/// branch is `left` commits numbered 1000.., the right `right` numbered
/// 2000... Returns the held set and each branch's tip number.
fn fork(common: usize, left: usize, right: usize) -> (Vec<Held>, usize, usize) {
    let mut v = vec![held_of(0, 0, None)];
    for i in 1..common {
        push(&mut v, i, i - 1);
    }
    let mut tips = [common - 1, common - 1];
    for (side, (start, len)) in [(1000, left), (2000, right)].into_iter().enumerate() {
        for k in 0..len {
            push(&mut v, start + k, tips[side]);
            tips[side] = start + k;
        }
    }
    (v, tips[0], tips[1])
}

/// Add commit `i` over the held commit numbered `parent`.
fn extend(v: &mut Vec<Held>, parent: usize, i: usize) -> usize {
    push(v, i, parent);
    i
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Catches any verdict, head or fork point that departs from rule E
    /// over arbitrary trees (tallest-wins departs wherever both sides of a
    /// contest are extended to different heights).
    #[test]
    fn the_verdict_is_rule_e(t in tree(14)) {
        let held = t.held();
        prop_assert_eq!(read(&held), reference(&held));
    }

    /// Catches tallest-wins: two extended branches are Error at any
    /// heights; and a head list that drops the shorter branch's tip (the
    /// heads are the leaves above the fork point, of unequal heights).
    // @docket: sc-l2814 :: scripts/docket-run sc-l2814
    #[test]
    fn both_extended_is_error_at_any_heights(
        common in 1usize..4, left in 2usize..6, right in 2usize..6,
    ) {
        let (held, l, r) = fork(common, left, right);
        prop_assert!(is_error(&held), "heights {left} vs {right}");
        let mut tips = vec![format!("c{l}"), format!("c{r}")];
        tips.sort();
        prop_assert_eq!(assessment(&held, &[]).heads, tips, "both branch tips are heads");
    }

    /// Catches a rule that skips position 0: two genesis commits are a
    /// contest like any other. Neither extended is Error at {0, no pre};
    /// one extended is selected; both is Error, at any heights.
    #[test]
    fn two_genesis_commits_are_a_contest(left in 0usize..4, right in 0usize..4) {
        let mut v = vec![held_of(0, 0, None), held_of(1, 0, None)];
        let (mut l, mut r) = (0, 1);
        for k in 0..left { l = extend(&mut v, l, 100 + k); }
        for k in 0..right { r = extend(&mut v, r, 200 + k); }
        let got = read(&v);
        match (left, right) {
            (0, 0) => prop_assert_eq!(got, Verdict::Error {
                height: 0, pre: None, heads: vec!["c0".to_owned(), "c1".to_owned()],
            }),
            (_, 0) => prop_assert_eq!(got, Verdict::Active { head: format!("c{l}") }),
            (0, _) => prop_assert_eq!(got, Verdict::Active { head: format!("c{r}") }),
            _ => prop_assert!(matches!(got, Verdict::Error { height: 0, pre: None, .. }), "{got:?}"),
        }
    }

    /// Catches an exit by out-building: from a both-extended fork, any
    /// further commits that verify leave it Error.
    // @docket: sc-l2814 :: scripts/docket-run sc-l2814
    #[test]
    fn building_on_a_both_extended_fork_never_leaves_error(
        left in 2usize..4, right in 2usize..4,
        adds in proptest::collection::vec(any::<bool>(), 1..8),
    ) {
        let (mut held, mut l, mut r) = fork(2, left, right);
        for (n, on_left) in adds.into_iter().enumerate() {
            if on_left {
                l = extend(&mut held, l, 5000 + n);
            } else {
                r = extend(&mut held, r, 5000 + n);
            }
            prop_assert!(is_error(&held), "after {n} adds");
        }
    }

    /// Catches "abandoned for good": one extended branch selects, and one
    /// extension of the abandoned branch re-opens the fork, whatever the
    /// heights.
    // @docket: sc-l2814 :: scripts/docket-run sc-l2814
    #[test]
    fn one_extended_selects_and_the_other_extended_reopens(left in 2usize..6) {
        let (mut held, _, _) = fork(2, left, 1);
        prop_assert_eq!(read(&held), Verdict::Active { head: format!("c{}", 1000 + left - 1) });
        extend(&mut held, 2000, 5000);
        prop_assert!(is_error(&held), "re-opened");
    }

    /// Catches a rule that never lets a commit resolve: with neither
    /// branch extended it is Error, and one commit on either leaves it.
    #[test]
    fn one_commit_on_an_unextended_tie_resolves(pick_left in any::<bool>(), common in 1usize..4) {
        let (mut held, l, r) = fork(common, 1, 1);
        prop_assert!(is_error(&held));
        let new = extend(&mut held, if pick_left { l } else { r }, 5000);
        prop_assert_eq!(read(&held), Verdict::Active { head: format!("c{new}") });
    }

    /// Catches order dependence: the verdict is invariant under
    /// permutation and duplication of what is held.
    #[test]
    fn the_verdict_ignores_order_and_duplicates(
        t in tree(12), seed in any::<u64>(), dup in 0usize..4,
    ) {
        let held = t.held();
        let mut shuffled = held.clone();
        for k in 0..dup { shuffled.push(held[k % held.len()].clone()); }
        // deterministic shuffle
        let mut s = seed | 1;
        for i in (1..shuffled.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            shuffled.swap(i, (s % (i as u64 + 1)) as usize);
        }
        let (a, b) = (assessment(&held, &[]), assessment(&shuffled, &[]));
        prop_assert_eq!(a.consensus, b.consensus);
        prop_assert_eq!(a.heads, b.heads);
        prop_assert_eq!(a.fork_point, b.fork_point);
    }
}

/// If two genesis commits could share a Principal Root (a hash collision;
/// honest signing never produces one, see the storage tests), a commit at
/// position 1 names the PR of both, so both count as extended: Error, with
/// no extra rule. Catches a rule that reads the shared PR as one chain.
#[test]
fn a_shared_genesis_pr_is_both_extended() {
    let mut a = held_of(0, 0, None);
    let mut b = held_of(1, 0, None);
    a.pr = "shared".to_owned();
    b.pr = "shared".to_owned();
    let mut c = held_of(2, 1, None);
    c.pre = Some("shared".to_owned());
    let held = [a, b, c];
    assert!(is_error(&held), "{:?}", assessment(&held, &[]));
    assert_eq!(
        assessment(&held, &[]).fork_point.map(|f| (f.height, f.pre)),
        Some((0, None))
    );
}
