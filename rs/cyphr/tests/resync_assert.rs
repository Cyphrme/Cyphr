//! Rule E with assertions (SPEC 15.8 item 2): a held
//! `resync/create` proof of possession names a commit's PR (`asserted`),
//! and at a contest on the walk the children whose subtree holds an
//! asserted commit decide it. One such child is followed whatever is
//! extended elsewhere; more than one is Error for good; none is rule E.
//!
//! The reference below is that rule written the plain way over generated
//! trees; `cyphr::fork::assessment` taking the asserted set must agree.

use cyphr::fork::{Assessment, Consensus, Held, assessment};
use proptest::prelude::*;

/// `assessment(held, asserted)` over the PRs of held commits that carry a
/// valid held PoP.
fn assess(held: &[Held], asserted: &[String]) -> Assessment {
    assessment(held, asserted)
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

/// Node `n >= roots` has an earlier node as parent.
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

    fn nodes(&self) -> usize {
        self.roots + self.parents.len()
    }
}

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

/// A tree and a non-empty set of its nodes' PRs (some may repeat).
fn asserted_tree(max: usize) -> impl Strategy<Value = (Tree, Vec<String>)> {
    tree(max).prop_flat_map(|t| {
        let n = t.nodes();
        (
            Just(t),
            proptest::collection::vec(0..n, 1..4)
                .prop_map(|v| v.into_iter().map(|i| format!("p{i}")).collect()),
        )
    })
}

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

/// Rule E with assertions, the plain way. Asserted PRs naming nothing held
/// count for nothing.
fn reference(held: &[Held], asserted: &[String]) -> Verdict {
    let mut seen = std::collections::HashSet::new();
    let held: Vec<Held> = held
        .iter()
        .filter(|h| seen.insert(h.id.clone()))
        .cloned()
        .collect();
    let held = held.as_slice();
    let kids = |pr: Option<&str>| -> Vec<&Held> {
        held.iter().filter(|c| c.pre.as_deref() == pr).collect()
    };
    let extended = |c: &Held| held.iter().any(|d| d.pre.as_deref() == Some(c.pr.as_str()));
    let asserts_below = |c: &Held| {
        let mut frontier = vec![c];
        while let Some(n) = frontier.pop() {
            if asserted.contains(&n.pr) {
                return true;
            }
            frontier.extend(kids(Some(n.pr.as_str())));
        }
        false
    };
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
                let chosen: Vec<&&Held> = children.iter().filter(|c| asserts_below(c)).collect();
                let ext: Vec<&&Held> = children.iter().filter(|c| extended(c)).collect();
                match (chosen.as_slice(), ext.as_slice()) {
                    ([only], _) => at = Some(**only),
                    ([], [only]) => at = Some(**only),
                    _ => {
                        // The heads: the leaves at or above every child of
                        // the contest the walk cannot pass.
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
                    },
                }
            },
        }
    }
}

fn read(held: &[Held], asserted: &[String]) -> Verdict {
    let a = assess(held, asserted);
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

/// A fork after `common` chain commits (genesis included): the left branch
/// is `left` commits numbered 1000.., the right `right` numbered 2000..
/// Returns the held set and each branch's tip number.
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

/// Error at the contest after `common` chain commits, the heads the two
/// branch tips `l` and `r`.
fn error_at(common: usize, l: usize, r: usize) -> Verdict {
    let mut heads = vec![format!("c{l}"), format!("c{r}")];
    heads.sort();
    Verdict::Error {
        height: common as u64,
        pre: Some(pr(common - 1)),
        heads,
    }
}

fn pr(i: usize) -> String {
    format!("p{i}")
}

/// No regression file: a red run must not write one into the tree.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Audits the oracle: with nothing asserted the reference is today's
    /// rule E, so the properties below measure the assertions alone.
    #[test]
    fn the_reference_is_rule_e_without_assertions(t in tree(14)) {
        let held = t.held();
        prop_assert_eq!(read(&held, &[]), reference(&held, &[]));
    }

    /// Catches any verdict that departs from rule E with assertions over
    /// arbitrary trees and assertion sets (R1-R3 as one property).
    #[test]
    fn the_verdict_is_rule_e_with_assertions((t, asserted) in asserted_tree(12)) {
        let held = t.held();
        prop_assert_eq!(read(&held, &asserted), reference(&held, &asserted));
    }

    /// R1. Catches re-opening by extension: with one branch asserted, the
    /// walk follows it, and any commits under the other branch (which may
    /// extend it, so rule E alone would call Error) change nothing.
    // @docket: sc-l2822 :: scripts/docket-run sc-l2822
    #[test]
    fn one_asserted_child_is_followed_whatever_is_extended_elsewhere(
        common in 1usize..4, left in 1usize..4, right in 1usize..4,
        at in 0usize..3, more in 0usize..4, pick_left in any::<bool>(),
    ) {
        let (mut held, l, r) = fork(common, left, right);
        let (own, base, other) = if pick_left { (1000, l, r) } else { (2000, r, l) };
        let asserted = vec![pr(own + at % if pick_left { left } else { right })];
        let tip = if pick_left { l } else { r };
        prop_assert_eq!(read(&held, &asserted), Verdict::Active { head: format!("c{tip}") });
        let mut cur = other;
        for k in 0..more {
            push(&mut held, 5000 + k, cur);
            cur = 5000 + k;
            prop_assert_eq!(
                read(&held, &asserted),
                Verdict::Active { head: format!("c{base}") },
                "after {} commits under the other branch", k + 1
            );
        }
    }

    /// R2. Catches a PoP race: assertions in two children are Error at the
    /// fork point, and no added commit or assertion returns Active.
    // @docket: sc-l2822 :: scripts/docket-run sc-l2822
    #[test]
    fn assertions_in_two_children_are_error_for_good(
        common in 1usize..4, left in 1usize..4, right in 1usize..4,
        adds in proptest::collection::vec(any::<bool>(), 0..6),
        extra in proptest::collection::vec(0usize..3, 0..4),
    ) {
        let (mut held, mut l, mut r) = fork(common, left, right);
        let mut asserted = vec![pr(1000), pr(2000)];
        let want = error_at(common, l, r);
        prop_assert_eq!(read(&held, &asserted), want);
        for (n, on_left) in adds.into_iter().enumerate() {
            let cur = if on_left { &mut l } else { &mut r };
            push(&mut held, 5000 + n, *cur);
            *cur = 5000 + n;
            if let Some(&e) = extra.get(n) {
                asserted.push(pr(if e == 0 { 5000 + n } else { 1000 + e % left }));
            }
            let want = error_at(common, l, r);
            prop_assert_eq!(read(&held, &asserted), want, "after {} adds", n + 1);
        }
    }

    /// R3. Catches pre-emption and regression: assertions at or below the
    /// fork point (the common chain), or naming nothing held, select no
    /// child, so the verdict is rule E's; and an empty set is rule E.
    #[test]
    fn assertions_that_select_no_child_change_nothing(
        common in 1usize..4, left in 1usize..4, right in 1usize..4,
        below in proptest::collection::vec(0usize..4, 0..3),
        unheld in 0usize..3,
        extend_both in any::<bool>(),
    ) {
        let (mut held, ..) = fork(common, left, right);
        if extend_both {
            push(&mut held, 6000, 1000);
            push(&mut held, 6001, 2000);
        }
        let want = read(&held, &[]);
        let mut asserted: Vec<String> = below.into_iter().map(|i| pr(i % common)).collect();
        asserted.extend((0..=unheld).map(|k| format!("unheld-{k}")));
        prop_assert_eq!(read(&held, &asserted), want);
    }

    /// R4. Catches order dependence: the verdict is invariant under
    /// permutation and duplication of the held commits and of the asserted
    /// set.
    #[test]
    fn the_verdict_ignores_order_and_duplicates(
        (t, asserted) in asserted_tree(10), seed in any::<u64>(), dup in 0usize..4,
    ) {
        let held = t.held();
        let mut held2 = held.clone();
        let mut asserted2 = asserted.clone();
        for k in 0..dup {
            held2.push(held[k % held.len()].clone());
            asserted2.push(asserted[k % asserted.len()].clone());
        }
        let mut s = seed | 1;
        let mut shuffle = |n: usize| {
            let mut idx: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                idx.swap(i, (s % (i as u64 + 1)) as usize);
            }
            idx
        };
        let held2: Vec<Held> = shuffle(held2.len()).into_iter().map(|i| held2[i].clone()).collect();
        let asserted2: Vec<String> =
            shuffle(asserted2.len()).into_iter().map(|i| asserted2[i].clone()).collect();
        let (a, b) = (assess(&held, &asserted), assess(&held2, &asserted2));
        prop_assert_eq!(a.consensus, b.consensus);
        prop_assert_eq!(a.heads, b.heads);
        prop_assert_eq!(a.fork_point, b.fork_point);
    }
}
