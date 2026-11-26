//! One parent walk and one divergence point (FIX-FRAME 2.2 "Exact
//! contracts"): `fork::parent_of` and `fork::first_divergence`.
//!
//! - `parent_of(held, child)` is the element `child` extends; with several qualifying, the smallest
//!   `id`, so the answer does not depend on the slice's order. A commit with no `pre`, or whose
//!   parent is not held, has none.
//! - `first_divergence(ours, theirs)` is the smallest index below both lengths where the ids
//!   differ; `None` when one is a prefix of the other, equal slices included. Metamorphic:
//!   symmetric, and unchanged by a common suffix.
//!
//! Red before K1: neither function exists.

use cyphr::fork::{Held, first_divergence, parent_of};
use cyphr::state::{HashAlg, TaggedDigest};
use proptest::prelude::*;

fn held(id: &str, sequence: u64, pre: Option<&str>, pr: &str) -> Held {
    Held {
        sequence,
        id: id.to_string(),
        pre: pre.map(str::to_string),
        pr: pr.to_string(),
        signed: vec![],
    }
}

/// A chain of `n` commits, `c0` genesis, each over the previous, plus a
/// rival `r{i}` at every position over the same parent as `c{i}`.
fn chain_with_rivals(n: usize) -> Vec<Held> {
    let mut out = Vec::new();
    for i in 0..n {
        let pre = (i > 0).then(|| format!("p{}", i - 1));
        out.push(held(
            &format!("c{i}"),
            i as u64,
            pre.as_deref(),
            &format!("p{i}"),
        ));
        out.push(held(
            &format!("r{i}"),
            i as u64,
            pre.as_deref(),
            &format!("q{i}"),
        ));
    }
    out
}

proptest! {
    #[test]
    fn parent_of_is_the_commit_extended(n in 1usize..8, rot in 0usize..16) {
        let mut all = chain_with_rivals(n);
        let len = all.len();
        all.rotate_left(rot % len);
        for child in &all {
            let want = all.iter().filter(|p| child.extends(p)).map(|p| p.id.as_str()).min();
            prop_assert_eq!(parent_of(&all, child).map(|p| p.id.as_str()), want);
        }
        let genesis = all.iter().find(|h| h.sequence == 0).expect("genesis");
        prop_assert!(parent_of(&all, genesis).is_none());
    }

    #[test]
    fn parent_of_ignores_slice_order(n in 1usize..8) {
        let all = chain_with_rivals(n);
        let mut reversed = all.clone();
        reversed.reverse();
        for child in &all {
            prop_assert_eq!(
                parent_of(&all, child).map(|p| &p.id),
                parent_of(&reversed, child).map(|p| &p.id)
            );
        }
    }
}

/// Two held commits claim the same `(sequence, pr)`: the smaller id wins,
/// whichever comes first.
#[test]
fn a_tie_goes_to_the_smallest_id() {
    let child = held("k", 5, Some("p"), "next");
    let (a, b) = (held("a", 4, None, "p"), held("b", 4, None, "p"));
    for held in [vec![a.clone(), b.clone()], vec![b, a]] {
        assert_eq!(parent_of(&held, &child).map(|p| p.id.as_str()), Some("a"));
    }
}

#[test]
fn a_child_whose_parent_is_not_held_has_none() {
    let child = held("k", 5, Some("missing"), "next");
    assert!(parent_of(&[held("a", 4, None, "p")], &child).is_none());
}

fn ids(v: &[u8]) -> Vec<TaggedDigest> {
    v.iter()
        .map(|&b| TaggedDigest::new(HashAlg::Sha256, vec![b; 32]).expect("width"))
        .collect()
}

proptest! {
    #[test]
    fn first_divergence_is_the_first_unequal_index(
        ours in proptest::collection::vec(0u8..3, 0..8),
        theirs in proptest::collection::vec(0u8..3, 0..8),
    ) {
        let want = ours.iter().zip(&theirs).position(|(a, b)| a != b);
        prop_assert_eq!(first_divergence(&ids(&ours), &ids(&theirs)), want);
        prop_assert_eq!(first_divergence(&ids(&theirs), &ids(&ours)), want);
    }

    #[test]
    fn a_prefix_does_not_diverge(
        base in proptest::collection::vec(0u8..3, 0..8),
        tail in proptest::collection::vec(0u8..3, 0..4),
    ) {
        let mut longer = base.clone();
        longer.extend(&tail);
        prop_assert_eq!(first_divergence(&ids(&base), &ids(&longer)), None);
        prop_assert_eq!(first_divergence(&ids(&base), &ids(&base)), None);
    }

    #[test]
    fn a_common_suffix_moves_nothing(
        pairs in proptest::collection::vec((0u8..3, 0u8..3), 0..6),
        suffix in proptest::collection::vec(0u8..3, 0..4),
    ) {
        let ours: Vec<u8> = pairs.iter().map(|p| p.0).collect();
        let theirs: Vec<u8> = pairs.iter().map(|p| p.1).collect();
        let (mut o, mut t) = (ours.clone(), theirs.clone());
        o.extend(&suffix);
        t.extend(&suffix);
        let with_suffix = first_divergence(&ids(&o), &ids(&t));
        prop_assert_eq!(with_suffix, first_divergence(&ids(&ours), &ids(&theirs)));
    }
}
