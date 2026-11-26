//! One parent-link rule: `Held::extends(&parent)` is the `pre` and
//! `sequence + 1` test every storage, client and CLI copy hand-writes
//! (`.pre.as_deref()` plus `checked_sub(1)`).
//!
//! Property over generated trees of held commits (unique ids and PRs): a
//! commit extends exactly the commit its tree names as its parent, and no
//! other. Metamorphic: moving the child's `sequence` by anything but one,
//! or changing its `pre`, severs the link; a genesis commit (no `pre`)
//! extends nothing.
//!
//! Red before K1: `Held::extends` does not exist. `parent_of` and
//! `first_divergence` are in `fork_walk.rs`; `binds` left K1.

use cyphr::fork::Held;
use proptest::prelude::*;

/// Commit `i` at `sequence` over `parent`; ids and PRs are unique per `i`.
fn held(i: usize, sequence: u64, parent: Option<usize>) -> Held {
    Held {
        sequence,
        id: format!("c{i}"),
        pre: parent.map(|p| format!("p{p}")),
        pr: format!("p{i}"),
        signed: vec![format!("k{i}")],
    }
}

/// `n` commits: node 0 is genesis, node `i`'s parent is `parents[i - 1]`
/// (an earlier node); each sits one above its parent.
fn tree() -> impl Strategy<Value = Vec<(Held, Option<usize>)>> {
    (1usize..12)
        .prop_flat_map(|n| (1..n).map(|i| 0..i).collect::<Vec<_>>())
        .prop_map(|parents| {
            let mut seq = vec![0u64];
            let mut out = vec![(held(0, 0, None), None)];
            for (i, &p) in parents.iter().enumerate() {
                let n = i + 1;
                seq.push(seq[p] + 1);
                out.push((held(n, seq[n], Some(p)), Some(p)));
            }
            out
        })
}

proptest! {
    #[test]
    fn a_commit_extends_exactly_its_tree_parent(nodes in tree()) {
        for (i, (child, parent)) in nodes.iter().enumerate() {
            for (j, (other, _)) in nodes.iter().enumerate() {
                prop_assert_eq!(
                    child.extends(other),
                    *parent == Some(j),
                    "node {} over node {}", i, j
                );
            }
        }
    }

    #[test]
    fn a_wrong_position_or_pre_severs_the_link(nodes in tree(), skew in 0u64..5, other in "[a-z]{3}") {
        for (child, parent) in nodes.iter().filter_map(|(c, p)| p.map(|p| (c, p))) {
            let parent = &nodes[parent].0;
            let mut moved = child.clone();
            moved.sequence = child.sequence + 2 + skew;
            prop_assert!(!moved.extends(parent));
            let mut renamed = child.clone();
            renamed.pre = Some(format!("x{other}"));
            prop_assert!(!renamed.extends(parent));
            let mut genesis = child.clone();
            genesis.pre = None;
            prop_assert!(!genesis.extends(parent));
        }
    }
}
