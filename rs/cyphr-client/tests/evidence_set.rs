//! Properties of fork-evidence verification as a set
//! ([`cyphr_client::evidence::verify_fork_items`]), the one verifier the
//! pull step and the scenario oracle share. A peer serves one item per
//! commit it retains: a fork at a position of the holder's chain, then one
//! item per commit extending the rival, whose `pre` is off that chain.
//! Built offline from real chains; no server takes part.

mod common;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use common::*;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::PatchEntry;
use cyphr_client::evidence::verify_fork_items;
use proptest::prelude::*;
use serde_json::{Value, json};

/// The rival branch's length past the fork: items 1..=DEPTH.
const DEPTH: usize = 4;

struct Line {
    entries: Vec<Vec<String>>,
    prs: Vec<String>,
    ids: Vec<String>,
}

async fn line(g: &Kp, keys: &[&Kp], t: i64) -> Line {
    let mut chain = Chain::new(g).await;
    let id = |c: &Chain<'_>| {
        c.principal
            .commits()
            .last()
            .expect("a commit")
            .tr()
            .0
            .tagged_first()
            .expect("id")
            .to_string()
    };
    let mut l = Line {
        entries: vec![chain.genesis_commit.clone()],
        prs: vec![chain.principal.pr_tagged().expect("pr")],
        ids: vec![id(&chain)],
    };
    for (i, k) in keys.iter().enumerate() {
        let blobs = chain.commit(k, t + i as i64).await;
        l.entries.push(blobs);
        l.prs.push(chain.principal.pr_tagged().expect("pr"));
        l.ids.push(id(&chain));
    }
    l
}

struct Fixture {
    g: Kp,
    pg: String,
    canonical: Line,
    rival: Line,
    /// A branch of the same principal no served item forks from.
    unrelated: Line,
    /// The rival's first commit, then a commit of its own at 2: a second
    /// extension of the rival's first commit.
    sibling: Line,
}

fn item(pg: &str, height: usize, pre: &str, a: &Line, b: &Line) -> Value {
    json!({
        "kind": "principal-fork", "pg": pg, "height": height, "pre": pre,
        "a": entry_bundle(height, &a.entries[height]),
        "b": entry_bundle(height, &b.entries[height]),
    })
}

impl Fixture {
    /// The valid item at `height`: the fork at 1, an extension above it.
    fn valid(&self, height: usize) -> Value {
        let pre = if height == 1 {
            &self.canonical.prs[0]
        } else {
            &self.rival.prs[height - 1]
        };
        item(&self.pg, height, pre, &self.canonical, &self.rival)
    }

    /// A forged item of kind `which`.
    fn forged(&self, which: u8) -> Value {
        match which {
            // A bad signature on the rival's commit.
            0 => {
                let mut v = self.valid(2);
                let tx = v["b"]["txs"][0][0].as_str().expect("tx").to_owned();
                let mut coz: Value =
                    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(&tx).expect("b64"))
                        .expect("coz");
                let sig = coz["sig"].as_str().expect("sig");
                let flipped = if sig.starts_with('A') { "B" } else { "A" };
                coz["sig"] = json!(format!("{flipped}{}", &sig[1..]));
                v["b"]["txs"][0][0] = json!(Base64UrlUnpadded::encode_string(
                    &serde_json::to_vec(&coz).expect("json")
                ));
                v
            },
            // An extension naming the holder's chain as its `pre`.
            1 => item(
                &self.pg,
                3,
                &self.canonical.prs[2],
                &self.canonical,
                &self.rival,
            ),
            // A commit off every served branch.
            2 => item(
                &self.pg,
                2,
                &self.unrelated.prs[1],
                &self.canonical,
                &self.unrelated,
            ),
            // A `pre` from later in the rival branch: a cycle in the chain.
            _ => item(
                &self.pg,
                2,
                &self.rival.prs[3],
                &self.canonical,
                &self.rival,
            ),
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        runtime().block_on(async {
            let g = kp();
            let keys: Vec<Kp> = (0..=3 * DEPTH).map(|_| kp()).collect();
            let refs: Vec<&Kp> = keys.iter().collect();
            let t = 1_700_000_100;
            let canonical = line(&g, &refs[..DEPTH], t).await;
            let rival = line(&g, &refs[DEPTH..2 * DEPTH], t).await;
            let unrelated = line(&g, &refs[2 * DEPTH..3 * DEPTH], t).await;
            let sibling = line(&g, &[refs[DEPTH], refs[3 * DEPTH]], t).await;
            Fixture {
                pg: g.tmb.to_b64(),
                g,
                canonical,
                rival,
                unrelated,
                sibling,
            }
        })
    })
}

/// The forks and extensions `items` prove against the canonical chain:
/// (fork rival ids, extension ids, rejected count).
fn verdict(items: &[Value]) -> (BTreeSet<String>, BTreeSet<String>, usize) {
    let f = fixture();
    runtime().block_on(async {
        let base = cyphr::Principal::implicit(f.g.domain_key(1_700_000_000))
            .await
            .expect("genesis");
        let entries: Vec<PatchEntry> =
            f.canonical
                .entries
                .iter()
                .enumerate()
                .map(|(i, blobs)| PatchEntry {
                    sequence: i as u64,
                    bundle: Ok(serde_json::from_value::<WireBundle>(entry_bundle(i, blobs))
                        .expect("bundle")),
                })
                .collect();
        let ids: Vec<Option<String>> = f.canonical.ids.iter().cloned().map(Some).collect();
        let refs: Vec<&Value> = items.iter().collect();
        let set = verify_fork_items(&refs, &f.pg, &base, &entries, &ids).await;
        let forks = set
            .forks
            .iter()
            .map(|(p, _)| p.commits[1].clone())
            .collect();
        let exts = set.extensions.iter().map(|e| e.id.clone()).collect();
        (forks, exts, set.rejected.len())
    })
}

/// What the valid items at `kept` heights prove: the fork when 1 is kept,
/// and each extension whose whole branch below it is kept.
fn expected(kept: &BTreeSet<usize>) -> (BTreeSet<String>, BTreeSet<String>) {
    let f = fixture();
    let forks = if kept.contains(&1) {
        BTreeSet::from([f.rival.ids[1].clone()])
    } else {
        BTreeSet::new()
    };
    let exts = (2..=DEPTH)
        .take_while(|h| (1..=*h).all(|i| kept.contains(&i)))
        .map(|h| f.rival.ids[h].clone())
        .collect();
    (forks, exts)
}

/// Both commits of one item may extend the rival tip below it: the
/// serving peer retained two extensions of one rival commit. Each is a
/// commit of the rival's branch, so both are proved, not only the one
/// tried first. A plain test, not a property: the case is one shape, and
/// no generated order reaches it.
#[test]
fn both_commits_of_an_item_can_extend_the_rival() {
    let f = fixture();
    let both = item(&f.pg, 2, &f.rival.prs[1], &f.sibling, &f.rival);
    let (_, exts, rejected) = verdict(&[f.valid(1), both]);
    assert_eq!(rejected, 0);
    assert_eq!(
        exts,
        BTreeSet::from([f.rival.ids[2].clone(), f.sibling.ids[2].clone()]),
        "both extensions of the rival's first commit are proved"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Any order, repetition or omission of valid items proves exactly the
    /// fork and the unbroken prefix of the rival branch they carry, and
    /// refuses an item whose parent is missing (a broken link), never
    /// accepting it.
    #[test]
    fn order_and_repetition_do_not_change_the_verdict(
        picks in proptest::collection::vec(1..=DEPTH, 0..12),
    ) {
        let f = fixture();
        let items: Vec<Value> = picks.iter().map(|h| f.valid(*h)).collect();
        let kept: BTreeSet<usize> = picks.iter().copied().collect();
        let (forks, exts, rejected) = verdict(&items);
        let (want_forks, want_exts) = expected(&kept);
        prop_assert_eq!(forks, want_forks);
        prop_assert_eq!(&exts, &want_exts);
        // Every item past a broken link is refused, once per copy.
        let accepted = picks
            .iter()
            .filter(|h| **h == 1 || exts.contains(&f.rival.ids[**h]))
            .count();
        prop_assert_eq!(rejected, picks.len() - accepted);
    }

    /// A forged item (a bad signature, a `pre` on the holder's chain, a
    /// commit off every branch, a `pre` from later in the branch) anywhere
    /// among the valid items is refused and changes nothing they prove.
    #[test]
    fn a_forged_item_is_refused_and_changes_nothing(
        which in 0u8..4,
        at in 0usize..=DEPTH,
        reversed in any::<bool>(),
    ) {
        let f = fixture();
        let mut items: Vec<Value> = (1..=DEPTH).map(|h| f.valid(h)).collect();
        if reversed {
            items.reverse();
        }
        let clean = verdict(&items);
        items.insert(at, f.forged(which));
        let (forks, exts, rejected) = verdict(&items);
        prop_assert_eq!(rejected, 1);
        prop_assert_eq!((forks, exts), (clean.0, clean.1));
    }
}

/// archrev:B2. A verifier holding the rival branch is served the items a
/// peer on the other branch retains: the fork at 1, then one item per
/// commit past it. The fork is evidence; the later items concern commits
/// of the verifier's own branch and prove nothing against it, but they are
/// honest, so none may be filed as rejected (a rejection means "this item
/// is not evidence", which would taint an honest peer).
///
/// Turns red if an item whose `pre` falls on the holder's chain is always
/// read as a fork claim, so honest extension items are rejected.
/// End-to-end: no; the item set is the unit the pull step and the
/// scenario oracle share, and this builds it from real chains.
#[test]
#[ignore = "RED(archrev:B2): needs a second item kind, a wire change across server/scenarios"]
fn archrev_b2_honest_items_are_not_rejected_for_a_holder_on_the_other_branch() {
    let f = fixture();
    runtime().block_on(async {
        let base = cyphr::Principal::implicit(f.g.domain_key(1_700_000_000))
            .await
            .expect("genesis");
        let entries: Vec<PatchEntry> = f
            .rival
            .entries
            .iter()
            .enumerate()
            .map(|(i, blobs)| PatchEntry {
                sequence: i as u64,
                bundle: Ok(serde_json::from_value::<WireBundle>(entry_bundle(i, blobs))
                    .expect("bundle")),
            })
            .collect();
        let ids: Vec<Option<String>> = f.rival.ids.iter().cloned().map(Some).collect();
        let items: Vec<Value> = (1..=DEPTH).map(|h| f.valid(h)).collect();
        let refs: Vec<&Value> = items.iter().collect();
        let set = verify_fork_items(&refs, &f.pg, &base, &entries, &ids).await;
        assert_eq!(set.forks.len(), 1, "the fork at 1 is proved");
        assert!(
            set.rejected.is_empty(),
            "honest items rejected: {:?}",
            set.rejected
        );
    });
}
