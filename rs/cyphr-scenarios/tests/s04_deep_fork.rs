// Fork over an agreed history, S04's theft at depth: in both tests the
// agreed history is k = 3 commits beyond genesis (two commits, then the
// laptop's pairing) before the fork.
//
// Equal branches: every server converges on Error plus evidence, as at
// depth 0.
// One branch extended: a commit naming a fork child as its `pre` is what
// selects it (SPEC 15.8 item 1), so every server converges on Active at
// the extended tip with the other kept as evidence. A thief's stale copy
// of a device (made before the owner's later commits) forks that far
// down, and the owner's two commits against the thief's one select the
// owner's branch because only it is extended, not because it is taller.
// Both extended: the fork stays an error whatever the heights (the spec
// author on #203: "They're both out of compliance"), and no further
// commit on either side leaves it.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip,audit,data-commit.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);
const CAPS: &[Capability] = &[
    Capability::Transport,
    Capability::CliNetwork,
    Capability::BranchStore,
    Capability::Evidence,
    Capability::PeerGossip,
    Capability::Audit,
    Capability::DataCommit,
];

#[tokio::test(flavor = "multi_thread")]
async fn deep_fork_converges_on_error() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    // The agreed history is grown before the laptop is paired: the laptop
    // takes its copy at pairing, so what it lacks it cannot fork over.
    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.commit_data(&pr, "agreed one").await);
    h.ok(alice.add_backup_key(&pr).await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    h.ok(thief.steal_key(&laptop, &laptop_key).await);

    h.ok(alice.commit_data(&pr, "alice").await);
    h.ok(thief.commit_data(&pr, "thief").await);
    let at = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h
        .ok(thief.push(&pr, &["p3"]).await)
        .accepted("thief branch");
    assert_ne!(at, tt, "the thief must have forked");

    h.eventually(
        "every verdict to converge on Error plus evidence",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &all).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    let forked = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&forked, &pr, &Expect::new(&all, &pr.0))
        .await;
    assert!(forked.branches.contains(&at) && forked.branches.contains(&tt));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_only_extended_branch_selects_the_fork() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.commit_data(&pr, "agreed one").await);
    h.ok(alice.add_backup_key(&pr).await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    // Alice goes on after the pairing, so the stolen laptop is a stale
    // copy and the fork lies below her tip.
    h.ok(alice.commit_data(&pr, "alice one").await);
    h.ok(alice.add_backup_key(&pr).await);
    h.ok(thief.steal_key(&laptop, &laptop_key).await);
    h.ok(thief.commit_data(&pr, "thief").await);
    let at = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h
        .ok(thief.push(&pr, &["p3"]).await)
        .accepted("thief branch");
    assert_ne!(at, tt, "the thief must have forked");

    h.eventually(
        "every server to settle on the extended branch",
        CONVERGE,
        || async {
            for peer in all {
                if h.peer_view(peer, &pr).await.map(|v| v.tip) != Some(at.clone()) {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;
    let v = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&v, &pr, &Expect::new(&all, &pr.0)).await;
    assert_eq!(
        v.standing,
        Standing::Active,
        "only the extended branch is selected"
    );
    assert_eq!(v.tip, at);
    assert!(v.evidence.contains(&Evidence::PrincipalFork(pr.clone())));
    assert!(v.abandoned.contains(&tt), "the unextended branch is kept");
}

/// Alice makes `alice` commits and the thief `thief` commits over the
/// fork, both past the agreed history; every server must read Error.
async fn both_extended(alice: usize, thief: usize) {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (a, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (t, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(a.create_principal().await);
    h.ok(a.commit_data(&pr, "agreed one").await);
    h.ok(a.add_backup_key(&pr).await);
    let laptop_key = h.ok(a.pair_device(&pr, &laptop).await);
    h.ok(a.push(&pr, &["p1", "p2"]).await).accepted("base push");
    h.ok(t.steal_key(&laptop, &laptop_key).await);
    for n in 0..alice {
        h.ok(a.commit_data(&pr, &format!("alice {n}")).await);
    }
    for n in 0..thief {
        h.ok(t.commit_data(&pr, &format!("thief {n}")).await);
    }
    h.ok(a.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    h.ok(t.push(&pr, &["p3"]).await).accepted("thief branch");

    // Catches tallest-wins: the taller branch must not make any server
    // Active, and no server may hold a single tip.
    h.eventually(
        "every verdict to converge on Error plus evidence",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &all).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    // Catches split witnesses: each server reports the tie itself.
    h.eventually("every server to report Error", CONVERGE, || async {
        for peer in all {
            match h.peer_view(peer, &pr).await {
                Some(v) if v.heads.len() > 1 => {},
                _ => return Ok(false),
            }
        }
        Ok(true)
    })
    .await;
    let v = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&v, &pr, &Expect::new(&all, &pr.0)).await;
    assert_eq!(v.standing, Standing::Error, "{alice} vs {thief} commits");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taller_owner_branch_does_not_settle_a_both_extended_fork() {
    both_extended(3, 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taller_thief_branch_does_not_settle_a_both_extended_fork() {
    both_extended(2, 3).await;
}
