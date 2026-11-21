// Fork over an agreed history, S04's theft at depth (k = 3 agreed commits
// beyond genesis before the fork).
//
// Equal branches: every server converges on Error plus evidence, as at
// depth 0.
// Unequal branches: the taller branch settles the fork (SPEC 15.8, the
// fork rule in cyphr/src/fork.rs), so every server converges on Active at
// the taller tip with the shorter kept as evidence, never on Error. A
// thief's stale copy of a device (made before the owner's later commits)
// forks that far down, and the owner's longer chain wins without resolving.
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
async fn a_taller_branch_settles_the_fork() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(alice.create_principal().await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
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
        "every server to settle on the taller branch",
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
    assert_eq!(v.standing, Standing::Active, "the longer branch settles it");
    assert_eq!(v.tip, at);
    assert!(v.evidence.contains(&Evidence::PrincipalFork(pr.clone())));
    assert!(v.abandoned.contains(&tt), "the shorter branch is kept");
}
