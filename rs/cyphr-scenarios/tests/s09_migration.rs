// Scenario S09: migration.
// Fault: a peer leaves the network for good.
// Alice moves her principal to P3; P1 goes away. Bob adds P3 to the peers
// he asks: a plain peer-list edit, with no discovery and no claim to follow.
// Must hold: Bob's verdict reads Alice's newest tip from P3 although P1 is
// gone; only his verdict's peer list changes (same anchor, Active, no
// evidence); the move itself forks nothing.
//
// Required capabilities: transport,cli-network,evidence,data-commit.
// End to end: Alice and Bob use the `cyphr` CLI against real peers; P1 is
// stopped, not partitioned.
// Turns red if: P3 does not take the chain as Alice pushes it, a verdict
// over a list naming a dead peer fails or reads an old tip, the anchor
// changes with the peer list, or the move reads as a fork.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn s09_migration() {
    let h = Harness::start(&["p1", "p3"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
        Capability::DataCommit,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let t1 = h.ok(alice.push(&pr, &["p1"]).await).accepted("push to P1");
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let before = h.ok(bob.verdict(&pr, &[]).await);
    h.check_verdict(&before, &pr, &Expect::new(&["p1"], &pr.0))
        .await;
    assert_eq!(before.tip, t1);

    // Alice moves: the same chain, pushed to a peer that never held it.
    let moved = h.ok(alice.push(&pr, &["p3"]).await).accepted("push to P3");
    assert_eq!(moved, t1, "the same chain moves to P3");
    h.ok(h.stop_peer("p1").await);
    assert!(h.peer_down("p1").await, "P1 must actually be gone");

    // A commit that lands on P3 only after P1 is gone, so a verdict that
    // replays an old view, or a cache, cannot show it.
    h.ok(alice.commit_data(&pr, "after the move").await);
    let t2 = h
        .ok(alice.push(&pr, &["p3"]).await)
        .accepted("push to P3 after P1 left");
    assert_ne!(t2, t1);
    assert_eq!(
        h.settled_view("p3", &pr).await.map(|v| v.tip),
        Some(t2.clone())
    );

    // Bob's edit: P3 joins the peers he asks; P1 stays on his list, dead.
    let after = h.ok(bob.verdict(&pr, &["p1", "p3"]).await);
    // The verdict names the peers it used: P3 answered, P1 could not.
    h.check_verdict(&after, &pr, &Expect::new(&["p3"], &pr.0))
        .await;
    assert_eq!(after.tip, t2, "Bob reads Alice's newest tip from P3");
    assert_eq!(after.anchor, before.anchor, "only the peer list may change");
    assert_eq!(after.standing, Standing::Active);
    assert!(after.evidence.is_empty(), "a move is not a fork");
    assert_eq!(after.branches, std::slice::from_ref(&t2));
}
