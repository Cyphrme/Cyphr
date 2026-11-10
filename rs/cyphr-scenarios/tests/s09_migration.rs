// Scenario S09: migration.
// Fault: a peer leaves the network for good.
// Alice moves to P3, updates her self-claim; P1 goes away.
// Must hold: Bob follows the claim to P3; only his verdict's peer list changes.
//
// Required capabilities: transport,cli-network,discovery,evidence,data-commit.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(discovery): G4"]
async fn s09_migration() {
    let h = Harness::start(&["p1", "p2", "p3"])
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Discovery,
        Capability::Evidence,
        Capability::DataCommit,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let t1 = h.ok(alice.push(&pr, &["p1"]).await).accepted("push to P1");
    h.ok(alice.publish_self_claim(&pr, &["p1"]).await);
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let before = h.ok(bob.verdict(&pr, &[]).await);
    assert_eq!(
        before.peers,
        ["p1"],
        "peers lists those used, even for an empty `from`"
    );
    assert_eq!(before.tip, t1);

    let moved = h.ok(alice.push(&pr, &["p3"]).await).accepted("push to P3");
    assert_eq!(moved, t1, "the same chain moves to P3");
    assert_eq!(
        h.peer_view("p3", &pr).await.map(|v| v.tip),
        Some(t1.clone())
    );
    h.ok(alice.publish_self_claim(&pr, &["p3"]).await);
    h.ok(h.stop_peer("p1").await);
    assert!(h.peer_down("p1").await, "P1 must actually be gone");

    // A new commit lands on P3 only after P1 is gone, so a verdict that
    // merely replays an old view (or a cache) cannot show it.
    h.ok(alice.commit_data(&pr, "after the move").await);
    let t2 = h
        .ok(alice.push(&pr, &["p3"]).await)
        .accepted("push to P3 after P1 left");
    assert_ne!(t2, t1);
    assert_eq!(
        h.settled_view("p3", &pr).await.map(|v| v.tip),
        Some(t2.clone())
    );

    h.ok(bob.follow_claim(&pr).await);
    h.eventually(
        "Bob to follow the claim to P3's new tip",
        CONVERGE,
        || async { Ok(bob.verdict(&pr, &[]).await?.tip == t2) },
    )
    .await;
    let after = h.ok(bob.verdict(&pr, &[]).await);
    h.check_verdict(&after, &pr, &Expect::new(&["p3"], &pr.0))
        .await;
    assert_eq!(after.peers, ["p3"], "Bob follows the claim to P3");
    assert_eq!(after.tip, t2);
    assert_eq!(after.anchor, before.anchor, "only the peer list may change");
    assert_eq!(after.standing, Standing::Active);
    assert!(after.evidence.is_empty());
}
