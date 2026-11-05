// Scenario S09: migration.
// Fault: a peer leaves the network for good.
// Alice moves to P3, updates her self-claim; P1 goes away.
// Must hold: Bob follows the claim to P3; only his verdict's peer list changes.
//
// Required capabilities: transport,cli-network,discovery.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s09_migration() {
    let h = Harness::start(&["p1", "p2", "p3"])
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Discovery,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await);
    h.ok(alice.publish_self_claim(&pr, &["p1"]).await);
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let before = h.ok(bob.verdict(&pr, &[]).await);
    assert_eq!(before.peers, ["p1"]);

    h.ok(alice.push(&pr, &["p3"]).await);
    h.ok(alice.publish_self_claim(&pr, &["p3"]).await);
    h.ok(h.stop_peer("p1").await);

    h.ok(bob.follow_claim(&pr).await);
    let after = h.ok(bob.verdict(&pr, &[]).await);
    assert_eq!(after.peers, ["p3"], "Bob follows the claim to P3");
    assert_eq!(after.tip, before.tip);
    assert_eq!(after.anchor, before.anchor);
    assert_eq!(after.standing, Standing::Active);
    assert!(after.evidence.is_empty());
}
