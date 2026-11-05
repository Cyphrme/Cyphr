// Scenario S02: partition.
// Fault: network partition of P2.
// P2 is partitioned while Alice rotates on P1; Bob reads only P2; then heal.
// Must hold: during the partition Bob sees "stale, age t", not "current"; after
// healing, anti-entropy converges; no evidence (prefix).
//
// Required capabilities: transport,cli-network,peer-gossip,pinning.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s02_partition() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::PeerGossip,
        Capability::Pinning,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await);
    h.ok(bob.trust_genesis(&pr, &["p2"]).await);
    h.ok(bob.watch(&pr).await);

    // P2 is cut off from P1 and from Alice; Bob can still reach P2.
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice", "p2");
    h.ok(alice.rotate_key(&pr).await);
    let tip = match h.ok(alice.push(&pr, &["p1"]).await) {
        PushOutcome::Accepted(t) => t,
        other => panic!("rotation push to P1: {other:?}"),
    };

    let during = h.ok(bob.verdict(&pr, &["p2"]).await);
    match during.freshness {
        Freshness::Stale { age } => assert!(age > Duration::ZERO, "stale needs an age"),
        Freshness::Current => panic!("a partitioned view must not read as current"),
    }
    assert_ne!(during.tip, tip, "P2 cannot have seen the rotation");

    h.proxy.heal("p1", "p2");
    h.proxy.heal("alice", "p2");
    h.eventually(
        "anti-entropy to bring P2 to Alice's tip",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &["p2"]).await?;
            Ok(v.tip == tip && v.freshness == Freshness::Current)
        },
    )
    .await;
    let after = h.ok(bob.verdict(&pr, &["p2"]).await);
    assert_eq!(after.standing, Standing::Active);
    assert!(after.evidence.is_empty(), "a strict prefix is not evidence");
}
