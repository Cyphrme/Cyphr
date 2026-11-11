// Scenario S02: partition.
// Fault: network partition of P2.
// P2 is partitioned while Alice rotates on P1; Bob reads only P2; then heal.
// Must hold: during the partition Bob sees "stale, age t", not "current"; after
// healing, anti-entropy converges; no evidence (prefix).
//
// Required capabilities: transport,cli-network,evidence,peer-gossip,pinning.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::{Duration, Instant};

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(key-pairing): N22 rotate_key; watch is G3, landed"]
async fn s02_partition() {
    let h = Harness::start_gossiping(&["p1", "p2"], 1)
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::Pinning,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let before = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("initial push");
    h.ok(bob.trust_genesis(&pr, &["p2"]).await);
    h.ok(bob.watch(&pr).await);
    let last_update = Instant::now();

    // P2 is cut off from P1 and from Alice; Bob can still reach P2. Verify
    // each fault before relying on it.
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice", "p2");
    assert!(
        !h.reach("alice", "p2").await,
        "Alice must be cut off from P2"
    );
    assert!(h.reach("bob", "p2").await, "Bob must still reach P2");

    h.ok(alice.rotate_key(&pr).await);
    let tip = h
        .ok(alice.push(&pr, &["p1"]).await)
        .accepted("rotation push to P1");
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(tip.clone())
    );

    // The peer-to-peer link must be exercised, not merely declared: the
    // partition has to have blocked real traffic between the peers.
    h.eventually(
        "a peer-to-peer attempt on the cut link",
        CONVERGE,
        || async { Ok(h.proxy.stats("p1", "p2").blocked > 0) },
    )
    .await;
    assert_eq!(
        h.peer_view("p2", &pr).await.map(|v| v.tip),
        Some(before.clone()),
        "a partitioned P2 must not learn the rotation"
    );

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let during = h.ok(bob.verdict(&pr, &["p2"]).await);
    assert_eq!(during.tip, before, "Bob can only see P2's old tip");
    assert!(
        during.freshness.age >= last_update.elapsed().saturating_sub(Duration::from_secs(1)),
        "the view's age must have grown with the partition, got {:?}",
        during.freshness.age
    );
    assert!(
        during.freshness.age <= last_update.elapsed() + Duration::from_secs(1),
        "a view cannot be older than the time since its last update, got {:?}",
        during.freshness.age
    );

    h.proxy.heal("p1", "p2");
    h.proxy.heal("alice", "p2");
    h.eventually(
        "anti-entropy to bring P2 to Alice's tip",
        CONVERGE,
        || async { Ok(h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(tip.clone())) },
    )
    .await;
    h.eventually("Bob to catch up", CONVERGE, || async {
        let v = bob.verdict(&pr, &["p2"]).await?;
        Ok(v.tip == tip && !v.freshness.peer_reported_newer)
    })
    .await;
    let after = h.ok(bob.verdict(&pr, &["p2"]).await);
    h.check_verdict(&after, &pr, &Expect::new(&["p2"], &pr.0))
        .await;
    assert_eq!(after.standing, Standing::Active);
    assert!(after.evidence.is_empty(), "a strict prefix is not evidence");
}
