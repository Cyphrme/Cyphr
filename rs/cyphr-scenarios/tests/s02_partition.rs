// Scenario S02: partition.
// Fault: network partition of P2.
// P2 is partitioned while Alice rotates on P1; Bob reads only P2; then heal.
// Must hold: during the partition Bob sees "stale, age t", not "current"; once
// Bob is cut from P2 too and asks both peers, his verdict reads "P2 unreachable
// since t", with the newest verified tip from P1; after healing, anti-entropy
// converges; no evidence (prefix).
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

    // A view's age counts from the peer's last update, which the first push
    // makes, so no view can be older than the time since that push began.
    let watch_began = Instant::now();
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

    // Wait for the view to have aged, rather than for a fixed time that a
    // loaded machine may stretch or shrink.
    h.eventually("Bob's view of P2 to age a second", CONVERGE, || async {
        Ok(bob.verdict(&pr, &["p2"]).await?.freshness.age >= Duration::from_secs(1))
    })
    .await;
    let read_at = unix_now();
    let during = h.ok(bob.verdict(&pr, &["p2"]).await);
    assert_eq!(during.tip, before, "Bob can only see P2's old tip");
    assert!(
        during.freshness.age >= last_update.elapsed().saturating_sub(Duration::from_secs(2)),
        "the view's age must have grown with the partition, got {:?}",
        during.freshness.age
    );
    assert!(
        during.freshness.age <= watch_began.elapsed() + Duration::from_secs(2),
        "a view cannot be older than the time since the first push began (whole-second clocks at \
         both ends add up to 2s), got {:?}",
        during.freshness.age
    );

    // Bob loses P2 as well and asks both peers: P2 is reported unreachable
    // since it last answered him (the read above), and the tip is P1's.
    h.proxy.partition("bob", "p2");
    let cut_at = unix_now();
    let both = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(both.tip, tip, "the newest verified tip, from P1");
    assert_eq!(both.peers, ["p1"], "only P1 answered");
    match both.unreachable.as_slice() {
        [(peer, Some(since))] if peer == "p2" => assert!(
            (read_at..=cut_at).contains(since),
            "P2 unreachable since its last answer ({read_at}..={cut_at}), got {since}"
        ),
        other => panic!("P2 must read unreachable since its last answer, got {other:?}"),
    }
    h.check_verdict(&both, &pr, &Expect::new(&["p1"], &pr.0))
        .await;

    h.proxy.heal("p1", "p2");
    h.proxy.heal("alice", "p2");
    h.proxy.heal("bob", "p2");
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

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
