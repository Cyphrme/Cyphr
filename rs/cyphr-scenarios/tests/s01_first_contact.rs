// Scenario S01: first contact.
// Fault: none (baseline first contact; the fresh-start trust path).
// Alice creates a principal and a backup key, pushes to P1 and P2, and publishes a
// discovery self-claim. Bob holds her genesis out of band plus a hint. Carol hears of
// Alice only from Bob.
// Must hold: Bob and Carol replay to the same tip; each verdict names its anchor,
// peers and freshness.
//
// Required capabilities: transport,cli-network,choices-file,key-pairing,discovery.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::{Duration, Instant};

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s01_first_contact() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::ChoicesFile,
        Capability::KeyPairing,
        Capability::Discovery,
    ])
    .await;

    let started = Instant::now();
    let (alice, bob, carol) = (h.client("alice"), h.client("bob"), h.client("carol"));

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.add_backup_key(&pr).await);
    // The pushed tip and the peers' own state are the independent truth.
    let tip = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("first push");
    for peer in ["p1", "p2"] {
        let held = h.peer_view(peer, &pr).await;
        assert_eq!(
            held.map(|v| v.tip),
            Some(tip.clone()),
            "{peer} must hold Alice's push"
        );
    }
    h.ok(alice.publish_self_claim(&pr, &["p1", "p2"]).await);

    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    h.ok(carol.learn_from(&bob, &pr).await);

    let vb = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    let vc = h.ok(carol.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(vb.tip, tip, "Bob must replay to the tip Alice pushed");
    assert_eq!(vc.tip, tip, "Carol must replay to the tip Alice pushed");
    for v in [&vb, &vc] {
        assert_eq!(v.standing, Standing::Active);
        assert!(v.evidence.is_empty());
        assert_eq!(v.anchor.id, pr.0, "the anchor is Alice's genesis");
        let mut used = v.peers.clone();
        used.sort();
        assert_eq!(used, ["p1", "p2"], "a verdict names the peers it used");
        assert!(!v.freshness.peer_reported_newer);
        assert!(
            v.freshness.age <= started.elapsed() + Duration::from_secs(1),
            "a view cannot be older than this run"
        );
    }
    assert_eq!(
        vb.anchor.source,
        AnchorSource::TrustedGenesis,
        "Bob holds the genesis"
    );
    assert_eq!(
        vc.anchor.source,
        AnchorSource::Hint,
        "Carol only heard of it from Bob"
    );
}
