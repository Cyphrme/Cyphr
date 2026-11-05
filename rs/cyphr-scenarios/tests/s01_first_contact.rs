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

    let (alice, bob, carol) = (h.client("alice"), h.client("bob"), h.client("carol"));

    let pr = h.ok(alice.create_principal().await);
    let backup = h.ok(alice.add_backup_key(&pr).await);
    let genesis_key = pr.clone();
    assert_ne!(backup.0, genesis_key.0, "a backup key is a second key");
    let out = h.ok(alice.push(&pr, &["p1", "p2"]).await);
    assert!(
        matches!(out, PushOutcome::Accepted(_)),
        "first push: {out:?}"
    );
    h.ok(alice.publish_self_claim(&pr, &["p1", "p2"]).await);

    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    h.ok(carol.learn_from(&bob, &pr).await);

    let vb = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    let vc = h.ok(carol.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(vb.tip, vc.tip, "Bob and Carol must replay to the same tip");
    for v in [&vb, &vc] {
        assert_eq!(v.standing, Standing::Active);
        assert!(!v.freshness.peer_reported_newer);
        assert!(!v.anchor.id.is_empty(), "a verdict names its anchor");
        assert!(!v.peers.is_empty(), "a verdict names its peers");
        assert!(v.evidence.is_empty());
    }
}
