// Scenario S05: peer equivocation.
// Attacker: a peer that equivocates.
// A rigged P1 serves Bob and Carol non-prefix branches at different heights.
// Must hold: after Bob and Carol gossip, both hold evidence naming P1 alone; a
// replayed old genuine view of P2 does not frame P2.
//
// Required capabilities: transport,cli-network,evidence,client-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s05_peer_equivocation() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
        Capability::ClientGossip,
    ])
    .await;

    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (bob, carol) = (h.client("bob"), h.client("carol"));

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await);
    h.ok(bob.trust_genesis(&pr, &["p1", "p2"]).await);
    h.ok(carol.trust_genesis(&pr, &["p1", "p2"]).await);
    let old = h.ok(bob.verdict(&pr, &["p2"]).await).tip;

    // Two non-prefix branches at different heights: A is two commits long,
    // B one commit on a divergent device.
    h.ok(alice.commit_data(&pr, "a1").await);
    let tip_a = h.ok(alice.commit_data(&pr, "a2").await);
    let tip_b = h.ok(laptop.commit_data(&pr, "b1").await);
    h.ok(alice.push(&pr, &["p2"]).await);

    h.ok(h
        .equivocate("p1", &pr, &[(&bob, tip_a), (&carol, tip_b)])
        .await);
    h.ok(bob.verdict(&pr, &["p1"]).await);
    h.ok(carol.verdict(&pr, &["p1"]).await);
    h.ok(bob.gossip_with(&carol).await);
    h.ok(carol.gossip_with(&bob).await);

    for who in [&bob, &carol] {
        let v = h.ok(who.verdict(&pr, &["p1", "p2"]).await);
        assert!(
            v.evidence
                .contains(&Evidence::PeerEquivocation { peer: "p1".into() }),
            "{} must hold evidence naming P1",
            who.name
        );
        assert!(
            v.evidence
                .iter()
                .all(|e| *e != Evidence::PeerEquivocation { peer: "p2".into() }),
            "evidence must name P1 alone"
        );
    }

    // A replayed old genuine view of P2 is a prefix, not equivocation.
    h.ok(h.equivocate("p2", &pr, &[(&carol, old)]).await);
    h.ok(carol.verdict(&pr, &["p2"]).await);
    h.ok(carol.gossip_with(&bob).await);
    let v = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    assert!(
        v.evidence
            .iter()
            .all(|e| *e != Evidence::PeerEquivocation { peer: "p2".into() }),
        "a replayed genuine view must not frame P2"
    );
}
