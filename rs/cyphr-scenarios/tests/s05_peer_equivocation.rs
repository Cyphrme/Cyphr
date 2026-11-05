// Scenario S05: peer equivocation.
// Attacker: a peer that equivocates.
// A rigged P1 serves Bob and Carol non-prefix branches at different heights.
// Must hold: after Bob and Carol gossip, both hold evidence naming P1 alone; a
// replayed old genuine view of P2 does not frame P2.
//
// Required capabilities: transport,cli-network,evidence,client-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

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
    let old = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    h.ok(bob.trust_genesis(&pr, &["p1", "p2"]).await);
    h.ok(carol.trust_genesis(&pr, &["p1", "p2"]).await);

    // Two non-prefix branches at different heights: A is two commits long,
    // B one commit on a divergent device.
    h.ok(alice.commit_data(&pr, "a1").await);
    let tip_a = h.ok(alice.commit_data(&pr, "a2").await);
    let tip_b = h.ok(laptop.commit_data(&pr, "b1").await);
    assert_ne!(tip_a, tip_b);
    let pushed = h.ok(alice.push(&pr, &["p2"]).await).accepted("push to P2");
    assert_eq!(pushed, tip_a);
    assert_eq!(
        h.peer_view("p2", &pr).await.map(|v| v.tip),
        Some(tip_a.clone())
    );

    h.ok(h
        .equivocate("p1", &pr, &[(&bob, tip_a.clone()), (&carol, tip_b.clone())])
        .await);
    assert_eq!(h.ok(bob.verdict(&pr, &["p1"]).await).tip, tip_a);
    assert_eq!(h.ok(carol.verdict(&pr, &["p1"]).await).tip, tip_b);
    h.ok(bob.gossip_with(&carol).await);
    h.ok(carol.gossip_with(&bob).await);

    for who in [&bob, &carol] {
        h.eventually("evidence naming P1", CONVERGE, || async {
            let v = who.verdict(&pr, &["p1", "p2"]).await?;
            Ok(v.evidence
                .contains(&Evidence::PeerEquivocation { peer: "p1".into() }))
        })
        .await;
        // Only now, with the positive established, is absence meaningful.
        let v = h.ok(who.verdict(&pr, &["p1", "p2"]).await);
        let named: Vec<_> = v
            .evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::PeerEquivocation { peer } => Some(peer.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(named, ["p1"], "{}: evidence must name P1 alone", who.name);
    }

    // A replayed old genuine view of P2 is a stale prefix, not equivocation.
    h.ok(h.serve_stale_view("p2", &pr, &carol, &old).await);
    let stale = h.ok(carol.verdict(&pr, &["p2"]).await);
    assert_eq!(stale.tip, old, "Carol was served the old view");
    h.ok(carol.gossip_with(&bob).await);
    h.eventually(
        "Carol to learn a peer holds something newer",
        CONVERGE,
        || async {
            Ok(carol
                .verdict(&pr, &["p2"])
                .await?
                .freshness
                .peer_reported_newer)
        },
    )
    .await;
    let v = h.ok(carol.verdict(&pr, &["p1", "p2"]).await);
    assert!(
        !v.evidence
            .contains(&Evidence::PeerEquivocation { peer: "p2".into() }),
        "a replayed genuine view must not frame P2"
    );
    assert_eq!(
        h.peer_view("p2", &pr).await.map(|v| v.tip),
        Some(tip_a),
        "serving a stale view must not change P2"
    );
}
