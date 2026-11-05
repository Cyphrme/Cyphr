// Scenario S05: peer equivocation.
// Attacker: a peer that equivocates.
// A rigged P1 serves Bob and Carol non-prefix branches at different heights.
// Must hold: after Bob and Carol gossip, both hold evidence naming P1 alone; a
// replayed old genuine view of P2 does not frame P2.
//
// Required capabilities: transport,cli-network,evidence,client-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

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
}
