// Scenario S10: hostile.
// Attacker: sends hostile and oversized input.
// Unknown envelope version, oversized and malformed bodies, an evidence flood.
// Must hold: clients fail closed on the unknown version; peers stay bounded.
//
// Required capabilities: transport,version-check,peer-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s10_hostile() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::VersionCheck,
        Capability::PeerGossip,
    ])
    .await;
}
