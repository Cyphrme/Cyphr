// Scenario S07: peer rollover.
// Fault: none (peer key rotation, a legitimate change).
// P1 rotates its own key.
// Must hold: clients follow P1's chain; old-key statements stay attributable; nothing
// is mistaken for evidence.
//
// Required capabilities: transport,cli-network,peer-rollover.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s07_peer_rollover() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::PeerRollover,
    ])
    .await;
}
