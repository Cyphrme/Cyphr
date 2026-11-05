// Scenario S09: migration.
// Fault: a peer leaves the network for good.
// Alice moves to P3, updates her self-claim; P1 goes away.
// Must hold: Bob follows the claim to P3; only his verdict's peer list changes.
//
// Required capabilities: transport,cli-network,discovery.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s09_migration() {
    let h = Harness::start(&["p1", "p2", "p3"])
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Discovery,
    ])
    .await;
}
