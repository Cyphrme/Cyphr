// Scenario S02: partition.
// Fault: network partition of P2.
// P2 is partitioned while Alice rotates on P1; Bob reads only P2; then heal.
// Must hold: during the partition Bob sees "stale, age t", not "current"; after
// healing, anti-entropy converges; no evidence (prefix).
//
// Required capabilities: transport,cli-network,peer-gossip,pinning.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s02_partition() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::PeerGossip,
        Capability::Pinning,
    ])
    .await;
}
