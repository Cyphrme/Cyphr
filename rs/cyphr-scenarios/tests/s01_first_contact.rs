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
}
