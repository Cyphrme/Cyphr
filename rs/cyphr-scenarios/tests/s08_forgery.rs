// Scenario S08: forgery.
// Attacker: forges with a retired key and replays old material.
// A backdated data action signed by a retired key, a replayed data action, a
// re-pushed old commit.
// Must hold: the forgery is rejected by every peer; replays leave state unchanged
// (SPEC 7.6).
//
// Required capabilities: transport,cli-network,idempotency.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s08_forgery() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Idempotency,
    ])
    .await;
}
