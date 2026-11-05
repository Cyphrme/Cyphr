// Scenario S04: theft.
// Attacker: holds a stolen device key.
// A thief with Alice's laptop key pushes a fork to P3.
// Must hold: convergence on Error plus evidence; Alice naked-revokes the key (reaches
// all by gossip) and resolves; verdicts follow her branch, show the resolving key, and
// keep the thief branch.
// Variant: the thief rotates or resolves first; Alice rotates and carries on; every
// verdict keeps both branches, reports the fork in Error, and never picks a branch.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip,audit.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s04_theft() {
    let h = Harness::start(&["p1", "p2", "p3"])
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::Audit,
    ])
    .await;
}
