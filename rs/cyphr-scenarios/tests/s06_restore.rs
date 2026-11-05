// Scenario S06: restore.
// Fault: a peer restored from a stale backup.
// P2 is restored from an older backup.
// Must hold: P2 does not sign a lower tip; re-push fills the gap; no client holds
// peer-equivocation evidence against P2.
//
// Required capabilities: transport,peer-backup,evidence.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s06_restore() {
    let h = Harness::start(&["p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::PeerBackup,
        Capability::Evidence,
    ])
    .await;
}
