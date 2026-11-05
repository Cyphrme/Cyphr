// Scenario S06: restore.
// Fault: a peer restored from a stale backup.
// P2 is restored from an older backup.
// Must hold: P2 does not sign a lower tip; re-push fills the gap; no client holds
// peer-equivocation evidence against P2.
//
// Required capabilities: transport,peer-backup,evidence.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
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

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let first = match h.ok(alice.push(&pr, &["p2"]).await) {
        PushOutcome::Accepted(t) => t,
        other => panic!("first push: {other:?}"),
    };
    h.ok(bob.trust_genesis(&pr, &["p2"]).await);
    let backup = h.ok(h.backup_peer("p2").await);

    h.ok(alice.commit_data(&pr, "after the backup").await);
    let latest = match h.ok(alice.push(&pr, &["p2"]).await) {
        PushOutcome::Accepted(t) => t,
        other => panic!("second push: {other:?}"),
    };
    assert_eq!(h.ok(bob.verdict(&pr, &["p2"]).await).tip, latest);

    h.ok(h.restore_peer("p2", &backup).await);
    match bob.verdict(&pr, &["p2"]).await {
        Err(ActionError::Refused(_)) => {},
        Ok(v) => assert_ne!(v.tip, first, "a restored peer must not sign a lower tip"),
        Err(e) => h.ok::<()>(Err(e)),
    }

    assert_eq!(
        h.ok(alice.push(&pr, &["p2"]).await),
        PushOutcome::Accepted(latest.clone())
    );
    let v = h.ok(bob.verdict(&pr, &["p2"]).await);
    assert_eq!(v.tip, latest, "re-push fills the gap");
    assert!(
        v.evidence
            .iter()
            .all(|e| !matches!(e, Evidence::PeerEquivocation { .. })),
        "no client may hold peer-equivocation evidence against a restored peer"
    );
}
