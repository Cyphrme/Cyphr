// Scenario S06: restore.
// Fault: a peer restored from a stale backup.
// P2 is restored from an older backup.
// Must hold: P2 does not sign a lower tip; re-push fills the gap; no client holds
// peer-equivocation evidence against P2.
//
// Required capabilities: transport,peer-backup,evidence.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(peer-backup): N19"]
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
    let first = h.ok(alice.push(&pr, &["p2"]).await).accepted("first push");
    h.ok(bob.trust_genesis(&pr, &["p2"]).await);
    let backup = h.ok(h.backup_peer("p2").await);

    h.ok(alice.commit_data(&pr, "after the backup").await);
    let latest = h.ok(alice.push(&pr, &["p2"]).await).accepted("second push");
    assert_ne!(first, latest);
    let held = h.peer_view("p2", &pr).await.expect("P2 holds both commits");
    assert_eq!(held.tip, latest);
    assert_eq!(h.ok(bob.verdict(&pr, &["p2"]).await).tip, latest);

    h.ok(h.restore_peer("p2", &backup).await);
    // The restore must have taken effect: P2 now holds the older tip.
    let rolled_back = h
        .peer_view("p2", &pr)
        .await
        .expect("P2 still knows the principal");
    assert_eq!(rolled_back.tip, first, "P2 must hold the backup's tip");
    assert!(rolled_back.height < held.height);

    match bob.verdict(&pr, &["p2"]).await {
        Err(ActionError::Refused(r)) => assert_eq!(r.kind, RefusalKind::Rollback),
        Ok(v) => assert_ne!(v.tip, first, "a restored peer must not sign a lower tip"),
        Err(e) => h.ok::<()>(Err(e)),
    }

    let repush = h.ok(alice.push(&pr, &["p2"]).await).accepted("re-push");
    assert_eq!(repush, latest);
    h.eventually("re-push to fill P2's gap", CONVERGE, || async {
        Ok(h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(latest.clone()))
    })
    .await;
    h.eventually("Bob to see the filled gap", CONVERGE, || async {
        Ok(bob.verdict(&pr, &["p2"]).await?.tip == latest)
    })
    .await;
    // The positive is established; absence of equivocation evidence now counts.
    let v = h.ok(bob.verdict(&pr, &["p2"]).await);
    h.check_verdict(&v, &pr, &Expect::new(&["p2"], &pr.0)).await;
    assert!(
        v.evidence
            .iter()
            .all(|e| !matches!(e, Evidence::PeerEquivocation { .. })),
        "no client may hold peer-equivocation evidence against a restored peer"
    );
}
