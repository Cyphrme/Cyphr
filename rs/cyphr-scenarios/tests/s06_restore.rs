// Scenario S06: restore.
// Fault: a peer restored from a stale backup.
// P2 is restored from an older backup.
// Must hold: a restored peer catches up and nothing accuses it. The restore
// reports the window it lost; P2 serves the backup's tip; Alice's re-push
// extends it and fills the gap; a verifier pulling from P1 carries on; no
// client holds peer-equivocation evidence against P2.
//
// Peers mirror principal-signed objects and sign no watermark,
// so there is no rollback refusal to assert.
//
// Required capabilities: transport,peer-backup,evidence,data-commit.
// End to end: P2 is backed up and restored with the shipped
// `cyphr-server backup` and `restore`; Alice and Bob use the `cyphr` CLI.
// Turns red if: the restore loses its window silently, P2 does not hold the
// backup's tip, the re-push is refused or leaves a gap, or any client holds
// peer-equivocation evidence against the restored peer.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
async fn s06_restore() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::PeerBackup,
        Capability::Evidence,
        Capability::DataCommit,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let first = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("first push");
    h.ok(bob.trust_genesis(&pr, &["p1", "p2"]).await);
    let backup = h.ok(h.backup_peer("p2").await);

    h.ok(alice.commit_data(&pr, "after the backup").await);
    let latest = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("second push");
    assert_ne!(first, latest);
    let held = h.peer_view("p2", &pr).await.expect("P2 holds both commits");
    assert_eq!(held.tip, latest);

    let report = h.ok(h.restore_peer("p2", &backup).await);
    assert!(
        report.contains("lost window: 1 commit(s)"),
        "the restore must report the window it lost: {report}"
    );
    let restored = h
        .peer_view("p2", &pr)
        .await
        .expect("P2 still knows the principal");
    assert_eq!(restored.tip, first, "P2 must hold the backup's tip");
    assert!(restored.height < held.height);

    // A verifier that reads another peer carries on at the latest tip.
    assert_eq!(h.ok(bob.verdict(&pr, &["p1"]).await).tip, latest);

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
    let v = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    h.check_verdict(&v, &pr, &Expect::new(&["p1", "p2"], &pr.0))
        .await;
    assert!(
        v.evidence
            .iter()
            .all(|e| !matches!(e, Evidence::PeerEquivocation { .. })),
        "no client may hold peer-equivocation evidence against a restored peer"
    );
}
