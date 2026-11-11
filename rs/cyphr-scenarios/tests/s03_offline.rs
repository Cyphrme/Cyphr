// Scenario S03: offline.
// Fault: an offline device, then a partition that lets a real fork form.
// Alice's laptop is offline and commits while her phone commits via P1.
// Must hold: case 1, the laptop push is refused as stale and rebases, no fork;
// case 2, the commits reach different partitioned peers (a real principal fork):
// Error plus evidence until Alice resolves (SPEC 15.8); the abandoned branch is kept.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip,data-commit.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(RES-1c): peers switch canonical branch on a resolution commit (SPEC 15.8)"]
async fn s03_offline() {
    let h = Harness::start_gossiping(&["p1", "p2"], 1)
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::DataCommit,
    ])
    .await;

    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let observer = h.client("bob");
    let both = ["p1", "p2"];

    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.pair_device(&pr, &phone).await);
    let base = h.ok(laptop.push(&pr, &both).await).accepted("base push");
    let h0 = h
        .peer_view("p1", &pr)
        .await
        .expect("P1 holds the base")
        .height;

    // Case 1: the laptop is offline and commits locally while the phone
    // pushes via P1.
    h.proxy.offline("alice-laptop");
    assert!(
        !h.reach("alice-laptop", "p1").await,
        "the laptop must be offline"
    );
    h.ok(laptop.commit_data(&pr, "laptop, offline").await);
    let before_offline = h.peer_view("p1", &pr).await.expect("P1 holds the base");
    let offline_push = h.ok(laptop.push(&pr, &["p1"]).await);
    assert_eq!(
        offline_push.refused("push while offline"),
        RefusalKind::Unreachable,
        "an offline device cannot reach the peer"
    );
    assert_eq!(
        h.settled_view("p1", &pr).await,
        Some(before_offline),
        "an unreachable push must not move P1"
    );
    h.ok(phone.commit_data(&pr, "phone").await);
    let phone_tip = h.ok(phone.push(&pr, &["p1"]).await).accepted("phone push");
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(phone_tip.clone())
    );
    h.proxy.online("alice-laptop");
    assert!(
        h.reach("alice-laptop", "p1").await,
        "the laptop must be back"
    );

    let stale = h.ok(laptop.push(&pr, &["p1"]).await);
    assert_eq!(
        stale.refused("laptop push on a stale view"),
        RefusalKind::Stale
    );
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(phone_tip.clone()),
        "a refused push must not move the peer"
    );
    let rebased = h.ok(laptop.rebase(&pr).await);
    assert_ne!(rebased, phone_tip, "a rebase adds the laptop's own commit");
    let merged = h.ok(laptop.push(&pr, &both).await).accepted("rebased push");
    for peer in both {
        let v = h
            .settled_view(peer, &pr)
            .await
            .expect("peer holds the chain");
        assert_eq!(
            (v.tip, v.height),
            (merged.clone(), h0 + 2),
            "{peer}: base + phone + laptop"
        );
    }
    let v = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&v, &pr, &Expect::new(&both, &pr.0)).await;
    assert_eq!(
        v.branches,
        std::slice::from_ref(&merged),
        "a stale refusal must not fork"
    );
    assert!(v.evidence.is_empty());
    assert_ne!(base, merged);

    // The phone starts case 2 from the merged tip, so the fork below comes
    // from the partition and not from a stale local view.
    assert_eq!(h.ok(phone.sync(&pr, &both).await), merged);

    // Case 2: the devices commit to different, partitioned peers.
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    assert!(!h.reach("alice-laptop", "p1").await && !h.reach("alice-phone", "p2").await);
    assert!(h.reach("alice-laptop", "p2").await && h.reach("alice-phone", "p1").await);
    h.ok(laptop.commit_data(&pr, "laptop, branch").await);
    h.ok(phone.commit_data(&pr, "phone, branch").await);
    let lt = h
        .ok(laptop.push(&pr, &["p2"]).await)
        .accepted("laptop branch");
    let pt = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("phone branch");
    assert_ne!(lt, pt, "the two devices must have forked");
    assert_eq!(
        h.peer_view("p2", &pr).await.map(|v| v.tip),
        Some(lt.clone())
    );
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(pt.clone())
    );
    h.eventually(
        "a peer-to-peer attempt on the cut link",
        CONVERGE,
        || async { Ok(h.proxy.stats("p1", "p2").blocked > 0) },
    )
    .await;
    h.proxy.heal("p1", "p2");

    h.eventually(
        "the fork to surface as Error plus evidence",
        CONVERGE,
        || async {
            let v = observer.verdict(&pr, &both).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    let forked = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&forked, &pr, &Expect::new(&both, &pr.0))
        .await;
    let mut seen = forked.branches.clone();
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want = [lt.clone(), pt.clone()];
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(seen, want, "exactly the two pushed branches");

    // Alice resolves (SPEC 15.8); the abandoned branch stays in the record.
    let resolved = h.ok(phone.resolve_fork(&pr, &pt).await);
    h.eventually("the peers to hold the resolution", CONVERGE, || async {
        Ok(
            h.peer_view("p1", &pr).await.map(|v| v.tip) == Some(resolved.clone())
                && h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(resolved.clone()),
        )
    })
    .await;
    let healed = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&healed, &pr, &Expect::new(&both, &pr.0))
        .await;
    assert_eq!(healed.standing, Standing::Active);
    assert_eq!(healed.tip, resolved);
    assert!(
        healed.branches.contains(&lt),
        "the abandoned branch is kept"
    );
    assert!(healed.resolved_by.is_some());
}
