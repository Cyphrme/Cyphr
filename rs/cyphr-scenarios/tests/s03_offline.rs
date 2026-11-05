// Scenario S03: offline.
// Fault: an offline device, then a partition that lets a real fork form.
// Alice's laptop is offline and commits while her phone commits via P1.
// Must hold: case 1, the laptop push is refused as stale and rebases, no fork;
// case 2, the commits reach different partitioned peers (a real principal fork):
// Error plus evidence until Alice resolves (SPEC 15.8); the abandoned branch is kept.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s03_offline() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
    ])
    .await;

    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let observer = h.client("bob");

    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.pair_device(&pr, &phone).await);
    h.ok(laptop.push(&pr, &["p1", "p2"]).await);

    // Case 1: the laptop commits while offline; the phone commits via P1.
    h.proxy.offline("alice-laptop");
    h.ok(laptop.commit_data(&pr, "laptop, offline").await);
    h.ok(phone.commit_data(&pr, "phone").await);
    assert!(matches!(
        h.ok(phone.push(&pr, &["p1"]).await),
        PushOutcome::Accepted(_)
    ));
    h.proxy.online("alice-laptop");

    assert_eq!(
        h.ok(laptop.push(&pr, &["p1"]).await),
        PushOutcome::RefusedStale
    );
    h.ok(laptop.rebase(&pr).await);
    assert!(matches!(
        h.ok(laptop.push(&pr, &["p1"]).await),
        PushOutcome::Accepted(_)
    ));
    let v = h.ok(observer.verdict(&pr, &["p1"]).await);
    assert_eq!(v.branches.len(), 1, "a refused-stale push must not fork");
    assert!(v.evidence.is_empty());

    // Case 2: the two devices commit to different, partitioned peers.
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    h.ok(laptop.commit_data(&pr, "laptop, branch").await);
    h.ok(phone.commit_data(&pr, "phone, branch").await);
    let lt = h.ok(laptop.push(&pr, &["p2"]).await);
    let pt = h.ok(phone.push(&pr, &["p1"]).await);
    assert!(matches!(
        (&lt, &pt),
        (PushOutcome::Accepted(_), PushOutcome::Accepted(_))
    ));
    h.proxy.heal("p1", "p2");

    h.eventually(
        "the fork to surface as Error plus evidence",
        CONVERGE,
        || async {
            let v = observer.verdict(&pr, &["p1", "p2"]).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    let forked = h.ok(observer.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(forked.branches.len(), 2);

    // Alice resolves (SPEC 15.8); the abandoned branch stays in the record.
    let keep = forked.branches[0].clone();
    h.ok(phone.resolve_fork(&pr, &keep).await);
    let healed = h.ok(observer.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(healed.standing, Standing::Active);
    assert_eq!(healed.branches.len(), 2, "the abandoned branch is kept");
    assert!(healed.resolved_by.is_some());
}
