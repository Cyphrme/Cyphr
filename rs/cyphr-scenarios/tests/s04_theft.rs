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

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

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

    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    // Part one: Alice's branch wins by naked revoke and resolution.
    let pr = h.ok(alice.create_principal().await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await);
    h.ok(thief.steal_key(&laptop, &laptop_key).await);

    h.ok(alice.commit_data(&pr, "alice").await);
    h.ok(thief.commit_data(&pr, "thief").await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await);
    h.ok(thief.push(&pr, &["p3"]).await);

    h.eventually(
        "every verdict to converge on Error plus evidence",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &all).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    let forked = h.ok(bob.verdict(&pr, &all).await);
    assert_eq!(forked.branches.len(), 2);
    let alice_tip = match h.ok(alice.verdict(&pr, &["p1"]).await).tip {
        t if forked.branches.contains(&t) => t,
        t => panic!("Alice's tip {t:?} is not one of the branches"),
    };

    h.ok(alice.naked_revoke(&pr, &laptop_key).await);
    h.ok(alice.resolve_fork(&pr, &alice_tip).await);
    h.eventually("verdicts to follow Alice's branch", CONVERGE, || async {
        let v = bob.verdict(&pr, &all).await?;
        Ok(v.standing == Standing::Active && v.tip == alice_tip)
    })
    .await;
    let after = h.ok(bob.verdict(&pr, &all).await);
    assert!(
        after.resolved_by.is_some(),
        "the verdict shows the resolving key"
    );
    assert_eq!(after.branches.len(), 2, "the thief's branch is kept");
    let audit = h.ok(alice.audit(&pr).await);
    assert!(audit.branches.len() >= 2, "an audit sees both branches");

    // Variant: the thief rotates first; Alice rotates and carries on. No
    // verdict may pick a branch.
    let pr2 = h.ok(alice.create_principal().await);
    let key2 = h.ok(alice.pair_device(&pr2, &laptop).await);
    h.ok(alice.push(&pr2, &["p1", "p2"]).await);
    h.ok(thief.steal_key(&laptop, &key2).await);
    h.ok(thief.rotate_key(&pr2).await);
    h.ok(thief.push(&pr2, &["p3"]).await);
    h.ok(alice.rotate_key(&pr2).await);
    h.ok(alice.push(&pr2, &["p1", "p2"]).await);

    h.eventually("both branches to be reported", CONVERGE, || async {
        Ok(bob.verdict(&pr2, &all).await?.branches.len() == 2)
    })
    .await;
    let v = h.ok(bob.verdict(&pr2, &all).await);
    assert_eq!(v.standing, Standing::Error, "the fork is reported in Error");
    assert!(v.evidence.contains(&Evidence::PrincipalFork(pr2.clone())));
    assert!(
        v.resolved_by.is_none(),
        "no branch is ever picked for Alice"
    );
}
