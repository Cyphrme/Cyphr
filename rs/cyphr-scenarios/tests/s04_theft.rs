// Scenario S04: theft.
// Attacker: holds a stolen device key.
// A thief with Alice's laptop key pushes a fork to P3.
// Must hold: convergence on Error plus evidence; Alice naked-revokes the key (reaches
// all by gossip) and resolves; verdicts follow her branch, show the resolving key, and
// keep the thief branch.
// Variant: the thief rotates or resolves first; Alice rotates and carries on; every
// verdict keeps both branches, reports the fork in Error, and never picks a branch.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip,audit,data-commit.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
async fn s04_theft() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::Audit,
        Capability::DataCommit,
    ])
    .await;

    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    // Part one: Alice's branch wins by naked revoke and resolution.
    let pr = h.ok(alice.create_principal().await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    h.ok(thief.steal_key(&laptop, &laptop_key).await);

    h.ok(alice.commit_data(&pr, "alice").await);
    h.ok(thief.commit_data(&pr, "thief").await);
    let at = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h
        .ok(thief.push(&pr, &["p3"]).await)
        .accepted("thief branch");
    assert_ne!(at, tt, "the thief must have forked");
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(at.clone())
    );
    assert_eq!(
        h.peer_view("p3", &pr).await.map(|v| v.tip),
        Some(tt.clone())
    );

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
    h.check_verdict(&forked, &pr, &Expect::new(&all, &pr.0))
        .await;
    assert!(forked.branches.contains(&at) && forked.branches.contains(&tt));
    assert_eq!(forked.branches.len(), 2);

    // The revoke is self-signed (SPEC 6.4): the laptop, which still holds
    // its own key, signs it; Alice holds only the genesis key.
    h.ok(laptop.naked_revoke(&pr, &laptop_key).await);
    // SPEC 6.4: on a naked revoke the principal removes the key by a
    // key/delete and commits. That commit, on Alice's branch, is the
    // resolution (SPEC 15.8): a commit that carries no key/delete or
    // key/revoke does not resolve a fork, and the peers answer it 423.
    h.ok(alice.remove_key(&pr, &laptop_key).await);
    let rt = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("resolution push");
    h.eventually("all peers to hold Alice's resolution", CONVERGE, || async {
        for peer in all {
            if h.peer_view(peer, &pr).await.map(|v| v.tip) != Some(rt.clone()) {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await;
    let after = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&after, &pr, &Expect::new(&all, &pr.0))
        .await;
    assert_eq!(after.standing, Standing::Active);
    assert_eq!(after.tip, rt);
    assert!(
        after.resolved_by.is_some(),
        "the verdict shows the resolving key"
    );
    // The abandoned branch is retained as proof of error (SPEC 15.8), not as
    // a live head: the verdict's branches are the one head peers agree on.
    assert!(after.abandoned.contains(&tt), "the thief's branch is kept");
    let audit = h.ok(alice.audit(&pr).await);
    assert!(audit.abandoned.contains(&tt));

    // The stolen key must stop working once revoked.
    // The CLI will not build a commit on the resolved chain with a key it
    // no longer holds active, so the thief signs a data action and sends it.
    let act = h.ok(thief.data_action(&pr, "thief again").await);
    let late = h.ok(thief.submit(&act, "p3").await);
    // Alice's resolution also deleted the key (SPEC 6.4), so a peer may name
    // it not active or revoked; either way further use is rejected.
    let kind = late.refused("use of the revoked key");
    assert!(
        matches!(kind, RefusalKind::Revoked | RefusalKind::KeyNotActive),
        "the revoked key must be refused, got {kind:?}"
    );
    let settled = h.settled_view("p3", &pr).await.map(|v| v.tip);
    assert_eq!(
        settled,
        Some(rt.clone()),
        "a revoked key must not move any peer"
    );

    // Variant: the thief rotates first; Alice rotates and carries on. No
    // verdict may pick a branch.
    let pr2 = h.ok(alice.create_principal().await);
    let key2 = h.ok(alice.pair_device(&pr2, &laptop).await);
    h.ok(alice.push(&pr2, &["p1", "p2"]).await)
        .accepted("variant base");
    h.ok(thief.steal_key(&laptop, &key2).await);
    h.ok(thief.rotate_key(&pr2).await);
    h.ok(alice.rotate_key(&pr2).await);
    // Each side reaches its own peers before gossip carries the other's
    // rotation across: without the cut, whichever pushes second finds its
    // peers already on the rival branch.
    for from in ["p1", "p2"] {
        h.proxy.partition(from, "p3");
    }
    let tt2 = h
        .ok(thief.push(&pr2, &["p3"]).await)
        .accepted("thief rotation");
    let at2 = h
        .ok(alice.push(&pr2, &["p1", "p2"]).await)
        .accepted("alice rotation");
    for from in ["p1", "p2"] {
        h.proxy.heal(from, "p3");
    }
    assert_ne!(at2, tt2);

    // Both rotations are held and neither is a tip: each peer reports
    // Error with the two tied heads (SPEC 15.5). The peers are polled
    // inside the wait: an aggregate verdict can name both branches before
    // each peer has stored the other's.
    let want: std::collections::BTreeSet<Tip> = [at2.clone(), tt2.clone()].into_iter().collect();
    h.eventually(
        "both branches to be reported, and held by each peer",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr2, &all).await?;
            if !(v.branches.contains(&at2) && v.branches.contains(&tt2)) {
                return Ok(false);
            }
            for peer in ["p1", "p3"] {
                let heads: std::collections::BTreeSet<Tip> = match h.peer_view(peer, &pr2).await {
                    Some(view) => view.heads.iter().cloned().collect(),
                    None => return Ok(false),
                };
                if heads != want {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;
    let v = h.ok(bob.verdict(&pr2, &all).await);
    h.check_verdict(&v, &pr2, &Expect::new(&all, &pr2.0)).await;
    assert_eq!(v.standing, Standing::Error, "the fork is reported in Error");
    assert!(v.evidence.contains(&Evidence::PrincipalFork(pr2.clone())));
    assert!(
        v.resolved_by.is_none(),
        "no branch is ever picked for Alice"
    );
}
