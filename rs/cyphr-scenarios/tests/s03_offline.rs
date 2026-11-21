// Scenario S03: offline.
// Fault: an offline device, then a partition that lets a real fork form.
// Alice's laptop is offline and commits while her phone commits via P1.
// Must hold: case 1, the laptop push is refused as stale and rebases, no fork; an
// action the laptop recorded but never committed survives the rebase, re-signed
// and named in the rebase output (SPEC 15.9), and reaches the peers;
// case 2, the commits reach different partitioned peers (a real principal fork),
// each branch extended twice: Error plus evidence at every peer, both extended
// heads live and neither settled. Both branches being extended, no further
// ordinary commit on either head leaves Error (the spec author on #203: "They're
// both out of compliance"): the peers refuse it, and a restart of the peers
// changes nothing. A fork whose branches are not both extended is settled by
// one ordinary commit on a head (SPEC 15.8 item 1): see s03_resolver_differs.
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
    // A further action recorded and left uncommitted when the rebase comes.
    let pending = h.ok(laptop.record_data(&pr, "laptop, uncommitted").await);
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
    let p1_actions = h.peer_actions("p1", &pr).await.expect("P1 holds actions");
    let rebased = h.ok(laptop.rebase(&pr).await);
    assert_ne!(
        rebased.tip, phone_tip,
        "a rebase adds the laptop's own commit"
    );
    // SPEC 6.5: the laptop's key is active on the adopted chain at the
    // action's own `now`, so the rebase keeps the action as signed (a
    // re-signed copy would be a duplicate under a new digest) and re-signs
    // nothing.
    assert!(
        rebased.resigned.iter().all(|r| r.czd != pending),
        "the rebase keeps the uncommitted action as signed: {:?}",
        rebased.resigned
    );
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
    // Both of the laptop's actions, the committed one and the uncommitted
    // one, reach P1: nothing recorded offline is lost.
    assert_eq!(
        h.peer_actions("p1", &pr).await,
        Some(p1_actions + 2),
        "P1 holds the laptop's two actions"
    );
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

    // Case 2: the devices commit to different, partitioned peers, each
    // extending its branch past the fork point before anyone sees the
    // other.
    let (laptop_branch, phone_branch) = extend_both(&h, &laptop, &phone, &pr, 2).await;
    let (lt, pt) = (laptop_branch[1].clone(), phone_branch[1].clone());

    // Before the link heals each peer holds one branch, but an observer
    // asking both already sees two chains over one `pre`, each extended:
    // neither is settled (SPEC 15.8), so it is Error with both extended
    // heads live, and stays so once the rival's extension is served.
    let early = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        (early.standing, sorted(&early.branches)),
        (Standing::Error, sorted(&[lt.clone(), pt.clone()])),
        "both extended heads, unsettled, before the peers compare"
    );
    h.eventually(
        "a peer-to-peer attempt on the cut link",
        CONVERGE,
        || async { Ok(h.proxy.stats("p1", "p2").blocked > 0) },
    )
    .await;
    h.proxy.heal("p1", "p2");

    // Each peer retains the other's branch, and serves it as evidence, only
    // after its next gossip round. The oracle checks the verdict against
    // what the peers serve, so wait for both.
    h.eventually(
        "the fork to surface as Error plus evidence the peers serve",
        CONVERGE,
        || async {
            let v = observer.verdict(&pr, &both).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone()))
                && evidence(&h, "p1", &pr).await >= 1
                && evidence(&h, "p2", &pr).await >= 1)
        },
    )
    .await;
    let forked = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&forked, &pr, &Expect::new(&both, &pr.0))
        .await;
    assert_eq!(
        sorted(&forked.branches),
        sorted(&[lt.clone(), pt.clone()]),
        "exactly the two extended branch heads"
    );
    assert!(
        forked.resolved_by.is_none(),
        "no branch is settled while both are extended"
    );

    // Alice answers on the phone's head, a tied head: one further ordinary
    // commit. Both branches are extended, so it settles nothing: every
    // peer refuses it, and the verdict is what it was.
    assert_still_error(&h, &phone, &observer, &pr, &forked).await;

    // A restart of every peer changes nothing.
    for peer in both {
        h.ok(h.stop_peer(peer).await);
        h.peer(peer).restart(h.bins).await.expect("restart");
    }
    let restarted = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        (restarted.standing, sorted(&restarted.branches)),
        (Standing::Error, sorted(&forked.branches)),
        "a restart changes nothing"
    );
    for peer in both {
        assert!(
            evidence(&h, peer, &pr).await >= 1,
            "{peer} still serves the fork"
        );
    }
}

/// A late verifier: one that first looks only once the peers hold both
/// extended branches reports Error, and still does after the principal's
/// next ordinary commit, which settles nothing while both branches are
/// extended, as the peers do (a catches-tallest-wins scenario: the old rule
/// let that commit out-extend the rival branch).
#[tokio::test(flavor = "multi_thread")]
async fn s03_extension_does_not_settle_a_both_extended_fork() {
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
    assert_eq!(h.ok(phone.sync(&pr, &both).await), base);

    extend_both(&h, &laptop, &phone, &pr, 2).await;
    h.proxy.heal("p1", "p2");
    // Each peer holds the other's whole branch, both of its commits.
    h.eventually("each peer to hold the rival branch", CONVERGE, || async {
        Ok(evidence(&h, "p1", &pr).await >= 2 && evidence(&h, "p2", &pr).await >= 2)
    })
    .await;
    let forked = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&forked, &pr, &Expect::new(&both, &pr.0))
        .await;
    assert_eq!(forked.standing, Standing::Error, "both branches extended");

    assert_still_error(&h, &phone, &observer, &pr, &forked).await;
}

/// A fork the owner resolved stays in the record as an abandoned branch
/// (SPEC 15.8), never as a live head: when the principal forks a second
/// time, the verdict names the two new branches and the oracle must count
/// exactly those, not the first fork's abandoned tip as a third.
#[tokio::test(flavor = "multi_thread")]
async fn s03_resolved_fork_is_not_a_live_head() {
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
    h.ok(laptop.push(&pr, &both).await).accepted("base push");

    // First fork, one commit a side and so neither branch extended, resolved
    // on the phone's branch by one ordinary commit (SPEC 15.8 item 1).
    let (_, phone_branch) = extend_both(&h, &laptop, &phone, &pr, 1).await;
    h.proxy.heal("p1", "p2");
    h.eventually("each peer to hold the rival branch", CONVERGE, || async {
        Ok(evidence(&h, "p1", &pr).await >= 1 && evidence(&h, "p2", &pr).await >= 1)
    })
    .await;
    let resolved = resolve_by_extension(&h, &phone, &pr, &phone_branch[0]).await;
    let seen = [evidence(&h, "p1", &pr).await, evidence(&h, "p2", &pr).await];

    // Second fork from the resolved tip, the first one's abandoned tip
    // still retained.
    // The laptop holds the abandoned branch, so a fresh device takes its
    // place at the proxy.
    h.proxy.heal("alice-laptop", "p1");
    h.proxy.heal("alice-phone", "p2");
    let tablet = h.client("alice-laptop");
    h.ok(phone.pair_device(&pr, &tablet).await);
    let (laptop2, phone2) = extend_both(&h, &tablet, &phone, &pr, 2).await;
    h.proxy.heal("p1", "p2");
    h.eventually("each peer to hold the second rival", CONVERGE, || async {
        Ok(evidence(&h, "p1", &pr).await >= seen[0] + 2
            && evidence(&h, "p2", &pr).await >= seen[1] + 2)
    })
    .await;
    let forked = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        sorted(&forked.branches),
        sorted(&[laptop2[1].clone(), phone2[1].clone()]),
        "exactly the second fork's extended heads (after {resolved:?})"
    );
    h.check_verdict(&forked, &pr, &Expect::new(&both, &pr.0))
        .await;
}

/// The commit that resolves a fork is signed by a different key than the
/// commit below it: a third device, which holds none of the phone's keys,
/// takes the phone's branch from P1 and signs the resolution on it. Then
/// `resolved_by` names the tablet's key, and an oracle that read the signer
/// of the wrong position would name the phone's.
#[tokio::test(flavor = "multi_thread")]
async fn s03_resolver_differs_from_the_commit_below() {
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
    let tablet = h.client("alice-tablet");
    let observer = h.client("bob");
    let both = ["p1", "p2"];
    let pr = h.ok(laptop.create_principal().await);
    let tablet_key = h.ok(laptop.pair_device(&pr, &tablet).await);
    h.ok(laptop.pair_device(&pr, &phone).await);
    h.ok(laptop.push(&pr, &both).await).accepted("base push");

    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    assert!(!h.reach("alice-laptop", "p1").await && !h.reach("alice-phone", "p2").await);
    h.ok(laptop.commit_data(&pr, "laptop branch").await);
    h.ok(laptop.push(&pr, &["p2"]).await)
        .accepted("laptop branch");
    h.ok(phone.commit_data(&pr, "phone branch").await);
    let kept = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("phone branch");

    // The tablet reads the phone's branch while P1 holds only that one.
    assert_eq!(h.ok(tablet.sync(&pr, &["p1"]).await), kept);

    h.proxy.heal("p1", "p2");
    h.eventually("each peer to hold the rival branch", CONVERGE, || async {
        Ok(evidence(&h, "p1", &pr).await >= 1 && evidence(&h, "p2", &pr).await >= 1)
    })
    .await;
    // The tablet resolves on the phone's branch: the signer of the commit
    // below is the phone, the resolver's is not.
    let resolved = resolve_by_extension(&h, &tablet, &pr, &kept).await;
    let healed = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(healed.branches, vec![resolved]);
    assert_eq!(
        healed.resolved_by,
        Some(tablet_key),
        "the resolution is signed by the tablet's key"
    );
    h.check_verdict(&healed, &pr, &Expect::new(&both, &pr.0))
        .await;
}

/// Partition the laptop with P2 and the phone with P1, then have each
/// commit and push `rounds` times on its side: two branches over one `pre`,
/// both extended past the fork point when `rounds` is at least two. The
/// commits of each branch, in order.
async fn extend_both(
    h: &Harness,
    laptop: &Client<'_>,
    phone: &Client<'_>,
    pr: &Principal,
    rounds: usize,
) -> (Vec<Tip>, Vec<Tip>) {
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    assert!(!h.reach("alice-laptop", "p1").await && !h.reach("alice-phone", "p2").await);
    assert!(h.reach("alice-laptop", "p2").await && h.reach("alice-phone", "p1").await);
    let mut laptop_tips = Vec::new();
    let mut phone_tips = Vec::new();
    for round in 1..=rounds {
        h.ok(laptop
            .commit_data(pr, &format!("laptop, branch {round}"))
            .await);
        h.ok(phone
            .commit_data(pr, &format!("phone, branch {round}"))
            .await);
        laptop_tips.push(
            h.ok(laptop.push(pr, &["p2"]).await)
                .accepted("laptop branch"),
        );
        phone_tips.push(h.ok(phone.push(pr, &["p1"]).await).accepted("phone branch"));
    }
    assert_ne!(
        laptop_tips[0], phone_tips[0],
        "the two devices must have forked"
    );
    assert_eq!(
        h.peer_view("p2", pr).await.map(|v| v.tip),
        laptop_tips.last().cloned()
    );
    assert_eq!(
        h.peer_view("p1", pr).await.map(|v| v.tip),
        phone_tips.last().cloned()
    );
    (laptop_tips, phone_tips)
}

/// The phone signs one ordinary commit on its head `keep` (SPEC 15.8
/// item 1) and pushes it to every peer it knows: P1 holds the phone's
/// branch and P2 promotes it over the laptop's, which it does not extend. The
/// resolution's tip, once both peers hold it.
async fn resolve_by_extension(h: &Harness, phone: &Client<'_>, pr: &Principal, keep: &Tip) -> Tip {
    let resolved = h.ok(phone.resolve_fork(pr, keep).await);
    h.eventually("the peers to hold the resolution", CONVERGE, || async {
        Ok(
            h.peer_view("p1", pr).await.map(|v| v.tip) == Some(resolved.clone())
                && h.peer_view("p2", pr).await.map(|v| v.tip) == Some(resolved.clone()),
        )
    })
    .await;
    resolved
}

/// The phone's one further ordinary commit, pushed to both peers, is
/// refused where both branches are held and extended, and the verdict
/// read earlier, `before`, still stands: Error, its heads still live, no
/// branch settled or abandoned.
async fn assert_still_error(
    h: &Harness,
    phone: &Client<'_>,
    observer: &Client<'_>,
    pr: &Principal,
    before: &Verdict,
) {
    let both = ["p1", "p2"];
    h.ok(phone.commit_data(pr, "a further commit").await);
    // A peer in Error answers 423, which the CLI reports as a failed push.
    match phone.push(pr, &both).await {
        Ok(PushOutcome::Accepted(tip)) => {
            panic!("a further commit settled a both-extended fork at {tip:?}")
        },
        Ok(PushOutcome::Refused(r)) => {
            panic!("refused as {:?}, not as Error: {}", r.kind, r.detail)
        },
        Err(ActionError::Failed(why)) => assert!(why.contains("423"), "{why}"),
        Err(e) => panic!("scenario step failed: {e}"),
    }
    let after = h.ok(observer.verdict(pr, &both).await);
    assert_eq!(after.standing, Standing::Error, "still Error");
    assert!(
        before.branches.iter().all(|b| after.branches.contains(b)),
        "the heads it had are still live"
    );
    assert!(after.resolved_by.is_none() && after.abandoned.is_empty());
}

fn sorted(tips: &[Tip]) -> Vec<Tip> {
    let mut tips = tips.to_vec();
    tips.sort_by(|a, b| a.0.cmp(&b.0));
    tips
}

/// How many principal-fork items `peer` serves for `p`, read from the peer
/// itself and independent of any action under test.
async fn evidence(h: &Harness, peer: &str, p: &Principal) -> usize {
    let addr = h.peer(peer).addr();
    let body: serde_json::Value = h
        .http
        .get(format!("http://{addr}/evidence"))
        .query(&[("pr", p.0.as_str())])
        .send()
        .await
        .expect("evidence request")
        .json()
        .await
        .expect("evidence json");
    body["payload"]["items"].as_array().map_or(0, Vec::len)
}
