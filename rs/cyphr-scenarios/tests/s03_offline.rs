// Scenario S03: offline.
// Fault: an offline device, then a partition that lets a real fork form.
// Alice's laptop is offline and commits while her phone commits via P1.
// Must hold: case 1, the laptop push is refused as stale and rebases, no fork; an
// action the laptop recorded but never committed survives the rebase, re-signed
// and named in the rebase output (SPEC 15.9), and reaches the peers;
// case 2, the commits reach different partitioned peers (a real principal fork),
// each branch extended twice: Error plus evidence, both extended heads live and
// neither settled, until Alice deletes the rival's signer (SPEC 15.8); the
// abandoned branch is kept.
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
    // SPEC 15.9: a rebase re-signs the actions the peer lacks at the current
    // time and names each, with its old czd and time; never silently.
    let named = rebased.resigned.iter().find(|r| r.czd == pending);
    assert!(
        named.is_some_and(|r| r.was_now > 0),
        "the rebase names the uncommitted action it re-signed: {:?}",
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
    // one, reach P1 re-signed: nothing recorded offline is lost.
    assert_eq!(
        h.peer_actions("p1", &pr).await,
        Some(p1_actions + 2),
        "P1 holds the laptop's two re-signed actions"
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
    let (laptop_branch, phone_branch) = extend_both(&h, &laptop, &phone, &pr).await;
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

    // Alice resolves (SPEC 15.8); the abandoned branch stays in the record.
    // Both branches are extended, so one more commit on either settles
    // nothing (15.7.1): the phone deletes the laptop's key, and the
    // laptop's branch, signed by a key the chain removed, is evidence only.
    // The peers are in Error (15.5: no new transactions or actions until
    // resolved), so the resolution is a commit that carries everything it
    // needs, not a data commit whose action a peer in Error would refuse.
    let resolved = resolve_by_removal(&h, &phone, &pr).await;
    let healed = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&healed, &pr, &Expect::new(&both, &pr.0))
        .await;
    assert_eq!(healed.standing, Standing::Active);
    assert_eq!(
        healed.branches,
        std::slice::from_ref(&resolved),
        "one live head"
    );
    assert_eq!(healed.tip, resolved);
    // Retained as proof of error (SPEC 15.8), not as a live head.
    assert!(
        healed.abandoned.contains(&laptop_branch[0]),
        "the abandoned branch is kept"
    );
    assert!(healed.resolved_by.is_some());
}

/// SPEC 15.8 with a server's rule for a rival signed by a removed key: a
/// verifier that first looks only once the peers hold both extended
/// branches reports Error, then Active once the principal deletes the
/// rival's signer, as the peers do. A verifier that settles a fork only on a
/// branch continuing past it never leaves Error here.
#[tokio::test(flavor = "multi_thread")]
async fn s03_removal_settles_extended_fork() {
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

    let (laptop_branch, _) = extend_both(&h, &laptop, &phone, &pr).await;
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

    let resolved = resolve_by_removal(&h, &phone, &pr).await;
    let healed = h.ok(observer.verdict(&pr, &both).await);
    h.check_verdict(&healed, &pr, &Expect::new(&both, &pr.0))
        .await;
    assert_eq!(
        (healed.standing, healed.branches),
        (Standing::Active, vec![resolved]),
        "the rival's signer was deleted: Active, as the peers are"
    );
    assert!(
        healed.abandoned.contains(&laptop_branch[0]),
        "the abandoned branch is kept"
    );
}

/// Partition the laptop with P2 and the phone with P1, then have each
/// commit and push twice on its side: two branches over one `pre`, both
/// extended past the fork point. The commits of each branch, in order.
async fn extend_both(
    h: &Harness,
    laptop: &Client<'_>,
    phone: &Client<'_>,
    pr: &Principal,
) -> ([Tip; 2], [Tip; 2]) {
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    assert!(!h.reach("alice-laptop", "p1").await && !h.reach("alice-phone", "p2").await);
    assert!(h.reach("alice-laptop", "p2").await && h.reach("alice-phone", "p1").await);
    let mut laptop_tips = Vec::new();
    let mut phone_tips = Vec::new();
    for round in 1..=2 {
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
    let pair = |t: Vec<Tip>| -> [Tip; 2] { t.try_into().expect("two rounds") };
    (pair(laptop_tips), pair(phone_tips))
}

/// The phone deletes the laptop's key (the genesis key) and pushes to P1;
/// gossip carries it to P2, whose chain is the laptop's branch, and P2
/// promotes the phone's branch under it. The resolution's tip, once both
/// peers hold it.
async fn resolve_by_removal(h: &Harness, phone: &Client<'_>, pr: &Principal) -> Tip {
    let laptop_key = KeyRef(h.genesis_tmb(pr).expect("genesis tmb"));
    h.ok(phone.remove_key(pr, &laptop_key).await);
    let resolved = h
        .ok(phone.push(pr, &["p1"]).await)
        .accepted("the resolution");
    h.eventually("the peers to hold the resolution", CONVERGE, || async {
        Ok(
            h.peer_view("p1", pr).await.map(|v| v.tip) == Some(resolved.clone())
                && h.peer_view("p2", pr).await.map(|v| v.tip) == Some(resolved.clone()),
        )
    })
    .await;
    resolved
}

fn sorted(tips: &[Tip]) -> Vec<Tip> {
    let mut tips = tips.to_vec();
    tips.sort_by(|a, b| a.0.cmp(&b.0));
    tips
}

/// How many principal-fork items `peer` serves for `p`, read from the peer
/// itself and independent of any action under test.
async fn evidence(h: &Harness, peer: &str, p: &Principal) -> usize {
    let addr = h.peer(peer).addr;
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
