// Scenario G2: peers gossip by the same pull step a verifier runs.
// Fault: a partition of the peer-to-peer link, then a real principal fork.
// Two peers gossip every second through the proxy. A commit pushed to P1 only
// reaches P2 by gossip; a partition of P1 and P2 stops it, and the proxy counts
// the attempts the cut blocked; healing converges them; two devices that commit
// to different partitioned peers leave both peers holding both branches, each
// still serving its own chain and the principal fork as evidence.
//
// Required capabilities: cli-network,branch-store,evidence,peer-gossip,data-commit.
// Not S02/S03: those also need key rotation, fork resolution and `watch`,
// which other nodes supply. This is the gossip path alone, end to end.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(30);

/// Claim: peer-side anti-entropy is a timer calling the same pull step, and
/// peers converge by the rules a verifier uses: a commit reaches a peer that
/// holds the principal through gossip alone; the link the proxy cuts carries
/// (and blocks) the gossip, which cannot bypass it; a prefix is never a
/// fork; and two commits over one `pre` leave both branches kept at both
/// peers, neither merged.
///
/// Turns red if: P2 never learns P1's commit; the cut link shows no blocked
/// attempt (gossip bypasses the proxy); P2 learns a commit through the cut;
/// a fork is merged (a peer's tip moves to the other branch) or never shows
/// as evidence at both peers.
/// End-to-end scenario: yes (shipped `cyphr-server` and `cyphr` binaries).
#[tokio::test(flavor = "multi_thread")]
async fn gossip_timer_converges_peers_and_keeps_both_branches_of_a_fork() {
    let h = Harness::start_gossiping(&["p1", "p2"], 1)
        .await
        .expect("start gossiping peers");
    h.require(&[
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::DataCommit,
    ])
    .await;
    let (alice, phone) = (h.client("alice"), h.client("alice-phone"));
    let both = ["p1", "p2"];

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.pair_device(&pr, &phone).await);
    h.ok(alice.push(&pr, &both).await).accepted("base push");

    // A commit pushed to P1 only reaches P2 by gossip.
    h.ok(alice.commit_data(&pr, "one").await);
    let one = h.ok(alice.push(&pr, &["p1"]).await).accepted("push to P1");
    h.eventually("gossip to carry the commit to P2", CONVERGE, || async {
        Ok(h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(one.clone()))
    })
    .await;

    // A cut link blocks the gossip; the peer behind learns nothing; healing
    // converges it. The gossip is a prefix, not a fork.
    h.proxy.partition("p1", "p2");
    h.ok(alice.commit_data(&pr, "two").await);
    let two = h.ok(alice.push(&pr, &["p1"]).await).accepted("push to P1");
    h.eventually("gossip attempts on the cut link", CONVERGE, || async {
        Ok(h.proxy.stats("p1", "p2").blocked > 0)
    })
    .await;
    assert_eq!(
        h.peer_view("p2", &pr).await.map(|v| v.tip),
        Some(one.clone()),
        "a partitioned P2 must not learn the commit"
    );
    h.proxy.heal("p1", "p2");
    h.eventually("P2 to catch up after the heal", CONVERGE, || async {
        Ok(h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(two.clone()))
    })
    .await;
    for peer in both {
        assert_eq!(
            evidence(&h, peer, &pr).await,
            0,
            "{peer}: a prefix is no fork"
        );
    }

    // Two devices commit over one tip to different partitioned peers.
    assert_eq!(h.ok(phone.sync(&pr, &both).await), two);
    h.proxy.partition("p1", "p2");
    // Key commits, not data commits: the storage engine keeps a rival
    // branch only when the commits carry no data actions of their own, as
    // `cyphr-storage` `retain_rival` replays the stored branch's actions
    // into the rival's pre (reported to the G1 owner; S03's data-action
    // fork meets the same limit).
    h.ok(alice.add_backup_key(&pr).await);
    h.ok(phone.add_backup_key(&pr).await);
    let at = h
        .ok(alice.push(&pr, &["p1"]).await)
        .accepted("alice branch");
    let pt = h
        .ok(phone.push(&pr, &["p2"]).await)
        .accepted("phone branch");
    assert_ne!(at, pt, "the two devices must have forked");
    h.proxy.heal("p1", "p2");
    h.eventually(
        "both peers to hold the fork as evidence",
        CONVERGE,
        || async { Ok(evidence(&h, "p1", &pr).await >= 1 && evidence(&h, "p2", &pr).await >= 1) },
    )
    .await;
    for peer in both {
        assert_eq!(heads(&h, peer, &pr).await, 2, "{peer}: both branch heads");
    }
    // Neither peer merged: each still serves the chain it was pushed.
    let settled = |peer: &'static str| h.settled_view(peer, &pr);
    assert_eq!(settled("p1").await.map(|v| v.tip), Some(at));
    assert_eq!(settled("p2").await.map(|v| v.tip), Some(pt));
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

/// How many branch heads `peer` serves for `p`.
async fn heads(h: &Harness, peer: &str, p: &Principal) -> usize {
    let addr = h.peer(peer).addr;
    let body: serde_json::Value = h
        .http
        .get(format!("http://{addr}/branches"))
        .query(&[("pr", p.0.as_str())])
        .send()
        .await
        .expect("branches request")
        .json()
        .await
        .expect("branches json");
    body["payload"]["branches"].as_array().map_or(0, Vec::len)
}
