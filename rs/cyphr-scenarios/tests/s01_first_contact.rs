// Scenario S01: first contact.
// Fault: none (baseline first contact; the fresh-start trust path).
// Alice creates a principal on her laptop and pairs her phone by key create:
// the phone makes its own key and the laptop commits it. The phone then
// signs a commit of its own and pushes to P1 and P2. Bob holds her genesis
// out of band plus a hint. Carol hears of Alice only from Bob.
// Must hold: the phone's key is accepted by the peers as Alice's; Bob and
// Carol replay to the same tip; each verdict names its anchor, peers and
// freshness.
//
// Required capabilities: transport,cli-network,evidence; client-gossip for
// Carol, whose step ends the scenario as RED until it lands.

use std::time::{Duration, Instant};

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(client-gossip): G3"]
async fn s01_first_contact() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
    ])
    .await;

    let started = Instant::now();
    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let (bob, carol) = (h.client("bob"), h.client("carol"));

    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.pair_device(&pr, &phone).await);
    h.ok(laptop.push(&pr, &["p1", "p2"]).await)
        .accepted("pairing push");
    let paired = h.peer_view("p1", &pr).await.expect("P1 holds Alice");
    // The phone signs with its own key; the peers accepting it is what
    // shows the pairing made that key Alice's.
    h.ok(phone.add_backup_key(&pr).await);
    // The pushed tip and the peers' own state are the independent truth.
    let tip = h
        .ok(phone.push(&pr, &["p1", "p2"]).await)
        .accepted("the phone's push");
    for peer in ["p1", "p2"] {
        let held = h.peer_view(peer, &pr).await.expect("peer holds Alice");
        assert_eq!(held.tip, tip, "{peer} must hold the phone's push");
        assert_eq!(
            held.height,
            paired.height + 1,
            "{peer}: the phone's commit sits on the pairing"
        );
    }

    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let vb = h.ok(bob.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(vb.tip, tip, "Bob must replay to the tip the phone pushed");
    assert_eq!(
        vb.anchor.source,
        AnchorSource::TrustedGenesis,
        "Bob holds the genesis"
    );
    check(&h, &vb, &pr, started).await;

    h.ok(carol.learn_from(&bob, &pr).await);
    let vc = h.ok(carol.verdict(&pr, &["p1", "p2"]).await);
    assert_eq!(vc.tip, tip, "Carol must replay to the tip the phone pushed");
    assert_eq!(
        vc.anchor.source,
        AnchorSource::Hint,
        "Carol only heard of it from Bob"
    );
    check(&h, &vc, &pr, started).await;
}

async fn check(h: &Harness, v: &Verdict, pr: &Principal, started: Instant) {
    h.check_verdict(v, pr, &Expect::new(&["p1", "p2"], &pr.0))
        .await;
    assert_eq!(v.standing, Standing::Active);
    assert!(v.evidence.is_empty());
    assert!(pr.same_as(&v.anchor.id), "the anchor is Alice's genesis");
    let mut used = v.peers.clone();
    used.sort();
    assert_eq!(used, ["p1", "p2"], "a verdict names the peers it used");
    assert!(!v.freshness.peer_reported_newer);
    assert!(
        v.freshness.age <= started.elapsed() + Duration::from_secs(1),
        "a view cannot be older than this run"
    );
}
