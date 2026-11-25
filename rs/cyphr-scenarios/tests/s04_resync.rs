// Scenario S04, resync: theft of a key whose two holders fork with both
// branches extended (SPEC 15.8 item 2).
// Alice and a thief holding her laptop key each extend their own branch
// twice on partitioned peers.
// Must hold: Alice's resync makes every server Active on her tip; the
// thief's resync, which asserts a second branch, makes every server Error
// for good; and Alice's second PoP does not leave it. (Key revocation is
// the other exit; a PoP by a stolen key is exactly why a second branch's
// PoP cannot be allowed to win.)
//
// Required capabilities:
// transport,cli-network,branch-store,evidence,peer-gossip,data-commit,key-pairing.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(30);

// @docket: sc-l2822 :: scripts/docket-run sc-l2822
#[tokio::test(flavor = "multi_thread")]
async fn s04_a_second_branchs_pop_is_error_for_good() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
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
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(alice.create_principal().await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    h.ok(thief.steal_key(&laptop, &laptop_key).await);

    // Cut p3 from the others so each side extends its branch before the
    // other's arrives (as 03f350ec does for the theft scenarios).
    for from in ["p1", "p2"] {
        h.proxy.partition(from, "p3");
    }
    let (mut at, mut tt) = (None, None);
    for round in 1..=2 {
        h.ok(alice.commit_data(&pr, &format!("alice {round}")).await);
        h.ok(thief.commit_data(&pr, &format!("thief {round}")).await);
        at = Some(
            h.ok(alice.push(&pr, &["p1", "p2"]).await)
                .accepted("alice branch"),
        );
        tt = Some(
            h.ok(thief.push(&pr, &["p3"]).await)
                .accepted("thief branch"),
        );
    }
    let (at, tt) = (at.expect("alice tip"), tt.expect("thief tip"));
    assert_ne!(at, tt, "the thief forked");
    for from in ["p1", "p2"] {
        h.proxy.heal(from, "p3");
    }
    h.eventually("every verdict to read Error", CONVERGE, || async {
        Ok(bob.verdict(&pr, &all).await?.standing == Standing::Error)
    })
    .await;

    // The owner's PoP.
    assert_eq!(h.ok(alice.resync(&pr).await), at);
    h.eventually(
        "every server to be Active on Alice's tip",
        CONVERGE,
        || async {
            for peer in all {
                if h.peer_view(peer, &pr).await.map(|v| v.tip) != Some(at.clone()) {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;
    assert_eq!(
        h.ok(bob.verdict(&pr, &all).await).standing,
        Standing::Active
    );

    // The thief's PoP names a second branch: Error everywhere, for good.
    assert_eq!(h.ok(thief.resync(&pr).await), tt);
    h.eventually("every verdict to read Error again", CONVERGE, || async {
        Ok(bob.verdict(&pr, &all).await?.standing == Standing::Error)
    })
    .await;

    // A client on one branch must read what the servers read. Alice holds
    // her own branch and its PoP; the thief's PoP names a commit she does
    // not hold, and still makes the fork Error for good. Neither her
    // verdict nor a relying party's sign-in may read Active on her branch.
    let own = h.ok(alice.verdict(&pr, &all).await);
    assert_eq!(
        own.standing,
        Standing::Error,
        "the owner's own client must not read Active past the thief's PoP"
    );
    let rp = h.ok(h.start_relying_party().await);
    if let Ok(session) = alice.sign_in(&rp).await {
        panic!("a relying party signed in during Error: {session:?}");
    }

    // The owner's second PoP, on her tip again, does not leave it.
    h.ok(alice.resync(&pr).await);
    for peer in all {
        let view = h.settled_view(peer, &pr).await.expect("view");
        assert!(
            view.heads.len() >= 2,
            "{peer} still holds both heads: {view:?}"
        );
    }
    assert_eq!(h.ok(bob.verdict(&pr, &all).await).standing, Standing::Error);
}
