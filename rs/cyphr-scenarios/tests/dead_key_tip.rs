// Scenario: a dead key's commit at the tip, through the CLI verifier.
// A peer serves a principal whose tip is a commit by Alice's phone key,
// and the phone key's naked revoke beside it (it was revoked after the
// peer took the commit, so the peer still serves it as its chain).
// Must hold: the verifier learns the revoke and refuses the commit, which
// no live key's commit buries (SPEC 6.4): its verdict's tip is the commit
// before it, never the dead key's.
//
// Required capabilities: transport,cli-network,data-commit.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn verifier_refuses_a_dead_keys_tip_commit() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::DataCommit,
    ])
    .await;
    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let observer = h.client("bob");

    let pr = h.ok(laptop.create_principal().await);
    let phone_key = h.ok(laptop.pair_device(&pr, &phone).await);
    let base = h.ok(laptop.push(&pr, &["p1"]).await).accepted("base push");
    assert_eq!(h.ok(phone.sync(&pr, &["p1"]).await), base);
    // The verifier's own reading of the live history, in its spelling.
    let before = h.ok(observer.verdict(&pr, &["p1"]).await);
    h.ok(phone.commit_data(&pr, "phone, before its death").await);
    let dead = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("the phone's commit");
    h.ok(phone.naked_revoke(&pr, &phone_key).await);
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(dead.clone()),
        "a revoke never moves the chain a peer serves"
    );

    let v = h.ok(observer.verdict(&pr, &["p1"]).await);
    assert_eq!(
        (v.standing, v.tip),
        (Standing::Active, before.tip),
        "the verdict shows a dead key's commit as the tip"
    );
}
