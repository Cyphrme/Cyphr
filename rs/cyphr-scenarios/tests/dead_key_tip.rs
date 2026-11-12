// Scenario: a dead key's commit at the tip, through the CLI verifier.
// Alice's phone key is naked-revoked at P2; a commit the phone signs after
// that reaches only P1, which has not heard of the revoke and serves it as
// its tip.
// Must hold: a verifier asking both peers learns the revoke and refuses the
// commit dated after it (SPEC 6.4): its verdict's tip is the commit before,
// never the dead key's. History signed before the revoke stands.
//
// Required capabilities: transport,cli-network,data-commit.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn verifier_refuses_a_dead_keys_tip_commit() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::DataCommit,
    ])
    .await;
    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let observer = h.client("bob");
    let both = ["p1", "p2"];

    let pr = h.ok(laptop.create_principal().await);
    let phone_key = h.ok(laptop.pair_device(&pr, &phone).await);
    let base = h.ok(laptop.push(&pr, &both).await).accepted("base push");
    // The phone knows P2 alone when it revokes its own key.
    assert_eq!(h.ok(phone.sync(&pr, &["p2"]).await), base);
    let before = h.ok(observer.verdict(&pr, &both).await);
    h.ok(phone.naked_revoke(&pr, &phone_key).await);
    // Revokes carry whole seconds: the commit is dated after the death.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    h.ok(phone.commit_data(&pr, "phone, after its death").await);
    let dead = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("P1 has not heard of the revoke");
    assert_eq!(h.peer_view("p1", &pr).await.map(|v| v.tip), Some(dead));

    let v = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        v.tip, before.tip,
        "the verdict shows a dead key's commit as the tip"
    );
}
