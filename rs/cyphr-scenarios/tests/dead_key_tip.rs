// Scenario: a dead key's commit at the tip, through the CLI verifier.
// Alice's phone key is naked-revoked at P2. The phone's commits after that
// reach only P1, which has not heard of the revoke and serves them.
// Must hold: the verifier's cutoff for the phone key is its own Witness
// Receipt Timestamp of the revoke (spec author, #203: "honor it from the
// witness's own receipt time"), never the revoke's `now`. A commit the
// phone dated before the verifier received the revoke counts; one dated at
// or after it is refused (SPEC 6.4), so the verdict's tip is never it.
//
// Stated limit (late learning, WRT as designed): the verifier learned the
// revoke after P2 did, so the phone's commit dated between the two receipts
// counts here although P2 would refuse it. Carrying an earlier witness's
// receipt time to a late node is per-message WRT gossip, a later node.
//
// Deterministic: each step that must fall in a later second than the one
// before it waits past a whole second, since `now` and the receipt time
// are whole seconds; no outcome depends on two events sharing a second.
//
// Required capabilities: transport,cli-network,data-commit.

use std::time::Duration;

use cyphr_scenarios::{Capability, Harness};

/// Past a whole second, so the next `now` or receipt time is strictly later.
const NEXT_SECOND: Duration = Duration::from_millis(1100);

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
    h.ok(laptop.push(&pr, &both).await).accepted("base push");
    // The phone knows P2 alone when it revokes its own key.
    h.ok(phone.sync(&pr, &["p2"]).await);
    h.ok(phone.naked_revoke(&pr, &phone_key).await);

    // Dated before the verifier hears of the revoke: history there.
    h.ok(phone
        .commit_data(&pr, "phone, before the verifier's receipt")
        .await);
    let history = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("P1 has not heard of the revoke");
    tokio::time::sleep(NEXT_SECOND).await;
    let first = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        first.tip, history,
        "a commit dated before the verifier's receipt of the revoke counts"
    );

    // Dated after the verifier's receipt: dead.
    tokio::time::sleep(NEXT_SECOND).await;
    h.ok(phone
        .commit_data(&pr, "phone, after the verifier's receipt")
        .await);
    let dead = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("P1 has not heard of the revoke");
    assert_eq!(h.peer_view("p1", &pr).await.map(|v| v.tip), Some(dead));

    let v = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(
        v.tip, history,
        "the verdict shows a dead key's commit as the tip"
    );
}
