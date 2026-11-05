// Scenario S08: forgery.
// Attacker: forges with a retired key and replays old material.
// A backdated data action signed by a retired key, a replayed data action, a
// re-pushed old commit.
// Must hold: the forgery is rejected by every peer; replays leave state unchanged
// (SPEC 7.6).
//
// Required capabilities: transport,cli-network,idempotency.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s08_forgery() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Idempotency,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));
    let peers = ["p1", "p2"];

    let pr = h.ok(alice.create_principal().await);
    let retired = h.ok(alice.add_backup_key(&pr).await);
    h.ok(alice.remove_key(&pr, &retired).await);
    h.ok(alice.push(&pr, &peers).await);
    h.ok(bob.trust_genesis(&pr, &peers).await);

    // A backdated action from the retired key is refused everywhere.
    let forged = h.ok(alice.forge_backdated(&pr, &retired).await);
    for peer in peers {
        let out = h.ok(alice.submit(&forged, peer).await);
        assert!(
            matches!(out, PushOutcome::Rejected(_)),
            "{peer} accepted a forgery: {out:?}"
        );
    }

    // A replayed data action and a re-pushed old commit change nothing (SPEC 7.6).
    let act = h.ok(alice.data_action(&pr, "once").await);
    h.ok(alice.submit(&act, "p1").await);
    let settled = h.ok(bob.verdict(&pr, &["p1"]).await);
    h.ok(alice.submit(&act, "p1").await);
    h.ok(alice.repush_commit(&pr, "p1", 1).await);
    let replayed = h.ok(bob.verdict(&pr, &["p1"]).await);
    assert_eq!(
        replayed.tip, settled.tip,
        "a replay must leave the tip unchanged"
    );
    assert_eq!(replayed.standing, Standing::Active);
    assert!(replayed.evidence.is_empty());
}
