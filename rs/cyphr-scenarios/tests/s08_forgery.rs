// Scenario S08: forgery.
// Attacker: forges with a retired key and replays old material.
// A backdated data action signed by a retired key, a replayed data action, a
// re-pushed old commit.
// Must hold: the forgery is rejected by every peer; replays leave state unchanged
// (SPEC 7.6).
//
// Required capabilities: transport,cli-network,evidence,idempotency,data-commit.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn s08_forgery() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
        Capability::Idempotency,
        Capability::DataCommit,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));
    let peers = ["p1", "p2"];

    let pr = h.ok(alice.create_principal().await);
    let retired = h.ok(alice.add_backup_key(&pr).await);
    h.ok(alice.remove_key(&pr, &retired).await);
    h.ok(alice.push(&pr, &peers).await)
        .accepted("key removal push");
    h.ok(bob.trust_genesis(&pr, &peers).await);

    // A legitimate action must change state, or "unchanged" proves nothing.
    let act = h.ok(alice.data_action(&pr, "once").await);
    // An action-only bundle moves no tip, root or height, so what it changes
    // is the set of actions the peer holds.
    let pre = h
        .peer_actions("p1", &pr)
        .await
        .expect("P1 holds the principal");
    h.ok(alice.submit(&act, "p1").await)
        .accepted("the legitimate action");
    let applied = h
        .settled_view("p1", &pr)
        .await
        .expect("P1 holds the principal");
    let held = h
        .peer_actions("p1", &pr)
        .await
        .expect("P1 holds the principal");
    assert_eq!(
        held,
        pre + 1,
        "the legitimate action must change P1's state"
    );
    let p2_before = h
        .settled_view("p2", &pr)
        .await
        .expect("P2 holds the principal");

    // A backdated action from the key we retired with key/delete is refused
    // everywhere as not active, and changes nothing.
    let forged = h.ok(alice.forge_backdated(&pr, &retired).await);
    for peer in peers {
        let out = h.ok(alice.submit(&forged, peer).await);
        assert_eq!(
            out.refused(&format!("{peer} on a forgery")),
            RefusalKind::KeyNotActive,
            "{peer}: a key retired by key/delete is not active"
        );
    }

    // A replayed data action is accepted as a no-op (SPEC 7.6); a re-pushed
    // old commit re-includes applied transaction cozies and is refused as
    // reuse. Neither moves state.
    let replay = h.ok(alice.submit(&act, "p1").await);
    assert!(
        matches!(replay, PushOutcome::Accepted(_)),
        "a replayed data action is a no-op, not a refusal: {replay:?}"
    );
    let repush = h.ok(alice.repush_commit(&pr, "p1", 1).await);
    assert_eq!(
        repush.refused("re-pushed old commit"),
        RefusalKind::CozReuse
    );

    // Absence is only meaningful once the peers have gone quiet.
    assert_eq!(
        h.settled_view("p1", &pr).await,
        Some(applied.clone()),
        "attacks must not move P1"
    );
    assert_eq!(
        h.settled_view("p2", &pr).await,
        Some(p2_before),
        "attacks must not move P2"
    );
    assert_eq!(
        h.peer_actions("p1", &pr).await,
        Some(held),
        "attacks must not add an action to P1"
    );
    let v = h.ok(bob.verdict(&pr, &["p1"]).await);
    h.check_verdict(&v, &pr, &Expect::new(&["p1"], &pr.0)).await;
    assert_eq!(v.tip, applied.tip);
    assert_eq!(v.standing, Standing::Active);
    assert!(v.evidence.is_empty());
}
