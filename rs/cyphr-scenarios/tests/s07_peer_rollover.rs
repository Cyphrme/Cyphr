// Scenario S07: peer rollover.
// Fault: none (peer key rotation, a legitimate change).
// P1 rotates its own key.
// Must hold: clients follow P1's chain; old-key statements stay attributable; nothing
// is mistaken for evidence.
//
// Required capabilities: transport,cli-network,peer-rollover.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s07_peer_rollover() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::PeerRollover,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await);
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let before = h.ok(bob.verdict(&pr, &["p1"]).await);
    let id_before = h.peer("p1").id.clone();

    h.ok(h.rotate_peer_key("p1").await);

    // The peer's identity is its genesis digest, which a key rotation
    // must leave unchanged.
    let bytes = h
        .http
        .get(format!("http://{}/server", h.peer("p1").addr))
        .send()
        .await
        .expect("GET /server after rotation")
        .bytes()
        .await
        .expect("server identity body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("server identity json");
    assert_eq!(
        body["payload"]["pg"],
        id_before.as_str(),
        "peer identity must survive rotation"
    );

    h.ok(alice.commit_data(&pr, "after the rollover").await);
    h.ok(alice.push(&pr, &["p1"]).await);
    let after = h.ok(bob.verdict(&pr, &["p1"]).await);
    assert_eq!(after.standing, Standing::Active);
    assert!(!after.freshness.peer_reported_newer);
    assert!(
        after.evidence.is_empty(),
        "a legitimate rollover is not evidence"
    );
    assert_ne!(
        after.tip, before.tip,
        "clients follow the peer's chain forward"
    );
    assert_eq!(
        before.peers, after.peers,
        "old-key statements stay attributable to P1"
    );
}
