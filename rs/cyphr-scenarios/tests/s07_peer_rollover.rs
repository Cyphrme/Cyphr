// Scenario S07: peer rollover.
// Fault: none (peer key rotation, a legitimate change).
// P1 rotates its own key.
// Must hold: clients follow P1's chain; old-key statements stay attributable; nothing
// is mistaken for evidence.
//
// Required capabilities: transport,cli-network,evidence,peer-rollover.
// End to end: P1 is rotated with the shipped `cyphr-server rotate-key`, Alice
// pushes and Bob verifies through the `cyphr` CLI.
// Turns red if: rotation changes the peer's identity or keeps its key, a
// client stops following the chain, the rollover reads as evidence, or an
// old statement can no longer be attributed to the key that signed it.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);

#[tokio::test(flavor = "multi_thread")]
async fn s07_peer_rollover() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::Evidence,
        Capability::PeerRollover,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));

    let pr = h.ok(alice.create_principal().await);
    let t1 = h.ok(alice.push(&pr, &["p1"]).await).accepted("first push");
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    let before = h.ok(bob.verdict(&pr, &["p1"]).await);
    assert_eq!(before.tip, t1);
    let ident = server_identity(&h).await;
    // A statement signed before the rollover, held by Bob.
    let held = h.ok(bob.hold_statement(&pr, "p1").await);
    // Verified offline by the harness, under the old public key read from
    // /server before the rollover, independent of `attribute`.
    let (old_alg, old_pub, old_tmb) = (
        ident["payload"]["alg"].as_str().expect("alg"),
        ident["payload"]["pub"].as_str().expect("pub"),
        ident["payload"]["tmb"].as_str().expect("tmb"),
    );
    cyphr_scenarios::signed::verify_statement(&held.coz, old_alg, old_pub, old_tmb)
        .unwrap_or_else(|why| panic!("the held statement is not signed by P1's old key: {why}"));

    h.ok(h.rotate_peer_key("p1").await);

    // A rotation that changes nothing is no rotation: the signing key must
    // differ, while the peer's identity (its genesis digest) must not.
    let after_ident = server_identity(&h).await;
    assert_ne!(
        after_ident["payload"]["pub"], ident["payload"]["pub"],
        "the signing key must change"
    );
    assert_ne!(after_ident["payload"]["tmb"], ident["payload"]["tmb"]);
    assert_eq!(
        after_ident["payload"]["pg"], ident["payload"]["pg"],
        "identity survives rotation"
    );
    assert_eq!(after_ident["payload"]["pg"], h.peer("p1").id.as_str());

    // Any new commit shows clients following the chain; a key commit is
    // one the CLI can sign (it signs no data commit yet).
    h.ok(alice.add_backup_key(&pr).await);
    let t2 = h
        .ok(alice.push(&pr, &["p1"]).await)
        .accepted("push after rollover");
    assert_ne!(t1, t2);
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(t2.clone())
    );
    h.eventually("Bob to follow P1's chain", CONVERGE, || async {
        Ok(bob.verdict(&pr, &["p1"]).await?.tip == t2)
    })
    .await;
    let after = h.ok(bob.verdict(&pr, &["p1"]).await);
    h.check_verdict(&after, &pr, &Expect::new(&["p1"], &pr.0))
        .await;
    assert_eq!(after.standing, Standing::Active);
    assert!(!after.freshness.peer_reported_newer);
    assert!(
        after.evidence.is_empty(),
        "a legitimate rollover is not evidence"
    );
    // The old key is gone from /server, yet the old statement must still be
    // attributed to P1 and to the key that actually signed it.
    let who = h.ok(bob.attribute(&held).await);
    assert_eq!(who.peer, h.peer("p1").id, "attributed to P1");
    assert_eq!(
        serde_json::Value::from(who.signing_key_tmb.as_str()),
        ident["payload"]["tmb"],
        "attributed to the key P1 held when it signed"
    );
    assert_ne!(
        serde_json::Value::from(who.signing_key_tmb.as_str()),
        after_ident["payload"]["tmb"]
    );
}

async fn server_identity(h: &Harness) -> serde_json::Value {
    let bytes = h
        .http
        .get(format!("http://{}/server", h.peer("p1").addr))
        .send()
        .await
        .expect("GET /server")
        .bytes()
        .await
        .expect("server identity body");
    serde_json::from_slice(&bytes).expect("server identity json")
}
