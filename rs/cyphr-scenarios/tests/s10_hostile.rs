// Scenario S10: hostile.
// Attacker: sends hostile and oversized input.
// Unknown envelope version, oversized and malformed bodies, an evidence flood.
// Must hold: clients fail closed on the unknown version; peers stay bounded.
//
// Required capabilities: transport,version-check,peer-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s10_hostile() {
    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::VersionCheck,
        Capability::PeerGossip,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));
    let via = h.route("mallory", "p1").await;
    let url = format!("http://{via}");

    // Oversized and malformed bodies are refused as client errors, and the
    // peer keeps answering within a bound.
    for body in [vec![b'{'; 1024], vec![0u8; 16 * 1024 * 1024]] {
        let r = h.http.post(format!("{url}/push")).body(body).send().await;
        if let Ok(r) = r {
            assert!(
                r.status().is_client_error(),
                "hostile body got {}",
                r.status()
            );
        }
        let t = std::time::Instant::now();
        let ok = h
            .http
            .get(format!("{url}/server"))
            .send()
            .await
            .expect("peer still answers");
        assert!(ok.status().is_success());
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "peer stalled after a hostile body"
        );
    }

    h.ok(h.flood_evidence("p1", 10_000).await);
    let t = std::time::Instant::now();
    assert!(
        h.http
            .get(format!("{url}/server"))
            .send()
            .await
            .expect("answers after flood")
            .status()
            .is_success()
    );
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "peer stalled under an evidence flood"
    );

    // A client fails closed on an envelope version it does not know.
    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await);
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    h.ok(h.serve_envelope_version("p1", 99).await);
    match bob.verdict(&pr, &["p1"]).await {
        Err(ActionError::Refused(_)) => {},
        Ok(v) => panic!("an unknown envelope version was accepted: {v:?}"),
        Err(e) => h.ok::<()>(Err(e)),
    }
}
