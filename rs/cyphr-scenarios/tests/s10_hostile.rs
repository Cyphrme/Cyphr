// Scenario S10: hostile.
// Attacker: sends hostile and oversized input.
// Unknown envelope version, oversized and malformed bodies, an evidence flood.
// Must hold: clients fail closed on the unknown version; peers stay bounded.
//
// Required capabilities: transport,version-check,peer-gossip.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::{Duration, Instant};

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

    // The limit comes from the peer's own configuration, not a guess; this
    // scenario assumes the compiled default is exceeded by 16 MiB.
    // A valid-shaped push whose single blob is oversized, and a malformed one.
    let big = "A".repeat(16 * 1024 * 1024);
    let oversized = format!(r#"{{"principal_id":"SHA-512:AAAA","blobs":["{big}"]}}"#);
    for (what, body) in [("malformed", "{".to_owned()), ("oversized", oversized)] {
        let r = h
            .http
            .post(format!("{url}/push"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await;
        if let Ok(r) = r {
            let want: &[u16] = if what == "oversized" {
                &[413]
            } else {
                &[400, 422]
            };
            assert!(
                want.contains(&r.status().as_u16()),
                "{what} body got {}",
                r.status()
            );
        }
        let t = Instant::now();
        let ok = h
            .http
            .get(format!("{url}/server"))
            .send()
            .await
            .expect("peer still answers");
        assert!(ok.status().is_success());
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "peer stalled after a {what} body"
        );
    }

    h.ok(h.flood_evidence("p1", 10_000).await);
    let t = Instant::now();
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
    let tip = h.ok(alice.push(&pr, &["p1"]).await).accepted("push to P1");
    h.ok(bob.trust_genesis(&pr, &["p1"]).await);
    assert_eq!(
        h.ok(bob.verdict(&pr, &["p1"]).await).tip,
        tip,
        "sane before the rigging"
    );
    h.ok(h.serve_envelope_version("p1", 99).await);
    match bob.verdict(&pr, &["p1"]).await {
        Err(ActionError::Refused(r)) => assert_eq!(r.kind, RefusalKind::UnknownVersion),
        Ok(v) => panic!("an unknown envelope version was accepted: {v:?}"),
        Err(e) => h.ok::<()>(Err(e)),
    }
    assert_eq!(
        h.peer_view("p1", &pr).await.map(|v| v.tip),
        Some(tip),
        "the hostile traffic must not have moved P1"
    );
}
