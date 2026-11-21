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
use cyphr_scenarios::peer::Limits;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn s10_hostile() {
    // The body limit is pinned in the peers' own config and the oversized
    // blob derived from it, so a change to the compiled default cannot make
    // the oversized case pass or fail for the wrong reason.
    const LIMIT: u64 = 64 * 1024;
    let h = Harness::start_with(
        &["p1", "p2"],
        Limits {
            max_body_bytes: Some(LIMIT),
            ..Limits::default()
        },
    )
    .await
    .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::VersionCheck,
        Capability::PeerGossip,
    ])
    .await;

    let (alice, bob) = (h.client("alice"), h.client("bob"));
    let via = h.route("mallory", "p1").await;
    let url = format!("http://{via}");

    // A valid-shaped push whose single blob is sized relative to the pinned
    // limit: one under it (so the limit, not the shape, decides) and one over.
    let push_body = |blob_bytes: u64| {
        let blob = "A".repeat(blob_bytes as usize);
        format!(r#"{{"principal_id":"SHA-512:AAAA","txs":[["{blob}"]]}}"#)
    };
    let cases: [(&str, String, &[u16]); 3] = [
        ("malformed", "{".to_owned(), &[400, 422]),
        (
            "under the limit",
            push_body(LIMIT / 2),
            &[400, 401, 403, 422],
        ),
        ("oversized", push_body(LIMIT * 4), &[413]),
    ];
    for (what, body, want) in cases {
        // A reset or timeout is a failure here, not a pass: the peer must
        // answer a hostile body, never hang up on it.
        let r = h
            .http
            .post(format!("{url}/push"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{what} body: no response: {e}"));
        if what == "under the limit" {
            // Directly: the limit, not the shape, must not be what refused it.
            assert_ne!(
                r.status().as_u16(),
                413,
                "an under-limit body was refused as too large"
            );
            assert!(
                r.status().as_u16() < 500,
                "an under-limit body broke the peer"
            );
        }
        assert!(
            want.contains(&r.status().as_u16()),
            "{what} body got {}",
            r.status()
        );
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
    // The peer's per-IP fence may refuse the flood's tail (and, for a
    // moment, this request, which shares the loopback address): bounded
    // means it refuses, then answers again within seconds, never that it
    // hangs or dies.
    let t = Instant::now();
    loop {
        let answer = h.http.get(format!("{url}/server")).send().await;
        if answer.is_ok_and(|r| r.status().is_success()) {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "peer did not recover within 2s of an evidence flood"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

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
        h.settled_view("p1", &pr).await.map(|v| v.tip),
        Some(tip),
        "the hostile traffic must not have moved P1"
    );
}
