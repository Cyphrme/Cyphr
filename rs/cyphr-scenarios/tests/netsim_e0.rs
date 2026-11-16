// NETSIM E0: does a small gossiping network converge under the servers'
// default rate limits? A measurement, not a pass/fail scenario.
//
// 5 attestors in a full gossip mesh; 12 principals, each published to 3-5
// of them; a few ordinary commits each, pushed to one holder only, so the
// rest learn them by gossip alone; no faults. It prints the convergence
// time, the wall time, and each peer's refusal counters, then asserts
// convergence within a bound.
//
// Gated by CYPHR_NETSIM_E0=1 (it takes minutes; CI refuses a bare #[ignore]).
// CYPHR_NETSIM_E0_UNTHROTTLED=1 lifts every rate bucket, to tell a
// rate-limit effect from any other cause. CYPHR_NETSIM_E0_ALL=1 publishes
// every principal to all five peers (the architect's heavier variant).
// Run with `--nocapture`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use cyphr_scenarios::Harness;
use cyphr_scenarios::actions::*;
use cyphr_scenarios::peer::Limits;

const PEERS: [&str; 5] = ["p0", "p1", "p2", "p3", "p4"];
const PRINCIPALS: usize = 12;
const COMMITS: usize = 3;
const CONVERGE: Duration = Duration::from_secs(180);

fn on() -> bool {
    std::env::var("CYPHR_NETSIM_E0").is_ok_and(|v| v == "1")
}

/// `name{labels} value` lines of Prometheus text, as (series, value).
fn counters(text: &str) -> HashMap<String, u64> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.rsplit_once(' ')?;
            Some((k.to_owned(), v.parse().ok()?))
        })
        .collect()
}

async fn scrape(h: &Harness, peer: &str) -> HashMap<String, u64> {
    let url = format!("http://{}/metrics", h.peer(peer).addr());
    // The scrape rides the same per-IP bucket it measures; retry until served.
    for _ in 0..50 {
        if let Ok(r) = h.http.get(&url).send().await
            && r.status().is_success()
        {
            return counters(&r.text().await.expect("metrics body"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("metrics of `{peer}` never served");
}

#[tokio::test(flavor = "multi_thread")]
async fn netsim_e0_five_peers_default_limits() {
    if !on() {
        eprintln!("netsim_e0 skipped: set CYPHR_NETSIM_E0=1 to run");
        return;
    }
    let unthrottled = std::env::var("CYPHR_NETSIM_E0_UNTHROTTLED").is_ok_and(|v| v == "1");
    let all = std::env::var("CYPHR_NETSIM_E0_ALL").is_ok_and(|v| v == "1");
    let limits = Limits {
        unthrottled,
        ..Limits::default()
    };
    let h = Harness::start_gossiping_with(&PEERS, 1, limits)
        .await
        .expect("start peers");
    let t0 = Instant::now();

    let clients: Vec<_> = (0..PRINCIPALS)
        .map(|i| h.client(&format!("c{i}")))
        .collect();
    let mut client_refusals = 0usize;
    let mut client_429 = 0usize;
    let mut tips: Vec<(Principal, Vec<&str>, Tip)> = Vec::new();

    // A push the servers throttle is retried, and counted.
    let mut holders = Vec::new();
    for (i, c) in clients.iter().enumerate() {
        let pr = h.ok(c.create_principal().await);
        let hs: Vec<&str> = (0..if all { 5 } else { 3 + i % 3 })
            .map(|j| PEERS[(i + j) % 5])
            .collect();
        let mut tip = None;
        for attempt in 0..20 {
            match h.ok(c.push(&pr, &hs).await) {
                PushOutcome::Accepted(t) => {
                    tip = Some(t);
                    break;
                },
                PushOutcome::Refused(r) => {
                    client_refusals += 1;
                    client_429 += usize::from(format!("{r:?}").contains("429"));
                    eprintln!("publish refused (attempt {attempt}): {r:?}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                },
            }
        }
        holders.push((pr, hs, tip.expect("publish never accepted")));
    }
    for round in 0..COMMITS {
        for (c, (pr, hs, tip)) in clients.iter().zip(holders.iter_mut()) {
            h.ok(c.commit_data(pr, &format!("r{round}")).await);
            for attempt in 0..20 {
                match h.ok(c.push(pr, &hs[..1]).await) {
                    PushOutcome::Accepted(t) => {
                        *tip = t;
                        break;
                    },
                    PushOutcome::Refused(r) => {
                        client_refusals += 1;
                        client_429 += usize::from(format!("{r:?}").contains("429"));
                        eprintln!("commit push refused (attempt {attempt}): {r:?}");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }
            }
        }
    }
    tips.extend(holders);
    let setup = t0.elapsed();

    // Poll at 1 s: each poll is itself 12-ish GETs per peer from 127.0.0.1.
    let t1 = Instant::now();
    let converged = loop {
        let mut lagging = 0usize;
        for (pr, hs, tip) in &tips {
            for peer in hs {
                if h.peer_view(peer, pr).await.map(|v| v.tip).as_ref() != Some(tip) {
                    lagging += 1;
                }
            }
        }
        if lagging == 0 {
            break true;
        }
        if t1.elapsed() > CONVERGE {
            eprintln!("still lagging: {lagging} (principal, holder) pairs");
            break false;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let convergence = t1.elapsed();
    let wall = t0.elapsed();

    eprintln!("E0 unthrottled={unthrottled} all_holders={all} converged={converged}");
    eprintln!("E0 setup={setup:?} convergence={convergence:?} wall={wall:?}");
    eprintln!("E0 client refusals={client_refusals} client 429s={client_429}");
    for peer in PEERS {
        let m = scrape(&h, peer).await;
        let get = |k: &str| m.get(k).copied().unwrap_or(0);
        eprintln!(
            "E0 {peer}: requests={} pushes_accepted={} rate_limited={} server_error={}",
            get("cyphr_requests_total"),
            get("cyphr_pushes_accepted_total"),
            get("cyphr_refusals_total{kind=\"rate_limited\"}"),
            get("cyphr_refusals_total{kind=\"server_error\"}"),
        );
    }
    assert!(
        converged,
        "the network did not converge within {CONVERGE:?}"
    );
}
