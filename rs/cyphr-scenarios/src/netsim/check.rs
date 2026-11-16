//! The barrier and the invariants checked at it (N1, N6).
//!
//! A barrier heals every link, starts every peer, and waits until every
//! holder of every principal agrees with the principal's owner. Agreement
//! is measured against the owner's own chain (what its CLI printed and its
//! store holds) and the model's height, never against other peers alone,
//! because five peers can agree on a wrong or empty state.
//!
//! Quiescence is not "two reads 600 ms apart agree". After the first
//! agreement the barrier waits for each peer's gossip to complete two full
//! rounds, counted from the gossip log, and then reads everything again:
//! an unfinished exchange that would still change a holder has had two
//! chances to show itself.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::Size;
use super::model::Model;
use super::run::{Failure, PState, fail};
use crate::actions::{LocalView, PeerTip};
use crate::faults::{FaultKind, Link};
use crate::harness::Harness;

const POLL: Duration = Duration::from_secs(1);
/// Full gossip rounds every peer must complete after the first agreement.
const QUIET_ROUNDS: usize = 2;

/// What the owner's chain says every holder must hold.
struct Expected<'a> {
    p: usize,
    ps: &'a PState<'a>,
    view: LocalView,
}

/// Strip the algorithm tag: peers and the CLI spell one digest differently.
fn bare(s: &str) -> &str {
    s.split_once(':').map_or(s, |(_, d)| d)
}

/// How `got` (a peer's `/tip`) falls short of `want` (the owner's chain),
/// or `None` when they agree.
fn tip_diff(want: &LocalView, got: Option<&PeerTip>) -> Option<String> {
    let Some(got) = got else {
        return Some("holds nothing readable".into());
    };
    if got.heads != [want.tip.clone()] {
        return Some(format!("heads {:?}, owner tip {:?}", got.heads, want.tip));
    }
    if got.height != want.height {
        return Some(format!("height {}, owner {}", got.height, want.height));
    }
    if bare(&got.pr) != bare(&want.pr) {
        return Some(format!("pr {}, owner {}", got.pr, want.pr));
    }
    if bare(&got.ar) != bare(&want.ar) {
        return Some(format!("ar {}, owner {}", got.ar, want.ar));
    }
    None
}

/// N6 for one peer, from its lifetime counters and its log's panic lines.
pub fn n6_diff(peer: &str, counters: &HashMap<String, u64>, panics: &[String]) -> Option<String> {
    let get = |kind: &str| {
        counters
            .get(&format!("cyphr_refusals_total{{kind=\"{kind}\"}}"))
            .copied()
            .unwrap_or(0)
    };
    let mut why = Vec::new();
    if get("server_error") > 0 {
        why.push(format!("{} server_error answers", get("server_error")));
    }
    if get("rate_limited") > 0 {
        why.push(format!("{} rate_limited answers", get("rate_limited")));
    }
    if !panics.is_empty() {
        why.push(format!("a panic in its log: {}", panics[0]));
    }
    (!why.is_empty()).then(|| format!("peer `{peer}`: {}", why.join("; ")))
}

async fn heal_everything(h: &Harness, names: &[String]) -> Result<(), Failure> {
    for (a, na) in names.iter().enumerate() {
        for nb in &names[a + 1..] {
            let link = Link::new(na, nb);
            h.proxy.heal(na, nb);
            h.proxy.delay(&link, Duration::ZERO);
            h.proxy.apply(&FaultKind::Drop(link, 0.0));
        }
        if h.peer_down(na).await {
            h.start_peer(na)
                .await
                .map_err(|e| fail("DRIVER", format!("barrier: starting `{na}`: {e}")))?;
        }
    }
    Ok(())
}

/// Heal, wait for agreement and two quiet gossip rounds, then check N1 and
/// N6. Returns how long agreement took.
pub(crate) async fn barrier(
    h: &Harness,
    size: &Size,
    model: &Model,
    names: &[String],
    states: &[Option<PState<'_>>],
) -> Result<Duration, Failure> {
    heal_everything(h, names).await?;
    let began = Instant::now();

    let mut expected = Vec::new();
    for (p, slot) in states.iter().enumerate() {
        let Some(ps) = slot else { continue };
        let view = ps.clients[ps.pusher]
            .local_view(&ps.pr)
            .await
            .map_err(|e| fail("DRIVER", format!("principal {p}: owner view: {e}")))?;
        let pm = &model.principals[p];
        if view.tip != ps.tip || view.height != pm.height {
            return Err(fail(
                "MODEL",
                format!(
                    "principal {p}: the owner holds tip {:?} at height {}, the driver recorded \
                     {:?} and the model expects height {}",
                    view.tip, view.height, ps.tip, pm.height
                ),
            ));
        }
        expected.push(Expected { p, ps, view });
    }

    // (principal, holder) pairs not yet seen to agree.
    let mut pending: Vec<(usize, &str)> = expected
        .iter()
        .flat_map(|e| e.ps.holders.iter().map(move |h| (e.p, h.as_str())))
        .collect();
    let by_p: HashMap<usize, &Expected<'_>> = expected.iter().map(|e| (e.p, e)).collect();
    loop {
        let mut still = Vec::new();
        for (p, holder) in pending {
            let e = by_p[&p];
            let got = h.peer_view(holder, &e.ps.pr).await;
            if tip_diff(&e.view, got.as_ref()).is_some() {
                still.push((p, holder));
            }
        }
        pending = still;
        if pending.is_empty() {
            break;
        }
        if began.elapsed() > size.converge {
            return Err(non_convergence(h, &by_p, &pending, size).await);
        }
        tokio::time::sleep(POLL).await;
    }
    let convergence = began.elapsed();

    wait_quiet_rounds(h, size, model, names).await?;

    // Everything again, once, with nothing excused.
    for e in &expected {
        for holder in &e.ps.holders {
            let got = h.peer_view(holder, &e.ps.pr).await;
            if let Some(why) = tip_diff(&e.view, got.as_ref()) {
                return Err(fail(
                    "N1",
                    format!(
                        "principal {} at `{holder}` agreed and then differed after {QUIET_ROUNDS} \
                         further gossip rounds: {why}",
                        e.p
                    ),
                ));
            }
        }
    }

    for name in names {
        let counters = h
            .lifetime_counters(name)
            .await
            .map_err(|e| fail("DRIVER", e))?;
        let panics = h.log_lines(name, "panicked");
        if let Some(why) = n6_diff(name, &counters, &panics) {
            return Err(fail("N6", why));
        }
    }
    Ok(convergence)
}

async fn non_convergence(
    h: &Harness,
    by_p: &HashMap<usize, &Expected<'_>>,
    pending: &[(usize, &str)],
    size: &Size,
) -> Failure {
    let mut lines = Vec::new();
    for (p, holder) in pending {
        let e = by_p[p];
        let got = h.peer_view(holder, &e.ps.pr).await;
        let why = tip_diff(&e.view, got.as_ref()).unwrap_or_else(|| "agreed just now".into());
        lines.push(format!("  principal {p} at `{holder}`: {why}"));
    }
    fail(
        "N1",
        format!(
            "no convergence within {:?}: {} (principal, holder) pairs still differ from the \
             owner's chain\n{}",
            size.converge,
            pending.len(),
            lines.join("\n")
        ),
    )
}

/// Wait until every peer's gossip has completed `QUIET_ROUNDS` rounds past
/// the point where this is called. A round pulls each held principal from
/// each of the other peers, one log line apiece; counting from a snapshot,
/// `QUIET_ROUNDS + 1` rounds' worth of lines contains that many complete
/// rounds that began after it.
async fn wait_quiet_rounds(
    h: &Harness,
    size: &Size,
    model: &Model,
    names: &[String],
) -> Result<(), Failure> {
    let began = Instant::now();
    let mut need = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let held = model
            .principals
            .iter()
            .filter(|p| p.holders.contains(&i))
            .count();
        let per_round = held * (names.len() - 1);
        need.push((name, h.gossip_pulls(name), per_round * (QUIET_ROUNDS + 1)));
    }
    loop {
        let behind: Vec<&str> = need
            .iter()
            .filter(|(name, before, want)| h.gossip_pulls(name) < before + want)
            .map(|(name, ..)| name.as_str())
            .collect();
        if behind.is_empty() {
            return Ok(());
        }
        if began.elapsed() > size.converge {
            return Err(fail(
                "N1",
                format!(
                    "gossip made no progress at {behind:?} within {:?}",
                    size.converge
                ),
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}
