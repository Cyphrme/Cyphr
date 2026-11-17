//! The barrier and the invariants checked at it.
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
//!
//! Once the network is quiet the barrier also checks what only quiescence
//! can settle: N5's second half (every holder lists each revoked key), N9
//! (the witness equals its authority), the sampled verdicts and sign-ins
//! (N7, N8) and `verify-all` on a stopped peer (N3), and last N6.

use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, Instant};

use futures::FutureExt;
use serde_json::Value;

use super::Size;
use super::model::Model;
use super::plan::Op;
use super::run::{Failure, PState, Revoked, act, fail};
use crate::actions::{
    ActionError, Client, Evidence, KeyRef, LocalView, PeerTip, Principal, PushOutcome, RefusalKind,
    Standing, Tip, Verdict,
};
use crate::faults::{FaultKind, Link};
use crate::harness::Harness;
use crate::oracle::Expect;

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
pub(crate) fn tip_diff(want: &LocalView, got: Option<&PeerTip>) -> Option<String> {
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

/// The answer a server gives for a proof it does not keep (after a restart,
/// or an evicted principal): a 503 the asker meets by pulling without one.
/// It is designed, and counted as `server_error` all the same, so N6 takes
/// it off that counter by its log line.
const NO_PROOF: &str = "pull without one";

/// How many designed no-proof 503s `peer` answered, over every lifetime.
fn designed_503s(h: &Harness, peer: &str) -> u64 {
    h.log_lines(peer, NO_PROOF)
        .iter()
        .filter(|l| l.contains("server error"))
        .count() as u64
}

/// N6 for one peer, from its lifetime counters, the designed 503s among
/// them, and its log's panic lines.
pub fn n6_diff(
    peer: &str,
    counters: &HashMap<String, u64>,
    designed: u64,
    panics: &[String],
) -> Option<String> {
    let get = |kind: &str| {
        counters
            .get(&format!("cyphr_refusals_total{{kind=\"{kind}\"}}"))
            .copied()
            .unwrap_or(0)
    };
    let mut why = Vec::new();
    let errors = get("server_error").saturating_sub(designed);
    if errors > 0 {
        why.push(format!(
            "{errors} server_error answers besides {designed} designed no-proof 503s"
        ));
    }
    if get("rate_limited") > 0 {
        why.push(format!("{} rate_limited answers", get("rate_limited")));
    }
    if !panics.is_empty() {
        why.push(format!("a panic in its log: {}", panics[0]));
    }
    (!why.is_empty()).then(|| format!("peer `{peer}`: {}", why.join("; ")))
}

pub(crate) async fn heal_everything(h: &Harness, names: &[String]) -> Result<(), Failure> {
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

/// What a barrier needs besides the network: the sizes, the model, the
/// driver's principals, the peers, the witness, and the checks deferred to
/// this barrier.
pub(crate) struct Barrier<'a, 'h> {
    pub h: &'h Harness,
    pub size: &'a Size,
    pub model: &'a Model,
    pub names: &'a [String],
    pub states: &'a [Option<PState<'h>>],
    /// A witness of `names[0]`, when the size has one.
    pub witness: Option<&'a str>,
    /// `Verdict`, `SignIn` and `VerifyAll` ops since the last barrier.
    pub marks: &'a [Op],
    pub index: usize,
}

/// Heal, wait for agreement and two quiet gossip rounds, then check N1 and
/// everything quiescence settles. Returns how long agreement took.
pub(crate) async fn barrier(b: Barrier<'_, '_>) -> Result<Duration, Failure> {
    let Barrier {
        h,
        size,
        model,
        names,
        states,
        ..
    } = b;
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
    eprintln!("NETSIM barrier {} agreed after {convergence:.1?}", b.index);

    wait_quiet_rounds(h, size, names).await?;

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

    n5_listed(h, size, states).await?;
    if let Some(w) = b.witness {
        n9(h, size, w, &names[0], &expected).await?;
    }
    sampled(&b).await?;
    report_counters(h, names).await?;
    for name in names {
        let counters = h
            .lifetime_counters(name)
            .await
            .map_err(|e| fail("DRIVER", e))?;
        let panics = h.log_lines(name, "panicked");
        if let Some(why) = n6_diff(name, &counters, designed_503s(h, name), &panics) {
            return Err(fail("N6", why));
        }
    }
    Ok(convergence)
}

/// One line per peer of what it refused so far, so a run that fails N6
/// still reports its throttle counters.
async fn report_counters(h: &Harness, names: &[String]) -> Result<(), Failure> {
    let mut line = String::new();
    for name in names {
        let c = h
            .lifetime_counters(name)
            .await
            .map_err(|e| fail("DRIVER", e))?;
        let get = |k: &str| {
            c.get(&format!("cyphr_refusals_total{{kind=\"{k}\"}}"))
                .copied()
                .unwrap_or(0)
        };
        line.push_str(&format!(
            " {name}[rate_limited={} server_error={} (no-proof 503s {}) rounds={}]",
            get("rate_limited"),
            get("server_error"),
            designed_503s(h, name),
            c.get("cyphr_gossip_rounds_total").copied().unwrap_or(0)
        ));
    }
    eprintln!("NETSIM counters:{line}");
    Ok(())
}

/// Poll `unmet` once a second until it reports nothing unmet; on timeout
/// return its last lines. The whole network is slow only through gossip, so
/// every wait on peers is this one, bounded by `size.converge`.
pub(crate) async fn until<F, Fut>(size: &Size, what: &str, mut unmet: F) -> Result<Duration, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Vec<String>>,
{
    let began = Instant::now();
    loop {
        let lines = unmet().await;
        if lines.is_empty() {
            return Ok(began.elapsed());
        }
        if began.elapsed() > size.converge {
            return Err(format!(
                "{what} not reached within {:?}:\n  {}",
                size.converge,
                lines.join("\n  ")
            ));
        }
        tokio::time::sleep(POLL).await;
    }
}

/// What `GET path?pr=` answers at a peer, the envelope's payload.
async fn payload(h: &Harness, peer: &str, path: &str, query: &[(&str, &str)]) -> Result<Value, String> {
    let resp = h
        .http
        .get(format!("http://{}{path}", h.peer(peer).addr()))
        .query(query)
        .send()
        .await
        .map_err(|e| format!("`{peer}` {path}: {e}"))?;
    let status = resp.status();
    let v: Value = resp
        .json()
        .await
        .map_err(|e| format!("`{peer}` {path} answered {status} with no JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!("`{peer}` {path} answered {status}: {v}"));
    }
    Ok(v["payload"].clone())
}

/// How many fork-evidence items a peer serves for `p`.
pub(crate) async fn evidence_count(h: &Harness, peer: &str, p: &Principal) -> Result<usize, String> {
    let v = payload(h, peer, "/evidence", &[("pr", &p.0)]).await?;
    Ok(v["items"].as_array().map_or(0, Vec::len))
}

/// Whether `peer` serves a naked revoke of `key`.
async fn lists_revoked(h: &Harness, peer: &str, key: &KeyRef) -> Result<bool, String> {
    let v = payload(h, peer, "/revoked", &[("tmbs", &key.0)]).await?;
    Ok(v["revoked"].as_array().is_some_and(|r| !r.is_empty()))
}

/// N5, second half: at quiescence every holder lists every key the owner
/// revoked, so the revoke travelled by gossip and not only to the peer that
/// first acknowledged it. SPEC 6.4: "further use of the revoked key must be
/// rejected", which a peer that never heard of the revoke cannot do.
pub(crate) async fn n5_listed(
    h: &Harness,
    size: &Size,
    states: &[Option<PState<'_>>],
) -> Result<(), Failure> {
    for (p, ps) in states.iter().enumerate().filter_map(|(p, s)| Some((p, s.as_ref()?))) {
        for Revoked { key, forgotten_by } in &ps.revoked {
            until(size, &format!("principal {p}'s revoked key listed"), || async {
                let mut lines = Vec::new();
                for holder in ps.holders.iter().filter(|x| !forgotten_by.contains(x)) {
                    match lists_revoked(h, holder, key).await {
                        Ok(true) => {},
                        Ok(false) => lines.push(format!("`{holder}` does not list {}", key.0)),
                        Err(e) => lines.push(e),
                    }
                }
                lines
            })
            .await
            .map_err(|e| fail("N5", e))?;
        }
    }
    Ok(())
}

/// N5, first half, checked at the moment of use: a peer that has
/// acknowledged the revoke of `key` refuses an action signed with it and
/// its state does not move.
pub(crate) async fn n5_refused(
    h: &Harness,
    ps: &PState<'_>,
    signer: &Client<'_>,
    key: &KeyRef,
    peer: &str,
    what: &str,
) -> Result<(), Failure> {
    let read = || async {
        (
            h.peer_actions(peer, &ps.pr).await,
            h.peer_view(peer, &ps.pr).await,
        )
    };
    let before = read().await;
    let action = act(signer.action_by(&ps.pr, key, "after the revoke").await, what)?;
    match signer.submit(&action, peer).await {
        Ok(PushOutcome::Refused(r))
            if matches!(r.kind, RefusalKind::Revoked | RefusalKind::KeyNotActive) => {},
        Ok(PushOutcome::Refused(r)) => {
            return Err(fail(
                "N5",
                format!(
                    "{what}: `{peer}` refused the revoked key {} for the wrong reason, {:?}: {}",
                    key.0, r.kind, r.detail
                ),
            ));
        },
        Ok(PushOutcome::Accepted(tip)) => {
            return Err(fail(
                "N5",
                format!(
                    "{what}: `{peer}` accepted an action signed by the revoked key {} (tip {tip:?})",
                    key.0
                ),
            ));
        },
        Err(e) => return Err(fail("DRIVER", format!("{what}: submitting to `{peer}`: {e}"))),
    }
    if read().await != before {
        return Err(fail(
            "N5",
            format!("{what}: `{peer}`'s state moved after it refused the revoked key {}", key.0),
        ));
    }
    Ok(())
}

/// N8: a dead key, or a principal in Error, is refused at the relying
/// party; `Err` carries what it did instead.
pub(crate) async fn n8_refused(
    h: &Harness,
    c: &Client<'_>,
    p: &Principal,
    key: Option<&KeyRef>,
    why: &str,
    what: &str,
) -> Result<(), Failure> {
    let rp = act(h.start_relying_party().await, what)?;
    let session = match key {
        Some(k) => c.sign_in_with(&rp, p, k).await,
        None => c.sign_in(&rp).await,
    };
    match session {
        Err(ActionError::Refused(_)) => Ok(()),
        Err(e) => Err(fail("DRIVER", format!("{what}: sign-in ({why}): {e}"))),
        Ok(s) => Err(fail(
            "N8",
            format!("{what}: the relying party signed in {why}: token for {:?}", s.principal),
        )),
    }
}

/// What a verdict over every holder must say.
pub(crate) enum Want<'a> {
    /// An unforked principal: Active at the owner's tip, no evidence of any
    /// kind (so a peer's key rollover or restore is not mistaken for one).
    Active(&'a Tip),
    /// Two tied heads: Error, both branches live, the fork evidenced.
    Forked([&'a Tip; 2]),
    /// A resolved fork: Active at the owner's tip, the resolving key named,
    /// the abandoned branch kept.
    Resolved { tip: &'a Tip, abandoned: &'a Tip },
}

fn verdict_diff(v: &Verdict, pr: &Principal, want: &Want<'_>) -> Option<String> {
    let sorted = |ts: &[Tip]| {
        let mut ts = ts.to_vec();
        ts.sort();
        ts
    };
    let fork = Evidence::PrincipalFork(pr.clone());
    match want {
        Want::Active(tip) => {
            if v.standing != Standing::Active || &v.tip != *tip || v.branches != [(*tip).clone()] {
                return Some(format!(
                    "{:?} at {:?} over {:?}, owner is Active at {tip:?}",
                    v.standing, v.tip, v.branches
                ));
            }
            (!v.evidence.is_empty()).then(|| format!("evidence {:?} for a principal never forked", v.evidence))
        },
        Want::Forked([a, b]) => {
            let heads = sorted(&[(*a).clone(), (*b).clone()]);
            if v.standing != Standing::Error || sorted(&v.branches) != heads {
                return Some(format!(
                    "{:?} over {:?}, expected Error over the two heads {heads:?}",
                    v.standing, v.branches
                ));
            }
            (!v.evidence.contains(&fork)).then(|| format!("no fork evidence: {:?}", v.evidence))
        },
        Want::Resolved { tip, abandoned } => {
            if v.standing != Standing::Active || &v.tip != *tip {
                return Some(format!("{:?} at {:?}, expected Active at {tip:?}", v.standing, v.tip));
            }
            if !v.abandoned.contains(abandoned) {
                return Some(format!("abandoned {:?} lacks {abandoned:?}", v.abandoned));
            }
            v.resolved_by.is_none().then(|| "no resolving key named".to_owned())
        },
    }
}

/// A fresh observer's verdict over every holder of `ps`: the oracle's field
/// by field check of the verdict against what the peers themselves hold and
/// serve (offline-verified evidence included), then the expectation `want`
/// from the owner's own chain.
pub(crate) async fn verdict_check(
    h: &Harness,
    ps: &PState<'_>,
    observer: &str,
    invariant: &'static str,
    want: Want<'_>,
    what: &str,
) -> Result<Verdict, Failure> {
    let obs = h.client(observer);
    let holders: Vec<&str> = ps.holders.iter().map(String::as_str).collect();
    act(obs.trust_genesis(&ps.pr, &holders).await, what)?;
    let v = act(obs.verdict(&ps.pr, &holders).await, what)?;
    // The oracle asserts; a failed assertion is this invariant's red.
    // The verdict's anchor is the genesis key, which is the principal's PG
    // only for one opened by a single key.
    let anchor = act(h.genesis_tmb(&ps.pr), what)?;
    //
    // The oracle reads every retained rival tip as live unless a peer's
    // chain continues past it, so a principal whose earlier fork was
    // resolved (its abandoned tip is no one's ancestor) is judged by the
    // expectation below alone: a limit of `Harness::check_verdict`, seen at
    // the large size, where the verdict named the two live branches and the
    // oracle counted a third.
    let checked = if ps.abandoned.is_some() {
        Ok(())
    } else {
        AssertUnwindSafe(h.check_verdict(&v, &ps.pr, &Expect::new(&holders, &anchor)))
            .catch_unwind()
            .await
    };
    if let Err(panic) = checked {
        let msg = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "a non-string panic".into());
        return Err(fail(invariant, format!("{what}: the verdict failed the oracle: {msg}")));
    }
    match verdict_diff(&v, &ps.pr, &want) {
        None => Ok(v),
        Some(why) => Err(fail(invariant, format!("{what}: {why}"))),
    }
}

/// N9: the witness's view of each principal its authority holds equals the
/// owner's chain, which the authority was just shown to hold (SPEC 2.2.16:
/// a witness keeps a copy of another principal's state).
async fn n9(
    h: &Harness,
    size: &Size,
    witness: &str,
    authority: &str,
    expected: &[Expected<'_>],
) -> Result<(), Failure> {
    for e in expected.iter().filter(|e| e.ps.holders.iter().any(|x| x == authority)) {
        until(size, &format!("witness `{witness}` to equal `{authority}` on principal {}", e.p), || async {
            let got = h.peer_view(witness, &e.ps.pr).await;
            tip_diff(&e.view, got.as_ref()).into_iter().collect()
        })
        .await
        .map_err(|m| fail("N9", m))?;
    }
    Ok(())
}

/// The checks deferred to this barrier, once each: sampled verdicts (N7),
/// sampled sign-ins (N8), and `verify-all` on a stopped peer (N3).
async fn sampled(b: &Barrier<'_, '_>) -> Result<(), Failure> {
    let mut done: Vec<&Op> = Vec::new();
    for op in b.marks {
        if done.contains(&op) {
            continue;
        }
        done.push(op);
        let what = format!("{op} (barrier {})", b.index);
        match op {
            Op::Verdict { p } => {
                let Some(ps) = b.states[*p].as_ref() else { continue };
                // A principal that was forked keeps its evidence for good.
                let want = match &ps.abandoned {
                    Some(abandoned) => Want::Resolved { tip: &ps.tip, abandoned },
                    None => Want::Active(&ps.tip),
                };
                verdict_check(b.h, ps, &format!("obs-b{}p{p}", b.index), "N7", want, &what).await?;
            },
            Op::SignIn { p } => {
                let Some(ps) = b.states[*p].as_ref() else { continue };
                let rp = act(b.h.start_relying_party().await, &what)?;
                let c = &ps.clients[0];
                let skip = b.size.forgive_forked_sign_in && ps.abandoned.is_some();
                match if skip { Ok(None) } else { c.sign_in(&rp).await.map(Some) } {
                    Ok(_) => {},
                    Err(ActionError::Refused(r)) => {
                        return Err(fail(
                            "N8",
                            format!("{what}: an active key was refused sign-in: {:?}: {}", r.kind, r.detail),
                        ));
                    },
                    Err(e) => return Err(fail("DRIVER", format!("{what}: {e}"))),
                }
                for (thief, key) in &ps.thieves {
                    n8_refused(b.h, thief, &ps.pr, Some(key), "with a revoked, deleted key", &what).await?;
                }
            },
            Op::VerifyAll { peer } => n3(b, &b.names[*peer], &what).await?,
            other => return Err(fail("DRIVER", format!("`{other}` is not a deferred check"))),
        }
    }
    Ok(())
}

/// Everything `peer` serves for the principals it holds, with the
/// timestamps and signatures that legitimately vary left out.
async fn snapshot(h: &Harness, peer: &str, states: &[Option<PState<'_>>]) -> Result<Vec<(String, Value)>, String> {
    let mut out = Vec::new();
    for (p, ps) in states.iter().enumerate().filter_map(|(p, s)| Some((p, s.as_ref()?))) {
        if !ps.holders.iter().any(|x| x == peer) {
            continue;
        }
        let tip = h.peer_view(peer, &ps.pr).await;
        out.push((
            format!("principal {p} tip"),
            tip.map_or(Value::Null, |t| {
                serde_json::json!([t.heads.iter().map(|h| &h.0).collect::<Vec<_>>(), t.height, t.pr, t.ar])
            }),
        ));
        for path in ["/branches", "/evidence"] {
            out.push((format!("principal {p} {path}"), payload(h, peer, path, &[("pr", &ps.pr.0)]).await?));
        }
        if !ps.revoked.is_empty() {
            let tmbs = ps.revoked.iter().map(|k| k.key.0.as_str()).collect::<Vec<_>>().join(",");
            out.push((format!("principal {p} /revoked"), payload(h, peer, "/revoked", &[("tmbs", &tmbs)]).await?));
        }
    }
    Ok(out)
}

/// N3: stop a quiet peer, replay everything it stores with `verify-all`,
/// start it again: the command reports no failure and the peer serves the
/// same tip, branches, evidence and revoked set for every principal it
/// holds (the blob store is the record; the rebuilt index must agree with
/// the one it replaces, root I1).
async fn n3(b: &Barrier<'_, '_>, peer: &str, what: &str) -> Result<(), Failure> {
    let before = snapshot(b.h, peer, b.states).await.map_err(|e| fail("DRIVER", format!("{what}: {e}")))?;
    if let Err(e) = b.h.verify_all_peer(peer).await {
        return Err(fail("N3", format!("{what}: verify-all on `{peer}` failed: {e}")));
    }
    let after = snapshot(b.h, peer, b.states).await.map_err(|e| fail("N3", format!("{what}: `{peer}` after verify-all: {e}")))?;
    if before != after {
        let (label, was, now) = before
            .iter()
            .zip(&after)
            .find(|(x, y)| x != y)
            .map(|(x, y)| (x.0.clone(), x.1.clone(), y.1.clone()))
            .unwrap_or_else(|| ("the set of served items".into(), Value::Null, Value::Null));
        return Err(fail(
            "N3",
            format!("{what}: `{peer}` serves a different {label} after verify-all\n  before: {was}\n  after:  {now}"),
        ));
    }
    Ok(())
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
/// the point where this is called. Rounds are counted from each server's
/// `/metrics`, idle rounds included; a round already running at the
/// snapshot does not count, so `QUIET_ROUNDS + 1` more completions contain
/// that many rounds that began after it.
async fn wait_quiet_rounds(h: &Harness, size: &Size, names: &[String]) -> Result<(), Failure> {
    let began = Instant::now();
    let mut need = Vec::new();
    for name in names {
        let before = h
            .gossip_rounds(name)
            .await
            .map_err(|e| fail("N1", format!("reading {name}'s gossip rounds: {e}")))?;
        need.push((name, before + QUIET_ROUNDS as u64 + 1));
    }
    loop {
        let mut behind: Vec<&str> = Vec::new();
        for (name, until) in &need {
            // A failed scrape is a round not yet seen, not a verdict.
            if !matches!(h.gossip_rounds(name).await, Ok(r) if r >= *until) {
                behind.push(name.as_str());
            }
        }
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
