//! The driver: runs an op log against real peers and real CLIs.
//!
//! Principal-scoped ops run in order within a principal and up to
//! `Size::concurrency` principals at once; every other op (link faults,
//! stop/start, the episodes, barrier) is a fence that waits for the ops
//! before it. Each
//! honest op is `refresh if another device wrote, act, push to the home
//! peer`; an op the servers refuse for any reason but Stale is an N2
//! failure, and a Stale refusal is answered by the rebase the protocol
//! prescribes.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt;

use super::model::Model;
use super::plan::Op;
use super::{Size, check, episode};
use crate::actions::{
    ActionError, ActionResult, Backup, Client, KeyRef, Principal, PushOutcome, RefusalKind, Tip,
};
use crate::faults::{FaultKind, Link};
use crate::harness::Harness;
use crate::peer::Limits;

/// A violated invariant, or a run that could not be carried out.
#[derive(Debug)]
pub struct Failure {
    /// `N1` to `N9`, `MODEL` (the model and the owner's chain
    /// disagree: a defect in the test, not the servers) or `DRIVER` (a step
    /// failed outside every protocol refusal).
    pub invariant: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.invariant, self.detail)
    }
}

pub(crate) fn fail(invariant: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        invariant,
        detail: detail.into(),
    }
}

/// What a finished run measured.
#[derive(Debug, Default)]
pub struct Outcome {
    pub ops: usize,
    pub stale_retries: usize,
    pub concurrent_ops: usize,
    /// Fork and theft episodes carried out.
    pub episodes: usize,
    /// How long each barrier waited for the network to agree.
    pub convergence: Vec<Duration>,
    pub wall: Duration,
}

/// A naked revoke the owner made.
pub(crate) struct Revoked {
    pub key: KeyRef,
    /// Peers restored from a backup after the revoke. A restored peer
    /// never relearns a revoke of a key the chain has since deleted
    /// (reproduced by `tests/netsim_findings.rs`), so N5 does not ask them
    /// to list it. Drop this field when that test passes.
    pub forgotten_by: Vec<String>,
}

/// One principal as the driver knows it: its real identity and devices.
pub(crate) struct PState<'h> {
    pub pr: Principal,
    pub home: String,
    pub holders: Vec<String>,
    pub clients: Vec<Client<'h>>,
    /// The owner's last accepted tip: the expected tip at every holder.
    pub tip: Tip,
    /// Which devices hold the home's latest chain.
    pub fresh: Vec<bool>,
    /// The device that last pushed, whose store is the owner's chain.
    pub pusher: usize,
    /// Backup keys and the device holding each, oldest first.
    pub backups: VecDeque<(KeyRef, usize)>,
    /// The key each device signs with, when the driver was told it (the
    /// genesis device's is not).
    pub dev_keys: Vec<Option<KeyRef>>,
    /// Keys the owner revoked: every holder must list each, bar those that
    /// were restored from a backup older than the revoke (see
    /// [`Revoked::forgotten_by`]).
    pub revoked: Vec<Revoked>,
    /// Clients that hold a revoked key, which must open nothing.
    pub thieves: Vec<(Client<'h>, KeyRef)>,
    /// The tip of the latest branch an episode abandoned: the evidence of
    /// that fork is kept for good.
    pub abandoned: Option<Tip>,
    /// Devices ever made, so a new one never reuses a name.
    spawned: usize,
}

type Slot<'h> = Option<PState<'h>>;

/// Turn an action result into the driver's verdicts: a protocol refusal of
/// an honest op is N2, anything else that failed is the driver's.
pub(crate) fn act<T>(r: ActionResult<T>, what: &str) -> Result<T, Failure> {
    r.map_err(|e| match e {
        ActionError::Refused(r) => fail(
            "N2",
            format!(
                "{what}: an honest op was refused {:?}: {}",
                r.kind, r.detail
            ),
        ),
        // The CLI has no refusal kind for these two, so they arrive as an
        // unclassified failure carrying the status; both are server
        // answers an honest op must never draw (N2, N6).
        ActionError::Failed(m) if m.contains("status 429") => {
            fail("N2", format!("{what}: an honest op was rate limited: {m}"))
        },
        ActionError::Failed(m) if m.contains("status 5") => {
            fail("N6", format!("{what}: a server answered 5xx: {m}"))
        },
        ActionError::Failed(m) => fail("DRIVER", format!("{what}: {m}")),
    })
}

/// Push to the home peer; a Stale refusal is answered by rebase and a second
/// push, which is the only retry N2 allows.
async fn push_honest(
    ps: &mut PState<'_>,
    d: usize,
    stale: &AtomicUsize,
    what: &str,
) -> Result<(), Failure> {
    let c = &ps.clients[d];
    let home = [ps.home.as_str()];
    let mut outcome = act(c.push(&ps.pr, &home).await, what)?;
    let mut rebased = false;
    loop {
        match outcome {
            PushOutcome::Accepted(tip) => {
                ps.tip = tip;
                ps.pusher = d;
                ps.fresh = vec![false; ps.clients.len()];
                ps.fresh[d] = true;
                return Ok(());
            },
            PushOutcome::Refused(r) if r.kind == RefusalKind::Stale && !rebased => {
                rebased = true;
                stale.fetch_add(1, Ordering::Relaxed);
                act(c.rebase(&ps.pr).await, what)?;
                outcome = act(c.push(&ps.pr, &home).await, what)?;
            },
            PushOutcome::Refused(r) => {
                return Err(fail(
                    "N2",
                    format!(
                        "{what}: push refused {:?} (after a rebase: {rebased}): {}",
                        r.kind, r.detail
                    ),
                ));
            },
        }
    }
}

/// Bring device `d` up to the home's chain if another device wrote since.
pub(crate) async fn refresh(ps: &mut PState<'_>, d: usize, what: &str) -> Result<(), Failure> {
    if !ps.fresh[d] {
        act(ps.clients[d].sync(&ps.pr, &[ps.home.as_str()]).await, what)?;
        ps.fresh[d] = true;
    }
    Ok(())
}

async fn exec_op<'h>(
    h: &'h Harness,
    names: &[String],
    slot: &mut Slot<'h>,
    idx: usize,
    op: &Op,
    stale: &AtomicUsize,
) -> Result<(), Failure> {
    let what = op.to_string();
    // Every action carries its op's index: two identical actions by one key
    // in one second are one coz, which a principal may include only once
    // (SPEC 7.6), so an honest client does not send them.
    let msg = |tag: &str| format!("{tag}{idx}");
    if let Op::Create {
        p,
        multikey,
        holders,
    } = op
    {
        let c = h.client(&format!("c{p}d0"));
        let pr = act(
            if *multikey {
                c.create_multikey_principal().await
            } else {
                c.create_principal().await
            },
            &what,
        )?;
        let holders: Vec<String> = holders.iter().map(|i| names[*i].clone()).collect();
        let to: Vec<&str> = holders.iter().map(String::as_str).collect();
        let tip = match act(c.push(&pr, &to).await, &what)? {
            PushOutcome::Accepted(t) => t,
            PushOutcome::Refused(r) => {
                return Err(fail(
                    "N2",
                    format!("{what}: publishing was refused {:?}: {}", r.kind, r.detail),
                ));
            },
        };
        *slot = Some(PState {
            pr,
            home: holders[0].clone(),
            holders,
            clients: vec![c],
            tip,
            fresh: vec![true],
            pusher: 0,
            backups: VecDeque::new(),
            dev_keys: vec![None],
            revoked: Vec::new(),
            thieves: Vec::new(),
            abandoned: None,
            spawned: 1,
        });
        return Ok(());
    }
    let ps = slot
        .as_mut()
        .ok_or_else(|| fail("DRIVER", format!("{what}: principal does not exist yet")))?;
    match op {
        Op::Commit { d, .. } => {
            refresh(ps, *d, &what).await?;
            act(ps.clients[*d].commit_data(&ps.pr, &msg("c")).await, &what)?;
            push_honest(ps, *d, stale, &what).await
        },
        Op::Record { d, .. } => {
            refresh(ps, *d, &what).await?;
            act(ps.clients[*d].record_data(&ps.pr, &msg("r")).await, &what)?;
            push_honest(ps, *d, stale, &what).await
        },
        Op::AddKey { d, .. } => {
            refresh(ps, *d, &what).await?;
            let key = act(ps.clients[*d].add_backup_key(&ps.pr).await, &what)?;
            ps.backups.push_back((key, *d));
            push_honest(ps, *d, stale, &what).await
        },
        Op::Pair { d, .. } => {
            refresh(ps, *d, &what).await?;
            let p = op.principal().expect("pair is a principal op");
            let other = h.client(&format!("c{p}d{}", ps.spawned));
            ps.spawned += 1;
            let key = act(ps.clients[*d].pair_device(&ps.pr, &other).await, &what)?;
            push_honest(ps, *d, stale, &what).await?;
            ps.clients.push(other);
            ps.dev_keys.push(Some(key));
            // The new device imported the chain the pusher just pushed.
            ps.fresh = vec![true; ps.clients.len()];
            Ok(())
        },
        Op::Replace { d, .. } => {
            refresh(ps, *d, &what).await?;
            let key = act(ps.clients[*d].rotate_key(&ps.pr).await, &what)?;
            ps.dev_keys[*d] = Some(key);
            push_honest(ps, *d, stale, &what).await
        },
        Op::DelKey { d, .. } => {
            refresh(ps, *d, &what).await?;
            let (key, _) = ps
                .backups
                .pop_front()
                .ok_or_else(|| fail("DRIVER", format!("{what}: no backup key to delete")))?;
            act(ps.clients[*d].remove_key(&ps.pr, &key).await, &what)?;
            push_honest(ps, *d, stale, &what).await
        },
        Op::NakedRevoke { d, .. } => {
            refresh(ps, *d, &what).await?;
            let (key, holder) = ps
                .backups
                .pop_front()
                .ok_or_else(|| fail("DRIVER", format!("{what}: no backup key to revoke")))?;
            if holder != *d {
                return Err(fail("DRIVER", format!("{what}: device {holder} holds the key")));
            }
            let c = &ps.clients[*d];
            // Sent to the peers this device knows; the others learn of it
            // by gossip (N5 reads every holder at the barrier).
            act(c.naked_revoke(&ps.pr, &key).await, &what)?;
            act(c.remove_key(&ps.pr, &key).await, &what)?;
            push_honest(ps, *d, stale, &what).await?;
            ps.revoked.push(Revoked { key: key.clone(), forgotten_by: Vec::new() });
            let c = &ps.clients[*d];
            check::n5_refused(h, ps, c, &key, &ps.home, &what).await?;
            check::n8_refused(h, c, &ps.pr, Some(&key), "with a revoked, deleted key", &what).await
        },
        Op::Concurrent { .. } => {
            refresh(ps, 0, &what).await?;
            refresh(ps, 1, &what).await?;
            act(ps.clients[0].commit_data(&ps.pr, &msg("a")).await, &what)?;
            push_honest(ps, 0, stale, &what).await?;
            // Device 1 commits from the tip it held before device 0 wrote.
            act(ps.clients[1].commit_data(&ps.pr, &msg("b")).await, &what)?;
            push_honest(ps, 1, stale, &what).await
        },
        other => Err(fail("DRIVER", format!("`{other}` is not a principal op"))),
    }
}

async fn exec_chain<'h>(
    h: &'h Harness,
    names: &[String],
    slot: &mut Slot<'h>,
    ops: Vec<(usize, &Op)>,
    stale: &AtomicUsize,
) -> Result<(), Failure> {
    for (i, op) in ops {
        let t = Instant::now();
        exec_op(h, names, slot, i, op, stale).await?;
        eprintln!("op {i:>4} {op} ({:.1?})", t.elapsed());
    }
    Ok(())
}

async fn exec_global(h: &Harness, names: &[String], op: &Op) -> Result<(), Failure> {
    let link = |a: &usize, b: &usize| Link::new(&names[*a], &names[*b]);
    match op {
        Op::Partition { a, b } => h.proxy.partition(&names[*a], &names[*b]),
        Op::Heal { a, b } => h.proxy.heal(&names[*a], &names[*b]),
        Op::Degrade {
            a,
            b,
            delay_ms,
            drop_pct,
        } => {
            h.proxy.delay(&link(a, b), Duration::from_millis(*delay_ms));
            h.proxy
                .apply(&FaultKind::Drop(link(a, b), f64::from(*drop_pct) / 100.0));
        },
        Op::Calm { a, b } => {
            h.proxy.delay(&link(a, b), Duration::ZERO);
            h.proxy.apply(&FaultKind::Drop(link(a, b), 0.0));
        },
        Op::Stop { peer } => act(h.stop_peer(&names[*peer]).await, &op.to_string())?,
        Op::Start { peer } => act(h.start_peer(&names[*peer]).await, &op.to_string())?,
        other => return Err(fail("DRIVER", format!("`{other}` is not a fence op"))),
    }
    Ok(())
}

/// Run `ops` on `h`, whose peers must be `size.peers` gossiping attestors
/// named `p0..`. Always ends with a barrier, so the final state is checked
/// even for a truncated log.
pub async fn run(h: &Harness, size: &Size, ops: &[Op]) -> Result<Outcome, Failure> {
    let start = Instant::now();
    let names = size.peer_names();
    let mut model = Model::new(size.peers);
    let mut states: Vec<Slot<'_>> = Vec::new();
    let stale = AtomicUsize::new(0);
    let witness = size.witness.then(|| Size::WITNESS);
    let mut marks: Vec<Op> = Vec::new();
    let mut backup: Option<Backup> = None;
    let mut barriers = 0;
    let mut out = Outcome {
        ops: ops.len(),
        ..Outcome::default()
    };
    let mut i = 0;
    while i < ops.len() {
        let mut j = i;
        while j < ops.len() && ops[j].principal().is_some() {
            j += 1;
        }
        if j > i {
            let mut by_p: BTreeMap<usize, Vec<(usize, &Op)>> = BTreeMap::new();
            for (k, op) in ops.iter().enumerate().take(j).skip(i) {
                model
                    .apply(op)
                    .map_err(|e| fail("DRIVER", format!("op {k}: {e}")))?;
                if matches!(op, Op::Concurrent { .. }) {
                    out.concurrent_ops += 1;
                }
                by_p.entry(op.principal().expect("principal op"))
                    .or_default()
                    .push((k, op));
            }
            states.resize_with(model.principals.len(), || None);
            let chains = states
                .iter_mut()
                .enumerate()
                .filter_map(|(p, slot)| by_p.remove(&p).map(|c| (slot, c)))
                .map(|(slot, c)| exec_chain(h, &names, slot, c, &stale));
            let results: Vec<Result<(), Failure>> = futures::stream::iter(chains)
                .buffer_unordered(size.concurrency)
                .collect()
                .await;
            if let Some(f) = results.into_iter().find_map(Result::err) {
                return Err(f);
            }
            i = j;
            continue;
        }
        let op = &ops[i];
        model
            .apply(op)
            .map_err(|e| fail("DRIVER", format!("op {i}: {e}")))?;
        let t = Instant::now();
        let what = format!("op {i} `{op}`");
        let state_of = |states: &mut Vec<Slot<'_>>, p: usize| -> Result<(), Failure> {
            states
                .get(p)
                .and_then(Option::as_ref)
                .map(|_| ())
                .ok_or_else(|| fail("DRIVER", format!("{what}: principal {p} does not exist")))
        };
        match op {
            Op::Barrier => {
                let b = check::Barrier {
                    h,
                    size,
                    model: &model,
                    names: &names,
                    states: &states,
                    witness,
                    marks: &marks,
                    index: barriers,
                };
                out.convergence.push(check::barrier(b).await?);
                marks.clear();
                barriers += 1;
            },
            Op::Verdict { .. } | Op::SignIn { .. } | Op::VerifyAll { .. } => marks.push(op.clone()),
            Op::Fork { p } | Op::Theft { p } => {
                state_of(&mut states, *p)?;
                let ps = states[*p].as_mut().expect("checked above");
                if matches!(op, Op::Fork { .. }) {
                    episode::fork(h, size, &names, ps, i, &what).await?;
                } else {
                    episode::theft(h, size, &names, ps, i, &what).await?;
                }
                out.episodes += 1;
            },
            Op::Backup { peer } => backup = Some(act(h.backup_peer(&names[*peer]).await, &what)?),
            Op::Restore { peer } => {
                let b = backup
                    .take()
                    .ok_or_else(|| fail("DRIVER", format!("{what}: no backup was taken")))?;
                episode::restore(h, size, &names, &mut states, *peer, &b, &what).await?;
            },
            Op::RollPeerKey { peer } => {
                act(h.rotate_peer_key(&names[*peer]).await, &what)?;
            },
            _ => exec_global(h, &names, op).await?,
        }
        eprintln!("op {i:>4} {op} ({:.1?})", t.elapsed());
        i += 1;
    }
    if !matches!(ops.last(), Some(Op::Barrier)) {
        model.apply(&Op::Barrier).map_err(|e| fail("DRIVER", e))?;
        let b = check::Barrier {
            h,
            size,
            model: &model,
            names: &names,
            states: &states,
            witness,
            marks: &marks,
            index: barriers,
        };
        out.convergence.push(check::barrier(b).await?);
    }
    out.stale_retries = stale.load(Ordering::Relaxed);
    if out.stale_retries < out.concurrent_ops {
        return Err(fail(
            "N2",
            format!(
                "{} concurrent-device ops but only {} Stale refusals: a second device committing \
                 from a superseded tip was not refused",
                out.concurrent_ops, out.stale_retries
            ),
        ));
    }
    out.wall = start.elapsed();
    Ok(out)
}

/// The network a run needs: `size.peers` gossiping attestors named `p0..`
/// at the servers' default limits, and the witness the size asks for.
pub async fn start(size: &Size, seed: u64) -> Result<Harness, String> {
    let names = size.peer_names();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let h = Harness::start_gossiping_seeded(&names, 1, Limits::default(), seed)
        .await
        .map_err(|e| format!("starting the peers: {e}"))?;
    if size.witness {
        h.start_witness(Size::WITNESS, "p0")
            .await
            .map_err(|e| format!("starting the witness: {e}"))?;
    }
    Ok(h)
}

/// The op log for a run: `CYPHR_NETSIM_REPLAY=<file>` replays a recorded
/// log; otherwise the generator's, cut to `CYPHR_NETSIM_OPS=<n>` ops when
/// set (the first `n` ops are the same for every `n`, so bisecting on `n`
/// finds the shortest failing prefix).
pub fn plan_from_env(seed: u64, size: &Size) -> Result<Vec<Op>, String> {
    let mut ops = match std::env::var("CYPHR_NETSIM_REPLAY") {
        Ok(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("reading CYPHR_NETSIM_REPLAY `{path}`: {e}"))?;
            super::plan::parse(&text)?
        },
        Err(_) => super::plan::generate(seed, size),
    };
    if let Ok(n) = std::env::var("CYPHR_NETSIM_OPS") {
        let n: usize = n
            .parse()
            .map_err(|e| format!("CYPHR_NETSIM_OPS `{n}`: {e}"))?;
        ops.truncate(n);
    }
    Ok(ops)
}
