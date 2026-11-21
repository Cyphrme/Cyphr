//! The adversity episodes: a fork by two devices, a theft, and a restore.
//!
//! Each is a fence in the op log, built so its outcome does not depend on
//! gossip timing. A fork is made, not raced: the home peer is cut off from
//! every other peer, the two sides each take their writes, and only then do
//! the links heal. What the peers hold in between is read from the peers
//! (their heads, their served and offline-verified evidence), never
//! predicted; the model supplies only the owner's chain.
//!
//! The two flows are the ones the hand-written scenarios pin: two
//! unextended branches settled by the owner's next commit (S03), and a
//! stolen key's branch settled by the owner's naked revoke and `key/delete`
//! (S04). A fork whose branches are both extended has no exit in the
//! chain, so it ends a run and no episode builds one.

use super::Size;
use super::check::{
    Want, evidence_count, heal_everything, n5_refused, n8_refused, tip_diff, until, verdict_check,
};
use super::run::{Failure, PState, act, fail, refresh};
use crate::actions::{Backup, Client, KeyRef, PeerTip, PushOutcome, Tip};
use crate::harness::Harness;

/// Accept a push's tip or name the refusal as the invariant's failure.
fn accepted(r: PushOutcome, invariant: &'static str, what: &str) -> Result<Tip, Failure> {
    match r {
        PushOutcome::Accepted(t) => Ok(t),
        PushOutcome::Refused(r) => Err(fail(
            invariant,
            format!("{what}: the push was refused {:?}: {}", r.kind, r.detail),
        )),
    }
}

/// Cut the principal's home off from every other peer, after healing
/// whatever the generator had cut, so the two sides cannot meet.
async fn isolate_home(h: &Harness, names: &[String], home: &str) -> Result<(), Failure> {
    heal_everything(h, names).await?;
    for other in names.iter().filter(|n| n.as_str() != home) {
        h.proxy.partition(home, other);
    }
    Ok(())
}

/// Wait until every holder reports the two tied heads and serves evidence
/// of the fork: N4 before resolution.
async fn both_heads_everywhere(
    h: &Harness,
    size: &Size,
    ps: &PState<'_>,
    heads: [&Tip; 2],
    what: &str,
) -> Result<(), Failure> {
    let mut want = vec![heads[0].clone(), heads[1].clone()];
    want.sort();
    until(
        size,
        "every holder to report both heads with evidence",
        || async {
            let mut lines = Vec::new();
            for holder in &ps.holders {
                let got = h.peer_view(holder, &ps.pr).await;
                let mut have: Vec<Tip> = got.as_ref().map(|t| t.heads.clone()).unwrap_or_default();
                have.sort();
                if have != want {
                    lines.push(format!("`{holder}` heads {have:?}, expected {want:?}"));
                } else if evidence_count(h, holder, &ps.pr).await.unwrap_or(0) == 0 {
                    lines.push(format!("`{holder}` serves no fork evidence yet"));
                }
            }
            lines
        },
    )
    .await
    .map_err(|m| fail("N4", format!("{what}: {m}")))?;
    Ok(())
}

/// Wait until every holder is Active on the owner's resolution tip, then
/// check every holder still serves the abandoned branch: N4 after
/// resolution.
async fn resolved_everywhere(
    h: &Harness,
    size: &Size,
    ps: &PState<'_>,
    c0: &Client<'_>,
    what: &str,
) -> Result<(), Failure> {
    let view = act(c0.local_view(&ps.pr).await, what)?;
    until(
        size,
        "every holder to be Active on the resolution",
        || async {
            let mut lines = Vec::new();
            for holder in &ps.holders {
                let got: Option<PeerTip> = h.peer_view(holder, &ps.pr).await;
                if let Some(why) = tip_diff(&view, got.as_ref()) {
                    lines.push(format!("`{holder}`: {why}"));
                }
            }
            lines
        },
    )
    .await
    .map_err(|m| fail("N4", format!("{what}: {m}")))?;
    for holder in &ps.holders {
        let n = evidence_count(h, holder, &ps.pr)
            .await
            .map_err(|e| fail("N4", format!("{what}: {e}")))?;
        if n == 0 {
            return Err(fail(
                "N4",
                format!("{what}: `{holder}` no longer serves the abandoned branch (SPEC 15.8)"),
            ));
        }
    }
    Ok(())
}

/// Two devices fork the principal across a cut; the first resolves it.
pub(crate) async fn fork<'h>(
    h: &'h Harness,
    size: &Size,
    names: &[String],
    ps: &mut PState<'h>,
    idx: usize,
    what: &str,
) -> Result<(), Failure> {
    refresh(ps, 0, what).await?;
    refresh(ps, 1, what).await?;
    isolate_home(h, names, &ps.home).await?;
    let (home, other) = (ps.home.clone(), ps.holders[1].clone());
    let (c0, c1) = (&ps.clients[0], &ps.clients[1]);
    act(c0.commit_data(&ps.pr, &format!("fa{idx}")).await, what)?;
    let t0 = accepted(
        act(c0.push(&ps.pr, &[home.as_str()]).await, what)?,
        "N2",
        what,
    )?;
    // The verdict names an abandoned branch by the commit that took the
    // forked position (S03): here its only one.
    let abandoned = act(c1.commit_data(&ps.pr, &format!("fb{idx}")).await, what)?;
    let t1 = accepted(
        act(c1.push(&ps.pr, &[other.as_str()]).await, what)?,
        "N2",
        what,
    )?;
    heal_everything(h, names).await?;

    both_heads_everywhere(h, size, ps, [&t0, &t1], what).await?;
    verdict_check(
        h,
        ps,
        &format!("obs-f{idx}a"),
        "N4",
        Want::Forked([&t0, &t1]),
        what,
    )
    .await?;
    n8_refused(h, c0, &ps.pr, None, "for a principal in Error", what).await?;

    // SPEC 15.8 item 1: one ordinary commit on the first device's head,
    // the only extended branch.
    let resolved = c0
        .resolve_fork(&ps.pr, &t0)
        .await
        .map_err(|e| fail("N4", format!("{what}: the owner could not resolve: {e}")))?;
    resolved_everywhere(h, size, ps, c0, what).await?;
    verdict_check(
        h,
        ps,
        &format!("obs-f{idx}b"),
        "N4",
        Want::Resolved {
            tip: &resolved,
            abandoned: &abandoned,
        },
        what,
    )
    .await?;

    settle(ps, resolved, abandoned);
    Ok(())
}

/// A thief with the second device's key forks the principal; the owner
/// revokes the key, deletes it and resolves.
pub(crate) async fn theft<'h>(
    h: &'h Harness,
    size: &Size,
    names: &[String],
    ps: &mut PState<'h>,
    idx: usize,
    what: &str,
) -> Result<(), Failure> {
    let key: KeyRef = ps.dev_keys[1].clone().ok_or_else(|| {
        fail(
            "DRIVER",
            format!("{what}: the second device's key is unknown"),
        )
    })?;
    let began = std::time::Instant::now();
    let lap = |phase: &str| eprintln!("  {what}: {phase} at {:.1?}", began.elapsed());
    refresh(ps, 0, what).await?;
    refresh(ps, 1, what).await?;
    isolate_home(h, names, &ps.home).await?;
    let (home, other) = (ps.home.clone(), ps.holders[1].clone());
    let thief = h.client(&format!("thief{idx}"));
    act(thief.steal_key(&ps.clients[1], &key).await, what)?;
    let c0 = &ps.clients[0];
    act(c0.commit_data(&ps.pr, &format!("ta{idx}")).await, what)?;
    act(thief.commit_data(&ps.pr, &format!("tb{idx}")).await, what)?;
    let t0 = accepted(
        act(c0.push(&ps.pr, &[home.as_str()]).await, what)?,
        "N2",
        what,
    )?;
    let t1 = accepted(
        act(thief.push(&ps.pr, &[other.as_str()]).await, what)?,
        "N2",
        what,
    )?;
    heal_everything(h, names).await?;
    lap("forked");

    both_heads_everywhere(h, size, ps, [&t0, &t1], what).await?;
    lap("both heads everywhere");
    verdict_check(
        h,
        ps,
        &format!("obs-t{idx}a"),
        "N4",
        Want::Forked([&t0, &t1]),
        what,
    )
    .await?;
    lap("verdict in Error");
    n8_refused(h, c0, &ps.pr, None, "for a principal in Error", what).await?;
    lap("sign-in refused");

    // The revoke is self-signed (SPEC 6.4): the device that holds the key
    // signs it. The owner's `key/delete` commit on its own branch resolves
    // the fork (SPEC 15.8); a commit without one is refused.
    act(ps.clients[1].naked_revoke(&ps.pr, &key).await, what)?;
    act(ps.clients[0].remove_key(&ps.pr, &key).await, what)?;
    match act(ps.clients[0].push(&ps.pr, &[home.as_str()]).await, what)? {
        PushOutcome::Accepted(_) => {},
        PushOutcome::Refused(r) => {
            return Err(fail(
                "N4",
                format!(
                    "{what}: the owner's resolution was refused {:?}: {}",
                    r.kind, r.detail
                ),
            ));
        },
    }
    lap("resolution pushed");
    resolved_everywhere(h, size, ps, &ps.clients[0], what).await?;
    lap("resolved everywhere");
    let view = act(ps.clients[0].local_view(&ps.pr).await, what)?;
    for holder in &ps.holders {
        n5_refused(h, ps, &thief, &key, holder, what).await?;
    }
    lap("n5 probes");
    n8_refused(
        h,
        &thief,
        &ps.pr,
        Some(&key),
        "with a revoked, deleted key",
        what,
    )
    .await?;

    ps.revoked.push(key.clone());
    ps.thieves.push((thief, key));
    let tip = view.tip;
    settle(ps, tip, t1);
    Ok(())
}

/// The owner's first device is all that is left of the principal's devices:
/// the second holds the abandoned branch or a deleted key.
fn settle(ps: &mut PState<'_>, resolved: Tip, abandoned: Tip) {
    ps.tip = resolved;
    ps.abandoned = Some(abandoned);
    ps.pusher = 0;
    ps.clients.truncate(1);
    ps.dev_keys.truncate(1);
    ps.fresh = vec![true];
    ps.backups.retain(|(_, d)| *d == 0);
}

/// Restore a peer from its backup, then have each owner re-push what the
/// peer holds. Gossip does not discover a principal a peer never had, so
/// those the restore dropped come back only from their owner (S06).
pub(crate) async fn restore<'h>(
    h: &'h Harness,
    names: &[String],
    states: &mut [Option<PState<'h>>],
    peer: usize,
    backup: &Backup,
    what: &str,
) -> Result<(), Failure> {
    let name = names[peer].as_str();
    act(h.restore_peer(name, backup).await, what)?;
    for (p, ps) in states.iter_mut().enumerate() {
        let Some(ps) = ps.as_mut() else { continue };
        if !ps.holders.iter().any(|x| x == name) {
            continue;
        }
        let owner = &ps.clients[ps.pusher];
        let w = format!("{what}: re-push of principal {p}");
        accepted(act(owner.push(&ps.pr, &[name]).await, &w)?, "N2", &w)?;
    }
    Ok(())
}
