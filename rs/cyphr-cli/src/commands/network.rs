//! Network commands: `push`, `fetch` and `resync`.
//!
//! Peers are untrusted: every commit a peer serves is re-verified by the
//! local engine before it is stored, and `verify` reports what the local, never that the view is
//! current.

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr::state::TaggedDigest;
use cyphr_client::TipAnswer;
use cyphr_storage::engine::bare_digest;
use serde_json::{Value, json};

use super::common::{
    RawCommit, block_on, current_timestamp, get_principal_id, load_principal_from_engine,
    local_genesis, open_store, parse_principal_genesis, parse_store, raw_chain, store_path,
    submit_history,
};
use crate::keystore::KeyBackend;
use crate::net::{Peer, PeerError, PeerHistory};
use crate::{Cli, Error, OutputFormat};

fn emit(cli: &Cli, value: &Value, table: impl FnOnce()) -> crate::Result<()> {
    match cli.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Table => table(),
    }
    Ok(())
}

/// The id the wire and the engine both accept: the bare genesis digest.
fn wire_id(identity: &str) -> crate::Result<String> {
    let pg = parse_principal_genesis(identity)?;
    Ok(bare_digest(&get_principal_id(&pg)?).to_owned())
}

/// The position in `local` of the commit the peer's answer says it holds:
/// its tip, or while it is in Error (SPEC 15.5) the highest of its
/// heads that `local` holds. A commit extending a head resolves the fork
/// while neither branch is extended (SPEC 15.8), so one such head is enough
/// to push from; once both are, the peer refuses it as Errored.
fn held_position(tip: &TipAnswer, local: &[RawCommit]) -> Option<usize> {
    let at = |id: &TaggedDigest| local.iter().position(|c| c.commit_id == id.to_string());
    match tip {
        TipAnswer::Active { commit_id } => at(commit_id),
        TipAnswer::Error { heads, .. } => heads.iter().filter_map(|h| at(&h.commit_id)).max(),
    }
}

/// The peer's answer in words, for a refusal.
fn describe(tip: &TipAnswer) -> String {
    match tip {
        TipAnswer::Active { commit_id } => format!("peer tip {commit_id}"),
        TipAnswer::Error { heads, .. } => format!(
            "peer is in Error with heads {}; none of them",
            heads
                .iter()
                .map(|h| h.commit_id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The commit ids of `theirs`, in the algorithm the local ids use. A bundle
/// that does not decode is named `?`, since this only describes a refusal.
fn remote_ids(theirs: &[WireBundle], local: &[RawCommit]) -> Vec<String> {
    let alg = local
        .first()
        .and_then(|c| c.commit_id.parse::<TaggedDigest>().ok())
        .map(|id| id.alg());
    theirs
        .iter()
        .map(|b| {
            alg.and_then(|alg| b.decode().ok()?.commit_id(alg))
                .map_or_else(|| "?".to_owned(), |c| c.to_string())
        })
        .collect()
}

/// Where the local history and the peer's part, and what each holds after
/// it, for the warning a divergence is refused with.
fn divergence_report(local: &[RawCommit], theirs: &[WireBundle], parts: usize) -> String {
    let after = |ids: Vec<String>| ids[parts.min(ids.len())..].join(", ");
    let parting = match parts {
        0 => "before the first commit".to_owned(),
        n => format!("after commit {n} ({})", local[n - 1].commit_id),
    };
    format!(
        "the histories part {parting}; local commits after it: [{}]; peer commits after it: [{}]",
        after(local.iter().map(|c| c.commit_id.clone()).collect()),
        after(remote_ids(theirs, local)),
    )
}

/// `cyphr push`: send the commits the peer lacks, each preceded by the data
/// actions recorded before it (a `ds/create` includes exactly those, SPEC
/// 4.8.2), then the actions recorded after the last commit.
///
/// A peer cannot say which trailing actions it already holds: `GET /tip`
/// carries no data root, and a recorded action moves DR, and so PR, only
/// when a `ds/create` includes it (SPEC 4.8.2), so no tip field changes
/// with one. They are sent again on every push, one request per action; a
/// replayed action is a no-op (SPEC 7.6) and the peer stores it once
/// (content-addressed manifests). Batching them waits on the peer reporting
/// what it holds, which would remove the resend and with it the question.
pub fn push(cli: &Cli, identity: &str, peer_url: &str, assert_local: bool) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = super::common::open_backend(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
    // Loaded ahead of the async block: loading drives its own runtime.
    let principal = load_principal_from_engine(&store, &keystore, identity)?;

    let pushed = block_on(async {
        let local = raw_chain(&store, &principal_id).await?;
        if local.is_empty() {
            return Err(Error::EmptyHistory(identity.to_owned()));
        }
        // What the peer holds decides what to send; a tip the local
        // history does not contain means the peer is ahead of, or on a
        // different branch from, this sender: refuse, never overwrite.
        // A tip the local history does not contain is a peer on another
        // branch (a thief's line, say): the sender's own commits are a fork
        // there, and a fork is sent, never refused here, so the principal
        // can answer it. The peer keeps it as a rival, refuses it by its
        // caps, or reads Error; none of that is for this sender to judge.
        let mut forking: Option<String> = None;
        let mut in_error = false;
        let start = match peer.tip(&wire).await? {
            None => 0,
            Some(tip) => match held_position(&tip, &local) {
                Some(i) => i + 1,
                None => {
                    // Over the peer's tip: where the histories part decides
                    // what is sent. Local commits past the parting point
                    // are a fork against the peer, which is the user's
                    // choice to make: refused unless `--assert-local`. A
                    // lone commit beyond it is a stale view and moves the
                    // peer to Error for nothing the sender can finish, so
                    // it is refused even then; two or more extend a branch,
                    // which is the answer to a fork, and are sent.
                    let held = describe(&tip);
                    let theirs = peer.chain(&wire).await?.commits;
                    let same = |a: &WireBundle, b: &RawCommit| {
                        b.commit_id
                            .parse::<TaggedDigest>()
                            .ok()
                            .and_then(|id| {
                                a.decode().ok()?.commit_id(id.alg()).map(|c| c.to_string())
                            })
                            .is_some_and(|c| c == b.commit_id)
                    };
                    let parts = theirs
                        .iter()
                        .zip(&local)
                        .take_while(|(a, b)| same(a, b))
                        .count();
                    if local.len() == parts {
                        return Err(PeerError::Stale {
                            peer: peer.url().to_owned(),
                            detail: format!(
                                "the local commits are behind {held}, which they do not contain; \
                                 run `fetch`, then repeat the operation"
                            ),
                        }
                        .into());
                    }
                    if !assert_local {
                        return Err(PeerError::Stale {
                            peer: peer.url().to_owned(),
                            detail: format!(
                                "{held} is not in the local history: {}; `fetch --trust-remote` \
                                 discards the local commits after the parting point, `push \
                                 --assert-local` sends them as a fork",
                                divergence_report(&local, &theirs, parts)
                            ),
                        }
                        .into());
                    }
                    if local.len() - parts < 2 {
                        return Err(PeerError::Stale {
                            peer: peer.url().to_owned(),
                            detail: format!("{held} is not in the local history"),
                        }
                        .into());
                    }
                    forking = Some(held);
                    parts
                },
            },
        };
        // Actions hold no chain position (SPEC 4.8.1): every one is sent
        // after the commits, and the peer ignores those it holds (7.6).
        let actions = principal
            .actions()
            .map(|a| Ok(serde_json::to_vec(a.raw())?))
            .collect::<crate::Result<Vec<_>>>()?;
        let mut sent_actions = 0usize;
        // The commit a fork's previous answer left unplaced: a root the
        // peer's caps refused alone is offered again with its extension.
        let mut parent: Option<&WireBundle> = None;
        for (i, commit) in local.iter().enumerate().skip(start) {
            let offered_pair = parent.is_some();
            match peer
                .push_commit_with_parent(&wire, &commit.bundle, parent.take())
                .await
            {
                Ok(()) => {},
                // A fork over the peer's tip: the commits below the fork are
                // held (COZ_REUSE), and a commit above it is kept as a
                // rival, or refused by the caps or the Error state (409,
                // 423), so the next one goes with this as its `parent`.
                Err(PeerError::Refused { message, .. })
                    if forking.is_some() && message.contains("COZ_REUSE") => {},
                // A pair the peer answers 409 is kept as a fork there.
                Err(PeerError::Stale { .. }) if forking.is_some() && offered_pair => {},
                Err(PeerError::Stale { .. }) if forking.is_some() && i + 1 < local.len() => {
                    parent = Some(&commit.bundle);
                },
                // A lone commit over a tip the peer holds, with nothing after
                // it to offer it with: the peer did not take it.
                Err(PeerError::Stale { .. }) if forking.is_some() => {
                    return Err(PeerError::Stale {
                        peer: peer.url().to_owned(),
                        detail: format!(
                            "{} is not in the local history",
                            forking.as_deref().unwrap_or_default()
                        ),
                    }
                    .into());
                },
                // Over the peer's tip, a peer that turned to Error answers
                // 423 to a root its caps refuse, and the next commit may be
                // the extension that shows the pair. Pushed from a head the
                // peer holds, a 423 is the peer refusing a commit that does
                // not resolve its fork: a failure of this push.
                Err(PeerError::Status { status: 423, .. }) if forking.is_some() => {
                    in_error = true;
                    parent = Some(&commit.bundle);
                },
                // The peer took this commit from another peer (gossip) between
                // the tip read and the send, so it already holds it: the
                // push's goal is met, and the next commits still go.
                Err(PeerError::Refused { message, .. })
                    if message.contains("COZ_REUSE")
                        && peer
                            .tip(&wire)
                            .await?
                            .and_then(|tip| held_position(&tip, &local))
                            .is_some_and(|held| held >= i) => {},
                Err(e) => return Err(e.into()),
            }
        }
        for blob in actions {
            match peer
                .push_commit(&wire, &WireBundle::actions(vec![blob]))
                .await
            {
                Ok(()) => sent_actions += 1,
                // An action is refused while the peer is in Error.
                Err(PeerError::Status { status: 423, .. }) => in_error = true,
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<_, Error>((
            local.len() - start,
            sent_actions,
            local.last().map(|c| c.commit_id.clone()),
            in_error,
        ))
    })??;

    let (count, actions, tip, in_error) = pushed;
    let status = if in_error {
        "peer_in_error"
    } else if count == 0 {
        "up_to_date"
    } else {
        "accepted"
    };
    let out = json!({"identity": identity, "peer": peer_url, "pushed": count,
        "actions": actions, "tip": tip, "status": status});
    emit(cli, &out, || {
        println!("Push {status}: {count} commit(s), {actions} action(s) sent to {peer_url}");
    })
}

/// `cyphr resync`: sign a proof of possession of the local tip and send it
/// to the peer with the local commits the peer may lack (SPEC 15.8 item 2).
///
/// What the peer holds decides where the line starts: after the local
/// commit that is its tip, at its fork point while it is in Error, and
/// otherwise where its chain and the local one part. The peer verifies the
/// line and the proof; whether the proof resolves anything is the fork rule
/// over everything it holds.
pub fn resync(
    cli: &Cli,
    identity: &str,
    peer_url: &str,
    signer: Option<&str>,
) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = super::common::open_backend(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
    // Loaded ahead of the async block: loading drives its own runtime.
    let principal = load_principal_from_engine(&store, &keystore, identity)?;

    // The keys to try: the one named, or each keystore key active at the
    // local tip (a keystore may hold keys whose secret it does not).
    let candidates: Vec<String> = match signer {
        Some(tmb) => vec![tmb.to_owned()],
        None => keystore
            .list()?
            .into_iter()
            .map(|k| k.tmb)
            .filter(|t| {
                Base64UrlUnpadded::decode_vec(t)
                    .is_ok_and(|b| principal.is_key_active(&coz::Thumbprint::from_bytes(b)))
            })
            .collect(),
    };
    let tip = principal.pr_tagged()?;
    let now = current_timestamp();
    let typ = format!("{}/cyphr/resync/create", cli.authority);
    let mut signed = None;
    let mut last_error = Error::Signing("no keystore key is active at the local tip".into());
    for tmb in candidates {
        let attempt = keystore
            .signer(&tmb)
            .map_err(Error::from)
            .and_then(|signer| {
                super::data::sign(&signer, json!({"id": tip, "now": now, "typ": typ}))
            });
        match attempt {
            Ok(proof) => {
                signed = Some((tmb, proof));
                break;
            },
            Err(e) => last_error = e,
        }
    }
    let (tmb, proof) = signed.ok_or(last_error)?;

    let (answer, sent) = block_on(async {
        let local = raw_chain(&store, &principal_id).await?;
        if local.is_empty() {
            return Err(Error::EmptyHistory(identity.to_owned()));
        }
        let start = match peer.tip(&wire).await? {
            None => 0,
            Some(TipAnswer::Error { fork_point, .. }) => {
                usize::try_from(fork_point.height).map_or(local.len(), |h| h.min(local.len()))
            },
            Some(tip) => match held_position(&tip, &local) {
                Some(i) => i + 1,
                None => {
                    let theirs = peer.chain(&wire).await?.commits;
                    let same = |a: &WireBundle, b: &RawCommit| {
                        b.commit_id
                            .parse::<TaggedDigest>()
                            .ok()
                            .and_then(|id| {
                                a.decode().ok()?.commit_id(id.alg()).map(|c| c.to_string())
                            })
                            .is_some_and(|c| c == b.commit_id)
                    };
                    theirs
                        .iter()
                        .zip(&local)
                        .take_while(|(a, b)| same(a, b))
                        .count()
                },
            },
        };
        let line: Vec<WireBundle> = local[start..].iter().map(|c| c.bundle.clone()).collect();
        let answer = peer.post_resync(&wire, &proof.wire(), &line).await?;
        Ok::<_, Error>((answer, line.len()))
    })??;

    let out = json!({"identity": identity, "peer": peer_url, "tip": tip, "signer": tmb,
        "line": sent, "stored": answer["stored"], "promoted": answer["promoted"]});
    emit(cli, &out, || {
        println!("Resync of {tip} sent to {peer_url} ({sent} commit(s) of line)");
    })
}

/// `cyphr fetch`: verify and store the peer's commits the local store lacks.
///
/// Local commits that differ from the peer's at some position are a
/// divergence, and which side to trust is the user's choice: without
/// `trust_remote` it is refused and nothing changes; with it, only the local
/// commits after the parting point are discarded.
pub fn fetch(cli: &Cli, identity: &str, peer_url: &str, trust_remote: bool) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = super::common::open_backend(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let genesis = local_genesis(&keystore, identity)?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;

    let (history, local, diverged) = block_on(async {
        let history = peer.chain(&wire).await?;
        let local = raw_chain(&store, &principal_id).await?;
        // A bundle that does not decode is a bad answer, not a rival branch.
        for bundle in &history.commits {
            if let Err(why) = bundle.decode() {
                return Err(PeerError::Malformed {
                    peer: peer.url().to_owned(),
                    reason: why.to_string(),
                }
                .into());
            }
        }
        let diverged = first_divergence(&local, &history.commits);
        Ok::<_, Error>((history, local, diverged))
    })??;
    if let Some(height) = diverged {
        if !trust_remote {
            return Err(PeerError::Diverged {
                peer: peer.url().to_owned(),
                height,
                report: divergence_report(&local, &history.commits, height),
            }
            .into());
        }
        return adopt_remote(cli, identity, peer_url, store, history, &local, height);
    }

    let PeerHistory {
        commits: theirs,
        actions,
    } = history;
    let fetched = block_on(submit_history(
        &store,
        &principal_id,
        genesis,
        &theirs,
        &actions,
        local.len(),
    ))??;

    let out = json!({"identity": identity, "peer": peer_url, "fetched": fetched});
    emit(cli, &out, || {
        println!("Fetched {fetched} commit(s) from {peer_url}");
    })
}

/// What a signature binds in one coz blob: its `pay` with members sorted at
/// every depth (the form `canonical_coz` stores) and its `sig`. Everything
/// else a blob carries (extra top-level members, a key sidecar's `tag` and
/// `now`) is unsigned and dropped at ingest, so it is no part of the
/// commit's identity. A blob without both parts is its own identity.
fn signed_identity(blob: &[u8]) -> Vec<u8> {
    fn sorted(v: Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut members: Vec<_> = m.into_iter().map(|(k, v)| (k, sorted(v))).collect();
                members.sort_by(|a, b| a.0.cmp(&b.0));
                Value::Object(members.into_iter().collect())
            },
            Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    let signed = serde_json::from_slice::<Value>(blob).ok().and_then(|v| {
        let pay = v.get("pay")?.clone();
        let sig = v.get("sig")?.clone();
        serde_json::to_vec(&json!([sorted(pay), sig])).ok()
    });
    signed.unwrap_or_else(|| blob.to_vec())
}

/// Whether two commits are the same signed commit, whatever their encoding:
/// the same transaction cozies, grouped the same way (the grouping is a hash
/// input of TR, SPEC 3.7.5). The data actions a bundle carries inline are
/// recorded data, not part of the commit, so a holder that kept them apart
/// still holds the same commit.
fn same_commit(a: &WireBundle, b: &WireBundle) -> bool {
    let shape = |w: &WireBundle| w.txs.iter().map(Vec::len).collect::<Vec<_>>();
    shape(a) == shape(b)
        && a.txs
            .iter()
            .flatten()
            .zip(b.txs.iter().flatten())
            .all(|(x, y)| signed_identity(x) == signed_identity(y))
}

/// Index of the first commit at which `a` and `b` both hold one and differ.
fn first_divergence(a: &[RawCommit], b: &[WireBundle]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| !same_commit(&x.bundle, y))
}

/// Suffix of the file that records a store swap in progress.
pub const SWAP_MARKER: &str = ".adopt-swap";

/// Suffix of the scratch store a swap builds beside the real one.
pub const SCRATCH_SUFFIX: &str = ".adopt";

/// Prefix, after the store name, of the backup a swap leaves of the old
/// store.
pub const BACKUP_PREFIX: &str = ".pre-adopt-";

/// `path` with `suffix` appended to its final component.
fn sibling(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

/// Make renames in `path`'s parent directory durable.
fn sync_dir(path: &std::path::Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

/// Removes the scratch store on every exit path that has not handed it
/// over, so a failed adoption never blocks the next one.
struct Scratch(Option<std::path::PathBuf>);

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            // Best effort: nothing useful can be done with a failure here,
            // and the original error is the one worth reporting.
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Adopt the peer's history over local commits that diverge from it, on the
/// user's explicit choice to trust the peer (`fetch --trust-remote`).
///
/// Only the local commits after the parting point go; the shared prefix is
/// kept. The store is append-only (I1), so a diverged local commit cannot be
/// removed in place, and leaving it beside the peer's commit at the same
/// height would make the principal's chain unrecoverable on reindex. The
/// adoption therefore builds a fresh store, copies every other principal
/// into it unchanged, and swaps it in; the old store is kept as a backup.
/// Data actions recorded locally and in no commit survive.
fn adopt_remote(
    cli: &Cli,
    identity: &str,
    peer_url: &str,
    old: super::common::CliStorageEngine,
    history: PeerHistory,
    local: &[RawCommit],
    common: usize,
) -> crate::Result<()> {
    let keystore = super::common::open_backend(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let path = store_path(cli)?.to_owned();
    // A multi-key principal's identity is its PG, not a keystore key, so
    // its genesis comes from the stored history (as for the other
    // principals copied below).
    let genesis = match local_genesis(&keystore, identity)? {
        Some(g) => g,
        None => block_on(old.resolve_genesis(&principal_id, &[]))??,
    };
    let PeerHistory {
        commits: theirs,
        actions: their_actions,
    } = history;
    let discarded: Vec<String> = local[common..]
        .iter()
        .map(|c| c.commit_id.clone())
        .collect();

    // The data actions recorded locally, which a rebuild from the peer's
    // history must not lose (I1: the blob store is the source of truth).
    let local_actions: Vec<(Vec<u8>, Vec<u8>)> =
        load_principal_from_engine(&old, &keystore, identity)?
            .actions()
            .map(|a| Ok((a.czd().as_bytes().to_vec(), serde_json::to_vec(a.raw())?)))
            .collect::<crate::Result<_>>()?;

    let mut tmp = path.clone().into_os_string();
    tmp.push(SCRATCH_SUFFIX);
    let tmp = std::path::PathBuf::from(tmp);
    if tmp.exists() {
        return Err(Error::SwapWorkspace(tmp));
    }
    // Declared before the engine below so the engine closes its files first.
    let mut scratch = Scratch(Some(tmp.clone()));
    let mut resigned: Vec<Value> = Vec::new();
    {
        let new = open_store(&tmp, false)?;
        block_on(async {
            use cyphr_storage::index::Indexer;
            for summary in old.indexer().list_principals().await? {
                if summary.principal_id == principal_id {
                    continue;
                }
                let bare = bare_digest(&summary.principal_id);
                let g = match local_genesis(&keystore, bare)? {
                    Some(g) => g,
                    None => old.resolve_genesis(&summary.principal_id, &[]).await?,
                };
                let commits: Vec<WireBundle> = raw_chain(&old, &summary.principal_id)
                    .await?
                    .into_iter()
                    .map(|c| c.bundle)
                    .collect();
                let actions: Vec<Vec<Vec<u8>>> = old
                    .get_patch(&summary.principal_id, None, None)
                    .await?
                    .actions
                    .into_iter()
                    .map(|a| a.blobs)
                    .collect();
                submit_history(&new, &summary.principal_id, Some(g), &commits, &actions, 0).await?;
            }
            submit_history(
                &new,
                &principal_id,
                Some(genesis.clone()),
                &theirs,
                &their_actions,
                0,
            )
            .await?;
            Ok::<_, Error>(())
        })??;

        let principal = load_principal_from_engine(&new, &keystore, identity)?;
        // Re-record the local actions the peer's history lacks, as signed:
        // a re-signed action is a new digest, a duplicate of the original.
        // Only one the adopted history does not authorize at its own `now`
        // (SPEC 6.5) is re-signed with the current `now`, and named.
        let held: std::collections::HashSet<Vec<u8>> = principal
            .actions()
            .map(|a| a.czd().as_bytes().to_vec())
            .collect();
        let now = current_timestamp();
        let missing: Vec<_> = local_actions
            .iter()
            .filter(|(czd, _)| !held.contains(czd))
            .collect();
        for (czd, blob) in &missing {
            let submit = |blob: Vec<u8>| {
                block_on(new.submit_commit(
                    &principal_id,
                    Some(genesis.clone()),
                    &WireBundle::actions(vec![blob]),
                ))
            };
            match submit(blob.clone())? {
                Err(cyphr_storage::engine::EngineError::Protocol(e))
                    if e.is_inactive_signer()
                        && cyphr::replay::StoredCoz::from_wire(blob)
                            .is_ok_and(|c| principal.held_key(&c.header().tmb)) =>
                {
                    let mut pay = serde_json::from_slice::<Value>(blob)?["pay"].clone();
                    resigned.push(json!({
                        "czd": Base64UrlUnpadded::encode_string(czd),
                        "was_now": pay["now"].clone(),
                    }));
                    pay["now"] = now.into();
                    let tmb = pay["tmb"].as_str().ok_or(Error::MissingField("pay.tmb"))?;
                    let signed = super::data::sign(&keystore.signer(tmb)?, pay.clone())?;
                    submit(serde_json::to_vec(&signed.wire())?)??;
                },
                result => {
                    result?;
                },
            }
        }
        new.blob_store()
            .database()
            .persist(fjall::PersistMode::SyncAll)?;
    }
    drop(old);

    // Named by the second, so an adoption finishing in the same second as
    // an earlier one must not take that one's backup: rename onto a
    // non-empty directory fails.
    let stamp = current_timestamp();
    let backup = (0u32..)
        .map(|n| match n {
            0 => sibling(&path, &format!("{BACKUP_PREFIX}{stamp}")),
            n => sibling(&path, &format!("{BACKUP_PREFIX}{stamp}-{n}")),
        })
        .find(|candidate| !candidate.exists())
        .ok_or_else(|| Error::InvalidArgument("no free backup name".into()))?;
    // The marker names the backup before anything moves, so a process that
    // dies between the two renames leaves a trail `parse_store` refuses on.
    let marker = sibling(&path, SWAP_MARKER);
    std::fs::write(&marker, backup.display().to_string())?;
    sync_dir(&path)?;
    std::fs::rename(&path, &backup)?;
    // From here the scratch store is the only complete copy: keep it.
    scratch.0 = None;
    sync_dir(&path)?;
    std::fs::rename(&tmp, &path)?;
    sync_dir(&path)?;
    std::fs::remove_file(&marker)?;
    sync_dir(&path)?;

    let fetched = theirs.len() - common;
    let out = json!({"identity": identity, "peer": peer_url, "fetched": fetched,
        "discarded": discarded, "backup": backup.display().to_string(),
        "resigned_actions": resigned});
    emit(cli, &out, || {
        println!("Fetched {fetched} commit(s) from {peer_url}");
        println!(
            "Discarded {} local commit(s) after the parting point (old store kept at {}):",
            discarded.len(),
            backup.display()
        );
        for id in &discarded {
            println!("  {id}");
        }
        if !resigned.is_empty() {
            println!(
                "Re-signed {} action(s); original times and czds: {}",
                resigned.len(),
                Value::Array(resigned.clone())
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use cyphr_client::{ForkPoint, HeldHead};

    use super::*;

    fn digest(b: u8) -> TaggedDigest {
        format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[b; 32]))
            .parse()
            .expect("digest")
    }

    fn local(ids: &[u8]) -> Vec<RawCommit> {
        ids.iter()
            .map(|b| RawCommit {
                commit_id: digest(*b).to_string(),
                bundle: WireBundle::default(),
            })
            .collect()
    }

    fn error(heads: &[u8]) -> TipAnswer {
        TipAnswer::Error {
            fork_point: ForkPoint {
                height: 1,
                pre: None,
            },
            heads: heads
                .iter()
                .map(|b| HeldHead {
                    commit_id: digest(*b),
                    sequence: 2,
                    held_since: None,
                })
                .collect(),
        }
    }

    /// Backs `push` choosing where to send from: an Active peer's tip is
    /// found by id; for an Error peer (SPEC 15.5), the highest-positioned
    /// head the local history holds, since extending any head is
    /// admitted (SPEC 15.8); and a peer none of whose heads is held gives
    /// nothing to extend. Red if Error's heads are ignored, the lowest is
    /// taken, or an unheld head is found.
    #[test]
    fn push_start_follows_the_peer_tip_or_a_head() {
        let chain = local(&[1, 2, 3, 4]);
        assert_eq!(
            held_position(
                &TipAnswer::Active {
                    commit_id: digest(3)
                },
                &chain
            ),
            Some(2)
        );
        assert_eq!(held_position(&error(&[2, 9, 4]), &chain), Some(3));
        assert_eq!(held_position(&error(&[8, 9]), &chain), None);
        assert!(describe(&error(&[8, 9])).contains("Error"));
    }
}
