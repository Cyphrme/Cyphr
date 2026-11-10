//! Network commands: `push`, `fetch`, `rebase` and `verify`.
//!
//! Peers are untrusted: every commit a peer serves is re-verified by the
//! local engine before it is stored, and `verify` reports what the local
//! view and the peers' histories show, never that the view is current.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::engine::bare_digest;
use cyphr_storage::{CommitEntry, Genesis, KeyEntry, load_principal_from_commits};
use serde_json::{Value, json};

use super::common::{
    Placed, RawCommit, block_on, current_timestamp, get_principal_id, load_principal_from_engine,
    local_genesis, open_store, parse_principal_genesis, parse_store, place, raw_chain, store_path,
    submit_history,
};
use crate::choices::Choices;
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::net::{Peer, PeerError, PeerHistory};
use crate::{Cli, Error, OutputFormat};

/// Seconds a view may age before `verify` reports it as stale, absent a
/// choice.
const DEFAULT_FRESHNESS_SECS: u64 = 300;

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

/// `cyphr push`: send the commits the peer lacks, each preceded by the data
/// actions recorded before it (a `ds/create` includes exactly those, SPEC
/// 4.8.2), then the actions recorded after the last commit.
///
/// A peer cannot say which trailing actions it already holds, so those are
/// sent again on every push, one request per action; a replayed action is a
/// no-op (SPEC 7.6) and the peer stores it once (content-addressed
/// manifests). They could be batched later.
pub fn push(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
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
        let start = match peer.tip_commit_id(&wire).await? {
            None => 0,
            Some(tip) => match local.iter().position(|c| c.commit_id == tip) {
                Some(i) => i + 1,
                None => {
                    return Err(PeerError::Stale {
                        peer: peer.url().to_owned(),
                        detail: format!("peer tip {tip} is not in the local history"),
                    }
                    .into());
                },
            },
        };
        // Actions recorded when `n` commits existed precede commit `n`.
        let mut actions = principal
            .actions()
            .filter(|a| a.recorded_after() >= start)
            .map(|a| Ok((a.recorded_after(), serde_json::to_vec(a.raw())?)))
            .collect::<crate::Result<Vec<_>>>()?
            .into_iter()
            .peekable();
        let mut sent_actions = 0usize;
        for (i, commit) in local.iter().enumerate().skip(start) {
            while let Some((_, blob)) = actions.next_if(|(after, _)| *after <= i) {
                peer.push_commit(&wire, &[blob]).await?;
                sent_actions += 1;
            }
            peer.push_commit(&wire, &commit.blobs).await?;
        }
        for (_, blob) in actions {
            peer.push_commit(&wire, &[blob]).await?;
            sent_actions += 1;
        }
        Ok::<_, Error>((
            local.len() - start,
            sent_actions,
            local.last().map(|c| c.commit_id.clone()),
        ))
    })??;

    let (count, actions, tip) = pushed;
    let status = if count == 0 { "up_to_date" } else { "accepted" };
    let out = json!({"identity": identity, "peer": peer_url, "pushed": count,
        "actions": actions, "tip": tip, "status": status});
    emit(cli, &out, || {
        println!("Push {status}: {count} commit(s), {actions} action(s) sent to {peer_url}");
    })
}

/// `cyphr fetch`: verify and store the peer's commits the local store lacks.
pub fn fetch(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let genesis = local_genesis(&keystore, identity)?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;

    let fetched = block_on(async {
        let PeerHistory {
            commits: theirs,
            actions,
        } = peer.chain(&wire).await?;
        let local = raw_chain(&store, &principal_id).await?;
        if let Some(i) = first_divergence(&local, &theirs) {
            // A fork needs two histories that both replay; a peer chain that
            // does not is a bad answer, not a rival branch.
            let replay_from = match &genesis {
                Some(g) => g.clone(),
                None => store.resolve_genesis(&principal_id, &[]).await?,
            };
            if let Err(reason) = replays(&replay_from, &theirs, &actions) {
                return Err(PeerError::Malformed {
                    peer: peer.url().to_owned(),
                    reason,
                }
                .into());
            }
            return Err(PeerError::Diverged {
                peer: peer.url().to_owned(),
                height: i,
            }
            .into());
        }
        let applied = submit_history(
            &store,
            &principal_id,
            genesis.clone(),
            &theirs,
            &actions,
            local.len(),
        )
        .await?;
        Ok::<_, Error>(applied)
    })??;

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

/// Whether two commits are the same signed commit, whatever their encoding.
fn same_commit(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| signed_identity(x) == signed_identity(y))
}

/// Index of the first commit at which `a` and `b` both hold one and differ.
fn first_divergence(a: &[RawCommit], b: &[Vec<Vec<u8>>]) -> Option<usize> {
    a.iter().zip(b).position(|(x, y)| !same_commit(&x.blobs, y))
}

/// Suffix of the file that records a rebase swap in progress.
pub const SWAP_MARKER: &str = ".rebase-swap";

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

/// Removes the rebase scratch store on every exit path that has not
/// handed it over, so a failed rebase never blocks the next one.
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

/// A local commit's transaction, to be re-signed onto a new tip.
enum Intent {
    AddKey { id: String, signer: String },
    RevokeKey { signer: String },
}

/// Read the replayable intents out of a local commit's cozies. Terminal
/// `commit/create` cozies are the commit's own seal, re-made on replay.
fn intents(commit: &RawCommit) -> crate::Result<(Vec<Intent>, String)> {
    use cyphr::parsed_coz::typ;
    let mut out = Vec::new();
    let mut authority = String::new();
    for blob in &commit.blobs {
        let v: Value = serde_json::from_slice(blob)?;
        let pay = &v["pay"];
        let t = pay["typ"].as_str().ok_or(Error::MissingField("pay.typ"))?;
        let tmb = pay["tmb"].as_str().ok_or(Error::MissingField("pay.tmb"))?;
        if let Some(a) = t.strip_suffix(typ::KEY_CREATE) {
            authority = a.trim_end_matches('/').to_owned();
            let id = pay["id"].as_str().ok_or(Error::MissingField("pay.id"))?;
            out.push(Intent::AddKey {
                id: id.to_owned(),
                signer: tmb.to_owned(),
            });
        } else if let Some(a) = t.strip_suffix(typ::KEY_REVOKE) {
            authority = a.trim_end_matches('/').to_owned();
            out.push(Intent::RevokeKey {
                signer: tmb.to_owned(),
            });
        } else if !t.ends_with("commit/create") {
            return Err(Error::RebaseUnsupported(t.to_owned()));
        }
    }
    Ok((out, authority))
}

/// `cyphr rebase`: replay local, unpushed commits onto the peer's history.
///
/// The store is append-only (I1), so a diverged local commit cannot be
/// removed in place, and leaving it beside the peer's commit at the same
/// height would make the principal's chain unrecoverable on reindex. The
/// replay therefore builds a fresh store, copies every other principal into
/// it unchanged, and swaps it in; the old store is kept as a backup.
pub fn rebase(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let genesis = local_genesis(&keystore, identity)?
        .ok_or_else(|| Error::UnresolvableGenesis(identity.to_owned()))?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
    let path = store_path(cli)?.to_owned();

    let old = parse_store(cli)?;
    let (local, history) = block_on(async {
        let history = peer.chain(&wire).await?;
        let local = raw_chain(&old, &principal_id).await?;
        Ok::<_, Error>((local, history))
    })??;
    let PeerHistory {
        commits: theirs,
        actions: their_actions,
    } = history;
    let common = local
        .iter()
        .zip(&theirs)
        .take_while(|(x, y)| same_commit(&x.blobs, y))
        .count();
    let mut replay = Vec::new();
    let mut authority = cli.authority.clone();
    for commit in &local[common..] {
        let (found, auth) = intents(commit)?;
        if !auth.is_empty() {
            authority = auth;
        }
        replay.extend(found);
    }
    if local.len() == common || theirs.len() == common {
        // Nothing local to move, or the peer holds nothing the local
        // history lacks: the history already extends the peer's.
        let out = json!({"identity": identity, "peer": peer_url, "rebased": 0});
        return emit(cli, &out, || println!("Nothing to rebase"));
    }

    // The data actions recorded locally, which a rebuild from the peer's
    // history must not lose (I1: the blob store is the source of truth).
    let local_actions: Vec<(Vec<u8>, Vec<u8>)> =
        load_principal_from_engine(&old, &keystore, identity)?
            .actions()
            .map(|a| Ok((a.czd().as_bytes().to_vec(), serde_json::to_vec(a.raw())?)))
            .collect::<crate::Result<_>>()?;

    let mut tmp = path.clone().into_os_string();
    tmp.push(".rebase");
    let tmp = std::path::PathBuf::from(tmp);
    if tmp.exists() {
        return Err(Error::RebaseWorkspace(tmp));
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
                let commits: Vec<Vec<Vec<u8>>> = raw_chain(&old, &summary.principal_id)
                    .await?
                    .into_iter()
                    .map(|c| c.blobs)
                    .collect();
                let actions: Vec<(usize, Vec<Vec<u8>>)> = old
                    .get_patch(&summary.principal_id, None, None)
                    .await?
                    .actions
                    .into_iter()
                    .map(|a| (a.after as usize, a.blobs))
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

        let mut principal = load_principal_from_engine(&new, &keystore, identity)?;
        // Re-record the local actions the peer's history lacks, deduplicated
        // by czd, as one action-only bundle (recorded in `now` order).
        let held: std::collections::HashSet<Vec<u8>> = principal
            .actions()
            .map(|a| a.czd().as_bytes().to_vec())
            .collect();
        // An action older than the peer's latest commit is refused as past
        // (SPEC 14.1), so each is re-signed with the current `now`, as the
        // rebase re-signs the local commits it replays.
        let now = current_timestamp();
        let missing = local_actions
            .iter()
            .filter(|(czd, _)| !held.contains(czd))
            .map(|(czd, blob)| {
                let mut pay = serde_json::from_slice::<Value>(blob)?["pay"].clone();
                resigned.push(json!({
                    "czd": Base64UrlUnpadded::encode_string(czd),
                    "was_now": pay["now"].clone(),
                }));
                pay["now"] = now.into();
                let tmb = pay["tmb"].as_str().ok_or(Error::MissingField("pay.tmb"))?;
                let signed = super::data::sign(keystore.get(tmb)?, tmb, pay.clone())?;
                Ok(serde_json::to_vec(&signed.wire())?)
            })
            .collect::<crate::Result<Vec<Vec<u8>>>>()?;
        if !missing.is_empty() {
            let refs: Vec<&[u8]> = missing.iter().map(Vec::as_slice).collect();
            block_on(new.submit_commit(&principal_id, Some(genesis.clone()), &refs))??;
            principal = load_principal_from_engine(&new, &keystore, identity)?;
        }
        for intent in &replay {
            match intent {
                Intent::AddKey { id, signer } => {
                    let key = super::common::load_key_from_keystore(&keystore, id)?;
                    super::key::apply_key_create(
                        &mut principal,
                        &keystore,
                        id,
                        &key,
                        signer,
                        &authority,
                    )?;
                },
                Intent::RevokeKey { signer } => {
                    super::key::apply_key_revoke(
                        &mut principal,
                        &keystore,
                        signer,
                        signer,
                        &authority,
                    )?;
                },
            }
        }
        super::common::save_principal_to_engine(&new, &keystore, &principal)?;
        new.blob_store()
            .database()
            .persist(fjall::PersistMode::SyncAll)?;
    }
    drop(old);

    let backup = sibling(&path, &format!(".pre-rebase-{}", current_timestamp()));
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

    let out = json!({"identity": identity, "peer": peer_url,
        "rebased": local.len() - common, "backup": backup.display().to_string(),
        "resigned_actions": resigned});
    emit(cli, &out, || {
        println!(
            "Rebased {} commit(s); old store kept at {}",
            local.len() - common,
            backup.display()
        );
        if !resigned.is_empty() {
            println!(
                "Re-signed {} action(s) at rebase; original times and czds: {}",
                resigned.len(),
                Value::Array(resigned.clone())
            );
        }
    })
}

/// How two histories relate, compared commit by commit.
#[derive(Debug, PartialEq, Eq)]
enum Relation {
    Same,
    /// The first is a strict prefix of the second.
    Behind,
    /// The second is a strict prefix of the first.
    Ahead,
    /// Different commits at this height.
    Fork(usize),
}

fn relate(a: &[Vec<Vec<u8>>], b: &[Vec<Vec<u8>>]) -> Relation {
    if let Some(i) = a.iter().zip(b).position(|(x, y)| !same_commit(x, y)) {
        return Relation::Fork(i);
    }
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Equal => Relation::Same,
        std::cmp::Ordering::Less => Relation::Behind,
        std::cmp::Ordering::Greater => Relation::Ahead,
    }
}

fn b64_blobs(blobs: &[Vec<u8>]) -> Vec<String> {
    blobs
        .iter()
        .map(|b| Base64UrlUnpadded::encode_string(b))
        .collect()
}

/// Replay a peer's history from `genesis`; a history that does not replay
/// is not an answer about the principal.
fn replays(
    genesis: &Genesis,
    chain: &[Vec<Vec<u8>>],
    actions: &[(usize, Vec<Vec<u8>>)],
) -> Result<(), String> {
    let line = |blobs: &[Vec<u8>]| -> Result<CommitEntry, String> {
        let mut cozies = Vec::new();
        let mut keys = Vec::new();
        for blob in blobs {
            let v: Value = serde_json::from_slice(blob).map_err(|e| e.to_string())?;
            if let Some(k) = v.get("key") {
                if let Ok(ke) = serde_json::from_value::<KeyEntry>(k.clone()) {
                    keys.push(ke);
                }
            }
            cozies.push(v);
        }
        Ok(CommitEntry::new(
            cozies,
            keys,
            String::new(),
            None,
            None,
            String::new(),
        ))
    };
    let mut entries = Vec::with_capacity(chain.len() + actions.len());
    for step in place(chain, actions.iter().map(|(a, b)| (*a, b))) {
        let (Placed::Commit(_, blobs) | Placed::Actions(_, blobs)) = step;
        entries.push(line(blobs)?);
    }
    load_principal_from_commits(genesis.clone(), &entries)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `cyphr verify`: a principal's standing from the local view and peers.
pub fn verify(
    cli: &Cli,
    identity: &str,
    peer_flags: &[String],
    anchor_flag: Option<&str>,
    choices_path: Option<&std::path::Path>,
    freshness_flag: Option<u64>,
) -> crate::Result<()> {
    let choices = choices_path
        .map(Choices::load)
        .transpose()?
        .unwrap_or_default();
    let peers: Vec<String> = if peer_flags.is_empty() {
        choices.peers
    } else {
        peer_flags.to_vec()
    };
    if peers.is_empty() {
        return Err(Error::NoPeers);
    }
    let freshness = freshness_flag
        .or(choices.freshness_secs)
        .unwrap_or(DEFAULT_FRESHNESS_SECS);

    let store = parse_store(cli)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    // Replays the whole local history, so a bad signature is an error here.
    load_principal_from_engine(&store, &keystore, identity)?;
    let genesis = local_genesis(&keystore, identity)?;

    let (anchor_value, anchor_source) = match anchor_flag.map(str::to_owned).or(choices.anchor) {
        Some(a) => (a, "pinned"),
        None if genesis.is_some() => (identity.to_owned(), "trusted-genesis"),
        None => (identity.to_owned(), "hint"),
    };

    let (local, tip_state) = block_on(async {
        let local = raw_chain(&store, &principal_id).await?;
        let tip = store.get_tip(&principal_id).await?;
        Ok::<_, Error>((local, tip))
    })??;
    let tip_state = tip_state.ok_or_else(|| Error::EmptyHistory(identity.to_owned()))?;
    let local_blobs: Vec<Vec<Vec<u8>>> = local.iter().map(|c| c.blobs.clone()).collect();

    let answers = block_on(async {
        let mut answers = Vec::new();
        for url in &peers {
            let answer = match Peer::new(url, cli.peer_timeout_secs, cli.allow_cleartext) {
                Ok(peer) => peer.chain(&wire).await,
                Err(e) => Err(e),
            };
            answers.push((url.clone(), answer));
        }
        answers
    })?;

    let replay_genesis = match genesis {
        Some(g) => g,
        None => block_on(store.resolve_genesis(&principal_id, &[]))??,
    };
    let mut chains: Vec<(String, Vec<Vec<Vec<u8>>>)> = vec![("local".into(), local_blobs.clone())];
    let mut failed = Vec::new();
    let mut newer = false;
    for (url, answer) in answers {
        match answer {
            Err(e) => failed.push(json!({"peer": url, "reason": e.to_string(), "kind": e.kind()})),
            Ok(PeerHistory {
                commits: chain,
                actions,
            }) => match replays(&replay_genesis, &chain, &actions) {
                Err(reason) => {
                    failed.push(json!({"peer": url, "reason": reason, "kind": "malformed"}))
                },
                Ok(()) => {
                    if relate(&local_blobs, &chain) == Relation::Behind {
                        newer = true;
                    }
                    chains.push((url, chain));
                },
            },
        }
    }
    let queried = chains.len() - 1;
    if queried == 0 {
        let reason = failed
            .iter()
            .map(|f| format!("{}: {}", f["peer"], f["reason"]))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(PeerError::Unreachable {
            peer: peers.join(","),
            reason: format!("no peer gave an answer ({reason})"),
        }
        .into());
    }

    let mut evidence = Vec::new();
    for (i, (na, a)) in chains.iter().enumerate() {
        for (nb, b) in &chains[i + 1..] {
            if let Relation::Fork(h) = relate(a, b) {
                evidence.push(json!({"kind": "principal_fork", "height": h,
                    "branches": [
                        {"source": na, "blobs": b64_blobs(&a[h])},
                        {"source": nb, "blobs": b64_blobs(&b[h])}]}));
            }
        }
    }
    let bare_anchor = bare_digest(&anchor_value);
    let on_chain = bare_anchor == identity
        || local.iter().any(|c| c.commit_id == anchor_value)
        || block_on(async {
            use cyphr_storage::index::Indexer;
            store
                .indexer()
                .get_commit_chain(&principal_id, None, None)
                .await
                .map(|c| c.iter().any(|r| bare_digest(&r.pr) == bare_anchor))
        })??;
    if !on_chain {
        evidence.push(json!({"kind": "anchor_not_in_history", "anchor": anchor_value}));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let view_age = now.saturating_sub(u64::try_from(tip_state.last_updated).unwrap_or(0));
    let mut out = json!({
        "identity": identity,
        "tip": tip_state.commit_id,
        "view_age_secs": view_age,
        "newer_tip_reported": newer,
        "peers_queried": queried,
        "peers_failed": failed,
        "freshness_secs": freshness,
        "stale_view": view_age > freshness,
        // When the anchor is the identity itself, the "anchor is in the
        // history" check cannot fail, so it vouches for nothing.
        "anchor": {"value": anchor_value, "source": anchor_source,
            "is_identity": bare_digest(&anchor_value) == identity},
        "verdict": if evidence.is_empty() { "Active" } else { "Error" },
    });
    if !evidence.is_empty() {
        out["evidence"] = Value::Array(evidence);
    }
    emit(cli, &out, || {
        println!("Standing: {}", out["verdict"].as_str().unwrap_or(""));
        println!("  tip: {}", out["tip"].as_str().unwrap_or(""));
        println!("  view age: {view_age}s (freshness {freshness}s)");
        println!("  newer tip reported by a peer: {newer}");
        println!("  peers queried: {queried}");
        println!("  anchor: {anchor_value} ({anchor_source})");
        if let Some(e) = out.get("evidence") {
            println!("  evidence: {e}");
        }
    })
}
