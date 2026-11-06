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
    RawCommit, block_on, current_timestamp, get_principal_id, load_principal_from_engine,
    local_genesis, open_store, parse_principal_genesis, parse_store, raw_chain, store_path,
};
use crate::choices::Choices;
use crate::keystore::JsonKeyStore;
use crate::net::{Peer, PeerError};
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

/// `cyphr push`: send the commits the peer lacks.
pub fn push(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let peer = Peer::new(peer_url);

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
        for commit in &local[start..] {
            peer.push_commit(&wire, &commit.blobs).await?;
        }
        Ok::<_, Error>((
            local.len() - start,
            local.last().map(|c| c.commit_id.clone()),
        ))
    })??;

    let (count, tip) = pushed;
    let status = if count == 0 { "up_to_date" } else { "accepted" };
    let out = json!({"identity": identity, "peer": peer_url, "pushed": count,
        "tip": tip, "status": status});
    emit(cli, &out, || {
        println!("Push {status}: {count} commit(s) sent to {peer_url}");
    })
}

/// `cyphr fetch`: verify and store the peer's commits the local store lacks.
pub fn fetch(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let genesis = local_genesis(&keystore, identity, &principal_id)?;
    let peer = Peer::new(peer_url);

    let fetched = block_on(async {
        let theirs = peer.chain(&wire).await?;
        let local = raw_chain(&store, &principal_id).await?;
        if let Some(i) = first_divergence(&local, &theirs) {
            return Err(PeerError::Diverged {
                peer: peer.url().to_owned(),
                height: i,
            }
            .into());
        }
        let mut applied = 0usize;
        for blobs in theirs.iter().skip(local.len()) {
            let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
            store
                .submit_commit(&principal_id, genesis.clone(), &refs)
                .await?;
            applied += 1;
        }
        Ok::<_, Error>(applied)
    })??;

    let out = json!({"identity": identity, "peer": peer_url, "fetched": fetched});
    emit(cli, &out, || {
        println!("Fetched {fetched} commit(s) from {peer_url}");
    })
}

/// Index of the first commit at which `a` and `b` both hold one and differ.
fn first_divergence(a: &[RawCommit], b: &[Vec<Vec<u8>>]) -> Option<usize> {
    a.iter().zip(b).position(|(x, y)| x.blobs != *y)
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
    let genesis = local_genesis(&keystore, identity, &principal_id)?
        .ok_or_else(|| Error::UnresolvableGenesis(identity.to_owned()))?;
    let peer = Peer::new(peer_url);
    let path = store_path(cli)?.to_owned();

    let old = parse_store(cli)?;
    let (local, theirs) = block_on(async {
        let theirs = peer.chain(&wire).await?;
        let local = raw_chain(&old, &principal_id).await?;
        Ok::<_, Error>((local, theirs))
    })??;
    let common = local
        .iter()
        .zip(&theirs)
        .take_while(|(x, y)| x.blobs == **y)
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

    let mut tmp = path.clone().into_os_string();
    tmp.push(".rebase");
    let tmp = std::path::PathBuf::from(tmp);
    if tmp.exists() {
        return Err(Error::RebaseWorkspace(tmp));
    }
    {
        let new = open_store(&tmp, false)?;
        block_on(async {
            use cyphr_storage::index::Indexer;
            for summary in old.indexer().list_principals().await? {
                if summary.principal_id == principal_id {
                    continue;
                }
                let bare = bare_digest(&summary.principal_id);
                let g = match local_genesis(&keystore, bare, &summary.principal_id)? {
                    Some(g) => g,
                    None => old.resolve_genesis(&summary.principal_id, &[]).await?,
                };
                for c in raw_chain(&old, &summary.principal_id).await? {
                    let refs: Vec<&[u8]> = c.blobs.iter().map(Vec::as_slice).collect();
                    new.submit_commit(&summary.principal_id, Some(g.clone()), &refs)
                        .await?;
                }
            }
            for blobs in &theirs {
                let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
                new.submit_commit(&principal_id, Some(genesis.clone()), &refs)
                    .await?;
            }
            Ok::<_, Error>(())
        })??;

        let mut principal = load_principal_from_engine(&new, &keystore, identity)?;
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

    let backup = {
        let mut b = path.clone().into_os_string();
        b.push(format!(".pre-rebase-{}", current_timestamp()));
        std::path::PathBuf::from(b)
    };
    std::fs::rename(&path, &backup)?;
    std::fs::rename(&tmp, &path)?;

    let out = json!({"identity": identity, "peer": peer_url,
        "rebased": local.len() - common, "backup": backup.display().to_string()});
    emit(cli, &out, || {
        println!(
            "Rebased {} commit(s); old store kept at {}",
            local.len() - common,
            backup.display()
        );
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
    if let Some(i) = a.iter().zip(b).position(|(x, y)| x != y) {
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
fn replays(genesis: &Genesis, chain: &[Vec<Vec<u8>>]) -> Result<(), String> {
    let mut entries = Vec::with_capacity(chain.len());
    for blobs in chain {
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
        entries.push(CommitEntry::new(
            cozies,
            keys,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ));
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
    let genesis = local_genesis(&keystore, identity, &principal_id)?;

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
            let peer = Peer::new(url);
            answers.push((url.clone(), peer.chain(&wire).await));
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
            Ok(chain) => match replays(&replay_genesis, &chain) {
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
        "anchor": {"value": anchor_value, "source": anchor_source},
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
