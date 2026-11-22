//! Network commands: `push`, `fetch` and `rebase`.
//!
//! Peers are untrusted: every commit a peer serves is re-verified by the
//! local engine before it is stored, and `verify` reports what the local, never that the view is
//! current.

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr::state::TaggedDigest;
use cyphr_client::TipAnswer;
use cyphr_storage::engine::bare_digest;
use cyphr_storage::{CommitEntry, Genesis, load_principal_from_commits};
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
pub fn push(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
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
        let mut forking = false;
        let mut in_error = false;
        let start = match peer.tip(&wire).await? {
            None => 0,
            Some(tip) => match held_position(&tip, &local) {
                Some(i) => i + 1,
                None => {
                    forking = true;
                    0
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
                    if forking && message.contains("COZ_REUSE") => {},
                Err(PeerError::Stale { .. }) if forking => {
                    parent = Some(&commit.bundle);
                },
                // The peer is in Error: it refuses what does not resolve
                // its fork (or cannot keep it past its caps), and the next
                // commit may be the extension that shows the pair.
                Err(PeerError::Status { status: 423, .. }) => {
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

/// `cyphr fetch`: verify and store the peer's commits the local store lacks.
pub fn fetch(cli: &Cli, identity: &str, peer_url: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = super::common::open_backend(cli)?;
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
            if let Err(reason) = replays(&replay_from, &theirs, &actions).await {
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
    AddKey {
        id: String,
        signer: String,
    },
    DeleteKey {
        id: String,
        signer: String,
    },
    ReplaceKey {
        id: String,
        signer: String,
    },
    RevokeKey {
        signer: String,
    },
    /// A `ds/create`. Its `id` names the Data Root of a tree the rebased
    /// history does not have, so replay signs a fresh one over the rebased
    /// tree instead of repeating this.
    DsCreate {
        signer: String,
    },
}

/// Read the replayable intents out of a local commit's cozies. Terminal
/// `commit/create` cozies are the commit's own seal, re-made on replay.
fn intents(commit: &RawCommit) -> crate::Result<(Vec<Intent>, String)> {
    use cyphr::parsed_coz::typ;
    let mut out = Vec::new();
    let mut authority = String::new();
    for blob in commit.bundle.cozies() {
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
        } else if let Some(a) = t.strip_suffix(typ::KEY_DELETE) {
            authority = a.trim_end_matches('/').to_owned();
            let id = pay["id"].as_str().ok_or(Error::MissingField("pay.id"))?;
            out.push(Intent::DeleteKey {
                id: id.to_owned(),
                signer: tmb.to_owned(),
            });
        } else if let Some(a) = t.strip_suffix(typ::KEY_REPLACE) {
            authority = a.trim_end_matches('/').to_owned();
            let id = pay["id"].as_str().ok_or(Error::MissingField("pay.id"))?;
            out.push(Intent::ReplaceKey {
                id: id.to_owned(),
                signer: tmb.to_owned(),
            });
        } else if let Some(a) = t.strip_suffix(typ::KEY_REVOKE) {
            authority = a.trim_end_matches('/').to_owned();
            out.push(Intent::RevokeKey {
                signer: tmb.to_owned(),
            });
        } else if let Some(a) = t.strip_suffix(typ::DS_CREATE) {
            authority = a.trim_end_matches('/').to_owned();
            out.push(Intent::DsCreate {
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
    let keystore = super::common::open_backend(cli)?;
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let wire = wire_id(identity)?;
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
    let path = store_path(cli)?.to_owned();

    let old = parse_store(cli)?;
    // A multi-key principal's identity is its PG, not a keystore key, so
    // its genesis comes from the stored history (as for the other
    // principals copied below).
    let genesis = match local_genesis(&keystore, identity)? {
        Some(g) => g,
        None => block_on(old.resolve_genesis(&principal_id, &[]))??,
    };
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
        .take_while(|(x, y)| same_commit(&x.bundle, y))
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
    // Every local action is re-recorded before any intent replays, so the
    // rebased tree is whole and one `ds/create` over it includes what each
    // earlier one included: the last stands for all.
    if let Some(last) = replay
        .iter()
        .rposition(|i| matches!(i, Intent::DsCreate { .. }))
    {
        let mut at = 0;
        replay.retain(|i| {
            at += 1;
            !matches!(i, Intent::DsCreate { .. }) || at == last + 1
        });
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
    let mut included: Vec<Value> = Vec::new();
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

        let mut principal = load_principal_from_engine(&new, &keystore, identity)?;
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
        if !missing.is_empty() {
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
                Intent::DeleteKey { id, signer } => {
                    super::key::apply_key_delete(
                        &mut principal,
                        &keystore,
                        id,
                        signer,
                        &authority,
                    )?;
                },
                Intent::ReplaceKey { id, signer } => {
                    let key = super::common::load_key_from_keystore(&keystore, id)?;
                    super::key::apply_key_replace(
                        &mut principal,
                        &keystore,
                        id,
                        &key,
                        signer,
                        &authority,
                        None,
                    )?;
                },
                Intent::DsCreate { signer } => {
                    let dr = super::data::apply_ds_create(
                        &mut principal,
                        &keystore,
                        signer,
                        &authority,
                    )?;
                    included.push(json!({"signer": signer, "dr": dr}));
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

    // Named by the second, so a rebase finishing in the same second as an
    // earlier one must not take that one's backup: rename onto a non-empty
    // directory fails.
    let stamp = current_timestamp();
    let backup = (0u32..)
        .map(|n| match n {
            0 => sibling(&path, &format!(".pre-rebase-{stamp}")),
            n => sibling(&path, &format!(".pre-rebase-{stamp}-{n}")),
        })
        .find(|candidate| !candidate.exists())
        .ok_or_else(|| Error::InvalidArgument("no free rebase backup name".into()))?;
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
        "resigned_actions": resigned, "ds_create": included});
    emit(cli, &out, || {
        println!(
            "Rebased {} commit(s); old store kept at {}",
            local.len() - common,
            backup.display()
        );
        for inc in &included {
            println!(
                "Signed a fresh ds/create including the rebased DR {}",
                inc["dr"]
            );
        }
        if !resigned.is_empty() {
            println!(
                "Re-signed {} action(s) at rebase; original times and czds: {}",
                resigned.len(),
                Value::Array(resigned.clone())
            );
        }
    })
}

/// Replay a peer's history from `genesis`; a history that does not replay
/// is not an answer about the principal.
async fn replays(
    genesis: &Genesis,
    chain: &[WireBundle],
    actions: &[Vec<Vec<u8>>],
) -> Result<(), String> {
    let mut entries = Vec::with_capacity(chain.len() + actions.len());
    let bundles = chain.iter().cloned().chain(
        actions
            .iter()
            .map(|blobs| WireBundle::actions(blobs.clone())),
    );
    for bundle in bundles {
        entries.push(CommitEntry::from_bundle(&bundle).map_err(|e| e.to_string())?);
    }
    load_principal_from_commits(genesis.clone(), &entries)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
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
