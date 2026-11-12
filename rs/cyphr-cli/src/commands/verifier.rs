//! The verifier: `verify`, `watch`, `audit` and `gossip export|import`.
//!
//! All of them are one round of the G2 pull step ([`cyphr_client::pull`])
//! over a peer set (HTTP peers, or a bundle file served as peers), against
//! a record rebuilt from the local store. What the pull returns is what is
//! persisted (new commits into the store; peers, forks and naked revokes
//! into the [`state`](crate::state) file) and printed. No verdict rule
//! lives here: classification is the pull step's.
//!
//! One reading of SPEC 15.8 is made here, not in the pull: a fork is
//! resolved when the peers' own chain, pulled into a fresh record, is
//! fork-free and continues past one of the fork's two commits; the signer of
//! that continuing commit is the resolving key.

use std::time::Duration;

use cyphr::Key;
use cyphr::principal::system_clock;
use cyphr::replay::WireBundle;
use cyphr_client::{
    Anchor, BindingPolicy, Bundle, BundleError, Connector, HttpConnector, HttpOptions,
    PatchFailure, PatchRequest, PeerFailure, PeerStanding, PullPeer, PullReport, Record, RecordTip,
    Request, fetch_patch, opener_of, pull,
};
use cyphr_storage::Genesis;
use cyphr_storage::engine::{Consensus, ForkView, Recovery, Review, bare_digest};
use serde_json::{Value, json};

use super::common::{
    CliStorageEngine, block_on, current_timestamp, get_principal_id, parse_principal_genesis,
    parse_store, raw_chain, store_path,
};
use crate::choices::Choices;
use crate::keystore::KeyBackend;
use crate::net::PeerError;
use crate::state::{
    HeldFork, HeldRevoke, PeerSeen, PrincipalState, RecoveryChoice, Resolution, VerifierState,
    path_for,
};
use crate::{Cli, Error, OutputFormat};

/// Seconds a view may age before `verify` reports it as stale, absent a
/// choice.
const DEFAULT_FRESHNESS_SECS: u64 = 300;

/// What a run was told: the flags, with the choices file behind them.
pub struct Inputs<'a> {
    /// The identity (the principal's genesis, base64url).
    pub identity: &'a str,
    /// `--peer` flags.
    pub peers: &'a [String],
    /// `--anchor`.
    pub anchor: Option<&'a str>,
    /// `--choices`.
    pub choices: Option<&'a std::path::Path>,
    /// `--freshness-secs`.
    pub freshness: Option<u64>,
}

fn emit(cli: &Cli, value: &Value, table: impl FnOnce()) -> crate::Result<()> {
    match cli.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Table => table(),
    }
    Ok(())
}

/// Everything a round needs that does not change during it.
struct Round<'a> {
    cli: &'a Cli,
    identity: &'a str,
    /// The bare digest the wire and the pull step use.
    wire: String,
    /// The tagged id the store keys the principal by.
    principal_id: String,
    store: CliStorageEngine,
    anchor: Anchor,
    anchor_value: String,
    anchor_source: &'static str,
    freshness: u64,
}

/// The key a keystore entry holds, with its thumbprint computed from the
/// key and not from the entry's name.
fn keystore_key(keystore: &impl KeyBackend, name: &str) -> Option<Key> {
    let stored = keystore.public(name).ok()?;
    Key::from_pub_key(stored.alg, stored.pub_key).ok()
}

/// The refusal for an anchor that cannot tell chains apart.
fn anchor_rule(value: &str) -> Error {
    Error::AnchorRule(format!(
        "anchor `{value}` is not a genesis key this client can read or a genesis commit id; the \
         anchor is the genesis key or the genesis commit id, never the principal genesis alone \
         (one key set opened by different keys derives one PG)"
    ))
}

/// Choose the anchor: the flag or choices value when given (`pinned`),
/// else the genesis key the keystore holds (`trusted-genesis`), else the
/// opener the first commit held or offered discloses (`hint`).
fn choose_anchor(
    keystore: &impl KeyBackend,
    identity: &str,
    wire: &str,
    given: Option<&str>,
    first: Option<&WireBundle>,
) -> crate::Result<(Anchor, String, &'static str)> {
    let opener = first.and_then(|b| opener_of(b).ok());
    if let Some(value) = given {
        if let Some(key) = keystore_key(keystore, value).or_else(|| {
            opener
                .clone()
                .filter(|k| k.tmb().to_b64() == bare_digest(value))
        }) {
            let tmb = key.tmb().to_b64();
            return Ok((Anchor::GenesisKey(key), tmb, "pinned"));
        }
        if bare_digest(value) == wire || !value.contains(':') {
            return Err(anchor_rule(value));
        }
        return Ok((
            Anchor::GenesisCommit(value.to_owned()),
            value.to_owned(),
            "pinned",
        ));
    }
    if let Some(key) = keystore_key(keystore, identity) {
        let tmb = key.tmb().to_b64();
        return Ok((Anchor::GenesisKey(key), tmb, "trusted-genesis"));
    }
    match opener {
        Some(key) => {
            let tmb = key.tmb().to_b64();
            Ok((Anchor::GenesisKey(key), tmb, "hint"))
        },
        None => Err(Error::AnchorRule(format!(
            "no anchor for {identity}: name one with --anchor or the choices file, hold its \
             genesis key in the keystore, or import a bundle that carries its genesis commit"
        ))),
    }
}

impl<'a> Round<'a> {
    fn open(
        cli: &'a Cli,
        identity: &'a str,
        anchor_given: Option<&str>,
        freshness: u64,
        offered_first: Option<&WireBundle>,
    ) -> crate::Result<Self> {
        let store = parse_store(cli)?;
        let keystore = super::common::open_backend(cli)?;
        let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
        let wire = bare_digest(&principal_id).to_owned();
        let local = block_on(raw_chain(&store, &principal_id))??;
        let first = local.first().map(|c| &c.bundle).or(offered_first);
        let (anchor, anchor_value, anchor_source) =
            choose_anchor(&keystore, identity, &wire, anchor_given, first)?;
        Ok(Self {
            cli,
            identity,
            wire,
            principal_id,
            store,
            anchor,
            anchor_value,
            anchor_source,
            freshness,
        })
    }

    /// The record the local store holds, replayed from the anchor.
    async fn record(&self) -> crate::Result<Record> {
        use cyphr_client::{ActionBundle, PatchEntry};
        let patch = if self.store.get_tip(&self.principal_id).await?.is_some() {
            Some(self.store.get_patch(&self.principal_id, None, None).await?)
        } else {
            None
        };
        let entries: Vec<PatchEntry> = patch
            .as_ref()
            .map(|p| {
                p.entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| PatchEntry {
                        sequence: i as u64,
                        bundle: Ok(e.bundle.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let actions: Vec<ActionBundle> = patch
            .map(|p| {
                p.actions
                    .into_iter()
                    .map(|a| ActionBundle {
                        after: a.after,
                        blobs: Ok(a.blobs),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Record::from_entries(
            &self.wire,
            self.anchor.clone(),
            system_clock,
            &entries,
            &actions,
        )
        .await
        .map_err(|e| {
            Error::InvalidArgument(format!(
                "the local history of {} does not replay from the anchor: {e}",
                self.identity
            ))
        })
    }

    /// Write what the pull added to the store, which replays each bundle
    /// again before keeping it.
    async fn keep(&self, record: &Record, mark: usize) -> crate::Result<()> {
        let added = record.bundles_since(mark);
        let Some(first) = record.bundles_since(0).first() else {
            return Ok(());
        };
        let genesis = match &self.anchor {
            Anchor::GenesisKey(key) => Genesis::Implicit(key.clone()),
            Anchor::GenesisCommit(_) => Genesis::Implicit(
                opener_of(first).map_err(|e| Error::InvalidArgument(e.to_owned()))?,
            ),
        };
        for bundle in added {
            self.store
                .submit_commit(&self.principal_id, Some(genesis.clone()), bundle)
                .await?;
        }
        Ok(())
    }
}

fn standing_of(s: &PeerStanding) -> (&'static str, Option<String>) {
    match s {
        PeerStanding::Current => ("current", None),
        PeerStanding::Extended { .. } => ("extended", None),
        PeerStanding::Behind { .. } => ("behind", None),
        PeerStanding::Forked => ("forked", None),
        PeerStanding::Failed(f) => ("failed", Some(f.to_string())),
        _ => ("current", None),
    }
}

fn failure_kind(f: &PeerFailure) -> &'static str {
    match f {
        PeerFailure::Patch(PatchFailure::Unreachable(_)) => "unreachable",
        PeerFailure::Patch(PatchFailure::UnsupportedVersion { .. }) => "unknownversion",
        PeerFailure::Patch(PatchFailure::NonSuccess(_)) => "other",
        _ => "malformed",
    }
}

/// The latest `now` the record's chain carries. A data action's `now`
/// becomes the principal's latest only once a `ds/create` includes it
/// (SPEC 4.8.2), and that commit's `now` is no earlier, so actions are not
/// read: a pending one would date the view later than its tip.
fn latest_now(record: &Record) -> Option<i64> {
    record
        .bundles_since(0)
        .iter()
        .flat_map(|b| b.txs.iter().flatten().map(Vec::as_slice))
        .filter_map(|blob| serde_json::from_slice::<Value>(blob).ok())
        .filter_map(|coz| coz["pay"]["now"].as_i64())
        .max()
}

/// The signer of the commit at `index` of the record's chain.
fn signer_at(record: &Record, index: usize) -> Option<String> {
    let bundle = record.entries().get(index)?.bundle.as_ref().ok()?;
    let blob = bundle.cozies().next()?;
    serde_json::from_slice::<Value>(blob).ok()?["pay"]["tmb"]
        .as_str()
        .map(str::to_owned)
}

/// A fresh record pulled from the same peers: the chain they converge on,
/// which decides whether the forks held are resolved.
/// A branch head a peer serves beside its canonical chain: `(sequence, tip)`,
/// as `/branches` reports it.
type BranchHead = (usize, String);

/// The non-canonical heads the peers serve at `/branches`. A peer that
/// cannot answer contributes none: a fork then settles on the chain alone.
async fn rival_heads<C: Connector>(wire: &str, peers: &[PullPeer<'_, C>]) -> Vec<BranchHead> {
    let mut heads = Vec::new();
    for peer in peers {
        let Ok(body) = peer
            .connector
            .exchange(&Request::get(format!("/branches?pr={wire}")))
            .await
        else {
            continue;
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&body) else {
            continue;
        };
        for b in doc["payload"]["branches"].as_array().into_iter().flatten() {
            if b["canonical"].as_bool() == Some(false)
                && let (Some(seq), Some(tip)) = (b["sequence"].as_u64(), b["tip"].as_str())
                && let Ok(seq) = usize::try_from(seq)
            {
                heads.push((seq, tip.to_owned()));
            }
        }
    }
    heads
}

fn settle_resolutions(
    state: &mut PrincipalState,
    fresh: &Record,
    fresh_report: &PullReport,
    rivals: &[BranchHead],
) -> bool {
    let Some(RecordTip { commits, .. }) = fresh.tip() else {
        return false;
    };
    // Peers keep serving a resolved fork as evidence, so a fork finding
    // alone does not unsettle it. A finding of a fork this state does not
    // hold is a new fork, and nothing settles while one is open.
    if fresh_report
        .forks
        .iter()
        .any(|f| !state.forks.iter().any(|held| held.is(&f.commits)))
    {
        return false;
    }
    let mut resolved = false;
    for fork in state.forks.iter_mut().filter(|f| f.resolution.is_none()) {
        let Some(at) = fresh.commit_id_at(fork.height) else {
            continue;
        };
        let Some(other) = fork.commits.iter().find(|c| **c != at).cloned() else {
            continue;
        };
        // A rival head above the fork means both branches went on: the
        // fork stays unresolved (an Error neither side has settled).
        if rivals
            .iter()
            .any(|(seq, tip)| *seq > fork.height && fresh.commit_id_at(*seq).as_ref() != Some(tip))
        {
            continue;
        }
        if !fork.commits.contains(&at) || commits <= fork.height + 1 {
            continue;
        }
        let Some(by) = signer_at(fresh, fork.height + 1) else {
            continue;
        };
        fork.resolution = Some(Resolution {
            kept: at,
            abandoned: other,
            by,
        });
        resolved = true;
    }
    resolved
}

/// One round of the pull step over `peers`, persisted and described.
async fn run_round<C: Connector>(
    round: &Round<'_>,
    peers: &[PullPeer<'_, C>],
    prefailed: &[(String, String)],
) -> crate::Result<Value> {
    let state_path = path_for(store_path(round.cli)?);
    let mut state = VerifierState::load(&state_path)?;
    let now = current_timestamp();

    let mut record = round.record().await?;
    let mark = record.log_len();
    let held_before = record.tip().map_or(0, |t| t.commits);
    let report = pull(&mut record, peers).await;
    round.keep(&record, mark).await?;

    let answered: Vec<&str> = report
        .peers
        .iter()
        .filter(|o| !matches!(o.standing, PeerStanding::Failed(_)))
        .map(|o| o.peer.as_str())
        .collect();
    let mut failures: Vec<(String, String, &'static str)> = prefailed
        .iter()
        .map(|(p, why)| (p.clone(), why.clone(), "other"))
        .collect();
    failures.extend(report.peers.iter().filter_map(|o| match &o.standing {
        PeerStanding::Failed(f) => Some((o.peer.clone(), f.to_string(), failure_kind(f))),
        _ => None,
    }));
    if answered.is_empty() {
        return Err(no_answer(peers, &failures, &report));
    }
    let tip = record
        .tip()
        .ok_or_else(|| Error::EmptyHistory(round.identity.to_owned()))?;

    let entry = state
        .principals
        .entry(round.wire.clone())
        .or_insert_with(PrincipalState::default);
    for o in &report.peers {
        let (standing, detail) = standing_of(&o.standing);
        let answered_at = (standing != "failed")
            .then_some(now)
            .or_else(|| entry.peers.get(&o.peer).and_then(|p| p.answered_at));
        entry.peers.insert(
            o.peer.clone(),
            PeerSeen {
                answered_at,
                asked_at: now,
                standing: standing.to_owned(),
                detail,
            },
        );
    }
    for (peer, why, _) in &failures {
        entry.peers.entry(peer.clone()).or_insert(PeerSeen {
            answered_at: None,
            asked_at: now,
            standing: "failed".into(),
            detail: Some(why.clone()),
        });
    }
    entry.last_pull_at = Some(now);
    entry.commits_high = entry.commits_high.max(tip.commits);
    for found in &report.revoked {
        let tmb = found.tmb.to_b64();
        if !entry.revoked.iter().any(|r| r.tmb == tmb) {
            entry.revoked.push(HeldRevoke {
                tmb,
                rvk: found.rvk,
                peer: found.peer.clone(),
                envelope: found.envelope.clone(),
            });
        }
    }
    for fork in &report.forks {
        if !entry.forks.iter().any(|f| f.is(&fork.commits)) {
            entry.forks.push(HeldFork {
                height: fork.height,
                pre: fork.pre.clone(),
                commits: fork.commits.clone(),
                rival: fork.rival.clone(),
                first_seen: now,
                resolution: None,
            });
        }
    }

    // A fork is resolved by what the peers converge on, which only a fresh
    // record shows: the held one keeps the branch it already had.
    let mut shown = tip.clone();
    // The forks the peers serve evidence of in this round.
    let mut served: Vec<[String; 2]> = report.forks.iter().map(|f| f.commits.clone()).collect();
    if entry.forks.iter().any(|f| f.resolution.is_none()) || !report.forks.is_empty() {
        let mut fresh = Record::new(&round.wire, round.anchor.clone());
        let fresh_report = pull(&mut fresh, peers).await;
        served.extend(fresh_report.forks.iter().map(|f| f.commits.clone()));
        let rivals = rival_heads(&round.wire, peers).await;
        settle_resolutions(entry, &fresh, &fresh_report, &rivals);
        let followed = entry.forks.iter().any(|f| f.resolution.is_some());
        if let Some(t) = fresh.tip().filter(|t| followed && t.commits >= tip.commits) {
            shown = t;
        }
    }

    let added = tip.commits.saturating_sub(held_before);
    let unresolved: Vec<&HeldFork> = entry
        .forks
        .iter()
        .filter(|f| f.resolution.is_none())
        .collect();
    let resolved: Vec<&HeldFork> = entry
        .forks
        .iter()
        .filter(|f| f.resolution.is_some())
        .collect();
    let mut evidence: Vec<Value> = unresolved
        .iter()
        .map(|f| {
            json!({"kind": "principal_fork", "height": f.height, "pre": f.pre,
                "commits": f.commits, "first_seen": f.first_seen})
        })
        .collect();
    // A resolved fork stays evidence while the peers serve it: a verdict
    // that omitted the items would claim less than the peers show, and one
    // that kept them after the peers dropped them would claim more.
    evidence.extend(
        resolved
            .iter()
            .filter(|f| served.iter().any(|c| f.is(c)))
            .map(|f| {
                json!({"kind": "principal_fork", "height": f.height, "pre": f.pre,
                    "commits": f.commits, "first_seen": f.first_seen, "resolved": true})
            }),
    );
    evidence.extend(
        entry
            .revoked
            .iter()
            .map(|r| json!({"kind": "naked_revoke", "tmb": r.tmb, "rvk": r.rvk, "peer": r.peer})),
    );
    // Live heads only: once forks are resolved the chain has one head, and
    // the resolved pair is reported in `resolved_forks`.
    let branches: Vec<&str> = if unresolved.is_empty() {
        vec![shown.commit_id.as_str()]
    } else {
        unresolved
            .iter()
            .flat_map(|f| f.commits.iter().map(String::as_str))
            .collect()
    };
    let principal_now = latest_now(&record);
    let age = |t: i64| u64::try_from(now - t).unwrap_or(0);
    let pull_age = age(now);
    // What a peer served that did not verify is part of what it said.
    let rejected: std::collections::BTreeMap<&str, Vec<String>> = report
        .peers
        .iter()
        .map(|o| {
            let why = o
                .rejected_evidence
                .iter()
                .map(|e| format!("evidence: {e}"))
                .chain(o.rejected_revokes.iter().map(|r| format!("revoke: {r}")))
                .collect();
            (o.peer.as_str(), why)
        })
        .collect();
    let peers_json: Vec<Value> = entry
        .peers
        .iter()
        .filter(|(name, _)| {
            report.peers.iter().any(|o| &o.peer == *name) || failures.iter().any(|f| &f.0 == *name)
        })
        .map(|(name, seen)| {
            json!({"peer": name, "standing": seen.standing, "answered_at": seen.answered_at,
                "asked_at": seen.asked_at, "detail": seen.detail,
                "rejected": rejected.get(name.as_str()).cloned().unwrap_or_default()})
        })
        .collect();
    let out = json!({
        "identity": round.identity,
        "tip": shown.commit_id,
        "commits": shown.commits,
        "added": added,
        "view_age_secs": pull_age,
        "peers_queried": answered.len(),
        "peers_failed": failures.iter().map(|(p, why, kind)| json!({"peer": p, "reason": why, "kind": kind})).collect::<Vec<_>>(),
        "peers": peers_json,
        "freshness_secs": round.freshness,
        "stale_view": pull_age > round.freshness,
        "freshness": {
            "pull_age_secs": pull_age,
            "principal_now_age_secs": principal_now.map(age),
        },
        "principal_now": principal_now,
        // When the anchor is the identity itself the check cannot fail, so
        // it vouches for nothing.
        "anchor": {"value": round.anchor_value, "source": round.anchor_source,
            "is_identity": bare_digest(&round.anchor_value) == round.wire},
        "verdict": if unresolved.is_empty() { "Active" } else { "Error" },
        "branches": branches,
        "resolved_by": resolved.iter().filter_map(|f| f.resolution.as_ref()).next_back().map(|r| r.by.clone()),
        "resolved_forks": resolved.iter().filter_map(|f| f.resolution.as_ref().map(|r| json!({"height": f.height, "kept": r.kept, "abandoned": r.abandoned, "by": r.by}))).collect::<Vec<_>>(),
    });
    let mut out = out;
    // Reported beside the protocol verdict, never in place of it: shown for
    // a principal in Error, and for any viewer choice still in force (a
    // resolved fork's abandoned head included).
    let review = HumanRecovery(entry.recovery.clone()).review(
        &round.wire,
        if unresolved.is_empty() {
            Consensus::Active
        } else {
            Consensus::Error
        },
        &fork_views(&entry.forks),
    );
    if !unresolved.is_empty() || review.trusted.is_some() {
        out["recovery"] = json!({"note": review.note, "head": review.trusted,
            "reason": entry.recovery.as_ref().and_then(|c| c.reason.clone()),
            "chosen_at": review.trusted.as_ref().and(entry.recovery.as_ref().map(|c| c.chosen_at))});
    }
    if !evidence.is_empty() {
        out["evidence"] = Value::Array(evidence);
    }
    state.save(&state_path)?;
    Ok(out)
}

/// The forks a verifier holds, resolved or not, as the engine's
/// [`ForkView`]s.
fn fork_views(forks: &[HeldFork]) -> Vec<ForkView> {
    forks
        .iter()
        .map(|f| ForkView {
            height: u64::try_from(f.height).unwrap_or(u64::MAX),
            heads: f.commits.clone(),
            kept: f.resolution.as_ref().map(|r| r.kept.clone()),
        })
        .collect()
}

/// Human recovery as a [`Recovery`] strategy: it trusts the viewer's
/// chosen head while that head is still one a fork offers as an
/// alternative to the protocol's answer, and reports what it did. It never
/// changes the consensus it is shown.
struct HumanRecovery(Option<RecoveryChoice>);

impl Recovery for HumanRecovery {
    fn review(&self, _principal_id: &str, _protocol: Consensus, forks: &[ForkView]) -> Review {
        match self.0.as_ref().filter(|c| {
            forks
                .iter()
                .any(|f| f.alternatives().contains(&c.head.as_str()))
        }) {
            Some(c) => {
                let why = c
                    .reason
                    .as_deref()
                    .map_or_else(String::new, |r| format!(" ({r})"));
                Review {
                    trusted: Some(c.head.clone()),
                    note: format!("human recovery: trusting {} by local choice{why}", c.head),
                }
            },
            None => Review {
                trusted: None,
                note: "no branch chosen".to_owned(),
            },
        }
    }
}

/// Why a round with no answering peer failed: an unknown envelope version
/// everywhere is its own refusal, not unreachability.
fn no_answer<C>(
    peers: &[PullPeer<'_, C>],
    failures: &[(String, String, &'static str)],
    report: &PullReport,
) -> Error {
    let versions: Vec<(u64, u64)> = report
        .peers
        .iter()
        .filter_map(|o| match &o.standing {
            PeerStanding::Failed(PeerFailure::Patch(PatchFailure::UnsupportedVersion {
                found,
                supported,
            })) => Some((*found, *supported)),
            _ => None,
        })
        .collect();
    let names = peers.iter().map(|p| p.name).collect::<Vec<_>>().join(",");
    if let Some(&(found, supported)) = versions.first()
        && versions.len() == failures.len()
    {
        return PeerError::UnknownVersion {
            peer: names,
            found,
            supported,
        }
        .into();
    }
    let reason = failures
        .iter()
        .map(|(p, why, _)| format!("{p}: {why}"))
        .collect::<Vec<_>>()
        .join("; ");
    PeerError::Unreachable {
        peer: names,
        reason: format!("no peer gave an answer ({reason})"),
    }
    .into()
}

fn print_table(v: &Value) {
    println!("Standing: {}", v["verdict"].as_str().unwrap_or(""));
    println!("  tip: {}", v["tip"].as_str().unwrap_or(""));
    println!(
        "  anchor: {} ({})",
        v["anchor"]["value"].as_str().unwrap_or(""),
        v["anchor"]["source"].as_str().unwrap_or("")
    );
    for p in v["peers"].as_array().into_iter().flatten() {
        println!(
            "  peer {}: {} (answered {})",
            p["peer"].as_str().unwrap_or(""),
            p["standing"].as_str().unwrap_or(""),
            p["answered_at"]
        );
    }
    println!(
        "  freshness: newest pull {}s ago; principal's newest now {}s ago (verifier clock)",
        v["freshness"]["pull_age_secs"], v["freshness"]["principal_now_age_secs"]
    );
    println!("  branches: {}", v["branches"]);
    if let Some(by) = v["resolved_by"].as_str() {
        println!("  resolved by key: {by}");
    }
    if let Some(note) = v["recovery"]["note"].as_str() {
        println!("  {note}");
    }
    if let Some(e) = v.get("evidence") {
        println!("  evidence: {e}");
    }
}

/// The peers and freshness a run uses: flags win over the choices file.
fn settings(inputs: &Inputs<'_>) -> crate::Result<(Vec<String>, Option<String>, u64)> {
    let choices = inputs
        .choices
        .map(Choices::load)
        .transpose()?
        .unwrap_or_default();
    let peers = if inputs.peers.is_empty() {
        choices.peers
    } else {
        inputs.peers.to_vec()
    };
    let freshness = inputs
        .freshness
        .or(choices.freshness_secs)
        .unwrap_or(DEFAULT_FRESHNESS_SECS);
    Ok((
        peers,
        inputs.anchor.map(str::to_owned).or(choices.anchor),
        freshness,
    ))
}

/// One verify round over HTTP peers: the value `verify`, `watch` and
/// `audit` print.
fn verify_once(cli: &Cli, inputs: &Inputs<'_>) -> crate::Result<Value> {
    let (urls, anchor, freshness) = settings(inputs)?;
    if urls.is_empty() {
        return Err(Error::NoPeers);
    }
    let mut options = HttpOptions::new(Duration::from_secs(cli.peer_timeout_secs));
    options.allow_cleartext = cli.allow_cleartext;
    let mut connectors = Vec::new();
    let mut prefailed = Vec::new();
    for url in &urls {
        match HttpConnector::connect(url.trim_end_matches('/'), &options) {
            Ok(c) => connectors.push((url.as_str(), c)),
            Err(e) => prefailed.push((url.clone(), e.to_string())),
        }
    }
    let round = match Round::open(cli, inputs.identity, anchor.as_deref(), freshness, None) {
        // First contact with no anchor and no history: the genesis commit a
        // peer serves is a hint, reported as one, never as trust.
        Err(Error::AnchorRule(_)) if anchor.is_none() => {
            let wire = bare_digest(&get_principal_id(&parse_principal_genesis(
                inputs.identity,
            )?)?)
            .to_owned();
            let first = block_on(genesis_hint(&wire, &connectors))?;
            Round::open(cli, inputs.identity, None, freshness, first.as_ref())?
        },
        other => other?,
    };
    let peers: Vec<PullPeer<'_, HttpConnector>> = connectors
        .iter()
        .map(|(name, connector)| PullPeer { name, connector })
        .collect();
    block_on(run_round(&round, &peers, &prefailed))?
}

/// The first commit any of `peers` serves for `wire`: the one place a
/// verifier with no anchor and no history can read an opener from.
async fn genesis_hint(wire: &str, peers: &[(&str, HttpConnector)]) -> Option<WireBundle> {
    for (_, connector) in peers {
        let request = PatchRequest {
            principal_id: wire,
            anchor: None,
        };
        if let Ok(patch) = fetch_patch(connector, &request, BindingPolicy::NotRequired, None).await
            && let Some(Ok(first)) = patch.entries.into_iter().next().map(|e| e.bundle)
        {
            return Some(first);
        }
    }
    None
}

/// `cyphr verify`.
pub fn verify(cli: &Cli, inputs: &Inputs<'_>) -> crate::Result<()> {
    let out = verify_once(cli, inputs)?;
    emit(cli, &out, || print_table(&out))
}

/// `cyphr watch`: `verify` every `interval_secs`, `rounds` times (forever
/// when `None`). A round that fails is reported and does not end the watch:
/// a peer that is down is what a watch is for.
pub fn watch(
    cli: &Cli,
    inputs: &Inputs<'_>,
    interval_secs: u64,
    rounds: Option<u64>,
) -> crate::Result<()> {
    let mut done = 0u64;
    loop {
        match verify_once(cli, inputs) {
            Ok(out) => match cli.output {
                OutputFormat::Json => println!("{}", serde_json::to_string(&out)?),
                OutputFormat::Table => print_table(&out),
            },
            Err(e) => match cli.output {
                OutputFormat::Json => println!(
                    "{}",
                    json!({"error": {"kind": e.kind(), "message": e.to_string()}})
                ),
                OutputFormat::Table => println!("error: {e}"),
            },
        }
        done += 1;
        if rounds.is_some_and(|r| done >= r) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

/// `cyphr audit`: `verify`, with the evidence held printed in full.
pub fn audit(cli: &Cli, inputs: &Inputs<'_>) -> crate::Result<()> {
    let mut out = verify_once(cli, inputs)?;
    let state = VerifierState::load(&path_for(store_path(cli)?))?;
    let wire = bare_digest(&get_principal_id(&parse_principal_genesis(
        inputs.identity,
    )?)?)
    .to_owned();
    if let Some(held) = state.principals.get(&wire) {
        out["held"] = json!({
            "forks": held.forks.iter().map(|f| json!({"height": f.height, "pre": f.pre,
                "commits": f.commits, "first_seen": f.first_seen,
                "resolution": f.resolution})).collect::<Vec<_>>(),
            "revoked": held.revoked.iter().map(|r| json!({"tmb": r.tmb, "rvk": r.rvk, "peer": r.peer})).collect::<Vec<_>>(),
        });
    }
    emit(cli, &out, || {
        print_table(&out);
        println!("  held: {}", out["held"]);
    })
}

/// `cyphr recover`: set, replace or clear the local branch-head choice for
/// a principal in Error, or one whose fork was resolved fraudulently (the
/// abandoned head is then the choice). Local only: it touches the verifier state file and
/// nothing a server or a commit sees.
pub fn recover(
    cli: &Cli,
    identity: &str,
    head: Option<&str>,
    reason: Option<&str>,
) -> crate::Result<()> {
    let path = path_for(store_path(cli)?);
    let mut state = VerifierState::load(&path)?;
    let wire = bare_digest(&get_principal_id(&parse_principal_genesis(identity)?)?).to_owned();
    let entry = state.principals.entry(wire).or_default();
    entry.recovery = match head {
        None => None,
        Some(head) => {
            if !fork_views(&entry.forks)
                .iter()
                .any(|f| f.alternatives().contains(&head))
            {
                return Err(Error::InvalidArgument(format!(
                    "{head} is not a head of a fork held for {identity} that the protocol leaves \
                     open to choice (either head of an unresolved fork, the abandoned head of a \
                     resolved one): run `verify` first"
                )));
            }
            Some(RecoveryChoice {
                head: head.to_owned(),
                reason: reason.map(str::to_owned),
                chosen_at: current_timestamp(),
            })
        },
    };
    let out = json!({"identity": identity, "recovery": entry.recovery});
    state.save(&path)?;
    emit(cli, &out, || match &out["recovery"] {
        Value::Null => println!("recovery choice cleared: no branch chosen"),
        c => println!("recovery choice: trusting {}", c["head"]),
    })
}

/// `cyphr gossip export`: the record, the other branch of each fork held,
/// and the naked revokes held, as one file.
pub fn export(cli: &Cli, identity: &str, file: &std::path::Path) -> crate::Result<()> {
    let round = Round::open(cli, identity, None, DEFAULT_FRESHNESS_SECS, None)?;
    let state = VerifierState::load(&path_for(store_path(cli)?))?;
    let held = state.principals.get(&round.wire);
    let record = block_on(round.record())??;
    if record.tip().is_none() {
        return Err(Error::EmptyHistory(identity.to_owned()));
    }
    let forks: Vec<cyphr_client::ForkFinding> = held
        .into_iter()
        .flat_map(|h| h.forks.iter().filter(|f| f.resolution.is_none()))
        .map(|f| cyphr_client::ForkFinding {
            height: f.height,
            pre: f.pre.clone(),
            commits: f.commits.clone(),
            rival: f.rival.clone(),
        })
        .collect();
    let revoked = held
        .into_iter()
        .flat_map(|h| h.revoked.iter().map(|r| r.envelope.clone()))
        .collect();
    let bundle = Bundle::export(&record, &forks, revoked);
    std::fs::write(file, serde_json::to_vec_pretty(&bundle)?)?;
    let out = json!({"identity": identity, "file": file.display().to_string(),
        "chains": bundle.chains.len(), "revoked": bundle.revoked.len()});
    emit(cli, &out, || {
        println!(
            "Exported {} chain(s) to {}",
            bundle.chains.len(),
            file.display()
        );
    })
}

/// `cyphr gossip import`: replay a bundle file through the pull step, as
/// if each chain in it were a peer.
pub fn import(
    cli: &Cli,
    identity: &str,
    file: &std::path::Path,
    anchor: Option<&str>,
) -> crate::Result<()> {
    let bundle = Bundle::parse(&std::fs::read(file)?).map_err(|e| match e {
        BundleError::UnsupportedVersion { found, supported } => {
            Error::BundleVersion { found, supported }
        },
        BundleError::Malformed(why) => Error::InvalidArgument(format!("bundle file: {why}")),
    })?;
    let first = bundle.chains.first().and_then(|c| c.commits.first());
    let round = Round::open(cli, identity, anchor, DEFAULT_FRESHNESS_SECS, first)?;
    if bare_digest(&bundle.principal_id) != round.wire {
        return Err(Error::InvalidArgument(format!(
            "the bundle is of {}, not {identity}",
            bundle.principal_id
        )));
    }
    let connectors = bundle.connectors();
    let names: Vec<String> = (0..connectors.len())
        .map(|i| format!("bundle:{}", i + 1))
        .collect();
    let peers: Vec<PullPeer<'_, _>> = names
        .iter()
        .zip(&connectors)
        .map(|(name, connector)| PullPeer { name, connector })
        .collect();
    let out = block_on(run_round(&round, &peers, &[]))??;
    emit(cli, &out, || print_table(&out))
}
