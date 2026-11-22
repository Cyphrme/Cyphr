//! The verifier: `verify`, `watch`, `audit` and `gossip export|import`.
//!
//! All of them are one round of the G2 pull step ([`cyphr_client::pull`])
//! over a peer set (HTTP peers, or a bundle file served as peers), against
//! a record rebuilt from the local store. What the pull returns is what is
//! persisted (new commits, rival branches and naked revokes into the store;
//! peers and forks into the [`state`](crate::state) file) and printed. No
//! verdict rule lives here: classification is the pull step's, and whether
//! a fork stands, which heads are live and who settled a fork are the
//! store's [`assess`](cyphr_storage::engine::StorageEngine::assess), the
//! rule a peer applies, over the branches this verifier holds as a peer
//! holds them.
//!
//! What a verdict claims is bounded by what was seen: Active means no fork
//! was seen among the peers that answered this round, not that no fork
//! exists. A peer that lists a single branch head is not asked for
//! evidence, and a peer's evidence is read only up to a fixed number of
//! items, so a peer that pads its list with items that do not verify can
//! push a real fork past what is read.

use std::time::Duration;

use cyphr::Key;
use cyphr::principal::system_clock;
use cyphr::replay::WireBundle;
use cyphr_client::{
    Anchor, BindingPolicy, Bundle, BundleError, Connector, HttpConnector, HttpOptions,
    PatchFailure, PatchRequest, PeerFailure, PeerStanding, PullPeer, PullReport, Record,
    branch_bundles, fetch_patch, opener_of, pull,
};
use cyphr_storage::Genesis;
use cyphr_storage::engine::{
    Assessment, Consensus, EngineError, ForkView, Recovery, Review, bare_digest,
};
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
                    .map(|a| ActionBundle { blobs: Ok(a.blobs) })
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

    /// Hand `bundles` to the store, which replays each again and admits it,
    /// retains it as a branch, or refuses it, as a peer's store does. A
    /// refusal is the store's answer, not a failure of this round (a commit
    /// it holds, or one refused in Error and kept as evidence); a storage
    /// fault is.
    async fn keep(&self, record: &Record, bundles: &[WireBundle]) -> crate::Result<()> {
        let Some(first) = record.bundles_since(0).first() else {
            return Ok(());
        };
        let genesis = match &self.anchor {
            Anchor::GenesisKey(key) => Genesis::Implicit(key.clone()),
            Anchor::GenesisCommit(_) => Genesis::Implicit(
                opener_of(first).map_err(|e| Error::InvalidArgument(e.to_owned()))?,
            ),
        };
        for (i, bundle) in bundles.iter().enumerate() {
            let answer = self
                .store
                .submit_commit(&self.principal_id, Some(genesis.clone()), bundle)
                .await;
            // A cap refused the entry alone, but it may be a line root whose
            // extension changes the verdict: offer the two together.
            let answer = match (answer, bundles.get(i + 1)) {
                (
                    Err(EngineError::BranchLimit { .. } | EngineError::Errored { .. }),
                    Some(next),
                ) => {
                    self.store
                        .submit_pair(&self.principal_id, Some(genesis.clone()), bundle, next)
                        .await
                },
                (other, _) => other,
            };
            if let Err(err) = answer
                && is_store_fault(&err)
            {
                return Err(err.into());
            }
        }
        Ok(())
    }
}

/// Whether the store's answer to a bundle is a fault of the store rather
/// than its verdict on the bundle. A refusal is an answer (a held commit, a
/// fork kept as evidence); a fault, a failed sync included, means nothing
/// the round reports as kept is durable.
fn is_store_fault(err: &EngineError) -> bool {
    matches!(
        err,
        EngineError::BlobStore(_)
            | EngineError::Indexer(_)
            | EngineError::Storage(_)
            | EngineError::DurabilityLost(_)
    )
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

/// A held fork as the store's [`Assessment`] reads it: resolved once the
/// contest holding its commits settled, and unresolved again should it
/// stand once more.
fn resolution_of(fork: &HeldFork, assessed: &Assessment) -> Option<Resolution> {
    let contest = assessed
        .forks
        .iter()
        .find(|c| fork.commits.iter().all(|id| c.commits.contains(id)))?;
    let kept = contest.kept.clone()?;
    let abandoned = fork.commits.iter().find(|c| **c != kept)?.clone();
    Some(Resolution {
        kept,
        abandoned,
        by: contest.by.clone(),
    })
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

    let mut pulled = round.record().await?;
    let mark = pulled.log_len();
    let held_before = pulled.tip().map_or(0, |t| t.commits);
    let report = pull(&mut pulled, peers).await;
    // Verified revokes first: the store refuses a dead key's commits at
    // admission and judges forks by them.
    for found in &report.revoked {
        round
            .store
            .record_revoke(&found.envelope, system_clock())
            .await?;
    }
    let mut handed = pulled.bundles_since(mark).to_vec();
    handed.extend(branch_bundles(&pulled, &report, peers).await);
    round.keep(&pulled, &handed).await?;

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
    // What the store holds now, branches kept as a peer keeps them: its
    // canonical chain is the record, and its assessment the verdict.
    let record = round.record().await?;
    let assessed = round.store.assess(&round.principal_id).await?;
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

    for fork in &mut entry.forks {
        fork.resolution = resolution_of(fork, &assessed);
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
    // SPEC 15.8: the abandoned branch is discarded, "retaining it only as
    // proof of error". The verifier holds that proof verified, so it is
    // reported from its own record, not only while a peer happens to serve
    // it: one round's unreachable peer must not make it vanish.
    evidence.extend(resolved.iter().map(|f| {
        json!({"kind": "principal_fork", "height": f.height, "pre": f.pre,
                    "commits": f.commits, "first_seen": f.first_seen, "resolved": true})
    }));
    evidence.extend(
        entry
            .revoked
            .iter()
            .map(|r| json!({"kind": "naked_revoke", "tmb": r.tmb, "rvk": r.rvk, "peer": r.peer})),
    );
    // Live heads only: a resolved pair is reported in `resolved_forks`.
    let branches = &assessed.heads;
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
        "tip": tip.commit_id,
        "commits": tip.commits,
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
        "verdict": match assessed.consensus {
            Consensus::Active => "Active",
            Consensus::Error => "Error",
        },
        "branches": branches,
        "resolved_by": resolved.iter().filter_map(|f| f.resolution.as_ref()).next_back().and_then(|r| r.by.clone()),
        "resolved_forks": resolved.iter().filter_map(|f| f.resolution.as_ref().map(|r| json!({"height": f.height, "kept": r.kept, "abandoned": r.abandoned, "by": r.by}))).collect::<Vec<_>>(),
    });
    let mut out = out;
    // Reported beside the protocol verdict, never in place of it: shown for
    // a principal in Error, and for any viewer choice still in force (a
    // resolved fork's abandoned head included).
    let review = HumanRecovery(entry.recovery.clone()).review(
        &round.wire,
        assessed.consensus,
        &fork_views(&entry.forks),
    );
    if assessed.consensus == Consensus::Error || review.trusted.is_some() {
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

#[cfg(test)]
mod tests {
    use cyphr_storage::blob::BlobStoreError;

    use super::*;

    /// A failed sync is a fault of the store, so the round reports an
    /// error and not a kept commit; a refusal is the store's verdict. The
    /// CLI store is a concrete fjall store whose sync cannot be made to
    /// fail from here, so the classification is what is pinned. Turns red
    /// if `DurabilityLost` is read as a refusal.
    #[test]
    fn a_failed_sync_is_a_fault_and_a_refusal_is_not() {
        assert!(is_store_fault(&EngineError::DurabilityLost("eio".into())));
        assert!(is_store_fault(&EngineError::BlobStore(
            BlobStoreError::Backend("x".into())
        )));
        assert!(!is_store_fault(&EngineError::BranchLimit {
            key: "k".into()
        }));
        assert!(!is_store_fault(&EngineError::Protocol(
            cyphr::Error::CommitMismatch
        )));
    }
}
