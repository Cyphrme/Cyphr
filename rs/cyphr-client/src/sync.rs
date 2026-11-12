//! The pull step: one verifier procedure over the peers it chose
//! (GOSSIP-MIN section 2).
//!
//! A peer here is a mirror of principal-signed objects, never a source of
//! truth. [`pull`] reads three things from each chosen peer over its
//! [`Connector`]: the branch heads (`/branches`), the patch from the
//! verifier's own tip (`/patch`), and the naked revokes of the keys the
//! verifier's record holds (`/revoked`). Everything is replayed by the core
//! from the verifier's own [`Record`], so what a peer says changes the
//! verdict only through commits and revokes whose signatures verify:
//!
//! - **prefix-consistent**: the record becomes the longest verified chain;
//! - **two commits over one `pre`**: a [`ForkFinding`] naming both (SPEC 15.8). The record keeps
//!   the chain it held; a fork is evidence, never a merge (I2);
//! - **a verified naked revoke**: the key is inactive in the record from then on (SPEC 6.4);
//! - **a lower tip**: the peer is behind. The record never regresses.
//!
//! The anchor is the verifier's own and out of band: the genesis key, or
//! the genesis commit id ([`Anchor`]). A PG alone is not an anchor, because
//! one key set under different openers derives one PG from different
//! genesis commits, so the PG cannot tell the anchored chain from another
//! opener's.
//!
//! Peer heads (`/branches`) are hints that decide what to fetch, never what
//! to believe: a head is compared with the commit ids the verifier already
//! replayed, and anything it names that the verifier does not hold is
//! fetched and replayed or ignored.

use std::collections::BTreeMap;

use coz::Thumbprint;
use cyphr::eml::MemoryStorage;
use cyphr::principal::{Clock, system_clock};
use cyphr::replay::{BundleId, WireBundle};
use cyphr::{Key, Principal, StateDigest as _};
use serde_json::Value;

use crate::connector::{BindingPolicy, Connector, Request};
use crate::evidence::{
    EvidenceFailure, EvidenceItem, names_pg, pg_names, verify_principal_fork_with_actions,
};
use crate::patch::{
    ActionBundle, PatchEntry, PatchFailure, PatchRequest, Step, fetch_patch,
    percent_encode_query_value, replay_order,
};
use crate::peer::{EntryRefusal, PeerFailure, replay_entry};
use crate::revoke::{RevokeFailure, verify_naked_revoke};

/// Most patch entries one pull replays from one peer, unless the record
/// says otherwise ([`Record::with_patch_cap`]); the same bound
/// [`PeerLimits`](crate::PeerLimits) defaults to.
pub const DEFAULT_PATCH_CAP: usize = 10_000;

/// Most evidence items read from one peer per pull. A principal with more
/// distinct forks than this is already in `Error`.
const MAX_EVIDENCE_ITEMS: usize = 32;

/// Keys asked about per `/revoked` request.
const REVOKE_BATCH: usize = 64;

/// What the verifier holds out of band: the root a record replays from.
#[derive(Debug, Clone)]
pub enum Anchor {
    /// The genesis key. The record replays from the principal this key
    /// opens, so a chain opened by another key fails replay.
    GenesisKey(Key),
    /// The id of the genesis commit, as `ALG:digest`. The opener key is
    /// read from the genesis commit a peer serves, and the replayed commit
    /// must have exactly this id.
    GenesisCommit(String),
}

/// The verifier's own record of one principal: the chain it has replayed,
/// and the keys it has seen revoked. Built only from [`Record::new`] and
/// what [`pull`] verifies; it never regresses.
pub struct Record {
    id: String,
    anchor: Anchor,
    clock: Clock,
    patch_cap: usize,
    held: Option<Held>,
    /// Naked-revoked keys, by thumbprint, with their declared `rvk`.
    dead: BTreeMap<String, i64>,
}

struct Held {
    root: Key,
    principal: Principal<MemoryStorage>,
    entries: Vec<PatchEntry>,
    /// The identity of each commit bundle, one per entry.
    ids: Vec<BundleId>,
    /// The action-only bundles replayed, each with the commit count it
    /// followed (`after`) and its blobs, so a bundle a later patch serves
    /// again is not replayed twice.
    actions: Vec<ActionBundle>,
    /// Every bundle replayed, commits and action-only bundles, in replay
    /// order: what a holder that keeps the chain must store to catch up.
    log: Vec<WireBundle>,
}

/// How far a record reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordTip {
    /// Commits held.
    pub commits: usize,
    /// The tip Principal Root, tagged (`ALG:digest`).
    pub pr: String,
    /// The tip commit's id, tagged.
    pub commit_id: String,
}

impl Record {
    /// An empty record of the principal `principal_id` (its PG), anchored
    /// at `anchor`. The first pull fills it.
    #[must_use]
    pub fn new(principal_id: &str, anchor: Anchor) -> Self {
        Self {
            id: principal_id.to_owned(),
            anchor,
            clock: system_clock,
            patch_cap: DEFAULT_PATCH_CAP,
            held: None,
            dead: BTreeMap::new(),
        }
    }

    /// A record holding `entries` and the action-only bundles `actions`,
    /// replayed from `anchor`: how a holder that keeps the chain itself (a
    /// peer's store) opens a record to pull with.
    ///
    /// # Errors
    ///
    /// The [`PeerFailure`] of the first entry that does not replay from the
    /// anchor.
    pub async fn from_entries(
        principal_id: &str,
        anchor: Anchor,
        clock: Clock,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
    ) -> Result<Self, PeerFailure> {
        let mut record = Self::new(principal_id, anchor).with_clock(clock);
        if !entries.is_empty() {
            record.held = Some(record.replay_full(entries, actions).await?);
        }
        Ok(record)
    }

    /// Replay with `clock` instead of the system clock (which reads 0 on
    /// wasm32).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Refuse any one peer's patch longer than `cap` entries.
    #[must_use]
    pub fn with_patch_cap(mut self, cap: usize) -> Self {
        self.patch_cap = cap;
        self
    }

    /// The tip the record holds; `None` before the first verified pull.
    #[must_use]
    pub fn tip(&self) -> Option<RecordTip> {
        let held = self.held.as_ref()?;
        Some(RecordTip {
            commits: held.ids.len(),
            pr: held.principal.pr_tagged().ok()?,
            commit_id: held.ids.last().and_then(commit_id)?,
        })
    }

    /// The anchor the record replays from.
    #[must_use]
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    /// The subject the replayed chain names: the bare digest of its PG (or,
    /// for a principal with no genesis commit, its PR) in the algorithm the
    /// record was pinned under. Read from the replay, not from the id the
    /// record was opened with; replay refuses a chain that does not name
    /// that id, so the two agree. `None` before the first verified pull.
    #[must_use]
    pub fn subject(&self) -> Option<String> {
        let principal = &self.held.as_ref()?.principal;
        let want = self.bare_id();
        let named = |tagged: String| {
            let (_, bare) = tagged.split_once(':')?;
            names_pg(want, bare).then(|| bare.to_owned())
        };
        if let Some(pg) = principal.pg() {
            let digest = pg.as_multihash();
            if let Some(bare) = digest
                .algorithms()
                .filter_map(|alg| digest.tagged(alg).ok())
                .find_map(|t| named(t.to_string()))
            {
                return Some(bare);
            }
        }
        principal.pr_tagged().ok().and_then(named)
    }

    /// The principal this record is of, as given to [`Record::new`].
    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.id
    }

    /// The tagged id of the commit at `index`, if the record holds one.
    #[must_use]
    pub fn commit_id_at(&self, index: usize) -> Option<String> {
        self.held.as_ref()?.ids.get(index).and_then(commit_id)
    }

    /// The verified entries, in chain order.
    #[must_use]
    pub fn entries(&self) -> &[PatchEntry] {
        self.held.as_ref().map_or(&[], |h| h.entries.as_slice())
    }

    /// How many bundles the record has replayed. Take it before a pull and
    /// pass it to [`bundles_since`](Self::bundles_since) after, to learn
    /// what the pull added.
    #[must_use]
    pub fn log_len(&self) -> usize {
        self.held.as_ref().map_or(0, |h| h.log.len())
    }

    /// The bundles replayed after the first `mark` (see
    /// [`log_len`](Self::log_len)), in replay order, action-only bundles
    /// before the commit they precede. A record only ever grows by chains
    /// that agree with what it held, so the first `mark` bundles are
    /// unchanged.
    #[must_use]
    pub fn bundles_since(&self, mark: usize) -> &[WireBundle] {
        self.held
            .as_ref()
            .and_then(|h| h.log.get(mark..))
            .unwrap_or(&[])
    }

    /// Whether `tmb` is an active key of the record's chain with no
    /// verified naked revoke.
    #[must_use]
    pub fn is_key_active(&self, tmb: &Thumbprint) -> bool {
        !self.dead.contains_key(&tmb.to_b64())
            && self
                .held
                .as_ref()
                .is_some_and(|h| h.principal.is_key_active(tmb))
    }

    /// The record's key `tmb` as the replayed chain holds it, active or
    /// not: how a relying party reads the public half it verifies against.
    #[must_use]
    pub fn key(&self, tmb: &Thumbprint) -> Option<&Key> {
        self.held.as_ref()?.principal.get_key(tmb)
    }

    /// Whether the replayed chain's lifecycle state is `Active` (not
    /// frozen, deleted or errored by a fork). `false` before the first pull.
    #[must_use]
    pub fn is_principal_active(&self) -> bool {
        self.held.as_ref().is_some_and(|h| {
            h.principal.lifecycle_state() == cyphr::lifecycle::LifecycleState::Active
        })
    }

    /// The newest `now` any signed message of the replayed chain carries:
    /// the principal's own latest word on time.
    #[must_use]
    pub fn latest_now(&self) -> Option<i64> {
        self.bundles_since(0)
            .iter()
            .flat_map(|b| b.cozies().chain(b.actions.iter().map(Vec::as_slice)))
            .filter_map(|blob| serde_json::from_slice::<Value>(blob).ok())
            .filter_map(|coz| coz["pay"]["now"].as_i64())
            .max()
    }

    /// The principal the record has replayed; `None` before the first
    /// verified pull.
    #[must_use]
    pub fn principal(&self) -> Option<&Principal<MemoryStorage>> {
        self.held.as_ref().map(|h| &h.principal)
    }

    /// The keys with a verified naked revoke, and each `rvk`.
    pub fn dead_keys(&self) -> impl Iterator<Item = (&str, i64)> {
        self.dead.iter().map(|(tmb, rvk)| (tmb.as_str(), *rvk))
    }

    fn bare_id(&self) -> &str {
        self.id.split_once(':').map_or(&self.id, |(_, bare)| bare)
    }

    /// The chain `entries` form from the anchor, replayed from scratch.
    async fn replay_full(
        &self,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
    ) -> Result<Held, PeerFailure> {
        let root = match &self.anchor {
            Anchor::GenesisKey(key) => key.clone(),
            Anchor::GenesisCommit(_) => opener_key(entries)?,
        };
        let mut principal = Principal::implicit(root.clone())
            .await
            .map_err(|source| PeerFailure::Replay { commit: 0, source })?;
        principal.set_clock(self.clock);
        let named_by_key = principal
            .pr_tagged()
            .is_ok_and(|pr| names_pg(self.bare_id(), &pr));
        let mut held = Held {
            root,
            principal,
            entries: Vec::with_capacity(entries.len()),
            ids: Vec::with_capacity(entries.len()),
            actions: Vec::new(),
            log: Vec::new(),
        };
        held.replay(entries, actions).await?;
        if let Anchor::GenesisCommit(want) = &self.anchor
            && held.ids.first().and_then(commit_id).as_ref() != Some(want)
        {
            return Err(PeerFailure::AnchorMismatch);
        }
        if !named_by_key && !pg_names(&held.principal, self.bare_id()) {
            return Err(PeerFailure::PrincipalMismatch {
                id: self.id.clone(),
            });
        }
        Ok(held)
    }
}

impl Held {
    /// Replay `entries` (the commits after the ones held) and the action
    /// bundles that go with them onto this chain, in the order they were
    /// accepted.
    async fn replay(
        &mut self,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
    ) -> Result<(), PeerFailure> {
        for step in replay_order(self.ids.len(), entries, actions) {
            match step {
                Step::Commit(index, entry) => {
                    let bundle = entry.bundle.as_ref().map_err(|defect| PeerFailure::Entry {
                        index,
                        defect: *defect,
                    })?;
                    let id = replay_entry(&mut self.principal, bundle)
                        .await
                        .map_err(|refusal| entry_failure(index, refusal))?;
                    self.ids.push(id);
                    self.entries.push(entry.clone());
                    self.log.push(bundle.clone());
                },
                Step::Actions(bundle) => {
                    let index = usize::try_from(bundle.after).unwrap_or(usize::MAX);
                    let blobs = bundle.blobs.as_ref().map_err(|defect| PeerFailure::Entry {
                        index,
                        defect: *defect,
                    })?;
                    if self.actions.contains(bundle) {
                        continue;
                    }
                    let only = WireBundle::actions(blobs.clone());
                    replay_entry(&mut self.principal, &only)
                        .await
                        .map_err(|refusal| entry_failure(index, refusal))?;
                    self.actions.push(bundle.clone());
                    self.log.push(only);
                },
            }
        }
        Ok(())
    }

    /// This chain extended by `entries`, on a copy: a patch that does not
    /// replay leaves the record as it was.
    async fn extended(
        &self,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
        clock: Clock,
    ) -> Result<Self, PeerFailure> {
        let mut principal = self
            .principal
            .fork()
            .await
            .map_err(|source| PeerFailure::Replay {
                commit: self.ids.len(),
                source,
            })?;
        principal.set_clock(clock);
        let mut next = Self {
            root: self.root.clone(),
            principal,
            entries: self.entries.clone(),
            ids: self.ids.clone(),
            actions: self.actions.clone(),
            log: self.log.clone(),
        };
        next.replay(entries, actions).await?;
        Ok(next)
    }
}

fn entry_failure(index: usize, refusal: EntryRefusal) -> PeerFailure {
    match refusal {
        EntryRefusal::Malformed(what) => PeerFailure::Malformed {
            commit: index,
            what,
        },
        EntryRefusal::Replay(source) => PeerFailure::Replay {
            commit: index,
            source,
        },
    }
}

/// The key a genesis commit opens with, read from the commit a peer
/// served. It only picks the replay root: the anchor's commit id, checked
/// after replay, is what authenticates it.
fn opener_key(entries: &[PatchEntry]) -> Result<Key, PeerFailure> {
    let malformed = |what| PeerFailure::Malformed { commit: 0, what };
    let bundle = entries
        .first()
        .and_then(|e| e.bundle.as_ref().ok())
        .ok_or_else(|| malformed("no genesis commit"))?;
    opener_of(bundle).map_err(malformed)
}

/// The key a genesis commit opens with, as the commit itself discloses it.
/// Reading it authenticates nothing: it is a hint a verifier may adopt as
/// its anchor, never proof the commit is the principal's.
///
/// # Errors
///
/// What is wrong with the commit as a genesis commit.
pub fn opener_of(genesis: &WireBundle) -> Result<Key, &'static str> {
    let bundle = genesis
        .decode()
        .map_err(|_| "the genesis commit does not decode")?;
    let opener = bundle
        .cozies()
        .next()
        .and_then(|c| c.pay().get("tmb").and_then(Value::as_str))
        .ok_or("the genesis commit has no opener")?;
    bundle
        .introduced_keys()
        .find(|k| k.tmb().to_b64() == opener)
        .cloned()
        .ok_or("the genesis commit does not carry its opener's key")
}

fn commit_id(id: &BundleId) -> Option<String> {
    id.tr.as_ref()?.0.tagged_first().ok().map(|d| d.to_string())
}

fn pr_id(id: &BundleId) -> Option<String> {
    id.pr
        .as_multihash()
        .tagged_first()
        .ok()
        .map(|d| d.to_string())
}

/// One peer to pull from: a label for the report, and its carrier.
pub struct PullPeer<'a, C> {
    /// The peer's name in the report (its address, as the caller knows it).
    pub name: &'a str,
    /// How to reach it.
    pub connector: &'a C,
}

/// Where one peer stands against the verifier's record.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerStanding {
    /// The peer's tip is the record's.
    Current,
    /// The peer was ahead; its `added` commits replayed and now extend the
    /// record.
    Extended {
        /// Commits added to the record.
        added: usize,
    },
    /// The peer's tip is an earlier commit of the record: the peer is
    /// behind (stale), and the record did not change.
    Behind {
        /// Commits the peer holds.
        peer_commits: usize,
    },
    /// The peer's chain diverges from the record's; the [`ForkFinding`] is
    /// in [`PullReport::forks`].
    Forked,
    /// The peer could not be used; nothing it served changed the record.
    Failed(PeerFailure),
}

/// What one peer did, beyond its standing.
#[derive(Debug)]
pub struct PeerOutcome {
    /// The peer's name.
    pub peer: String,
    /// Where it stands.
    pub standing: PeerStanding,
    /// Evidence items it served that did not verify.
    pub rejected_evidence: Vec<EvidenceFailure>,
    /// Naked revokes it served that did not verify.
    pub rejected_revokes: Vec<RevokeFailure>,
    /// Why its naked revokes could not be fetched, if they could not.
    pub revoke_fetch: Option<PatchFailure>,
}

/// Two commits over one `pre`: the principal forked (SPEC 15.8). The state
/// is `Error` until a commit on one branch, or a resync, resolves it.
#[derive(Debug, Clone)]
pub struct ForkFinding {
    /// The commit position both commits take.
    pub height: usize,
    /// The Principal Root both extend; `None` at height 0.
    pub pre: Option<String>,
    /// The ids of the two commits.
    pub commits: [String; 2],
    /// The commit that is not the record's, for a holder that keeps
    /// branches. It verified against the record's chain at `pre`.
    pub rival: WireBundle,
}

/// A key a verified naked revoke made inactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedKey {
    /// The revoked key.
    pub tmb: Thumbprint,
    /// The revocation time the revoke declared.
    pub rvk: i64,
    /// The first peer that served the revoke.
    pub peer: String,
    /// The verified envelope (`{pay, sig, key}`), for a holder that keeps
    /// revokes and serves them on.
    pub envelope: Value,
}

/// The classification one [`pull`] reached.
#[derive(Debug, Default)]
pub struct PullReport {
    /// Each peer, in the order given.
    pub peers: Vec<PeerOutcome>,
    /// The forks found. Non-empty means the principal is in `Error`.
    pub forks: Vec<ForkFinding>,
    /// The keys newly made inactive by verified naked revokes.
    pub revoked: Vec<RevokedKey>,
}

/// A peer's branch head, as it claims it. A hint, never evidence.
struct Head {
    tip: String,
    sequence: usize,
    canonical: bool,
}

/// Pull from every peer, in order, into `record`.
///
/// Each peer is asked for its branch heads, the patch from the record's
/// tip, and (after all peers, so late keys are covered) the naked revokes
/// of the record's keys. A peer that fails is reported and skipped; the
/// record changes only by commits that replay and revokes that verify.
pub async fn pull<C: Connector>(record: &mut Record, peers: &[PullPeer<'_, C>]) -> PullReport {
    let mut report = PullReport::default();
    for peer in peers {
        let mut outcome = PeerOutcome {
            peer: peer.name.to_owned(),
            standing: PeerStanding::Current,
            rejected_evidence: Vec::new(),
            rejected_revokes: Vec::new(),
            revoke_fetch: None,
        };
        match pull_commits(record, peer.connector, &mut outcome).await {
            Ok((standing, forks)) => {
                outcome.standing = standing;
                for fork in forks {
                    if !report.forks.iter().any(|f| f.same_fork(&fork)) {
                        report.forks.push(fork);
                    }
                }
            },
            Err(failure) => outcome.standing = PeerStanding::Failed(failure),
        }
        report.peers.push(outcome);
    }
    for (peer, outcome) in peers.iter().zip(&mut report.peers) {
        pull_revokes(record, peer, outcome, &mut report.revoked).await;
    }
    report
}

/// What a holder that keeps branches is handed after `report`, in order:
/// each fork's rival, then the chain of each peer that forked, past the
/// lowest fork position, each commit with the data actions recorded before
/// it (as a rival carries them). A peer on the other side of a fork may have
/// extended its branch or resolved the fork; only its commits past the fork
/// show which.
///
/// Nothing here is verified past what the pull verified: the holder admits
/// or retains each commit only if it verifies, and refuses what it holds.
pub async fn branch_bundles<C: Connector>(
    record: &Record,
    report: &PullReport,
    peers: &[PullPeer<'_, C>],
) -> Vec<WireBundle> {
    let mut bundles: Vec<WireBundle> = report.forks.iter().map(|f| f.rival.clone()).collect();
    let Some(height) = report.forks.iter().map(|f| f.height).min() else {
        return bundles;
    };
    let forked = report
        .peers
        .iter()
        .filter(|o| matches!(o.standing, PeerStanding::Forked));
    for outcome in forked {
        let Some(peer) = peers.iter().find(|p| p.name == outcome.peer) else {
            continue;
        };
        let request = PatchRequest {
            principal_id: &record.id,
            anchor: None,
        };
        // A peer that cannot serve its chain now adds nothing: its fork
        // finding stands on the rival alone.
        let Ok(patch) =
            fetch_patch(peer.connector, &request, BindingPolicy::NotRequired, None).await
        else {
            continue;
        };
        for (index, entry) in patch.entries.iter().enumerate().skip(height + 1) {
            let Ok(mut bundle) = entry.bundle.clone() else {
                break;
            };
            let leading: Vec<Vec<u8>> = patch
                .actions
                .iter()
                .filter(|a| a.after == index as u64)
                .filter_map(|a| a.blobs.clone().ok())
                .flatten()
                .collect();
            bundle.actions.splice(0..0, leading);
            bundles.push(bundle);
        }
    }
    bundles
}

impl ForkFinding {
    fn same_fork(&self, other: &Self) -> bool {
        let sorted = |f: &Self| {
            let mut c = f.commits.clone();
            c.sort();
            c
        };
        self.height == other.height && sorted(self) == sorted(other)
    }
}

async fn fetch_payload<C: Connector>(connector: &C, target: &str) -> Result<Value, PatchFailure> {
    let body = connector.exchange(&Request::get(target)).await?;
    let body: Value = serde_json::from_slice(&body)
        .map_err(|err| PatchFailure::MalformedResponse(err.to_string()))?;
    let found = body
        .get("v")
        .and_then(Value::as_u64)
        .ok_or_else(|| PatchFailure::MalformedResponse("v missing or not an integer".into()))?;
    if found != crate::patch::ENVELOPE_VERSION {
        return Err(PatchFailure::UnsupportedVersion {
            found,
            supported: crate::patch::ENVELOPE_VERSION,
        });
    }
    body.get("payload")
        .cloned()
        .ok_or_else(|| PatchFailure::MalformedResponse("payload missing".into()))
}

fn parse_heads(payload: &Value) -> Result<Vec<Head>, PatchFailure> {
    let malformed = |what: &str| PatchFailure::MalformedResponse(format!("branches: {what}"));
    payload
        .get("branches")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("not an array"))?
        .iter()
        .map(|b| {
            Ok(Head {
                tip: b
                    .get("tip")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("no tip"))?
                    .to_owned(),
                sequence: b
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .and_then(|s| usize::try_from(s).ok())
                    .ok_or_else(|| malformed("no sequence"))?,
                canonical: b.get("canonical").and_then(Value::as_bool).unwrap_or(false),
            })
        })
        .collect()
}

/// Fetch and classify one peer's chain against the record.
async fn pull_commits<C: Connector>(
    record: &mut Record,
    connector: &C,
    outcome: &mut PeerOutcome,
) -> Result<(PeerStanding, Vec<ForkFinding>), PeerFailure> {
    let heads = parse_heads(
        &fetch_payload(
            connector,
            &format!("/branches?pr={}", percent_encode_query_value(&record.id)),
        )
        .await?,
    )?;
    let canonical = heads.iter().find(|h| h.canonical);

    let (standing, mut forks) = match (&record.held, canonical) {
        (_, None) => (PeerStanding::Behind { peer_commits: 0 }, Vec::new()),
        (Some(held), Some(head))
            if held.ids.get(head.sequence).and_then(commit_id).as_ref() == Some(&head.tip) =>
        {
            let standing = if head.sequence + 1 == held.ids.len() {
                PeerStanding::Current
            } else {
                PeerStanding::Behind {
                    peer_commits: head.sequence + 1,
                }
            };
            (standing, Vec::new())
        },
        _ => reach(record, connector).await?,
    };
    if heads.len() > 1 {
        evidence(record, connector, outcome, &mut forks).await;
    }
    Ok((standing, forks))
}

fn check_cap(record: &Record, offered: usize) -> Result<(), PeerFailure> {
    if offered > record.patch_cap {
        return Err(PeerFailure::PatchTooLarge {
            offered,
            cap: record.patch_cap,
        });
    }
    Ok(())
}

/// The peer's canonical head is not one the record holds: fetch what is
/// past the record's tip, or the whole chain if the peer lacks that tip.
async fn reach<C: Connector>(
    record: &mut Record,
    connector: &C,
) -> Result<(PeerStanding, Vec<ForkFinding>), PeerFailure> {
    if let Some(held) = &record.held {
        let tip = held
            .principal
            .pr_tagged()
            .map_err(|source| PeerFailure::Replay {
                commit: held.ids.len(),
                source,
            })?;
        let request = PatchRequest {
            principal_id: &record.id,
            anchor: Some(&tip),
        };
        match fetch_patch(connector, &request, BindingPolicy::NotRequired, None).await {
            Ok(patch) => {
                check_cap(record, patch.entries.len())?;
                if patch.entries.is_empty() && patch.actions.is_empty() {
                    return Ok((PeerStanding::Current, Vec::new()));
                }
                let next = held
                    .extended(&patch.entries, &patch.actions, record.clock)
                    .await?;
                record.held = Some(next);
                return Ok((
                    PeerStanding::Extended {
                        added: patch.entries.len(),
                    },
                    Vec::new(),
                ));
            },
            // The peer does not hold the record's tip, so it is behind or
            // on another branch: only the whole chain can tell which.
            Err(PatchFailure::NonSuccess(_)) => {},
            Err(other) => return Err(other.into()),
        }
    }
    compare_whole_chain(record, connector).await
}

/// How a peer's whole chain relates to the record's.
enum Relation {
    Equal,
    /// The peer's chain is a proper prefix of the record's.
    Behind,
    /// The record's chain is a proper prefix of the peer's.
    Ahead,
    /// First position at which both hold a different bundle.
    Diverges(usize),
}

/// Whether two replayed bundles are the same step of a chain. A commit is
/// named by its TR and the PR it leads to: the actions a bundle carries
/// inline are recorded data, and a peer that holds them as bundles of their
/// own holds the same commit, though the bundle's coz digests differ.
fn same_step(m: &BundleId, t: &BundleId) -> bool {
    match (&m.tr, &t.tr) {
        (Some(a), Some(b)) => a == b && m.pr == t.pr,
        _ => m == t,
    }
}

fn relate(mine: &[BundleId], theirs: &[BundleId]) -> Relation {
    if let Some(at) = mine.iter().zip(theirs).position(|(m, t)| !same_step(m, t)) {
        return Relation::Diverges(at);
    }
    match mine.len().cmp(&theirs.len()) {
        std::cmp::Ordering::Equal => Relation::Equal,
        std::cmp::Ordering::Greater => Relation::Behind,
        std::cmp::Ordering::Less => Relation::Ahead,
    }
}

async fn compare_whole_chain<C: Connector>(
    record: &mut Record,
    connector: &C,
) -> Result<(PeerStanding, Vec<ForkFinding>), PeerFailure> {
    let request = PatchRequest {
        principal_id: &record.id,
        anchor: None,
    };
    let patch = fetch_patch(connector, &request, BindingPolicy::NotRequired, None).await?;
    check_cap(record, patch.entries.len())?;
    if patch.entries.is_empty() {
        return Ok((PeerStanding::Behind { peer_commits: 0 }, Vec::new()));
    }
    // Replayed from the anchor, never from the record: the peer's chain
    // must stand on its own signatures.
    let theirs = record.replay_full(&patch.entries, &patch.actions).await?;
    let Some(mine) = &record.held else {
        let added = theirs.ids.len();
        record.held = Some(theirs);
        return Ok((PeerStanding::Extended { added }, Vec::new()));
    };
    match relate(&mine.ids, &theirs.ids) {
        Relation::Equal => Ok((PeerStanding::Current, Vec::new())),
        Relation::Behind => Ok((
            PeerStanding::Behind {
                peer_commits: theirs.ids.len(),
            },
            Vec::new(),
        )),
        Relation::Ahead => {
            let added = theirs.ids.len() - mine.ids.len();
            record.held = Some(theirs);
            Ok((PeerStanding::Extended { added }, Vec::new()))
        },
        Relation::Diverges(at) => {
            let (Some(ours), Some(rival)) = (commit_id(&mine.ids[at]), commit_id(&theirs.ids[at]))
            else {
                return Err(PeerFailure::Fork { index: at });
            };
            // One commit, different attached actions: the chains disagree
            // but no commit forked, so it is no finding.
            if ours == rival {
                return Err(PeerFailure::Fork { index: at });
            }
            let mut bundle = theirs.entries[at]
                .bundle
                .clone()
                .map_err(|defect| PeerFailure::Entry { index: at, defect })?;
            // The actions that precede the rival go with it, so a holder
            // that keeps the branch can replay it.
            let leading: Vec<Vec<u8>> = theirs
                .actions
                .iter()
                .filter(|a| a.after == at as u64)
                .filter_map(|a| a.blobs.clone().ok())
                .flatten()
                .collect();
            bundle.actions.splice(0..0, leading);
            let finding = ForkFinding {
                height: at,
                pre: at.checked_sub(1).and_then(|i| pr_id(&mine.ids[i])),
                commits: [ours, rival],
                rival: bundle,
            };
            Ok((PeerStanding::Forked, vec![finding]))
        },
    }
}

/// A peer that retains more than one branch serves the proof: fork
/// evidence the verifier replays from its own chain.
async fn evidence<C: Connector>(
    record: &Record,
    connector: &C,
    outcome: &mut PeerOutcome,
    forks: &mut Vec<ForkFinding>,
) {
    let Some(held) = &record.held else { return };
    let target = format!("/evidence?pr={}", percent_encode_query_value(&record.id));
    let Ok(payload) = fetch_payload(connector, &target).await else {
        outcome.rejected_evidence.push(EvidenceFailure::Malformed(
            "the evidence could not be fetched",
        ));
        return;
    };
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        outcome
            .rejected_evidence
            .push(EvidenceFailure::Malformed("items is not an array"));
        return;
    };
    for item in items.iter().take(MAX_EVIDENCE_ITEMS) {
        let verified = async {
            let mut base = Principal::implicit(held.root.clone())
                .await
                .map_err(|source| EvidenceFailure::Replay { commit: 0, source })?;
            base.set_clock(record.clock);
            let proof = verify_principal_fork_with_actions(
                item,
                record.bare_id(),
                base,
                &held.entries,
                &held.actions,
            )
            .await?;
            let EvidenceItem::PrincipalFork { a, b, .. } = EvidenceItem::parse(item)?;
            let height = usize::try_from(proof.height).unwrap_or(usize::MAX);
            let mine = held.ids.get(height).and_then(commit_id);
            let rival = if mine.as_ref() == Some(&proof.commits[1]) {
                a
            } else {
                b
            };
            Ok(ForkFinding {
                height,
                pre: proof.pre,
                commits: proof.commits,
                rival,
            })
        }
        .await;
        match verified {
            Ok(finding) => forks.push(finding),
            Err(failure) => outcome.rejected_evidence.push(failure),
        }
    }
}

/// Fetch the naked revokes `connector` holds for `tmbs`, as served and
/// unverified: pass each through [`verify_naked_revoke`] (or
/// [`PeerChain::observe_naked_revoke`](crate::PeerChain::observe_naked_revoke))
/// before believing it.
///
/// # Errors
///
/// A [`PatchFailure`] when the peer cannot be reached or does not answer in
/// the envelope shape.
pub async fn fetch_revoked<C: Connector>(
    connector: &C,
    tmbs: &[Thumbprint],
) -> Result<Vec<Value>, PatchFailure> {
    let list = tmbs
        .iter()
        .map(Thumbprint::to_b64)
        .collect::<Vec<_>>()
        .join(",");
    let target = format!("/revoked?tmbs={}", percent_encode_query_value(&list));
    fetch_payload(connector, &target)
        .await?
        .get("revoked")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| PatchFailure::MalformedResponse("revoked is not an array".into()))
}

async fn pull_revokes<C: Connector>(
    record: &mut Record,
    peer: &PullPeer<'_, C>,
    outcome: &mut PeerOutcome,
    revoked: &mut Vec<RevokedKey>,
) {
    let Some(held) = &record.held else { return };
    let asked: Vec<Thumbprint> = held
        .principal
        .active_keys()
        .map(|k| k.tmb().clone())
        .filter(|t| !record.dead.contains_key(&t.to_b64()))
        .collect();
    for batch in asked.chunks(REVOKE_BATCH) {
        let envelopes = match fetch_revoked(peer.connector, batch).await {
            Ok(envelopes) => envelopes,
            Err(failure) => {
                outcome.revoke_fetch = Some(failure);
                return;
            },
        };
        for envelope in &envelopes {
            match verify_naked_revoke(envelope) {
                // Only keys the record holds are recorded: a peer cannot
                // grow the record's memory with revokes of strangers.
                Ok(revoke) if batch.contains(&revoke.tmb) => {
                    let known = record.dead.get(&revoke.tmb.to_b64()).copied();
                    if known.is_none_or(|rvk| revoke.rvk < rvk) {
                        record.dead.insert(revoke.tmb.to_b64(), revoke.rvk);
                    }
                    if known.is_none() {
                        revoked.push(RevokedKey {
                            tmb: revoke.tmb,
                            rvk: revoke.rvk,
                            peer: peer.name.to_owned(),
                            envelope: envelope.clone(),
                        });
                    }
                },
                Ok(_) => {},
                Err(failure) => outcome.rejected_revokes.push(failure),
            }
        }
    }
}
