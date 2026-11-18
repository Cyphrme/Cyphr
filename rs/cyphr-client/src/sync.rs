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
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use coz::Thumbprint;
use cyphr::eml::MemoryStorage;
use cyphr::fork::Held as HeldCommit;
use cyphr::principal::{Clock, system_clock};
use cyphr::proof::Root;
use cyphr::replay::WireBundle;
use cyphr::{Commit, Key, Principal, StateDigest as _};
use serde_json::Value;

use crate::connector::{BindingPolicy, Connector, Request};
use crate::evidence::{EvidenceFailure, names_pg, pg_names, verify_fork_items};
use crate::extension::{Extension, ExtensionFailure, confirm_extension, verify_extension_at};
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
    /// Where the commits a [`resume`](Record::resume)d record holds only as
    /// verified state are stored.
    source: Option<Arc<dyn ChainSource>>,
    /// Naked-revoked keys, by thumbprint, each with its cutoff: the record's
    /// clock when it accepted the first revoke of the key.
    dead: BTreeMap<String, i64>,
    /// Commits this record has run through the core, whether the chain they
    /// built was kept or compared and dropped: what a pull cost in protocol
    /// checks, for a test or a metric to hold to "only what is new".
    replayed: AtomicU64,
}

struct Held {
    principal: Principal<MemoryStorage>,
    /// How many commits were verified before this record opened (its
    /// [`resume`](Record::resume) state): their entries are not held here,
    /// the record's [`ChainSource`] has them. 0 for a record built by
    /// replay.
    base: usize,
    /// The entries of the commits replayed since `base`, in chain order.
    entries: Vec<PatchEntry>,
    /// Every bundle replayed since the record opened, commits and
    /// action-only bundles, in replay order: what a holder that keeps the
    /// chain must store to catch up.
    log: Vec<WireBundle>,
}

/// Where the chain a resumed [`Record`] does not hold is stored. The
/// record needs it only to read the commits below a fork point, to check
/// a peer's evidence against; everything else it asks of its verified
/// state. What it reads is replayed by the core like anything a peer
/// serves, so the source is no more trusted than a peer.
pub trait ChainSource: Send + Sync {
    /// The first `count` stored commits, in chain order, or why they
    /// cannot be read.
    fn first(
        &self,
        count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<PatchEntry>, String>> + Send + '_>>;
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
            source: None,
            dead: BTreeMap::new(),
            replayed: AtomicU64::new(0),
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

    /// A record of `principal_id` that starts from `principal`, a state
    /// already verified (the engine's kept state, or a client's own), so
    /// a pull verifies only what is past its tip: O(new), where
    /// [`from_entries`](Self::from_entries) replays the chain. The anchor
    /// is the genesis commit the state itself holds.
    ///
    /// The commits the state covers are not held as entries, so
    /// [`entries`](Self::entries) and [`bundles_since`](Self::bundles_since)
    /// cover what the record replays after this, and `source` answers for
    /// the rest when a peer's fork evidence needs them.
    ///
    /// # Errors
    ///
    /// [`PeerFailure::PrincipalMismatch`] if `principal` is not the
    /// principal `principal_id` names, or holds no commit.
    pub fn resume(
        principal_id: &str,
        mut principal: Principal<MemoryStorage>,
        clock: Clock,
        source: Arc<dyn ChainSource>,
    ) -> Result<Self, PeerFailure> {
        let mut record = Self::new(principal_id, Anchor::GenesisCommit(String::new()));
        let mismatch = || PeerFailure::PrincipalMismatch {
            id: principal_id.to_owned(),
        };
        let genesis = principal
            .commit_at(0)
            .and_then(commit_id_of)
            .ok_or_else(mismatch)?;
        if !pg_names(&principal, record.bare_id()) {
            return Err(mismatch());
        }
        principal.set_clock(clock);
        record.anchor = Anchor::GenesisCommit(genesis);
        record.clock = clock;
        record.source = Some(source);
        record.held = Some(Held {
            base: principal.commit_count(),
            principal,
            entries: Vec::new(),
            log: Vec::new(),
        });
        Ok(record)
    }

    /// How many commits this record has run through the core, over its
    /// lifetime. A pull of a record that already holds the chain adds only
    /// the commits past its tip; a rebuild adds the whole chain.
    #[must_use]
    pub fn replayed(&self) -> u64 {
        self.replayed.load(Ordering::Relaxed)
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
            commits: held.principal.commit_count(),
            pr: held.principal.pr_tagged().ok()?,
            commit_id: held.principal.commits().last().and_then(commit_id_of)?,
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
        self.held.as_ref()?.commit_id_at(index)
    }

    /// The commits of the record's chain from position `from` up, as the
    /// protocol's fork rule reads them ([`cyphr::fork::assessment`]). A
    /// commit the record holds only as verified state has no signers here.
    #[must_use]
    pub fn commits_from(&self, from: usize) -> Vec<HeldCommit> {
        let Some(held) = &self.held else {
            return Vec::new();
        };
        let pr_of = |index: usize| {
            held.principal
                .commit_at(index)
                .and_then(|c| c.pr().as_multihash().tagged_first().ok())
                .map(|d| d.to_string())
        };
        (from..held.principal.commit_count())
            .filter_map(|index| {
                let signed = index
                    .checked_sub(held.base)
                    .and_then(|i| held.entries.get(i))
                    .and_then(|e| e.bundle.as_ref().ok())
                    .map_or_else(Vec::new, signers);
                Some(HeldCommit {
                    sequence: index as u64,
                    id: held.commit_id_at(index)?,
                    pre: index.checked_sub(1).and_then(pr_of),
                    pr: pr_of(index)?,
                    signed,
                })
            })
            .collect()
    }

    /// The entries of the commits this record replayed, in chain order: all
    /// of them for a record built by replay, only those after its state for
    /// a [`resume`](Self::resume)d one.
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

    /// The thumbprints of the keys a naked revoke could still change:
    /// every key the chain ever held, active or not (the owner removing a
    /// key does not make its revoke any less news to a holder that never
    /// heard it), less the keys with a verified revoke already. What
    /// [`pull`] asks each peer about, and what a holder that skips a pull
    /// must ask about instead.
    #[must_use]
    pub fn unrevoked_keys(&self) -> Vec<Thumbprint> {
        self.held.as_ref().map_or_else(Vec::new, |h| {
            h.principal
                .ever_held_keys()
                .into_iter()
                .filter(|t| !self.dead.contains_key(&t.to_b64()))
                .collect()
        })
    }

    /// Note `tmb` as already revoked, on the strength of a revoke this
    /// holder verified and keeps elsewhere, so [`Self::unrevoked_keys`]
    /// stops asking about it. Its cutoff here is the record's own clock,
    /// as for a revoke a pull accepts; a key already noted keeps its
    /// first cutoff.
    pub fn note_revoked(&mut self, tmb: &Thumbprint) {
        let now = (self.clock)();
        self.dead.entry(tmb.to_b64()).or_insert(now);
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

    /// The keys with a verified naked revoke, and each key's cutoff: the
    /// record's own clock at the first revoke of it accepted, never the
    /// revoke's `rvk` (SPEC 14.12).
    pub fn dead_keys(&self) -> impl Iterator<Item = (&str, i64)> {
        self.dead
            .iter()
            .map(|(tmb, cutoff)| (tmb.as_str(), *cutoff))
    }

    /// The entries of every commit the record holds, in chain order: those
    /// below a resumed record's state read from its [`ChainSource`].
    async fn chain_entries(&self) -> Result<Vec<PatchEntry>, &'static str> {
        let held = self.held.as_ref().ok_or("the record holds no chain")?;
        let mut entries = Vec::new();
        if held.base > 0 {
            let source = self
                .source
                .as_ref()
                .ok_or("the record's stored chain is not available")?;
            entries = source
                .first(held.base)
                .await
                .map_err(|_| "the record's stored chain could not be read")?;
            if entries.len() != held.base {
                return Err("the record's stored chain is shorter than its state");
            }
        }
        entries.extend(held.entries.iter().cloned());
        Ok(entries)
    }

    /// Extend the held chain by `entries` and `actions`, all or nothing.
    async fn extend(
        &mut self,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
        claim: Option<&Extension>,
    ) -> Result<(), PeerFailure> {
        let Some(held) = &mut self.held else {
            self.held = Some(self.replay_full(entries, actions).await?);
            return Ok(());
        };
        held.extend(entries, actions, claim, self.clock, &self.replayed)
            .await
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
        let mut principal = Principal::implicit(root)
            .await
            .map_err(|source| PeerFailure::Replay { commit: 0, source })?;
        principal.set_clock(self.clock);
        let named_by_key = principal
            .pr_tagged()
            .is_ok_and(|pr| names_pg(self.bare_id(), &pr));
        let mut held = Held {
            principal,
            base: 0,
            entries: Vec::with_capacity(entries.len()),
            log: Vec::new(),
        };
        held.replay(entries, actions, &self.replayed).await?;
        if let Anchor::GenesisCommit(want) = &self.anchor
            && held.commit_id_at(0).as_ref() != Some(want)
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
        tally: &AtomicU64,
    ) -> Result<(), PeerFailure> {
        for step in replay_order(self.principal.commit_count(), entries, actions) {
            match step {
                Step::Commit(index, entry) => {
                    let bundle = entry.bundle.as_ref().map_err(|defect| PeerFailure::Entry {
                        index,
                        defect: *defect,
                    })?;
                    replay_entry(&mut self.principal, bundle)
                        .await
                        .map_err(|refusal| entry_failure(index, refusal))?;
                    tally.fetch_add(1, Ordering::Relaxed);
                    self.entries.push(entry.clone());
                    self.log.push(bundle.clone());
                },
                Step::Actions(bundle) => {
                    let index = self.principal.commit_count();
                    let blobs = bundle.blobs.as_ref().map_err(|defect| PeerFailure::Entry {
                        index,
                        defect: *defect,
                    })?;
                    let only = WireBundle::actions(blobs.clone());
                    // A bundle already held is not replayed twice: a peer
                    // serves every action it holds with each patch.
                    if self.holds_actions(&only) {
                        continue;
                    }
                    replay_entry(&mut self.principal, &only)
                        .await
                        .map_err(|refusal| entry_failure(index, refusal))?;
                    self.log.push(only);
                },
            }
        }
        Ok(())
    }

    /// Whether every head is a commit this chain holds.
    fn holds_all(&self, heads: &[Head]) -> bool {
        heads
            .iter()
            .all(|h| self.commit_id_at(h.sequence).as_deref() == Some(h.tip.as_str()))
    }

    /// The tagged id of the commit at `index`.
    fn commit_id_at(&self, index: usize) -> Option<String> {
        self.principal.commit_at(index).and_then(commit_id_of)
    }

    /// Whether every action of `only` is one the principal already holds.
    fn holds_actions(&self, only: &WireBundle) -> bool {
        let Ok(decoded) = only.decode() else {
            return false;
        };
        let actions = decoded.action_cozies();
        !actions.is_empty()
            && actions
                .iter()
                .all(|a| self.principal.has_included(a.czd().as_bytes()))
    }

    /// Each commit as the pair a chain is compared by.
    fn links(&self) -> Vec<Link> {
        self.principal
            .commits()
            .map(|c| Link {
                tr: c.tr().clone(),
                pr: c.pr().clone(),
            })
            .collect()
    }

    /// Extend this chain by `entries` and `actions`, all or nothing: the
    /// replay runs on a copy of the principal and the held lists grow only
    /// as it succeeds, so a patch that does not replay leaves the record as
    /// it was without copying what it already holds.
    async fn extend(
        &mut self,
        entries: &[PatchEntry],
        actions: &[ActionBundle],
        claim: Option<&Extension>,
        clock: Clock,
        tally: &AtomicU64,
    ) -> Result<(), PeerFailure> {
        let mut principal = self
            .principal
            .fork()
            .await
            .map_err(|source| PeerFailure::Replay {
                commit: self.principal.commit_count(),
                source,
            })?;
        principal.set_clock(clock);
        let before = (self.entries.len(), self.log.len());
        std::mem::swap(&mut self.principal, &mut principal);
        // The claim is held to the replayed log before the chain is kept, so
        // a claim the commits contradict leaves the chain as it was.
        let replayed = match self.replay(entries, actions, tally).await {
            Ok(()) => claim.map_or(Ok(()), |c| {
                confirm_extension(&self.principal, c).map_err(PeerFailure::from)
            }),
            failed => failed,
        };
        if replayed.is_err() {
            std::mem::swap(&mut self.principal, &mut principal);
            self.entries.truncate(before.0);
            self.log.truncate(before.1);
        }
        replayed
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

fn commit_id_of(commit: &Commit) -> Option<String> {
    commit.tr().0.tagged_first().ok().map(|d| d.to_string())
}

/// What names a commit for comparing two chains: its TR and the PR it
/// leads to. The actions a commit carries inline are recorded data, and a
/// peer that holds them as bundles of their own holds the same commit.
#[derive(PartialEq, Eq)]
struct Link {
    tr: cyphr::TransactionRoot,
    pr: cyphr::PrincipalRoot,
}

fn pr_id_of(link: &Link) -> Option<String> {
    link.pr
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
    /// The revocation time the revoke declared. Informational: the key's
    /// cutoff is the receiver's own clock, not this (SPEC 14.12).
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
    /// Commits a peer serves as evidence that extend a fork's rival,
    /// each verified on the rival's branch, lowest first per branch.
    pub extensions: Vec<WireBundle>,
    /// The commits the pull verified off the record's chain: each fork's
    /// rival and the commits past it, as the protocol's fork rule reads
    /// them ([`cyphr::fork::assessment`]).
    pub branches: Vec<HeldCommit>,
}

/// A peer's branch head, as it claims it. A hint, never evidence.
struct Head {
    tip: String,
    sequence: usize,
    canonical: bool,
}

/// The view a peer states of one principal: the commit ids it lists as
/// heads. A plain value, so the idle predicate does not care where it
/// came from; today the source is the peer's `/branches`, pending the
/// shape of gossip messages (GitHub #211).
pub struct PeerHeads(Vec<Head>);

impl PeerHeads {
    /// Whether the peer has nothing to teach the holder: every head it
    /// lists, on its canonical chain or as a retained branch, is a commit
    /// `holds` says the holder has. The one idle predicate, asked by
    /// [`pull`] of the record it replayed and by a holder that keeps the
    /// chain itself (a server's gossip gate) of its own store.
    ///
    /// It reads heads only, so it is exactly as blind as the heads: a
    /// peer's data actions that moved no head are invisible to it, as they
    /// are to the pull's own skip (GitHub #211, the spec author's ruling
    /// on data actions is pending).
    #[must_use]
    pub fn idle(&self, holds: impl Fn(&str) -> bool) -> bool {
        Self::idle_of(&self.0, holds)
    }

    fn idle_of(heads: &[Head], holds: impl Fn(&str) -> bool) -> bool {
        heads.iter().all(|h| holds(&h.tip))
    }

    /// The commit ids the peer names as heads.
    pub fn tips(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|h| h.tip.as_str())
    }
}

/// The branch heads `connector` lists for `principal_id`. `None` when the
/// peer does not hold the principal (404): it has nothing to pull from,
/// which is idle.
///
/// # Errors
///
/// A [`PatchFailure`] when the peer cannot be reached or does not answer
/// in the envelope shape.
pub async fn peer_heads<C: Connector>(
    connector: &C,
    principal_id: &str,
) -> Result<Option<PeerHeads>, PatchFailure> {
    let target = format!("/branches?pr={}", percent_encode_query_value(principal_id));
    match fetch_payload(connector, &target).await {
        Ok(payload) => Ok(Some(PeerHeads(parse_heads(&payload)?))),
        Err(PatchFailure::NonSuccess(404)) => Ok(None),
        Err(other) => Err(other),
    }
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
        let mut sink = Sink {
            extensions: &mut report.extensions,
            branches: &mut report.branches,
        };
        match pull_commits(record, peer.connector, &mut outcome, &mut sink).await {
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
/// each fork's rival, the verified commits extending a rival, then the
/// chain of each peer that forked, past the lowest fork position. A peer
/// on the other side of a fork may have extended its branch or resolved
/// the fork; only its commits past the fork show which.
///
/// Of a forked peer's chain, no more is handed on than the record itself
/// holds from the fork up: a branch changes the holder's chain only by
/// out-extending the holder's own, and the rival with that many commits
/// past it does. Once the holder is on the peer's branch, the rest of it
/// is an ordinary extension, verified by the next pull. So what a peer can
/// make the holder submit is bounded by the holder's own chain, however
/// long a chain the peer serves.
///
/// Nothing here is verified past what the pull verified: the holder admits
/// or retains each commit only if it verifies, and refuses what it holds.
pub async fn branch_bundles<C: Connector>(
    record: &Record,
    report: &PullReport,
    peers: &[PullPeer<'_, C>],
) -> Vec<WireBundle> {
    let mut bundles: Vec<WireBundle> = report.forks.iter().map(|f| f.rival.clone()).collect();
    bundles.extend(report.extensions.iter().cloned());
    let Some(height) = report.forks.iter().map(|f| f.height).min() else {
        return bundles;
    };
    let own_past_fork = record
        .held
        .as_ref()
        .map_or(0, |held| held.principal.commit_count())
        .saturating_sub(height);
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
        for entry in patch.entries.iter().skip(height + 1).take(own_past_fork) {
            let Ok(bundle) = entry.bundle.clone() else {
                break;
            };
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

/// Where one peer's pull puts the commits it verified off the record's
/// chain.
struct Sink<'a> {
    extensions: &'a mut Vec<WireBundle>,
    branches: &'a mut Vec<HeldCommit>,
}

/// A verified commit as the protocol's fork rule reads it. The signers are
/// those of the bundle's cozies, in bundle order.
fn held_commit(
    sequence: usize,
    id: String,
    pre: Option<String>,
    pr: String,
    bundle: &WireBundle,
) -> HeldCommit {
    HeldCommit {
        sequence: sequence as u64,
        id,
        pre,
        pr,
        signed: signers(bundle),
    }
}

fn signers(bundle: &WireBundle) -> Vec<String> {
    bundle.decode().map_or_else(
        |_| Vec::new(),
        |b| b.cozies().map(|c| c.header().tmb.to_b64()).collect(),
    )
}

/// Fetch and classify one peer's chain against the record.
async fn pull_commits<C: Connector>(
    record: &mut Record,
    connector: &C,
    outcome: &mut PeerOutcome,
    sink: &mut Sink<'_>,
) -> Result<(PeerStanding, Vec<ForkFinding>), PeerFailure> {
    // The gate treats a peer that lacks the principal as idle; a pull
    // still reports it as the failure it is, so callers that read
    // "answered" keep their meaning.
    let Some(PeerHeads(heads)) = peer_heads(connector, &record.id).await? else {
        return Err(PatchFailure::NonSuccess(404).into());
    };
    let canonical = heads.iter().find(|h| h.canonical);

    let (standing, mut forks) = match (&record.held, canonical) {
        (_, None) => (PeerStanding::Behind { peer_commits: 0 }, Vec::new()),
        (Some(held), Some(head))
            if held.commit_id_at(head.sequence).as_ref() == Some(&head.tip) =>
        {
            let standing = if head.sequence + 1 == held.principal.commit_count() {
                PeerStanding::Current
            } else {
                PeerStanding::Behind {
                    peer_commits: head.sequence + 1,
                }
            };
            (standing, Vec::new())
        },
        _ => reach(record, connector, sink.branches).await?,
    };
    // A peer whose every head is a commit the record holds has no rival
    // branch to prove.
    let idle = record
        .held
        .as_ref()
        .is_some_and(|held| held.holds_all(&heads));
    if heads.len() > 1 && !idle {
        evidence(record, connector, outcome, &mut forks, sink).await;
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
    branches: &mut Vec<HeldCommit>,
) -> Result<(PeerStanding, Vec<ForkFinding>), PeerFailure> {
    let tip = match &record.held {
        Some(held) => Some(
            held.principal
                .pr_tagged()
                .map_err(|source| PeerFailure::Replay {
                    commit: held.principal.commit_count(),
                    source,
                })?,
        ),
        None => None,
    };
    let offered = if tip.is_some() {
        match offered_extension(record, connector).await? {
            Offer::Extends(offer) => Some(offer),
            // A peer's tree is its own word: when no fork can be proved from
            // it (it is fabricated, or the log does extend), the pull goes
            // on without it, so a fork never hides behind what the peer
            // says of its tree.
            Offer::Diverged(head) => match locate_fork(record, connector, &head, branches).await {
                Ok(Some(finding)) => return Ok((PeerStanding::Forked, vec![finding])),
                Ok(None) | Err(_) => None,
            },
            Offer::Unavailable => None,
        }
    } else {
        None
    };
    if let Some(tip) = tip {
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
                record
                    .extend(&patch.entries, &patch.actions, offered.as_deref())
                    .await?;
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
    compare_whole_chain(record, connector, branches).await
}

/// What a peer's answer to a request for the proof that its tip extends
/// the record's comes to.
enum Offer {
    Extends(Box<Extension>),
    /// The head the peer offered, which the held log cannot be shown to
    /// precede.
    Diverged(Root),
    /// The peer cannot say (it serves no such route, or has nothing the
    /// record can be judged against): the pull goes on without a proof.
    Unavailable,
}

/// Ask the peer for its head and the certificate that it extends the
/// record's log, and judge them against the record's own log. The head is
/// the peer's claim: it is checked and never pinned.
async fn offered_extension<C: Connector>(
    record: &Record,
    connector: &C,
) -> Result<Offer, PeerFailure> {
    let Some(held) = &record.held else {
        return Ok(Offer::Unavailable);
    };
    let held_size = held.principal.commit_count() as u64;
    // Whatever stops the answer (no such route, an unreachable peer) is
    // met again by the fetch that follows, which reports it.
    let Ok(payload) = fetch_payload(
        connector,
        &format!("/head?pr={}", percent_encode_query_value(&record.id)),
    )
    .await
    else {
        return Ok(Offer::Unavailable);
    };
    // A peer that answers a route with something that is not a root or a
    // certificate is pulled as one that serves none: every commit is still
    // replayed, so the answer decides only what is fetched, never what is
    // believed.
    let Ok(head) = Extension::head_from_payload(&payload) else {
        return Ok(Offer::Unavailable);
    };
    if head.size <= held_size {
        return Ok(Offer::Diverged(head));
    }
    let target = format!(
        "/consistency?pr={}&from={held_size}&to={}",
        percent_encode_query_value(&record.id),
        head.size
    );
    let Ok(payload) = fetch_payload(connector, &target).await else {
        return Ok(Offer::Unavailable);
    };
    let Ok(certificate) = Extension::certificate_from_payload(&payload) else {
        return Ok(Offer::Unavailable);
    };
    let offer = Extension::new(head, certificate);
    match verify_extension_at(&held.principal, held_size, &offer) {
        Ok(()) => Ok(Offer::Extends(Box::new(offer))),
        Err(ExtensionFailure::NotAnExtension | ExtensionFailure::NotLonger) => {
            Ok(Offer::Diverged(offer.head))
        },
        Err(_) => Ok(Offer::Unavailable),
    }
}

/// Where the peer's log leaves the record's, by extension proofs, and the
/// one commit the peer holds there, proved a fork by its signatures.
///
/// A commit commits to the one before it, so the peer's log extends the
/// record's first `k` commits exactly when the two agree below position
/// `k`, and the first position at which they differ is found in O(log n)
/// asks, each answered by an extension proof (which crosses any algorithm
/// rotation on the way) checked against the record's own log at that size.
/// The peer's answers only steer; what is returned is verified from the
/// record's own chain and the peer's one commit, the way a served fork
/// item is, so a peer's word is never the evidence. `None` when no
/// position within both logs differs.
async fn locate_fork<C: Connector>(
    record: &Record,
    connector: &C,
    head: &Root,
    branches: &mut Vec<HeldCommit>,
) -> Result<Option<ForkFinding>, PeerFailure> {
    let Some(held) = &record.held else {
        return Ok(None);
    };
    let unlocatable = |what: &str| {
        PeerFailure::Extension(ExtensionFailure::Malformed(format!(
            "fork location: {what}"
        )))
    };
    let overlap = held
        .principal
        .commit_count()
        .min(usize::try_from(head.size).unwrap_or(usize::MAX));
    // Whether the peer's log extends the record's first `k` commits. The
    // record pins every size of its own chain, so each answer is checked
    // against what the record holds; the head stays the peer's claim.
    let extends = async |k: usize| -> Result<bool, PeerFailure> {
        if k as u64 == head.size {
            // The same size: the logs are the same exactly when the roots
            // are.
            return Ok(held.principal.root_at(k as u64).as_ref() == Some(head));
        }
        let target = format!(
            "/consistency?pr={}&from={k}&to={}",
            percent_encode_query_value(&record.id),
            head.size
        );
        let payload = fetch_payload(connector, &target).await?;
        let certificate = Extension::certificate_from_payload(&payload)?;
        let offer = Extension::new(head.clone(), certificate);
        match verify_extension_at(&held.principal, k as u64, &offer) {
            Ok(()) => Ok(true),
            Err(ExtensionFailure::NotAnExtension) => Ok(false),
            Err(other) => Err(other.into()),
        }
    };
    if overlap == 0 || extends(overlap).await? {
        return Ok(None);
    }
    let (mut low, mut high) = (0, overlap);
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if extends(mid).await? {
            low = mid;
        } else {
            high = mid;
        }
    }
    let height = low;

    let pre = match height.checked_sub(1) {
        Some(below) => {
            let commit = held
                .principal
                .commit_at(below)
                .ok_or_else(|| unlocatable("no pre"))?;
            let tagged = commit.pr().as_multihash().tagged_first();
            Some(tagged.map_err(|_| unlocatable("no pre"))?.to_string())
        },
        None => None,
    };
    let mut target = format!("/patch?pr={}", percent_encode_query_value(&record.id));
    if let Some(pre) = &pre {
        target.push_str(&format!("&from={}", percent_encode_query_value(pre)));
    }
    target.push_str(&format!("&to={height}"));
    let body = connector
        .exchange(&Request::get(target))
        .await
        .map_err(PatchFailure::from)?;
    let patch = crate::patch::verify_patch_body(&body, &record.id, None)?;
    let [rival] = patch.entries.as_slice() else {
        return Err(unlocatable(
            "the peer did not serve exactly the one commit asked for",
        ));
    };
    let rival = rival.bundle.clone().map_err(|defect| PeerFailure::Entry {
        index: height,
        defect,
    })?;

    let (base, prefix) = fork_context(record).await.map_err(unlocatable)?;
    let ours = prefix
        .get(height)
        .and_then(|e| e.bundle.clone().ok())
        .ok_or_else(|| unlocatable("the record's own commit is unreadable"))?;
    let proved = |rival: &WireBundle| {
        serde_json::json!({
            "kind": "principal-fork",
            "pg": record.bare_id(),
            "height": height,
            "pre": pre,
            "a": ours,
            "b": rival,
        })
    };
    let proof = match crate::evidence::verify_principal_fork(
        &proved(&rival),
        record.bare_id(),
        base,
        &prefix,
    )
    .await
    {
        Ok(proof) => (proof, rival),
        // The commit may name data actions the patch carries apart.
        Err(EvidenceFailure::CommitRefused { .. }) => {
            let mut with_actions = rival.clone();
            for action in &patch.actions {
                if let Ok(blobs) = &action.blobs {
                    with_actions.actions.extend(blobs.iter().cloned());
                }
            }
            let (base, _) = fork_context(record).await.map_err(unlocatable)?;
            let proof = crate::evidence::verify_principal_fork(
                &proved(&with_actions),
                record.bare_id(),
                base,
                &prefix,
            )
            .await
            .map_err(|_| unlocatable("the peer's commit is no fork of the record's"))?;
            (proof, with_actions)
        },
        Err(_) => return Err(unlocatable("the peer's commit is no fork of the record's")),
    };
    // The item named the record's commit `a` and the peer's `b`.
    let [_, id] = proof.0.commits.clone();
    let [_, pr] = proof.0.prs.clone();
    branches.push(held_commit(height, id, proof.0.pre.clone(), pr, &proof.1));
    Ok(Some(ForkFinding {
        height,
        pre: proof.0.pre,
        commits: proof.0.commits,
        rival: proof.1,
    }))
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

/// Whether two commits are the same step of a chain.
fn same_step(m: &Link, t: &Link) -> bool {
    m == t
}

fn relate(mine: &[Link], theirs: &[Link]) -> Relation {
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
    branches: &mut Vec<HeldCommit>,
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
        let added = theirs.principal.commit_count();
        record.held = Some(theirs);
        return Ok((PeerStanding::Extended { added }, Vec::new()));
    };
    let (mine_links, their_links) = (mine.links(), theirs.links());
    match relate(&mine_links, &their_links) {
        Relation::Equal => Ok((PeerStanding::Current, Vec::new())),
        Relation::Behind => Ok((
            PeerStanding::Behind {
                peer_commits: their_links.len(),
            },
            Vec::new(),
        )),
        Relation::Ahead => {
            // The peer's chain stands on its own signatures; the record
            // takes only the commits past its tip, onto the state it has,
            // so what it keeps stays what it verified.
            let held = mine_links.len();
            record
                .extend(&patch.entries[held..], &patch.actions, None)
                .await?;
            Ok((
                PeerStanding::Extended {
                    added: their_links.len() - held,
                },
                Vec::new(),
            ))
        },
        Relation::Diverges(at) => {
            let (Some(ours), Some(rival)) = (mine.commit_id_at(at), theirs.commit_id_at(at)) else {
                return Err(PeerFailure::Fork { index: at });
            };
            // One commit, different attached actions: the chains disagree
            // but no commit forked, so it is no finding.
            if ours == rival {
                return Err(PeerFailure::Fork { index: at });
            }
            let bundle = theirs.entries[at]
                .bundle
                .clone()
                .map_err(|defect| PeerFailure::Entry { index: at, defect })?;
            // The peer's whole chain was replayed: its commits from the
            // fork up are a branch the record does not hold.
            for (index, entry) in theirs.entries.iter().enumerate().skip(at) {
                let (Some(id), Some(pr), Ok(bundle)) = (
                    theirs.commit_id_at(index),
                    their_links.get(index).and_then(pr_id_of),
                    entry.bundle.as_ref(),
                ) else {
                    continue;
                };
                let pre = index
                    .checked_sub(1)
                    .and_then(|i| their_links.get(i))
                    .and_then(pr_id_of);
                branches.push(held_commit(index, id, pre, pr, bundle));
            }
            let finding = ForkFinding {
                height: at,
                pre: at.checked_sub(1).and_then(|i| pr_id_of(&mine_links[i])),
                commits: [ours, rival],
                rival: bundle,
            };
            Ok((PeerStanding::Forked, vec![finding]))
        },
    }
}

/// What a fork is verified against: a principal at the record's genesis
/// and the record's chain, whole.
async fn fork_context(
    record: &Record,
) -> Result<(Principal<MemoryStorage>, Vec<PatchEntry>), &'static str> {
    let prefix = record.chain_entries().await?;
    let root = match &record.anchor {
        Anchor::GenesisKey(key) => Ok(key.clone()),
        Anchor::GenesisCommit(_) => opener_key(&prefix),
    };
    const NOT_OPENED: &str = "the record's genesis does not open a principal";
    let root = root.map_err(|_| NOT_OPENED)?;
    let mut base = Principal::implicit(root).await.map_err(|_| NOT_OPENED)?;
    base.set_clock(record.clock);
    Ok((base, prefix))
}

/// A peer that retains more than one branch serves the proof: fork
/// evidence the verifier replays from its own chain.
async fn evidence<C: Connector>(
    record: &Record,
    connector: &C,
    outcome: &mut PeerOutcome,
    forks: &mut Vec<ForkFinding>,
    sink: &mut Sink<'_>,
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
    let (base, prefix) = match fork_context(record).await {
        Ok(context) => context,
        Err(why) => {
            outcome
                .rejected_evidence
                .push(EvidenceFailure::Malformed(why));
            return;
        },
    };
    let items: Vec<&Value> = items.iter().take(MAX_EVIDENCE_ITEMS).collect();
    let chain_ids: Vec<Option<String>> = held.principal.commits().map(commit_id_of).collect();
    let set = verify_fork_items(&items, record.bare_id(), &base, &prefix, &chain_ids).await;
    for (proof, rival) in set.forks {
        let height = usize::try_from(proof.height).unwrap_or(usize::MAX);
        if let Some((id, pr)) = proof.rival(&chain_ids) {
            sink.branches
                .push(held_commit(height, id, proof.pre.clone(), pr, &rival));
        }
        forks.push(ForkFinding {
            height,
            pre: proof.pre,
            commits: proof.commits,
            rival,
        });
    }
    for e in set.extensions {
        let height = usize::try_from(e.height).unwrap_or(usize::MAX);
        sink.branches
            .push(held_commit(height, e.id, Some(e.pre), e.pr, &e.bundle));
        sink.extensions.push(e.bundle);
    }
    outcome.rejected_evidence.extend(set.rejected);
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
    let asked = record.unrevoked_keys();
    if record.held.is_none() {
        return;
    }
    let found = match verified_revokes(peer.connector, peer.name, &asked).await {
        Ok((found, rejected)) => {
            outcome.rejected_revokes.extend(rejected);
            found
        },
        Err(failure) => {
            outcome.revoke_fetch = Some(failure);
            return;
        },
    };
    for revoke in found {
        // Every Coz-valid revoke is accepted; the first of a key sets its
        // cutoff at our own receipt time, and later ones change nothing.
        if let std::collections::btree_map::Entry::Vacant(slot) =
            record.dead.entry(revoke.tmb.to_b64())
        {
            slot.insert((record.clock)());
            revoked.push(revoke);
        }
    }
}

/// The naked revokes `connector` (named `peer`) serves for `keys`, each
/// verified (SPEC 6.4), and why each other one was refused. Only revokes
/// of keys asked about are kept: a peer cannot grow a holder's memory with
/// revokes of strangers. The pull step and a witness's sync both ask
/// through this.
///
/// # Errors
///
/// A [`PatchFailure`] when the revokes cannot be fetched.
pub async fn verified_revokes<C: Connector>(
    connector: &C,
    peer: &str,
    keys: &[Thumbprint],
) -> Result<(Vec<RevokedKey>, Vec<RevokeFailure>), PatchFailure> {
    let mut found: Vec<RevokedKey> = Vec::new();
    let mut rejected = Vec::new();
    for batch in keys.chunks(REVOKE_BATCH) {
        for envelope in &fetch_revoked(connector, batch).await? {
            match verify_naked_revoke(envelope) {
                // One revoke per key, the first served: a peer that repeats
                // a key's revoke adds nothing.
                Ok(revoke)
                    if batch.contains(&revoke.tmb)
                        && !found.iter().any(|f| f.tmb == revoke.tmb) =>
                {
                    found.push(RevokedKey {
                        tmb: revoke.tmb,
                        rvk: revoke.rvk,
                        peer: peer.to_owned(),
                        envelope: envelope.clone(),
                    });
                },
                Ok(_) => {},
                Err(failure) => rejected.push(failure),
            }
        }
    }
    Ok((found, rejected))
}
