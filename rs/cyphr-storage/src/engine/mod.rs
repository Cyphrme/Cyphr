//! # Storage Engine
//!
//! Coordination layer that joins [`BlobStore`] and [`Indexer`] into
//! coherent read and write paths.
//!
//! The engine does not own storage or indexing logic — it orchestrates
//! both to serve assembled responses. This is the layer that the HTTP
//! server (Phase 4) programs against.
//!
//! ## Read Path
//!
//! - [`StorageEngine::get_tip`] — current principal state (index only)
//! - [`StorageEngine::get_patch`] — commit chain + blob content (index → blobs)
//! - [`StorageEngine::get_entity`] — digest resolution + blob fetch (index → blob)
//!
//! ## Write Path
//!
//! - [`StorageEngine::ingest_commit`] — store blobs, build index entry

mod error;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cyphr::replay::WireBundle;
use cyphr::state::{StateDigest, TaggedDigest};
pub use error::EngineError;

use crate::KeyEntry;
use crate::blob::{Blake3Hash, BlobStore};
use crate::index::{
    CommitRef, DeriveToken, IndexableCommit, IndexableCoz, Indexer, IndexerWrite, TipState,
};

/// A commit's metadata paired with its bundle.
///
/// The bundle's cozies, in bundle order ([`WireBundle::cozies`]), are the
/// blobs `commit.blob_hashes` names, in order.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// Commit metadata from the index.
    pub commit: CommitRef,
    /// The commit's bundle, grouped by transaction as it was accepted.
    pub bundle: WireBundle,
}

/// Response from [`StorageEngine::get_patch`].
#[derive(Debug, Clone)]
pub struct PatchResponse {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Ordered commit entries with their blob contents.
    pub entries: Vec<PatchEntry>,
    /// The chain position the range starts at: the position just after the
    /// resync anchor, whichever algorithm spelled it; `None` for a full
    /// chain. An empty range with `from == tip.commit_count` is caught up.
    pub from: Option<u64>,
    /// Every action-only bundle the principal holds, by its earliest
    /// `now` (SPEC 4.8.1): actions hold no chain position, so a range
    /// bounds the commits only.
    pub actions: Vec<PatchActions>,
    /// In Error, for [`StorageEngine::get_served_patch`]: the fork point and
    /// each tied branch from it; `entries` then end below the fork point.
    /// `None` while Active, and always for `get_patch`.
    pub fork: Option<PatchFork>,
}

/// An Error principal's patch beyond the common chain.
#[derive(Debug, Clone)]
pub struct PatchFork {
    /// Where the branches part.
    pub fork_point: ForkPoint,
    /// Each tied branch, ordered by head commit id.
    pub branches: Vec<PatchBranch>,
}

/// One accepted action-only bundle (SPEC 4.8.1): its actions are recorded
/// in DT, not chained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchActions {
    /// The action cozies' raw blobs.
    pub blobs: Vec<Vec<u8>>,
}

/// Post-commit roots re-derived directly from the authoritative blob store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DerivedRoots {
    pub pr: String,
    /// `None` for a Dead principal with no data.
    pub sr: Option<String>,
    /// `None` for a Dead principal.
    pub ar: Option<String>,
    pub cr: String,
}

/// Result from [`StorageEngine::ingest_commit`] and
/// [`StorageEngine::submit_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// The canonical (genesis-derived) id the commit was stored under, which
    /// may differ from the spelling the caller submitted. Read back under
    /// this id: a claimed alias can stop resolving once the commit moves
    /// the principal's state.
    pub principal_id: String,
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
    /// BLAKE3 hash of this commit's durable [`CommitManifest`] blob.
    ///
    /// `None` for an action-only bundle (`submit_commit`'s action-only
    /// branch): no commit was formed, so there is no commit manifest (its
    /// actions are kept under an action manifest instead).
    pub manifest_hash: Option<Blake3Hash>,
    /// The tip this commit produced, computed during ingest from the same
    /// replayed state the index entry is written from, so a caller can
    /// report the committed state without re-reading the index (a re-read
    /// is a fallible step AFTER the commit is durable).
    ///
    /// For an action-only bundle no commit was formed, so this is the
    /// principal's unchanged tip, or `None` if it has no committed state.
    pub tip: Option<CommittedTip>,
}

/// The principal's tip immediately after one accepted commit, as the
/// indexer records it (primary-algorithm variant of each root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTip {
    /// The commit's 0-indexed position in the principal's chain.
    pub sequence: u64,
    /// Commit ID (tagged digest).
    pub commit_id: String,
    /// Principal Root after the commit.
    pub pr: String,
    /// State Root after the commit (`None` if absent).
    pub sr: Option<String>,
    /// Auth Root after the commit (`None` if absent).
    pub ar: Option<String>,
    /// Commit Root after the commit (empty if the EML log has no leaf yet,
    /// matching [`TipState::cr`]).
    pub cr: String,
}

impl CommittedTip {
    /// The tip `commit` leaves: the first (primary-algorithm) variant of
    /// each digest, the same selection every [`Indexer`] applies when it
    /// writes its tip, so this equals what a `get_tip` would then return.
    fn of(commit: &IndexableCommit) -> Self {
        let first = |v: &[String]| v.first().cloned().unwrap_or_default();
        Self {
            sequence: commit.sequence,
            commit_id: first(&commit.commit_ids),
            pr: first(&commit.prs),
            sr: commit.srs.first().cloned(),
            ar: commit.ars.first().cloned(),
            cr: first(&commit.crs),
        }
    }
}

/// Discriminator embedded in every [`CommitManifest`]. Since manifests
/// moved behind [`COMMIT_MANIFEST_PREFIX`] it no longer separates them from
/// wire blobs; it survives as the shape of the legacy manifests
/// [`StorageEngine::rebuild_index_from_manifests`] refuses.
const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// Marks a blob as a [`CommitManifest`]: every stored manifest is these
/// bytes followed by its JSON.
///
/// This is the manifest keyspace inside the shared blob store. A wire blob
/// can never carry it: [`canonical_coz`] re-serializes every submitted coz
/// itself, so a stored wire blob is always a JSON object and begins with
/// `{`, while the leading NUL here is not valid at the start of any JSON
/// document. Separation therefore rests on the engine's own serializer,
/// never on inspecting caller bytes for a marker (an escaped member name
/// such as `"\u006bind"` would defeat any such inspection). Chosen over a
/// second backend keyspace because `BlobStore` has out-of-tree
/// implementors; a backend keyspace is the stronger form if that trait is
/// ever widened.
pub const COMMIT_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/commit-manifest/v1\0";

/// A durable, content-addressed record of one [`ingest_commit`](StorageEngine::ingest_commit)
/// call's fully-resolved [`IndexableCommit`] — written to the blob store
/// (never only to the index) so a commit's intra-commit transaction order
/// and derived state digests survive independently of the index.
///
/// This is the signal that lets an index rebuild ([`StorageEngine::rebuild_index_from_manifests`])
/// re-derive a commit directly, without the permutation search
/// that reconstructing same-timestamp mutation order would need. Per root `AGENTS.md` invariant I1,
/// the manifest is itself blob-store content, not a new index-only source of truth.
///
/// Stored as [`COMMIT_MANIFEST_PREFIX`] followed by this struct's JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CommitManifest {
    kind: String,
    commit: IndexableCommit,
    /// How the commit's blobs group into its bundle; required, so a
    /// manifest written before grouping was recorded is malformed rather
    /// than read as one transaction per coz.
    shape: Shape,
    /// When this engine first stored the commit (Unix seconds; SPEC 15.9,
    /// "I saw this at x time"), so a rebuild serves the time the commit
    /// was seen, not the time of the rebuild. `None` in a manifest written
    /// before it was recorded.
    #[serde(default)]
    seen: Option<i64>,
    /// The embedded principals the commit's signers were authorized
    /// through, each with the state of it this engine held at admission:
    /// this node's own statement of what it authenticated against (SPEC
    /// 10.7, 6.2). A replay judges the commit against that state, never a
    /// later one, so a rebuild reaches what the admission reached (I1).
    /// Absent in a manifest of a commit no embedded principal signed, so
    /// every manifest written before the field exists is unchanged and the
    /// manifest version is not bumped. A store holding embedded-signed
    /// objects is not readable by an earlier build: it quarantines them as
    /// unreplayable rather than judging them without their pin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    embedded: Vec<EmbeddedPin>,
}

/// An embedded principal B at the state an admitted commit of A was
/// judged against: `member` is the digest in A's Key Tree (B's PG or a PR
/// it held), `b` the PR B had at admission, tagged `ALG:digest`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EmbeddedPin {
    member: String,
    b: String,
}

/// How a commit's blobs (`IndexableCommit::blob_hashes`, in bundle order)
/// group into its bundle: the first `actions` are its data actions, then
/// each entry of `txs` is the coz count of one transaction (SPEC 4.6.2).
/// The bundle's order is retained at ingest, never recovered (root U1).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Shape {
    actions: usize,
    txs: Vec<usize>,
}

impl Shape {
    fn of(bundle: &WireBundle) -> Self {
        Self {
            actions: bundle.actions.len(),
            txs: bundle.txs.iter().map(Vec::len).collect(),
        }
    }

    /// How many blobs the shape groups.
    fn len(&self) -> usize {
        self.actions + self.txs.iter().sum::<usize>()
    }

    /// `blobs` grouped by this shape, with `keys`; `None` when the count
    /// differs.
    fn group(&self, mut blobs: Vec<Vec<u8>>, keys: Vec<KeyEntry>) -> Option<WireBundle> {
        if blobs.len() != self.len() {
            return None;
        }
        let rest = blobs.split_off(self.actions);
        let mut rest = rest.into_iter();
        let txs = self
            .txs
            .iter()
            .map(|&n| rest.by_ref().take(n).collect())
            .collect();
        Some(WireBundle {
            actions: blobs,
            txs,
            keys,
        })
    }
}

/// Stored commits of one principal, replayable: each commit's entry and
/// the embedded principals it was admitted through, by position.
#[derive(Default)]
struct StoredChain {
    entries: Vec<crate::CommitEntry>,
    pins: Vec<Vec<EmbeddedPin>>,
    /// Each commit's PR, the first (primary) spelling.
    prs: Vec<String>,
}

/// A commit B holds, canonical or retained: what walking a PR's ancestry by
/// `pre` needs to know before loading it.
struct HeldCommit<'m> {
    sequence: u64,
    pr: String,
    pre: Option<String>,
    origin: HeldOrigin<'m>,
}

enum HeldOrigin<'m> {
    Canonical(crate::index::CommitRef),
    Retained(Box<Retained>),
    Manifest(&'m CommitManifest),
}

/// Where the principals a commit was admitted through are read from: the
/// engine's index, or, when rebuilding the index, the manifests being
/// replayed (the index is not built yet). It also holds the memo of one
/// call: each embedded principal's chain replayed once, forward, however
/// many states of it the call pins. A fold of held blobs dropped with the
/// call, never a cache that outlives it.
struct PinSource<'m> {
    /// The canonical manifests and the rest (displaced and retained).
    manifests: Option<ManifestLists<'m>>,
    memo: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<ChainMemo>>>>>,
}

type ManifestLists<'m> = (
    &'m [(Blake3Hash, CommitManifest)],
    &'m [(Blake3Hash, CommitManifest)],
);

/// An embedded principal's chain replayed as far as the call needed, with
/// the state at each PR passed.
struct ChainMemo {
    chain: StoredChain,
    principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    next: usize,
    at: HashMap<String, cyphr::PrincipalState>,
}

impl<'m> PinSource<'m> {
    fn stored() -> Self {
        Self {
            manifests: None,
            memo: std::sync::Mutex::default(),
        }
    }

    fn manifests(
        canonical: &'m [(Blake3Hash, CommitManifest)],
        rest: &'m [(Blake3Hash, CommitManifest)],
    ) -> Self {
        Self {
            manifests: Some((canonical, rest)),
            memo: std::sync::Mutex::default(),
        }
    }

    fn slot(&self, member: &str) -> Arc<tokio::sync::Mutex<Option<ChainMemo>>> {
        self.memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(member.to_string())
            .or_default()
            .clone()
    }
}

/// The held tips of embedded principals read during one call, by the digest
/// that names them (`None`: it names no held principal): each principal is
/// replayed once however many candidate states of the principal embedding it
/// the call tries. Dropped with the call, never a cache across calls.
type HeldCache<S> = HashMap<String, Option<HeldTip<S>>>;

/// A held embedded principal: the tip it gives, the PR it stands at, and the
/// principal itself.
type HeldTip<S> = (cyphr::Tip, String, cyphr::Principal<S>);

/// What reading a held tip yields, boxed ([`StorageEngine::held_tip`]).
type HeldRead<'a, S> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<HeldTip<S>>, EngineError>> + Send + 'a>,
>;

/// The tips of embedded principals this engine holds, for the core to
/// follow ([`StorageEngine::follow_held`]): the engine's own store, never a
/// network. A failure to read a held principal is kept, not swallowed, and
/// the digest meanwhile has no tip (fails closed).
struct HeldTips<'e, B, I, S: cyphr::eml::Storage> {
    engine: &'e StorageEngine<B, I, S>,
    own_id: &'e str,
    cache: &'e mut HeldCache<S>,
    /// The followed digests that name a held principal, read from `cache`.
    found: std::collections::BTreeSet<String>,
    failed: Option<EngineError>,
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> cyphr::TipSource
    for HeldTips<'_, B, I, S>
{
    async fn tip(&mut self, member: &str) -> Option<cyphr::Tip> {
        if !self.cache.contains_key(member) {
            match self.engine.held_tip(member, self.own_id).await {
                Ok(held) => {
                    self.cache.insert(member.to_string(), held);
                },
                Err(e) => {
                    self.failed.get_or_insert(e);
                    return None;
                },
            }
        }
        let (tip, ..) = self.cache.get(member)?.as_ref()?;
        self.found.insert(member.to_string());
        Some(tip.clone())
    }
}

/// A [`cyphr::TipSource`] that holds no tip.
struct NoTips;

impl cyphr::TipSource for NoTips {
    async fn tip(&mut self, _member: &str) -> Option<cyphr::Tip> {
        None
    }
}

/// How many embedded principals may nest when a pin is replayed. A pin
/// names a state held before its commit was admitted, so the real depth is
/// finite; the bound is for a store that forged a cycle.
const EMBED_DEPTH: u8 = 16;

/// What the index's commit record lacks for a stored chain commit: how its
/// blobs group into its bundle and the keys it introduced (to serve the
/// bundle), who signed it when (to judge it against a revocation), and
/// when it was first seen.
#[derive(Debug, Clone)]
struct Frame {
    shape: Shape,
    keys: Vec<KeyEntry>,
    signed: Signed,
    seen: Option<i64>,
    embedded: Vec<EmbeddedPin>,
}

/// The thumbprints that signed a commit's cozies, in coz order: who
/// settled a fork ([`Contest::by`]).
type Signed = Vec<String>;

fn signed_of(commit: &IndexableCommit) -> Signed {
    commit.cozies.iter().map(|c| c.tmb.clone()).collect()
}

/// The engine's clock, Unix seconds; `None` before the epoch.
fn unix_now() -> Option<i64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    i64::try_from(secs).ok()
}

/// The key entries of a commit's index keys: what the engine keeps of a
/// bundle's `keys` (`alg`, `pub`, `tmb`; `tag` and `now` are unsigned
/// labels).
fn key_entries(keys: &[crate::PublicKeyInfo]) -> Vec<KeyEntry> {
    keys.iter()
        .map(|k| KeyEntry {
            alg: k.algorithm.clone(),
            pub_key: k.public_key.clone(),
            tmb: k.thumbprint.clone(),
            tag: None,
            now: None,
        })
        .collect()
}

/// Discriminator of a [`CommitManifest`] that records a retained branch
/// instead of a chain commit.
const BRANCH_MANIFEST_KIND: &str = "cyphr-storage/branch-manifest/v1";

/// Marks a blob as a retained-branch manifest: these bytes followed by a
/// [`CommitManifest`]'s JSON whose `kind` is [`BRANCH_MANIFEST_KIND`].
///
/// A keyspace distinct from [`COMMIT_MANIFEST_PREFIX`] is the whole
/// mechanism: [`StorageEngine::rebuild_index_with_report`] indexes exactly
/// the blobs behind the commit prefix, so a branch can never be chosen as
/// (or flip) a principal's canonical chain whatever order manifest hashes
/// sort in. Branches are read back into the engine's branch table by the
/// same scan, never into the [`Indexer`].
pub const BRANCH_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/branch-manifest/v1\0";

/// A commit that was ever canonical is never removed, by a cap or
/// otherwise: promotion retains each commit it displaces one for one and
/// without quota, and the caps below refuse a new rival at admission and
/// evict nothing. An embedding principal's pin names a state of this one
/// (SPEC 14.12), and finds it again only because nothing held is deleted.
///
/// Retained non-canonical branches kept per principal. A key holder can
/// mint any number of rivals at one position; the bound caps what one
/// principal can make the store keep, and the next rival is refused as
/// [`EngineError::BranchLimit`].
pub const BRANCH_LIMIT: usize = 16;

/// Retained rivals kept per signing key of one principal. A key that
/// forked once is already proven to equivocate by its first rival, so a
/// small quota loses no evidence. A principal can therefore hold at most
/// `min(BRANCH_LIMIT, BRANCH_PER_KEY * active keys)` rivals: a thief who
/// holds one key cannot starve rivals signed by the principal's other
/// keys, and shares that key's quota if it is the owner's only key. A
/// thief who first adds keys to the principal (each a further slot pair)
/// can still fill [`BRANCH_LIMIT`].
pub const BRANCH_PER_KEY: usize = 2;

/// The leading bytes of every blob the engine itself writes (each prefix
/// above extends it). A wire coz is JSON and never starts with NUL, so a
/// blob that starts with this but matches no known prefix is the engine's
/// own record in a version this build cannot read.
const ENGINE_BLOB_NAMESPACE: &[u8] = b"\0cyphr-storage/";

/// Marks a blob as a revoke record: these bytes followed by the JSON of a
/// [`RevokeRecord`]. A keyspace of its own, as [`COMMIT_MANIFEST_PREFIX`]
/// is. A rebuild re-verifies the revoke it carries rather than trusting it.
pub const REVOKE_RECORD_PREFIX: &[u8] = b"\0cyphr-storage/revoke-record/v2\0";

/// The first revoke record version, the bare envelope with no receipt
/// time; a rebuild quarantines one rather than guess its cutoff.
const REVOKE_RECORD_V1_PREFIX: &[u8] = b"\0cyphr-storage/revoke-record/v1\0";

/// A naked revoke this node accepted, and when: the record of a key's
/// death (SPEC 6.4).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RevokeRecord {
    /// This node's Witness Receipt Timestamp of the revoke, Unix seconds:
    /// the key's cutoff (the spec author on #203: "honor it from the
    /// witness's own receipt time"). The node's own statement in its own
    /// store, not something the revoke's signature proves.
    wrt: i64,
    /// The verified `{pay, sig, key}` envelope as received.
    evidence: serde_json::Value,
}

/// Verify a naked revoke's `{pay, sig, key}` envelope by the one core
/// rule ([`cyphr::revoke::verify_naked_revoke`]), returning the revoked
/// thumbprint (base64url).
fn verify_revoke(evidence: &serde_json::Value) -> Result<String, String> {
    cyphr::revoke::verify_naked_revoke(evidence)
        .map(|revoke| revoke.tmb.to_b64())
        .map_err(|e| e.to_string())
}

/// Discriminator of an [`ActionManifest`].
const ACTION_MANIFEST_KIND: &str = "cyphr-storage/action-manifest/v1";

/// Marks a blob as an [`ActionManifest`]: these bytes followed by its
/// JSON. A keyspace of its own, separated from wire blobs as
/// [`COMMIT_MANIFEST_PREFIX`] is, so a rebuild never reads one as a commit.
pub const ACTION_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/action-manifest/v1\0";

/// The durable record of one accepted action-only bundle: its data
/// actions are recorded in DT, not chained (SPEC 4.8.1), so they form no
/// commit and hold no chain position. Every replay records them once the
/// commits are in, each judged at its own `now` (SPEC 6.5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ActionManifest {
    kind: String,
    principal_id: String,
    blob_hashes: Vec<Blake3Hash>,
    /// As on [`CommitManifest`]: the embedded principals the actions were
    /// judged through, absent (and the manifest byte-identical to one
    /// written before this field) when none was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    embedded: Vec<EmbeddedPin>,
}

/// An accepted action-only bundle as the engine tracks it: a cache of its
/// [`ActionManifest`] (I1).
#[derive(Debug, Clone)]
struct StoredActions {
    manifest: Blake3Hash,
    blobs: Vec<Blake3Hash>,
    embedded: Vec<EmbeddedPin>,
}

/// An action-only bundle read back for replay.
struct ActionBundle {
    manifest: Blake3Hash,
    blobs: Vec<Blake3Hash>,
    embedded: Vec<EmbeddedPin>,
    bundle: cyphr::replay::Bundle,
}

impl ActionBundle {
    /// The engine's record of this bundle.
    fn stored(self) -> StoredActions {
        StoredActions {
            manifest: self.manifest,
            blobs: self.blobs,
            embedded: self.embedded,
        }
    }
}

/// A principal's action-only bundles, in replay order ([`replay_order`]).
type ActionHistory = Vec<ActionBundle>;

/// A retained rival as the engine tracks it: the listed [`BranchTip`],
/// the key that signed its closing `commit/create`, and the stored blobs
/// the evidence route serves back.
#[derive(Debug, Clone)]
struct Retained {
    tip: BranchTip,
    /// The commit's Principal Root: what a commit extending it names as
    /// its `pre`.
    pr: String,
    signer: String,
    blobs: Vec<Blake3Hash>,
    shape: Shape,
    keys: Vec<KeyEntry>,
    signed: Signed,
    /// The embedded principals its signers were authorized through, as the
    /// branch manifest records them.
    embedded: Vec<EmbeddedPin>,
}

/// The key that signed a commit: its closing `commit/create` coz, else
/// the last coz.
fn commit_signer(commit: &IndexableCommit) -> String {
    commit
        .cozies
        .iter()
        .rev()
        .find(|c| is_commit_create_typ(&c.typ))
        .or(commit.cozies.last())
        .map(|c| c.tmb.clone())
        .unwrap_or_default()
}

/// Whether `signer` may still retain a rival beside `kept`.
fn has_slot(kept: &[Retained], signer: &str) -> bool {
    kept.len() < BRANCH_LIMIT && kept.iter().filter(|r| r.signer == signer).count() < BRANCH_PER_KEY
}

/// A fork of a stored principal: two distinct commits that both verify at
/// the same `pre`, as the wire blobs of each. One is the canonical commit
/// at `sequence`, the other a retained rival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvidence {
    /// The chain position both commits take.
    pub sequence: u64,
    /// The Principal Root both extend, tagged; `None` at sequence 0.
    pub pre: Option<String>,
    /// The canonical commit's bundle.
    pub canonical: WireBundle,
    /// The retained rival's bundle.
    pub rival: WireBundle,
    /// When this engine first stored the canonical commit, if recorded.
    pub canonical_seen: Option<i64>,
    /// When this engine first stored the rival, if recorded.
    pub rival_seen: Option<i64>,
}

/// One branch head of a principal: its canonical chain's tip or a
/// retained rival, as listed by [`StorageEngine::list_branches`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BranchTip {
    /// The branch commit's id, in the form of [`TipState::commit_id`].
    pub tip: String,
    /// The Principal Root the commit was verified against (the parent PR,
    /// in the tagged anchor form `/patch` takes); `None` at sequence 0.
    pub pre: Option<String>,
    /// The commit's 0-indexed chain position.
    pub sequence: u64,
    /// Whether this is the head of the principal's canonical chain.
    pub canonical: bool,
    /// When this engine first stored the commit (Unix seconds), if
    /// recorded: kept across a rebuild (I1).
    pub seen: Option<i64>,
}

/// A principal's consensus state (SPEC 15.5), as far as forks decide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Consensus {
    /// No unresolved fork.
    Active,
    /// An unresolved fork: nothing that leaves it standing is admitted.
    Error,
}

/// One fork as a viewer sees it: two commits over one `pre`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkView {
    /// The commit position both commits take.
    pub height: u64,
    /// The two commit ids.
    pub heads: [String; 2],
    /// The head the chain kept, once it continued past one branch (SPEC
    /// 15.8); `None` while the fork is unresolved.
    pub kept: Option<String>,
}

impl ForkView {
    /// The heads a viewer may choose to trust instead of the protocol's
    /// answer: both while the fork is unresolved, else only the abandoned
    /// one (trusting the kept head is the protocol's own answer).
    #[must_use]
    pub fn alternatives(&self) -> Vec<&str> {
        self.heads
            .iter()
            .map(String::as_str)
            .filter(|h| self.kept.as_deref() != Some(h))
            .collect()
    }
}

/// What a recovery strategy adopted, reported beside the protocol's
/// verdict, never in place of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// The branch head the strategy trusts, if it chose one.
    pub trusted: Option<String>,
    /// Why, or that nothing was chosen, in words for the viewer.
    pub note: String,
}

/// A recovery strategy (SPEC 14): how a viewer reviews the protocol's
/// verdict on a principal, for when a resolution was itself fraudulent
/// (say, a stolen key resolved the fork first). Recovery is not fully
/// defined by the protocol and a viewer may bring its own, so it is a seam
/// a viewer consults over the forks it holds and never a rule the engine
/// applies: what the engine admits is the protocol alone,
/// and a strategy never overrides the [`Consensus`] it is shown.
pub trait Recovery: Send + Sync {
    /// The head this strategy trusts for `principal_id`, given the
    /// protocol's verdict and every fork the viewer holds, resolved or not.
    fn review(&self, principal_id: &str, protocol: Consensus, forks: &[ForkView]) -> Review;
}

/// A principal's forks as the protocol reads them (SPEC 15.5-15.8), from
/// the commits and revocations a holder keeps: the one rule the engine's
/// admission ([`StorageEngine::is_errored`]) and a verifier's verdict
/// ([`StorageEngine::assess`]) both apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Error while two held commits share the greatest height.
    pub consensus: Consensus,
    /// The heads, sorted: the held commits of the greatest height. One
    /// while Active; in Error, each tied head.
    pub heads: Vec<String>,
    /// Every position where two or more held commits share a `pre`, in
    /// position order.
    pub forks: Vec<Contest>,
    /// Where the tied heads part: `Some` exactly in Error.
    pub fork_point: Option<ForkPoint>,
}

/// Where tied branches part: the first position the walk cannot choose a
/// commit at, and the Principal Root every branch shares there (SPEC
/// 15.7.1: commits over the same `pre`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForkPoint {
    /// The commit position the branches first differ at; the common chain
    /// is the commits below it.
    pub height: u64,
    /// The common chain's Principal Root; `None` at position 0.
    pub pre: Option<String>,
}

/// A tied head and when this engine first stored it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldHead {
    /// The head's commit id.
    pub commit_id: String,
    /// The head's commit position.
    pub sequence: u64,
    /// When this engine first stored the commit (Unix seconds), if
    /// recorded: kept across a rebuild (I1). SPEC 13.6 "first seen".
    pub held_since: Option<i64>,
}

/// A principal in Error as a reader is told of it: the fork point and
/// every tied head, in place of a tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorState {
    /// Where the heads part.
    pub fork_point: ForkPoint,
    /// The tied heads, sorted by commit id.
    pub heads: Vec<HeldHead>,
}

/// One commit of a tied branch, as served.
#[derive(Debug, Clone)]
pub struct BranchEntry {
    /// The commit id.
    pub commit_id: String,
    /// The commit position.
    pub sequence: u64,
    /// The commit's Principal Root.
    pub pr: String,
    /// The commit's bundle, grouped as accepted.
    pub bundle: WireBundle,
}

/// One tied branch of an Error principal: the commits from the fork point
/// to its head, in order.
#[derive(Debug, Clone)]
pub struct PatchBranch {
    /// The branch's head commit id.
    pub head: String,
    /// Whether this is the head of the chain the engine's index serves
    /// (what `/branches` marks canonical): the chain `/evidence` items are
    /// stated against. Exactly one branch is.
    pub canonical: bool,
    /// The branch's commits, lowest first.
    pub entries: Vec<BranchEntry>,
}

/// Two or more held commits over one `pre`, and how the protocol reads
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contest {
    /// The commit position they take.
    pub sequence: u64,
    /// The Principal Root they share; `None` at sequence 0.
    pub pre: Option<String>,
    /// Their commit ids, sorted.
    pub commits: Vec<String>,
    /// The commit the fork rule's walk follows here; `None` where the walk
    /// stops at a tie, or follows none of them.
    pub kept: Option<String>,
    /// The key that settled it: the first signer of the walked commit
    /// extending the kept one. `None` while the fork stands, or when no
    /// commit settled it (a revoke left the kept commit alone).
    pub by: Option<String>,
}

/// Why a stored manifest was left out of a rebuilt index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineReason {
    /// The manifest blob is not a well-formed manifest.
    Malformed(String),
    /// The manifest names blobs the store does not hold.
    Unsupported(String),
    /// The manifest is not bound to the principal it names.
    Unbound(String),
    /// Indexing it would re-point an exclusive claim (a PG alias).
    Conflict(String),
    /// A different commit holds this manifest's chain position
    /// `(principal, sequence)`: a commit that extends a held commit but
    /// lost the canonical walk and is not kept as a branch. Fork evidence
    /// (I2), kept out of the index.
    Fork(String),
    /// An earlier commit of the same principal was quarantined, so indexing
    /// this one would leave a gap in the chain.
    Orphaned(String),
    /// Replaying the manifest's blobs onto its principal does not yield the
    /// commit the manifest records (only a rebuild from scratch replays).
    Unreplayable(String),
}

/// A manifest a rebuild left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedManifest {
    /// BLAKE3 hash of the manifest blob.
    pub manifest: Blake3Hash,
    /// The principal id the manifest claims, when it parsed far enough.
    pub principal_id: Option<String>,
    /// Why it was left out.
    pub reason: QuarantineReason,
}

/// What a rebuild did: how many manifests it indexed, and which it
/// quarantined. A quarantined manifest never fails the rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReport {
    /// Manifests indexed (including those already indexed).
    pub indexed: usize,
    /// Manifests left out, in canonical order.
    pub quarantined: Vec<QuarantinedManifest>,
}

/// Opens each principal's commit log (its EML, a cache of its canonical
/// chain, I1) by generation. A fork resolved by re-pointing the chain
/// leaves the old log holding the abandoned branch's leaves, so the engine
/// regenerates the log into the next generation and retires the old one;
/// the factory records which generation is current, beside the logs, so a
/// restart opens it. The record names a cache, never chain state: losing
/// it costs one more regeneration.
pub trait LogFactory<S>: Send + Sync {
    /// The current generation of `principal_id`'s log: the last one
    /// [`Self::retire_below`] made current, else 0.
    ///
    /// # Errors
    ///
    /// Why the record cannot be read.
    fn generation(&self, principal_id: &str) -> Result<u64, String>;

    /// Open generation `generation` of `principal_id`'s log, independent
    /// of every other principal's and generation's. A generation above the
    /// current one opens empty.
    ///
    /// # Errors
    ///
    /// Why the log cannot be opened.
    fn open(&self, principal_id: &str, generation: u64) -> Result<S, String>;

    /// Make `generation` the current generation of `principal_id`'s log,
    /// retiring the older ones.
    ///
    /// # Errors
    ///
    /// Why the record cannot be written.
    fn retire_below(&self, principal_id: &str, generation: u64) -> Result<(), String>;

    /// Whether a log outlives the principal that wrote it, so that opening
    /// it again finds the leaves it was given. Only then can a kept
    /// [`cyphr::PrincipalState`] resume over it; for a log that does not,
    /// the engine keeps no state.
    fn durable(&self) -> bool {
        true
    }
}

/// The [`LogFactory`] of in-memory logs: every open is a fresh, empty
/// [`cyphr::eml::MemoryStorage`], so a log never outlives its principal and
/// is never stale.
pub struct MemoryLogs;

impl LogFactory<cyphr::eml::MemoryStorage> for MemoryLogs {
    fn generation(&self, _principal_id: &str) -> Result<u64, String> {
        Ok(0)
    }

    fn open(
        &self,
        _principal_id: &str,
        _generation: u64,
    ) -> Result<cyphr::eml::MemoryStorage, String> {
        Ok(cyphr::eml::MemoryStorage::new())
    }

    fn retire_below(&self, _principal_id: &str, _generation: u64) -> Result<(), String> {
        Ok(())
    }

    fn durable(&self) -> bool {
        false
    }
}

/// A small insertion-ordered cache that never holds more than `capacity`
/// entries: when full, the oldest insertion is evicted.
///
/// Used only for memoizing replay-derived answers under keys that name the
/// exact tip they were derived at, so an entry can never be stale (a new
/// commit changes the key) and eviction costs only a recomputation.
pub struct BoundedCache<K, V> {
    capacity: usize,
    entries: std::sync::Mutex<(HashMap<K, V>, std::collections::VecDeque<K>)>,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> BoundedCache<K, V> {
    /// An empty cache holding at most `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: std::sync::Mutex::new((HashMap::new(), std::collections::VecDeque::new())),
        }
    }

    /// The value stored under `key`, if still held.
    pub fn get(&self, key: &K) -> Option<V> {
        let guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.get(key).cloned()
    }

    /// Store `value` under `key`, evicting the oldest entry if over capacity.
    pub fn insert(&self, key: K, value: V) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.insert(key.clone(), value).is_none() {
            order.push_back(key);
            while map.len() > self.capacity {
                match order.pop_front() {
                    Some(oldest) => {
                        map.remove(&oldest);
                    },
                    None => break,
                }
            }
        }
    }
}

/// What a kept [`cyphr::PrincipalState`] was folded from beyond the chain:
/// the tip it stands at and the naked revokes noted into it. Both are read
/// fresh under the principal's write lock on every write, and the state is
/// used only when both equal what is read now; any difference is a miss.
///
/// The held actions are no part of the key: every one is stored by a write
/// that holds the state under the same lock, so a state kept after it holds
/// it too.
#[derive(Debug, Clone, PartialEq)]
struct KeptKey {
    tip: String,
    revoked: Revoked,
}

impl KeptKey {
    /// What a state at the commit `tip` was folded from, with `revoked`.
    fn at(tip: &str, revoked: Revoked) -> Self {
        Self {
            tip: tip.to_string(),
            revoked,
        }
    }
}

/// A principal's verified state kept between its writes, so a write checks
/// only what arrives, not the history before it. A cache of what a replay of the blob store derives
/// (I1), never authoritative and never persisted: losing it costs one replay.
#[derive(Debug, Clone)]
struct Kept {
    state: cyphr::PrincipalState,
    key: KeptKey,
}

/// A principal over its engine's durable commit log, for reading proofs
/// from: [`StorageEngine::kept_log`]. It hands out only a shared reference,
/// so nothing a holder does can append to the log.
pub struct LogReader<S: cyphr::eml::Storage>(cyphr::Principal<S>);

impl<S: cyphr::eml::Storage> LogReader<S> {
    /// The principal, to read its commit log's size, roots and proofs.
    #[must_use]
    pub fn principal(&self) -> &cyphr::Principal<S> {
        &self.0
    }
}

/// The kept states, at most `capacity` of them, the least recently stored
/// evicted first.
///
/// Every access takes the principal's write-lock guard as a witness and
/// names its principal through it, so an entry can be read or written only
/// by the one writer of its principal (I2), and no call can pair one
/// principal's guard with another's id; the map's own mutex only orders the
/// map, and is never held across an `.await`.
struct KeptStates {
    capacity: usize,
    entries: std::sync::Mutex<(HashMap<String, Kept>, std::collections::VecDeque<String>)>,
}

/// [`StorageEngine::resume_kept`]'s boxed future.
type ResumeFuture<'a, S> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<Option<cyphr::Principal<S>>, EngineError>>
            + Send
            + 'a,
    >,
>;

/// Proof that the caller holds the write lock of one named principal:
/// built only by [`StorageEngine::lock_writes`] from that principal's own
/// lock, so another keyed lock (revoke, log generation, alias) cannot stand
/// for it.
struct WriteLock<'a> {
    principal: String,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl KeptStates {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: std::sync::Mutex::default(),
        }
    }

    /// A copy of the entry of the principal `write` locks, for a reader
    /// that must leave it in place ([`StorageEngine::kept_state`]).
    fn copy(&self, write: &WriteLock<'_>) -> Option<Kept> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .get(&write.principal)
            .cloned()
    }

    /// Move the entry out for the one write that holds `write`: the writer
    /// applies a bundle to it in place, and [`Self::put`] stores it again
    /// only if the write left it a state of the stored chain.
    fn take(&self, write: &WriteLock<'_>) -> Option<Kept> {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.1.retain(|id| *id != write.principal);
        guard.0.remove(&write.principal)
    }

    fn put(&self, kept: Kept, write: &WriteLock<'_>) {
        if self.capacity == 0 {
            return;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.insert(write.principal.clone(), kept).is_some() {
            order.retain(|id| *id != write.principal);
        }
        order.push_back(write.principal.clone());
        while map.len() > self.capacity {
            match order.pop_front() {
                Some(oldest) => {
                    map.remove(&oldest);
                },
                None => break,
            }
        }
    }

    /// Forget everything: a rebuild re-derives the engine's caches from
    /// the blobs, and so must the states folded from the old ones.
    fn clear(&self) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.clear();
        guard.1.clear();
    }
}

/// Kept states an engine holds unless told otherwise. Each is the size of
/// its principal's history, so the bound is on memory; an evicted
/// principal's next write replays, as every write once did.
const DEFAULT_KEPT_CAPACITY: usize = 128;

/// Derived-roots entries an engine memoizes by commit.
const ROOTS_MEMO_CAPACITY: usize = 1024;

// Compile-time proof that the engine's write path is `Send` for every
// backend, so the server's multi-threaded runtime can drive it over the
// durable store: a `!Send` value held across one of its awaits fails here.
const _: () = {
    fn assert_send<T: Send>(_: &T) {}
    #[allow(dead_code)]
    fn submit_commit_is_send<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage>(
        engine: &StorageEngine<B, I, S>,
    ) {
        assert_send(&engine.submit_commit("", None, &WireBundle::default()));
    }
};

/// A pushed bundle verified into the commit it forms, nothing yet written:
/// the commit's index record and the staged core commit whose log append
/// follows the blob store's record of it ([`StorageEngine::ingest_commit`]).
pub(crate) struct StagedBuild<'p, T: cyphr::eml::Storage> {
    commit: IndexableCommit,
    staged: cyphr::replay::StagedBundle<'p, T>,
    /// The embedded principals the commit was authorized through, set by
    /// the admission path that followed them; empty on a replay.
    embedded: Vec<EmbeddedPin>,
}

/// What a verified bundle forms ([`StorageEngine::build_staged`]).
pub(crate) enum Built<'p, T: cyphr::eml::Storage> {
    /// A commit, its log append not yet made.
    Commit(Box<StagedBuild<'p, T>>),
    /// Actions alone, verified and not yet held.
    Actions(cyphr::replay::StagedBundle<'p, T>),
}

/// Coordinated storage engine joining blob and index layers.
///
/// Generic over backend implementations. Use `MemoryBlobStore` +
/// `MemoryIndexer` for tests, production backends for deployment.
///
/// The third type parameter, `S`, is the storage backend for each
/// [`cyphr::Principal`]'s Commit Tree; it defaults to
/// [`cyphr::eml::MemoryStorage`] so every existing call site that spells the
/// bare `StorageEngine<B, I>` (via [`Self::new`]) continues to mean exactly
/// what it meant before this parameter existed. A durable backend is wired
/// up via [`Self::with_log_factory`] instead.
pub struct StorageEngine<B, I, S: cyphr::eml::Storage = cyphr::eml::MemoryStorage> {
    blob_store: B,
    indexer: I,
    /// Produces a fresh, independent `S` instance for each `Principal` this
    /// engine constructs or reconstructs. Never a single `S` instance
    /// shared/aliased across multiple live principals: `eml::Storage`'s
    /// methods take `&mut self` on an owned instance, so two principals can
    /// never validly share one. Fallible because opening a real
    /// disk-backed backend can fail.
    ///
    /// Keyed by the principal's `principal_id` and the log's generation, so
    /// a factory backed by a durable, physically-shared database can give
    /// each principal (and each regeneration of its log) an isolated
    /// keyspace instead of colliding on positional Commit Tree keys.
    logs: Box<dyn LogFactory<S>>,
    /// Per-principal serialization points for [`Self::submit_commit`].
    ///
    /// Keyed-mutex map: each `principal_id` gets its own
    /// `tokio::sync::Mutex`, so concurrent writers for the *same* principal
    /// serialize (each submit opens the principal's one durable log, so two
    /// at once would be two writers of it) while writers for *different*
    /// principals never contend. The outer
    /// `std::sync::Mutex` only ever guards the fast, non-blocking
    /// get-or-insert into the map itself, never the write critical section.
    ///
    /// Entries are never removed: the map's memory footprint grows with the
    /// number of distinct principals ever written to over the engine's
    /// lifetime. Acceptable for this in-process precursor (see root
    /// `AGENTS.md` I2); bounding it is future work alongside the
    /// cross-process write serialization this node explicitly defers.
    principal_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Set once [`Self::ensure_healed`] has run [`Self::rebuild_index_from_manifests`]
    /// successfully for this engine instance. See `ensure_healed`'s docs for
    /// why this is scoped per-instance rather than per-backend.
    healed: tokio::sync::OnceCell<()>,
    /// Retained non-canonical branches per canonical principal id: a cache
    /// of the branch manifests in the blob store (I1), filled by the
    /// rebuild scan and by retention, at most [`BRANCH_LIMIT`] per
    /// principal.
    branches: std::sync::Mutex<HashMap<String, Vec<Retained>>>,
    /// Accepted action-only bundles per principal id: a cache of the action
    /// manifests in the blob store (I1), filled by the rebuild scan and by
    /// ingest.
    actions: std::sync::Mutex<HashMap<String, Vec<StoredActions>>>,
    /// How each stored chain commit's blobs group into its bundle, and the
    /// keys it introduced, by principal id and commit id: a cache of the
    /// commit manifests in the blob store (I1), filled by the rebuild scan
    /// and by ingest. The index's commit records name blobs only.
    frames: std::sync::Mutex<HashMap<(String, String), Frame>>,
    /// Revocations in force: a cache of the revoke records in the blob
    /// store (I1), filled by the rebuild scan and by
    /// [`Self::record_revoke`].
    revoked: std::sync::Mutex<Revoked>,
    /// Stored commits [`Self::retain_rival`] has replayed, ever. Retention
    /// is paid by refused bundles, so its cost is the quantity tests pin.
    retention_replays: std::sync::atomic::AtomicU64,
    /// Candidate positions [`Self::retain_rival`] has tried a bundle at.
    retention_trials: std::sync::atomic::AtomicU64,
    /// Commits whose manifest was stored but whose commit-log append failed
    /// ([`Self::log_append_failures`]): the log is behind until the next
    /// load repairs it.
    log_append_failures: std::sync::atomic::AtomicU64,
    /// Each principal's verified state between its writes ([`Kept`]).
    kept: KeptStates,
    /// Whether the log factory's logs outlive a replay: states are kept
    /// only over logs that do.
    logs_durable: bool,
    /// Check every kept-state use against a cold replay
    /// ([`Self::with_kept_shadow`]).
    kept_shadow: bool,
    /// Writes served from a kept state, and writes that replayed.
    kept_hits: std::sync::atomic::AtomicU64,
    kept_misses: std::sync::atomic::AtomicU64,
    /// Shadow checks where the kept state was not the replayed one.
    kept_divergences: std::sync::atomic::AtomicU64,
    /// Stored commits replayed by [`Self::replay_onto`], ever.
    commits_replayed: std::sync::atomic::AtomicU64,
    /// Commit records read from the index by [`Self::chain`], ever.
    chain_rows_read: std::sync::atomic::AtomicU64,
    /// The four roots at each commit this engine admitted or derived,
    /// by principal id and commit id: a commit's roots depend on its
    /// history alone, so an entry is exact for the commit that names it.
    roots_at: BoundedCache<(String, String), DerivedRoots>,
}

impl<B: BlobStore, I: Indexer + IndexerWrite> StorageEngine<B, I, cyphr::eml::MemoryStorage> {
    /// Create a new engine wrapping the given backends, with each
    /// [`cyphr::Principal`]'s Commit Tree backed by an in-memory
    /// [`cyphr::eml::MemoryStorage`] instance (discarded when the principal
    /// is dropped — full history is always replayed from the blob/index
    /// layers on the next [`Self::load_principal`]).
    ///
    /// For a durable commit-tree backend, use [`Self::with_log_factory`].
    pub fn new(blob_store: B, indexer: I) -> Self {
        Self::with_log_factory(blob_store, indexer, MemoryLogs)
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Create a new engine wrapping the given backends, with `logs` opening
    /// each [`cyphr::Principal`]'s Commit Tree storage by principal and
    /// generation ([`LogFactory`]). See [`Self`]'s `logs` field docs for why
    /// this is a factory rather than a single shared `S` instance.
    pub fn with_log_factory(blob_store: B, indexer: I, logs: impl LogFactory<S> + 'static) -> Self {
        let logs_durable = logs.durable();
        Self {
            blob_store,
            indexer,
            logs: Box::new(logs),
            principal_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            healed: tokio::sync::OnceCell::new(),
            branches: std::sync::Mutex::new(HashMap::new()),
            actions: std::sync::Mutex::new(HashMap::new()),
            frames: std::sync::Mutex::new(HashMap::new()),
            revoked: std::sync::Mutex::new(Revoked::new()),
            retention_replays: std::sync::atomic::AtomicU64::new(0),
            retention_trials: std::sync::atomic::AtomicU64::new(0),
            log_append_failures: std::sync::atomic::AtomicU64::new(0),
            kept: KeptStates::new(if logs_durable {
                DEFAULT_KEPT_CAPACITY
            } else {
                0
            }),
            logs_durable,
            kept_shadow: std::env::var_os("CYPHR_KEPT_SHADOW").is_some_and(|v| v != "0"),
            kept_hits: std::sync::atomic::AtomicU64::new(0),
            kept_misses: std::sync::atomic::AtomicU64::new(0),
            kept_divergences: std::sync::atomic::AtomicU64::new(0),
            commits_replayed: std::sync::atomic::AtomicU64::new(0),
            chain_rows_read: std::sync::atomic::AtomicU64::new(0),
            roots_at: BoundedCache::new(ROOTS_MEMO_CAPACITY),
        }
    }

    /// Keep at most `capacity` principals' verified states between their
    /// writes; 0 keeps none, so every write replays the principal's
    /// history from the blob store. An engine over logs that do not outlive
    /// a replay ([`LogFactory::durable`]) keeps none whatever this says.
    #[must_use]
    pub fn with_kept_states(mut self, capacity: usize) -> Self {
        self.kept = KeptStates::new(if self.logs_durable { capacity } else { 0 });
        self
    }

    /// Replay cold, and compare with the kept state, every time a write
    /// would use one: a divergence is counted ([`Self::kept_divergences`]),
    /// logged, and fails the write with [`EngineError::Storage`], so a
    /// run that exercises it cannot pass over one. Also on when the
    /// `CYPHR_KEPT_SHADOW` environment variable is set and not `0`.
    #[must_use]
    pub fn with_kept_shadow(mut self, on: bool) -> Self {
        self.kept_shadow = on;
        self
    }

    /// Writes served from a kept state, over this engine's lifetime.
    pub fn kept_hits(&self) -> u64 {
        self.kept_hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Writes of an existing principal that replayed its history because
    /// no kept state matched.
    pub fn kept_misses(&self) -> u64 {
        self.kept_misses.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Shadow checks where a kept state differed from the replay. Must be
    /// 0: a kept state is a cache of the replay, never another answer.
    pub fn kept_divergences(&self) -> u64 {
        self.kept_divergences
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Stored commits replayed by whole-chain or bounded replays, over this
    /// engine's lifetime: what a write or a root derivation cost in
    /// protocol checks.
    pub fn commits_replayed(&self) -> u64 {
        self.commits_replayed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Commit records this engine has read from its index, over its
    /// lifetime: what a request cost in index reads, which the replay count
    /// cannot see (a walk of the chain checks no signature).
    pub fn chain_rows_read(&self) -> u64 {
        self.chain_rows_read
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The index's commit records of `principal_id` from `from` to `to`
    /// ([`Indexer::get_commit_chain`]), counted: every chain read the
    /// engine makes goes through here.
    async fn chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Vec<CommitRef>, crate::index::IndexerError> {
        let rows = self
            .indexer
            .get_commit_chain(principal_id, from, to)
            .await?;
        self.chain_rows_read
            .fetch_add(rows.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(rows)
    }

    /// The state the next write of `principal_id` would start from if it
    /// is kept and current (the tip and revokes it was folded from are what
    /// they are now). A cache of the replay of the
    /// stored chain, exposed so a test can hold it to that.
    pub async fn kept_state(&self, principal_id: &str) -> Option<cyphr::PrincipalState> {
        let key = self.resolve_key(principal_id).await.ok()?;
        let stored = key.as_deref().unwrap_or(principal_id);
        let lock = self.principal_lock(stored);
        let write = Self::lock_writes(&lock, stored).await;
        let tip = self.indexer.get_tip(stored).await.ok()??;
        let kept = self.kept.copy(&write)?;
        (kept.key == KeptKey::at(&tip.commit_id, self.revoked())).then_some(kept.state)
    }

    /// The principal `principal_id` as its next write would start from, if
    /// its state is kept and current, detached onto an in-memory commit log
    /// ([`cyphr::Principal::detach`]): a holder can verify commits against
    /// it, as a pull does, without writing to the engine's log or taking
    /// its write lock. The engine admits what that holder verified only
    /// through [`Self::submit_commit`], which checks it again.
    ///
    /// Costs the state's unshared part (the settled history is shared, not
    /// copied) and O(log n) commit-log nodes, never the history. `None`
    /// when no current state is kept: an evicted or never-written
    /// principal, one whose history embeds another principal's pin or Key
    /// Tree digest (those are always replayed), or an engine over logs
    /// that do not outlive a replay.
    pub async fn kept_principal(
        &self,
        principal_id: &str,
    ) -> Option<cyphr::Principal<cyphr::eml::MemoryStorage>> {
        let key = self.resolve_key(principal_id).await.ok()?;
        let stored = key.as_deref().unwrap_or(principal_id);
        let lock = self.principal_lock(stored);
        let write = Self::lock_writes(&lock, stored).await;
        let tip = self.indexer.get_tip(stored).await.ok()??;
        let kept = self.kept.copy(&write)?;
        if kept.key != KeptKey::at(&tip.commit_id, self.revoked()) {
            return None;
        }
        self.resume_over_log(stored, kept.state)
            .await?
            .detach()
            .await
            .ok()
    }

    /// The commit log `principal_id`'s next write would start from, read
    /// only: the engine's own durable log under the kept state, so a proof
    /// over any past size can be made without a replay. It can be asked
    /// for proofs and nothing else; it cannot append to the engine's log.
    /// `None` exactly when [`Self::kept_principal`] is.
    pub async fn kept_log(&self, principal_id: &str) -> Option<LogReader<S>> {
        let key = self.resolve_key(principal_id).await.ok()?;
        let stored = key.as_deref().unwrap_or(principal_id);
        let lock = self.principal_lock(stored);
        let write = Self::lock_writes(&lock, stored).await;
        let tip = self.indexer.get_tip(stored).await.ok()??;
        let kept = self.kept.copy(&write)?;
        if kept.key != KeptKey::at(&tip.commit_id, self.revoked()) {
            return None;
        }
        self.resume_over_log(stored, kept.state)
            .await
            .map(LogReader)
    }

    /// How many accepted commits have had their commit-log append fail
    /// after their manifest was stored, over this engine's lifetime. Each
    /// is repaired by the next load of its principal; a count that keeps
    /// rising means the log store is failing, which the push answers alone
    /// do not show.
    pub fn log_append_failures(&self) -> u64 {
        self.log_append_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Fetch (or create) this `principal_id`'s serialization point.
    ///
    /// Never blocks on a write: only ever holds the map's own lock for the
    /// duration of a `HashMap` lookup/insert, not across any `.await`.
    fn principal_lock(&self, principal_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        // A poisoned std Mutex means some prior holder of THIS lock panicked
        // while holding it. The critical section below is only a HashMap
        // entry/insert/clone on an owned String key -- no `.await`, no
        // user-controlled Hash/Eq impl, nothing that can panic -- so
        // poisoning here would imply a bug already crashing the server
        // elsewhere, not a condition adversarial request input can trigger.
        let mut locks = self
            .principal_locks
            .lock()
            .expect("principal lock map poisoned");
        locks
            .entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Take `principal_id`'s write lock, `lock` being its own entry of
    /// [`Self::principal_lock`].
    async fn lock_writes<'a>(
        lock: &'a Arc<tokio::sync::Mutex<()>>,
        principal_id: &str,
    ) -> WriteLock<'a> {
        WriteLock {
            principal: principal_id.to_string(),
            _guard: lock.lock().await,
        }
    }

    /// Get a reference to the underlying blob store.
    pub fn blob_store(&self) -> &B {
        &self.blob_store
    }

    /// Get a reference to the underlying indexer.
    pub fn indexer(&self) -> &I {
        &self.indexer
    }

    // ========================================================================
    // Index heal gate
    // ========================================================================

    /// Ensure this engine's index has no pending crash-window recovery
    /// before any of its own methods read or write against it.
    ///
    /// Implements [recovery-reindex] (docs/specs/storage-engine.md:236-241)
    /// for the "no explicit call" case: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent index write (see the
    /// crash-window doc on [`Self::rebuild_index_from_manifests`] below)
    /// must heal automatically the next time the engine is opened,
    /// without any caller remembering to invoke
    /// [`Self::rebuild_index_from_manifests`] itself. "Opened" here means
    /// construct-plus-first-use (engine constructors are synchronous, so
    /// there is no async open step to hook): this lazy once-per-instance
    /// guard runs the full manifest scan on this engine's first call into
    /// any of the methods below, and never again for the lifetime of this
    /// instance.
    ///
    /// Cost strategy: always a full [`Self::rebuild_index_from_manifests`]
    /// scan rather than a cheaper orphan-detection pre-check. Against this
    /// crate's backends the scan is already the mechanism full recovery
    /// relies on, `index_commit` is idempotent so
    /// a healthy store's scan is a pure read with no re-indexing writes,
    /// and it runs at most once per instance -- an orphan pre-check would
    /// only save a single redundant scan's read cost per process lifetime,
    /// not a recurring cost, so the simpler always-scan is what ships.
    ///
    /// Scoped to this engine's own methods: [`Self::indexer`] and
    /// [`Self::blob_store`] are raw accessors that bypass this gate by
    /// design (see their docs) -- a caller reaching the backends directly
    /// is outside the invariant this method closes.
    ///
    /// A heal failure surfaces as an `EngineError` from the caller's first
    /// call, same as any other engine error -- not a swallowed or
    /// reordered error, and not a public-error-contract change. The guard
    /// is left uninitialized on error (`get_or_try_init` does not cache
    /// failures), so the next call retries rather than wedging this
    /// instance in a permanently-failed state.
    async fn ensure_healed(&self) -> Result<(), EngineError> {
        self.healed
            .get_or_try_init(|| async { self.rebuild_index_from_manifests().await.map(|_| ()) })
            .await?;
        Ok(())
    }

    // ========================================================================
    // Read path
    // ========================================================================

    /// Retrieve the current tip state for a principal.
    ///
    /// Delegates directly to the indexer.
    #[tracing::instrument(skip(self))]
    pub async fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        Ok(self
            .indexer
            .get_tip(key.as_deref().unwrap_or(principal_id))
            .await?)
    }

    /// Retrieve a patch: commit chain metadata joined with blob content.
    ///
    /// For each commit in the range, fetches the raw blob bytes from
    /// the blob store. This is the engine's primary coordination value —
    /// neither trait can serve this alone.
    ///
    /// `from` is a content-digest resync anchor (Zami #140: "Content
    /// addressed digest for everything… Sequence is metadata"; S0.1 of the
    /// campaign IBC settles the anchor root as PR). It is resolved to the
    /// chain position it was produced at and the response starts
    /// immediately AFTER that position — sequence itself is never accepted
    /// as an anchor (see [`Self::resolve_anchor_position`]). `to` remains a
    /// bare sequence bound: only the resync ANCHOR needed content-addressing
    /// per #140, and widening `to` identically is out of this change's
    /// surface.
    #[tracing::instrument(skip(self))]
    pub async fn get_patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        self.patch(principal_id, from, to, false).await
    }

    /// [`Self::get_patch`] as a peer is served it (SPEC 15.7.1): while the
    /// principal is in Error, `entries` are the chain up to the fork point
    /// and [`PatchResponse::fork`] carries each tied branch, so no one
    /// branch is passed off as the chain. Active, it is `get_patch`.
    /// Callers that want the engine's canonical chain regardless use
    /// `get_patch`.
    #[tracing::instrument(skip(self))]
    pub async fn get_served_patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        self.patch(principal_id, from, to, true).await
    }

    async fn patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
        fork_aware: bool,
    ) -> Result<PatchResponse, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let principal_id = key.as_deref().unwrap_or(principal_id);
        let from_seq = match from {
            Some(anchor) => Some(self.resolve_anchor_position(principal_id, anchor).await?),
            None => None,
        };
        let error = if fork_aware {
            self.error_state_of(principal_id).await?
        } else {
            None
        };
        // In Error the common chain ends below the fork point: the chain
        // the index serves past it is one branch among the tied ones.
        let to = match &error {
            Some((point, _)) => point
                .height
                .checked_sub(1)
                .map(|last| to.map_or(last, |t| t.min(last))),
            None => to,
        };
        let chain = if error.as_ref().is_some_and(|(p, _)| p.height == 0) {
            Vec::new()
        } else {
            self.chain(principal_id, from_seq, to).await?
        };

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let bundle = self.commit_bundle(principal_id, &commit_ref).await?;
            entries.push(PatchEntry {
                commit: commit_ref,
                bundle,
            });
        }

        let fork = match error {
            Some((fork_point, heads)) => Some(PatchFork {
                branches: self.branches_of(principal_id, &fork_point, &heads).await?,
                fork_point,
            }),
            None => None,
        };

        let mut actions = Vec::new();
        for held in self.action_history(principal_id).await? {
            actions.push(PatchActions {
                blobs: self.read_blobs(&held.blobs).await?,
            });
        }

        Ok(PatchResponse {
            principal_id: principal_id.to_string(),
            entries,
            from: from_seq,
            actions,
            fork,
        })
    }

    /// Resolve a `/patch` resync anchor (a content digest) to the chain
    /// position immediately AFTER it — the inclusive `from` bound
    /// [`Indexer::get_commit_chain`] needs to serve exactly the entries a
    /// caller does not yet hold, never re-serving the anchored commit
    /// itself.
    ///
    /// An anchor that does not resolve to ANY indexed position at all is
    /// refused as [`EngineError::NotFound`] rather than silently degrading
    /// to "no anchor" (a full resync) or to sequence zero (which would
    /// silently wrap an unrecognized anchor onto genesis).
    ///
    /// Principal-scoped (forge #154): [`Indexer::resolve_digest_holders`]
    /// names every holder of the digest, and only a holder that is this
    /// principal's own commit bounds this chain. An anchor held solely by
    /// other principals is [`EngineError::NotFound`] here, never a position
    /// borrowed from a foreign chain; an anchor this principal holds at
    /// several positions is [`EngineError::Ambiguous`].
    async fn resolve_anchor_position(
        &self,
        principal_id: &str,
        anchor: &TaggedDigest,
    ) -> Result<u64, EngineError> {
        // A digest names a set of holders; only a holder that is this
        // principal's own commit bounds this chain. A digest held solely by
        // other principals names no position here (forge #154), and
        // holders at differing positions of this chain are ambiguous.
        let holders = self.indexer.resolve_digest_holders(anchor).await?;
        let mut own = holders
            .iter()
            .filter(|h| h.principal_id.as_deref() == Some(principal_id));
        let entity = own.next().ok_or_else(|| {
            EngineError::NotFound(format!(
                "resync anchor {anchor} not indexed (requested for principal {principal_id})"
            ))
        })?;
        if own.any(|other| other.sequence != entity.sequence) {
            return Err(EngineError::Ambiguous(format!(
                "resync anchor {anchor} is held at several positions of principal {principal_id}"
            )));
        }
        entity.sequence.map(|seq| seq + 1).ok_or_else(|| {
            EngineError::NotFound(format!(
                "resync anchor {anchor} carries no chain position (requested for principal \
                 {principal_id})"
            ))
        })
    }

    /// The bundle of a stored chain commit of `principal_id`: its blobs,
    /// grouped as the commit was accepted, with the keys it introduced.
    async fn commit_bundle(
        &self,
        principal_id: &str,
        commit: &CommitRef,
    ) -> Result<WireBundle, EngineError> {
        let mut blobs = Vec::with_capacity(commit.blob_hashes.len());
        for hash in &commit.blob_hashes {
            blobs.push(self.blob_store.get(hash).await?.ok_or_else(|| {
                EngineError::NotFound(format!(
                    "blob {hash} referenced by index commit {} missing",
                    commit.commit_id
                ))
            })?);
        }
        // An index entry no manifest backs is a corrupt index: the index is
        // a cache of the blob store (I1), and nothing recorded how its blobs
        // group. It is refused, never served.
        let Some(Frame { shape, keys, .. }) = self.frame(principal_id, commit) else {
            tracing::warn!(
                principal = %principal_id,
                commit = %commit.commit_id,
                "index entry with no commit manifest; refusing it as an inconsistent index"
            );
            return Err(EngineError::Indexer(
                crate::index::IndexerError::Consistency(format!(
                    "index commit {} of {principal_id} has no commit manifest",
                    commit.commit_id
                )),
            ));
        };
        shape.group(blobs, keys).ok_or_else(|| {
            EngineError::MalformedBlob(format!(
                "commit {}: its manifest groups a different number of blobs",
                commit.commit_id
            ))
        })
    }

    /// How the stored chain commit `commit` groups its blobs, if a manifest
    /// recorded it.
    fn frame(&self, principal_id: &str, commit: &CommitRef) -> Option<Frame> {
        self.frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(principal_id.to_string(), commit.commit_id.clone()))
            .cloned()
    }

    /// Record a chain commit's [`Frame`], in the `frames` cache.
    fn record_frame(
        &self,
        commit: &IndexableCommit,
        shape: &Shape,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) {
        let Some(id) = commit.commit_ids.first() else {
            return;
        };
        self.frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                (commit.principal_id.clone(), id.clone()),
                Frame {
                    shape: shape.clone(),
                    keys: key_entries(&commit.keys),
                    signed: signed_of(commit),
                    seen,
                    embedded: embedded.to_vec(),
                },
            );
    }

    /// Resolve a tagged digest to its raw blob content.
    ///
    /// Two-step: resolve digest → entity ref (index), then
    /// fetch blob content (blob store).
    #[tracing::instrument(skip(self))]
    pub async fn get_entity(&self, digest: &TaggedDigest) -> Result<Option<Vec<u8>>, EngineError> {
        self.ensure_healed().await?;
        let entity = match self.indexer.resolve_digest(digest).await? {
            Some(e) => e,
            None => return Ok(None),
        };

        let data = self.blob_store.get(&entity.blob_hash).await?;
        Ok(data)
    }

    /// Re-derive the current roots (`pr`, `sr`, `ar`, `cr`) for a principal
    /// directly from the authoritative blob store by replaying stored commits.
    ///
    /// Fails if the principal cannot be loaded from the blob store or if any
    /// referenced blob is missing or corrupt.
    #[tracing::instrument(skip(self))]
    pub async fn rederive_roots(&self, principal_id: &str) -> Result<DerivedRoots, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let genesis = self.resolve_genesis(&principal_id, &[]).await?;
        self.rederive_roots_with_genesis(&principal_id, genesis)
            .await
    }

    /// [`Self::rederive_roots`] for a caller that already holds the
    /// principal's genesis.
    #[tracing::instrument(skip(self, genesis))]
    pub async fn rederive_roots_with_genesis(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<DerivedRoots, EngineError> {
        self.ensure_healed().await?;
        let principal = self.load_principal(principal_id, genesis).await?;
        roots_of(&principal)
    }

    /// The roots `tip` names, derived from the stored commits up to and
    /// including that commit alone, never from the principal's current
    /// chain: a commit landing after `tip` was read changes nothing here,
    /// so what comes back is a statement about the commit `tip` names
    /// whatever the principal does meanwhile. `None` if the chain no longer
    /// has that commit at that position (a fork resolved under the read).
    ///
    /// Memoized by (principal, commit): a commit this engine admitted is
    /// already there, so for the tip of a live principal this is a lookup;
    /// otherwise (after a restart, or a commit another path stored) it is
    /// one replay of the history up to the commit, onto a private log.
    ///
    /// `genesis` for a principal whose genesis its blobs cannot express
    /// (the server's own); `None` reads it from the stored chain.
    ///
    /// # Errors
    ///
    /// As [`Self::load_principal`].
    #[tracing::instrument(skip(self, genesis))]
    pub async fn derive_roots_at(
        &self,
        tip: &TipState,
        genesis: Option<crate::Genesis>,
    ) -> Result<Option<DerivedRoots>, EngineError> {
        self.ensure_healed().await?;
        let key = (tip.principal_id.clone(), tip.commit_id.clone());
        if let Some(hit) = self.roots_at.get(&key) {
            return Ok(Some(hit));
        }
        let genesis = match genesis {
            Some(genesis) => genesis,
            None => self.resolve_genesis(&tip.principal_id, &[]).await?,
        };
        let principal = self
            .replay_onto(
                &tip.principal_id,
                genesis,
                cyphr::eml::MemoryStorage::new(),
                Some(tip.commit_count),
            )
            .await?;
        let ends_at_tip = match principal.commits().last() {
            Some(commit) => {
                principal.commits().count() as u64 == tip.commit_count
                    && format_multihash_all(&commit.tr().0)?.first() == Some(&tip.commit_id)
            },
            None => false,
        };
        if !ends_at_tip {
            return Ok(None);
        }
        let roots = roots_of(&principal)?;
        self.roots_at.insert(key, roots.clone());
        Ok(Some(roots))
    }

    // ========================================================================
    // Write path
    // ========================================================================

    /// Store this commit's coz blobs and its durable [`CommitManifest`],
    /// without touching the index.
    ///
    /// This is [`ingest_commit`](Self::ingest_commit)'s crash-safe first
    /// phase: once the manifest write here completes, the commit is
    /// durably recoverable from the blob store alone — a crash before it
    /// (mid coz-blob loop, or before the manifest itself lands) leaves
    /// only harmless, unreferenced content-addressed blobs behind, never
    /// a commit that's half-recorded. [`Self::rebuild_index_from_manifests`]
    /// is what completes the second phase (the index write) for a commit
    /// whose manifest landed but whose index write did not.
    async fn store_blobs_and_manifest(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        self.store_manifest(
            bundle,
            commit,
            COMMIT_MANIFEST_PREFIX,
            COMMIT_MANIFEST_KIND,
            seen,
            embedded,
        )
        .await
    }

    /// [`Self::store_blobs_and_manifest`] under a given manifest keyspace:
    /// a chain commit, or a retained branch ([`Self::keep_branch`]).
    async fn store_manifest(
        &self,
        bundle: &WireBundle,
        mut commit: IndexableCommit,
        prefix: &[u8],
        kind: &str,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        // Store each blob, in bundle order.
        let mut blob_hashes = Vec::with_capacity(commit.cozies.len());
        for (i, blob) in bundle.cozies().enumerate() {
            let hash = self.blob_store.put(blob).await?;
            blob_hashes.push(hash);
            if i < commit.cozies.len() {
                commit.cozies[i].blob_hash = hash;
            }
        }
        commit.blob_hashes = blob_hashes;

        // Durable commit point: once this manifest is stored, the full
        // IndexableCommit -- including the exact ingest-time order of its
        // cozies and how they group into transactions -- is recoverable
        // from the blob store alone.
        let manifest = CommitManifest {
            kind: kind.to_string(),
            commit: commit.clone(),
            shape: Shape::of(bundle),
            seen,
            embedded: embedded.to_vec(),
        };
        let mut manifest_bytes = prefix.to_vec();
        serde_json::to_writer(&mut manifest_bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("commit manifest serialize: {e}")))?;
        let manifest_hash = self.blob_store.put(&manifest_bytes).await?;

        Ok((commit, manifest_hash))
    }

    /// Ingest a pre-validated commit: store blobs and index metadata.
    ///
    /// Each coz of `bundle` is a raw coz byte slice. The engine:
    /// 1. Puts each blob into the blob store (content-addressed)
    /// 2. Builds an `IndexableCommit` from the metadata + blob hashes
    /// 3. Stores a durable [`CommitManifest`] recording that `IndexableCommit` and how its cozies
    ///    group into transactions (see [`Self::store_blobs_and_manifest`]) -- the crash-safe commit
    ///    point
    /// 4. Calls the indexer to record the commit's index entries
    ///
    /// Returns the BLAKE3 hashes of the stored blobs.
    ///
    /// **Note:** This method does NOT validate protocol-level
    /// signatures or state transitions. That responsibility belongs
    /// to the protocol validation layer (Phase 3b).
    ///
    /// # Locking
    ///
    /// This method holds no lock of its own: the read-then-write sequence
    /// it performs (resolving `commit.sequence` against the indexer's
    /// current tip, then writing) is only safe against concurrent writers
    /// for the same `principal_id` because [`Self::submit_commit`] -- its
    /// sole caller -- already holds that principal's serialization lock
    /// across its whole critical section, including this call.
    /// `pub(crate)` rather than `pub` so a caller outside this module
    /// cannot reach it without also reaching (and being reminded of) that
    /// invariant; call [`Self::submit_commit`] instead.
    ///
    /// ```compile_fail
    /// # async fn f(
    /// #     engine: &cyphr_storage::engine::StorageEngine<
    /// #         cyphr_storage::blob::MemoryBlobStore,
    /// #         cyphr_storage::index::MemoryIndexer,
    /// #     >,
    /// #     bundle: &cyphr::replay::WireBundle,
    /// #     commit: cyphr_storage::index::IndexableCommit,
    /// # ) {
    /// // ingest_commit is pub(crate): unreachable from outside this crate,
    /// // so a caller cannot bypass submit_commit's serialization lock.
    /// let _ = engine.ingest_commit(bundle, commit).await;
    /// # }
    /// ```
    pub(crate) async fn ingest_commit<T: cyphr::eml::Storage>(
        &self,
        bundle: &WireBundle,
        build: StagedBuild<'_, T>,
    ) -> Result<IngestResult, EngineError> {
        let StagedBuild {
            commit,
            staged,
            embedded,
        } = build;
        self.ingest(bundle, commit, Some(staged), &embedded).await
    }

    /// [`Self::ingest_commit`] of index metadata built by hand, with no
    /// core commit behind it (unit tests of the indexing path).
    #[cfg(test)]
    pub(crate) async fn ingest_metadata(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
    ) -> Result<IngestResult, EngineError> {
        self.ingest::<cyphr::eml::MemoryStorage>(bundle, commit, None, &[])
            .await
    }

    /// Store blobs and manifest, then the commit-log append (when there is
    /// a core commit), then the index: the I1 order.
    #[tracing::instrument(
        skip(self, bundle, commit, staged),
        fields(
            principal_id = %commit.principal_id,
            blob_count = bundle.cozies().count()
        )
    )]
    async fn ingest<T: cyphr::eml::Storage>(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        staged: Option<cyphr::replay::StagedBundle<'_, T>>,
        embedded: &[EmbeddedPin],
    ) -> Result<IngestResult, EngineError> {
        // The one exclusive claim (a PG alias) is checked before the first
        // durable write: a refused commit must leave no blob or manifest
        // for a later rebuild to trip over. Two ingests for different
        // principals contend for one alias without sharing a principal
        // lock, so the check and the write it admits are held under a lock
        // per alias (in sorted order, so contenders cannot deadlock).
        let alias_locks = self.alias_locks(&[&commit]);
        let mut _alias_guards = Vec::with_capacity(alias_locks.len());
        for lock in &alias_locks {
            _alias_guards.push(lock.lock().await);
        }
        self.indexer
            .check_commit(&commit, &DeriveToken::new())
            .await?;
        let seen = unix_now();
        let (commit, manifest_hash) = self
            .store_blobs_and_manifest(bundle, commit, seen, embedded)
            .await?;
        let blob_hashes = commit.blob_hashes.clone();

        // The blob store now records the commit (I1), so its commit-log
        // append may follow: the log is never ahead of the record. The log
        // is a cache of that record, so a failed append does not unmake the
        // commit: the push still succeeds, and the next load repairs the
        // log by replaying the manifest's commit onto it (as after a crash
        // here).
        if let Some(Err(e)) = match staged {
            Some(staged) => Some(staged.commit().await),
            None => None,
        } {
            self.log_append_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                principal = %commit.principal_id,
                error = %e,
                "commit stored but its log append failed; the next load replays it"
            );
        }

        // The roots of a commit this process just verified, by the commit
        // that names them, before the index can show the commit to a reader.
        let admitted = CommittedTip::of(&commit);
        self.roots_at.insert(
            (commit.principal_id.clone(), admitted.commit_id),
            DerivedRoots {
                pr: admitted.pr,
                sr: admitted.sr,
                ar: admitted.ar,
                cr: admitted.cr,
            },
        );
        // The manifest is stored, so its frame is known before the index
        // shows the commit: a reader that finds the commit in the index
        // must find its frame, or it refuses the index as inconsistent.
        self.record_frame(&commit, &Shape::of(bundle), seen, embedded);
        self.indexer
            .index_commit(&commit, &DeriveToken::new())
            .await?;
        // A commit refused while the principal was in Error and kept as
        // evidence is now canonical: it is listed once, as the chain.
        if let Some(id) = commit.commit_ids.first()
            && let Some(kept) = self
                .branches
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(&commit.principal_id)
        {
            kept.retain(|r| !(r.tip.tip == *id && r.tip.sequence == commit.sequence));
        }

        Ok(IngestResult {
            principal_id: commit.principal_id.clone(),
            blob_hashes,
            manifest_hash: Some(manifest_hash),
            tip: Some(CommittedTip::of(&commit)),
        })
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, returning how many were indexed.
    /// [`Self::rebuild_index_with_report`] is the same pass with the
    /// quarantined manifests named.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_manifests(&self) -> Result<usize, EngineError> {
        let report = self.rebuild_index_with_report().await?;
        for q in &report.quarantined {
            tracing::warn!(
                manifest = %q.manifest,
                principal = ?q.principal_id,
                reason = ?q.reason,
                "manifest quarantined: left out of the index"
            );
        }
        Ok(report.indexed)
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, quarantining any it cannot index.
    ///
    /// Closes the ingest crash window: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent `indexer.index_commit` call
    /// leaves a manifest durably stored with no index entry yet; this
    /// completes the index write from the manifest's already-resolved
    /// `IndexableCommit`. It also serves full reconstruction: clearing the
    /// index and calling this rebuilds every manifest-backed commit from
    /// the blob store alone (root `AGENTS.md` invariant I1).
    ///
    /// **The index is a function of the blob set.** Manifests are indexed
    /// in canonical order (sequence, then principal id, then manifest
    /// hash), never the blob store's listing order, and every index write
    /// is order-independent (digests name sets of holders). The one
    /// exclusive claim is a principal's PG alias: if two manifests contest
    /// one, the earlier in canonical order wins.
    ///
    /// **A manifest the index cannot take never fails the rebuild.** It is
    /// quarantined with a typed [`QuarantineReason`] (malformed, naming
    /// blobs the store lacks, not bound to its principal, contesting a
    /// PG alias, or rivalling a commit already at its chain position), and so are that principal's
    /// later commits, so no chain is indexed with a gap. Backend failures and a manifest-shaped
    /// wire blob ([`EngineError::LegacyManifest`]) still fail the rebuild.
    ///
    /// This does not replay: it trusts the engine-written manifests plus
    /// the blob-presence and binding checks. The replaying rebuild is
    /// [`Self::rebuild_index_from_scratch_with_report`].
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_with_report(&self) -> Result<RebuildReport, EngineError> {
        self.rebuild_pass(false).await
    }

    /// The rebuild pass. With `replay`, every manifest's blobs are also
    /// replayed onto its principal from genesis by the admission path
    /// ([`Self::build_commit`]), and a manifest whose commit the replay
    /// does not reproduce is quarantined ([`QuarantineReason::Unreplayable`]).
    async fn rebuild_pass(&self, replay: bool) -> Result<RebuildReport, EngineError> {
        self.kept.clear();
        self.rebuild_pass_on(&self.indexer, replay).await
    }

    /// [`Self::rebuild_pass`] building into `index` rather than the
    /// engine's own, so a scan can run without touching the real index.
    async fn rebuild_pass_on<X: Indexer + IndexerWrite>(
        &self,
        index: &X,
        replay: bool,
    ) -> Result<RebuildReport, EngineError> {
        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;

        let mut quarantined = Vec::new();
        // The earliest sequence at which a principal's chain broke, for any
        // reason; every later commit of that principal is orphaned, so the
        // indexed chain is always a gapless prefix.
        let mut broken_from: HashMap<String, u64> = HashMap::new();
        let mut manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut branch_manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut action_manifests: Vec<(Blake3Hash, ActionManifest)> = Vec::new();
        let mut revoked = Revoked::new();
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
            if data.starts_with(REVOKE_RECORD_V1_PREFIX) {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: None,
                    reason: QuarantineReason::Malformed(
                        "a v1 revoke record carries no receipt time".into(),
                    ),
                });
                continue;
            }
            if let Some(json) = data.strip_prefix(REVOKE_RECORD_PREFIX) {
                // The revoke a record carries is re-verified, never
                // trusted; its receipt time is this node's own statement.
                // One that fails costs only itself. That includes a record
                // an earlier build accepted that the current rule refuses
                // (an over-size revoke): it is quarantined here and its key
                // is not dead in the engine, so the warning below names it.
                let record = serde_json::from_slice::<RevokeRecord>(json);
                let verified = match &record {
                    Ok(r) => verify_revoke(&r.evidence).map(|tmb| (tmb, r.wrt)),
                    Err(e) => Err(e.to_string()),
                };
                if let Err(why) = &verified {
                    // A record that no longer verifies (for one, a v2
                    // record over the revoke size limit) leaves its key
                    // alive in the engine, so the log names the key.
                    let key = record
                        .as_ref()
                        .ok()
                        .and_then(|r| r.evidence["pay"]["tmb"].as_str())
                        .unwrap_or("unreadable");
                    tracing::warn!(
                        key,
                        reason = %why,
                        "revoke record quarantined on rebuild; its key is not dead in the engine"
                    );
                }
                match verified {
                    // Live keeps one record per key, the first accepted;
                    // were there two, the earliest receipt stands.
                    Ok((tmb, wrt)) => {
                        let death = Death {
                            wrt,
                            record: *hash.as_bytes(),
                        };
                        let at = revoked.entry(tmb).or_insert(death);
                        *at = (*at).min(death);
                    },
                    Err(why) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(format!("revoke record: {why}")),
                    }),
                }
                continue;
            }
            if let Some(json) = data.strip_prefix(ACTION_MANIFEST_PREFIX) {
                // Actions are not chained: a bad action manifest costs only
                // itself.
                match serde_json::from_slice::<ActionManifest>(json) {
                    Ok(m) if m.kind == ACTION_MANIFEST_KIND => action_manifests.push((hash, m)),
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "action manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            if let Some(json) = data.strip_prefix(BRANCH_MANIFEST_PREFIX) {
                // Retained branches never reach the index, so a bad one
                // costs only its own listing, never a chain position.
                match serde_json::from_slice::<CommitManifest>(json) {
                    Ok(m) if m.kind == BRANCH_MANIFEST_KIND => {
                        match self.check_manifest_supported(&hash, &m).await? {
                            Ok(()) => branch_manifests.push((hash, m)),
                            Err(reason) => quarantined.push(QuarantinedManifest {
                                manifest: hash,
                                principal_id: Some(m.commit.principal_id.clone()),
                                reason,
                            }),
                        }
                    },
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.commit.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "branch manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            let Some(json) = data.strip_prefix(COMMIT_MANIFEST_PREFIX) else {
                // The engine's own keyspace under a version this build does
                // not know: skipping it would report a clean store with
                // whatever it records missing (R6), so it is quarantined.
                if data.starts_with(ENGINE_BLOB_NAMESPACE) {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Unsupported(
                            "an engine blob of a version this build does not know".into(),
                        ),
                    });
                    continue;
                }
                // A wire blob. One shaped like a manifest cannot have been
                // written by this engine (it stores wire cozes in canonical
                // form only), so it is an old shared-store manifest or a
                // forged coz, and nothing here can tell which.
                if is_legacy_manifest(&data) {
                    return Err(EngineError::LegacyManifest { hash });
                }
                continue;
            };
            let manifest: CommitManifest = match serde_json::from_slice(json) {
                Ok(m) => m,
                Err(e) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    });
                    continue;
                },
            };
            if let Err(reason) = self.check_manifest_supported(&hash, &manifest).await? {
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason,
                });
                continue;
            }
            manifests.push((hash, manifest));
        }

        manifests.sort_by(|(ha, a), (hb, b)| {
            (a.commit.sequence, &a.commit.principal_id, ha.as_bytes()).cmp(&(
                b.commit.sequence,
                &b.commit.principal_id,
                hb.as_bytes(),
            ))
        });

        let unbound = self.unbound_principals(&manifests).await?;
        for (hash, manifest) in &manifests {
            if let Some(why) = unbound.get(&manifest.commit.principal_id) {
                quarantined.push(QuarantinedManifest {
                    manifest: *hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason: QuarantineReason::Unbound(why.clone()),
                });
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
            }
        }

        let Walk {
            canonical: manifests,
            rest: branch_manifests,
        } = walk_chains(manifests, branch_manifests, &unbound);
        let held: HeldRoots = manifests
            .iter()
            .chain(&branch_manifests)
            .flat_map(|(_, m)| {
                m.commit
                    .prs
                    .iter()
                    .map(|pr| (m.commit.principal_id.clone(), m.commit.sequence, pr.clone()))
            })
            .collect();

        let mut indexed = 0;
        // One memo for the whole rebuild: each embedded principal is replayed
        // once, whatever number of commits and actions pin it.
        let pins = PinSource::manifests(&manifests, &branch_manifests);
        let mut replays: HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>> =
            HashMap::new();
        // What the last replaying rebuild quarantined: a pass that does
        // not replay cannot judge those manifests, so it keeps them out.
        let skip: HashMap<Blake3Hash, String> = if replay {
            HashMap::new()
        } else {
            index.quarantined().await?.into_iter().collect()
        };
        let histories = self
            .read_action_manifests(action_manifests, &skip, &mut quarantined)
            .await?;
        for (hash, manifest) in &manifests {
            let hash = *hash;
            let commit = &manifest.commit;
            if unbound.contains_key(&commit.principal_id) {
                continue;
            }
            if broken_from
                .get(&commit.principal_id)
                .is_some_and(|from| commit.sequence > *from)
            {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Orphaned(
                        "an earlier commit of this principal was quarantined".into(),
                    ),
                });
                continue;
            }
            let refused = match skip.get(&hash) {
                Some(why) => Err(format!("quarantined by the last scratch rebuild: {why}")),
                None if replay => self.replay_manifest(&mut replays, manifest, &pins).await?,
                None => Ok(()),
            };
            if let Err(why) = refused {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Unreplayable(why),
                });
                broken_from
                    .entry(commit.principal_id.clone())
                    .or_insert(commit.sequence);
                continue;
            }
            let mut written = index.index_commit(commit, &DeriveToken::new()).await;
            if let Err(crate::index::IndexerError::Consistency(_)) = written {
                // The index holds another commit here: it was built before
                // the fork was resolved, and the chain is re-pointed.
                written = index
                    .replace_chain_from(
                        &commit.principal_id,
                        commit.sequence,
                        std::slice::from_ref(commit),
                        &DeriveToken::new(),
                    )
                    .await;
            }
            match written {
                Ok(()) => {
                    self.record_frame(commit, &manifest.shape, manifest.seen, &manifest.embedded);
                    indexed += 1;
                },
                Err(crate::index::IndexerError::Conflict(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Conflict(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(crate::index::IndexerError::Consistency(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Fork(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(e) => return Err(e.into()),
            }
        }

        // Actions hold no chain position: each principal's are recorded
        // once its chain is in, judged at their own `now` against the key
        // history (SPEC 6.5). The naked revokes are not in force: a stored
        // action was admitted when it arrived, and a revoke gates only what
        // arrives after it (SPEC 14.12). A replaying pass keeps the ones its
        // replay accepts; one that does not replay keeps those of a
        // principal the index holds.
        let mut actions: HashMap<String, Vec<StoredActions>> = HashMap::new();
        for (principal_id, history) in histories {
            let mut orphaned = |bundle: ActionBundle, reason| {
                quarantined.push(QuarantinedManifest {
                    manifest: bundle.manifest,
                    principal_id: Some(principal_id.clone()),
                    reason,
                });
            };
            if replay {
                let Some(principal) = replays.get_mut(&principal_id) else {
                    for bundle in history {
                        orphaned(
                            bundle,
                            QuarantineReason::Orphaned("its principal has no chain".into()),
                        );
                    }
                    continue;
                };
                for bundle in history {
                    if let Err(e) = self
                        .apply_pins(principal, &pins, &bundle.embedded, EMBED_DEPTH)
                        .await
                    {
                        orphaned(bundle, QuarantineReason::Unreplayable(e.to_string()));
                        continue;
                    }
                    match cyphr::replay::replay_held(principal, &bundle.bundle).await {
                        Ok(_) => actions
                            .entry(principal_id.clone())
                            .or_default()
                            .push(bundle.stored()),
                        Err(e) => orphaned(bundle, QuarantineReason::Unreplayable(e.to_string())),
                    }
                }
            } else if index.get_tip(&principal_id).await?.is_some() {
                actions
                    .entry(principal_id.clone())
                    .or_default()
                    .extend(history.into_iter().map(|b| b.stored()));
            } else {
                for bundle in history {
                    orphaned(
                        bundle,
                        QuarantineReason::Orphaned("its principal has no chain".into()),
                    );
                }
            }
        }
        *self.actions.lock().unwrap_or_else(|p| p.into_inner()) = actions;

        let branches = self
            .classify_branches(branch_manifests, &held, &mut quarantined)
            .await?;
        *self.branches.lock().unwrap_or_else(|p| p.into_inner()) = branches;
        *self.revoked.lock().unwrap_or_else(|p| p.into_inner()) = revoked;

        quarantined.sort_by_key(|q| *q.manifest.as_bytes());
        Ok(RebuildReport {
            indexed,
            quarantined,
        })
    }

    /// Read back the scanned action manifests' bundles by principal,
    /// quarantining any whose blobs are missing or are not an
    /// action-only bundle, and, in a pass that does not replay, any the
    /// last scratch rebuild quarantined (`skip`).
    async fn read_action_manifests(
        &self,
        manifests: Vec<(Blake3Hash, ActionManifest)>,
        skip: &HashMap<Blake3Hash, String>,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, ActionHistory>, EngineError> {
        let mut histories: HashMap<String, ActionHistory> = HashMap::new();
        'manifests: for (hash, manifest) in manifests {
            let mut reject = |reason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.principal_id.clone()),
                    reason,
                });
            };
            if let Some(why) = skip.get(&hash) {
                reject(QuarantineReason::Unreplayable(format!(
                    "quarantined by the last scratch rebuild: {why}"
                )));
                continue;
            }
            let mut blobs = Vec::with_capacity(manifest.blob_hashes.len());
            for blob in &manifest.blob_hashes {
                let Some(data) = self.blob_store.get(blob).await? else {
                    reject(QuarantineReason::Unsupported(format!(
                        "action manifest {hash} names blob {blob}, which is not stored"
                    )));
                    continue 'manifests;
                };
                blobs.push(data);
            }
            match action_bundle(blobs) {
                Ok(bundle) => histories
                    .entry(manifest.principal_id.clone())
                    .or_default()
                    .push(ActionBundle {
                        manifest: hash,
                        blobs: manifest.blob_hashes,
                        embedded: manifest.embedded,
                        bundle,
                    }),
                Err(why) => reject(QuarantineReason::Malformed(format!(
                    "action manifest {hash}: {why}"
                ))),
            }
        }
        for bundles in histories.values_mut() {
            replay_order(bundles);
        }
        Ok(histories)
    }

    /// Decide which stored manifests the canonical walk left out
    /// ([`walk_chains`]) are branches of the index just rebuilt. A branch is
    /// kept only if it forks the canonical chain: the canonical commit at
    /// its position exists and is a different commit, and its `pre` is the
    /// canonical parent's PR or the PR of a branch kept one position below
    /// (a branch extending a branch, as an unresolved fork's two extended
    /// heads leave). The rest are quarantined.
    ///
    /// The index is already final when this runs and is never read to
    /// decide the canonical chain here, so the result is a function of the
    /// blob set: manifests are taken by position, then in hash order, which
    /// fixes the order a branch can extend a kept branch. The retention
    /// caps ([`BRANCH_LIMIT`]) are admission rules and are not applied
    /// here.
    async fn classify_branches(
        &self,
        mut branch_manifests: Vec<(Blake3Hash, CommitManifest)>,
        held: &HeldRoots,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, Vec<Retained>>, EngineError> {
        branch_manifests.sort_by_key(|(hash, m)| (m.commit.sequence, *hash.as_bytes()));
        let mut kept: HashMap<String, Vec<Retained>> = HashMap::new();
        // The PRs of the branches kept so far, by principal and position.
        let mut kept_prs: std::collections::HashSet<(String, u64, String)> =
            std::collections::HashSet::new();
        for (hash, manifest) in branch_manifests {
            let CommitManifest {
                commit,
                shape,
                kind,
                seen,
                embedded,
            } = manifest;
            let tip = commit.commit_ids.first().cloned().unwrap_or_default();
            // A commit manifest that lost the canonical walk but extends a
            // held commit is fork evidence: whatever keeps it out of the
            // branch table, it is reported as a fork, never as damage.
            let fork = kind == COMMIT_MANIFEST_KIND
                && match &commit.pre {
                    None => commit.sequence == 0,
                    Some(pre) => commit.sequence.checked_sub(1).is_some_and(|below| {
                        held.contains(&(commit.principal_id.clone(), below, pre.clone()))
                    }),
                };
            let unless_fork = |why: String, otherwise: fn(String) -> QuarantineReason| {
                if fork {
                    QuarantineReason::Fork(why)
                } else {
                    otherwise(why)
                }
            };
            let mut reject = |reason: QuarantineReason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason,
                });
            };
            let from = commit.sequence.saturating_sub(1);
            let chain = self
                .chain(&commit.principal_id, Some(from), Some(commit.sequence))
                .await?;
            // A branch past the canonical head (refused while the principal
            // was in Error) has no canonical commit at its position; its
            // `pre` still must name the head or a kept branch, below.
            let canonical = chain.iter().find(|c| c.sequence == commit.sequence);
            if canonical.is_some_and(|c| c.commit_id == tip) {
                reject(QuarantineReason::Conflict(
                    "branch is the canonical commit at its position".into(),
                ));
                continue;
            }
            let parent = chain.iter().find(|c| c.sequence + 1 == commit.sequence);
            let on_branch = |pre: &String| {
                commit.sequence > 0
                    && kept_prs.contains(&(
                        commit.principal_id.clone(),
                        commit.sequence - 1,
                        pre.clone(),
                    ))
            };
            if commit.pre.as_ref() != parent.map(|c| &c.pr)
                && !commit.pre.as_ref().is_some_and(on_branch)
            {
                reject(unless_fork(
                    "branch's pre is not the canonical parent's PR".into(),
                    QuarantineReason::Orphaned,
                ));
                continue;
            }
            let of_principal = kept.entry(commit.principal_id.clone()).or_default();
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                continue;
            }
            let signer = commit_signer(&commit);
            // No quota here: the caps bound what ingest admits, and a
            // promotion retains its displaced commits past them, so a
            // quota in the rebuild would drop a once-canonical commit the
            // live store keeps (I1).
            for pr in &commit.prs {
                kept_prs.insert((commit.principal_id.clone(), commit.sequence, pr.clone()));
            }
            of_principal.push(Retained {
                pr: commit.prs.first().cloned().unwrap_or_default(),
                signed: signed_of(&commit),
                tip: BranchTip {
                    tip,
                    pre: commit.pre,
                    sequence: commit.sequence,
                    canonical: false,
                    seen,
                },
                signer,
                keys: key_entries(&commit.keys),
                blobs: commit.blob_hashes,
                shape,
                embedded,
            });
        }
        Ok(kept)
    }

    /// A corruption detector, not a security boundary. Without replay: the
    /// genesis a principal's first sequence-0 manifest (in canonical
    /// order) discloses in its blobs ([`disclosed_genesis`]) must derive
    /// the principal id the manifests carry ([`record_key`]). Returns each failing principal with
    /// why; they are quarantined.
    ///
    /// Scope: a principal whose blobs disclose no genesis is not judged
    /// here (the replaying rebuild quarantines it), and when several
    /// sequence-0 manifests claim one id only the first is checked. The
    /// guarantee that a forged manifest cannot re-point a principal comes
    /// from the manifest keyspace plus the single writer
    /// ([`COMMIT_MANIFEST_PREFIX`], [`canonical_coz`]), not from this
    /// check.
    async fn unbound_principals(
        &self,
        manifests: &[(Blake3Hash, CommitManifest)],
    ) -> Result<HashMap<String, String>, EngineError> {
        let mut firsts: HashMap<&str, &CommitManifest> = HashMap::new();
        for (_, manifest) in manifests {
            if manifest.commit.sequence == 0 {
                firsts
                    .entry(&manifest.commit.principal_id)
                    .or_insert(manifest);
            }
        }
        let mut unbound = HashMap::new();
        let mut principals: Vec<&str> = manifests
            .iter()
            .map(|(_, m)| m.commit.principal_id.as_str())
            .collect();
        principals.sort_unstable();
        principals.dedup();
        for principal_id in principals {
            let Some(first) = firsts.get(principal_id) else {
                unbound.insert(
                    principal_id.to_string(),
                    "no sequence-0 manifest for the principal".to_string(),
                );
                continue;
            };
            let bundle = self.manifest_bundle(first).await?;
            // Without a disclosed genesis the id cannot be proven from
            // blobs; this pass does not judge it (the replaying rebuild
            // quarantines it).
            let genesis = match disclosed_genesis(&bundle) {
                Some(Ok(genesis)) => genesis,
                None => continue,
                Some(Err(e)) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("genesis not derivable from its blobs: {e}"),
                    );
                    continue;
                },
            };
            // The key is a function of the record (I1: not of what a
            // manifest claims), so that one commit is replayed, not the
            // chain ([`record_key`]).
            let derived = record_key(&genesis, &bundle).await;
            // Strict by decision: the project is pre-1.0 with nothing
            // deployed, so a store keyed by a PG-to-be exists only in test
            // runs and needs no lenient branch.
            if derived.as_deref() != Some(principal_id) {
                unbound.insert(
                    principal_id.to_string(),
                    "its first commit does not derive this id as its key".to_string(),
                );
            }
        }
        Ok(unbound)
    }

    /// Replay `commit`'s blobs onto its principal (`replays` holds each
    /// principal's state, advanced manifest by manifest in sequence order)
    /// and compare the commit the admission path builds with the one the
    /// manifest records. `Ok(Err(why))` is a manifest to quarantine.
    ///
    /// A principal is replayed from the genesis its sequence-0 blobs
    /// disclose ([`disclosed_genesis`]): every chain begins with a genesis
    /// commit (SPEC 5.1), so one that discloses none is quarantined.
    async fn replay_manifest(
        &self,
        replays: &mut HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>>,
        manifest: &CommitManifest,
        pins: &PinSource<'_>,
    ) -> Result<Result<(), String>, EngineError> {
        let commit = &manifest.commit;
        let bundle = self.manifest_bundle(manifest).await?;
        let principal = match replays.entry(commit.principal_id.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let Some(genesis) = disclosed_genesis(&bundle) else {
                    return Ok(Err("its first commit discloses no genesis".into()));
                };
                let opened = match genesis {
                    Ok(genesis) => {
                        Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new())
                            .await
                    },
                    Err(e) => Err(e),
                };
                match opened {
                    Ok(principal) => e.insert(principal),
                    Err(e) => return Ok(Err(format!("genesis does not replay: {e}"))),
                }
            },
        };
        // The embedded principals the commit was admitted through are
        // replayed from the manifests themselves: the index that would
        // serve them is being rebuilt.
        if let Err(e) = self
            .apply_pins(principal, pins, &manifest.embedded, EMBED_DEPTH)
            .await
        {
            return Ok(Err(format!("an embedded principal does not replay: {e}")));
        }
        let built =
            Self::build_commit(principal, &bundle, &commit.principal_id, commit.sequence).await;
        let StagedBuild {
            commit: mut replayed,
            staged,
            ..
        } = match built {
            Ok(Some(build)) => build,
            Ok(None) => return Ok(Err("its blobs form no commit".into())),
            Err(e) => return Ok(Err(format!("its blobs do not replay: {e}"))),
        };
        if let Err(e) = staged.commit().await {
            return Ok(Err(format!("its blobs do not replay: {e}")));
        }
        // `store_manifest` fills these in at ingest.
        replayed.blob_hashes.clone_from(&commit.blob_hashes);
        for (coz, hash) in replayed.cozies.iter_mut().zip(&commit.blob_hashes) {
            coz.blob_hash = *hash;
        }
        let same = serde_json::to_value(&replayed).ok() == serde_json::to_value(commit).ok();
        Ok(if same {
            Ok(())
        } else {
            Err("it records a commit its blobs do not yield".into())
        })
    }

    /// The bundle a commit manifest records: its blobs grouped by its
    /// shape, with the keys its commit introduced.
    async fn manifest_bundle(&self, manifest: &CommitManifest) -> Result<WireBundle, EngineError> {
        let blobs = self.read_blobs(&manifest.commit.blob_hashes).await?;
        manifest
            .shape
            .group(blobs, key_entries(&manifest.commit.keys))
            .ok_or_else(|| {
                EngineError::MalformedBlob(
                    "a commit manifest's shape groups a different number of blobs".into(),
                )
            })
    }

    /// Whether a manifest's commit names blobs the store holds: the index
    /// is a cache of the blobs (I1), so a manifest field the blobs do not
    /// support must not reach it. `Ok(Err(reason))` is a manifest to
    /// quarantine; `Err` is a backend failure.
    async fn check_manifest_supported(
        &self,
        manifest_hash: &Blake3Hash,
        manifest: &CommitManifest,
    ) -> Result<Result<(), QuarantineReason>, EngineError> {
        let commit = &manifest.commit;
        if manifest.shape.len() != commit.blob_hashes.len() {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest_hash}: its shape groups a different number of blobs"
            ))));
        }
        let manifest = manifest_hash;
        if commit.blob_hashes.is_empty()
            || commit.cozies.len() != commit.blob_hashes.len()
            || commit
                .cozies
                .iter()
                .zip(&commit.blob_hashes)
                .any(|(coz, hash)| coz.blob_hash != *hash)
        {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest}: cozies and blob hashes disagree"
            ))));
        }
        for hash in &commit.blob_hashes {
            if !self.blob_store.exists(hash).await? {
                return Ok(Err(QuarantineReason::Unsupported(format!(
                    "commit manifest {manifest} names blob {hash}, which is not stored"
                ))));
            }
        }
        Ok(Ok(()))
    }

    // ========================================================================
    // Principal lifecycle
    // ========================================================================

    /// Reconstruct a live [`cyphr::Principal`] by replaying stored commits.
    ///
    /// Fetches the full commit chain from the indexer, retrieves each
    /// blob from the blob store, and delegates to the existing
    /// [`import::replay_commits`] infrastructure, with the action-only
    /// bundles accepted between commits recorded where they were accepted.
    ///
    /// # Arguments
    ///
    /// * `principal_id` — The tagged-digest identifier for the principal.
    /// * `genesis` — How this principal was originally created.
    ///
    /// # Errors
    ///
    /// - `EngineError::Indexer` — commit chain lookup failed.
    /// - `EngineError::BlobStore` — blob retrieval failed.
    /// - `EngineError::NotFound` — blob referenced by index is missing.
    /// - `EngineError::MalformedBlob` — stored blob is not valid JSON.
    /// - `EngineError::Load` — replay/validation failed.
    #[tracing::instrument(skip(self, genesis))]
    pub async fn load_principal(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let stored = key.as_deref().unwrap_or(principal_id);
        // The writer's lock: a push appends to the durable log before it
        // writes the index, and a load in that window sees a log one leaf
        // ahead of the chain and regenerates it for nothing.
        let lock = self.principal_lock(stored);
        let _no_write_in_flight = lock.lock().await;
        self.replay_stored(stored, genesis).await
    }

    /// [`load_principal`](Self::load_principal) for an id already known to
    /// be the stored spelling.
    async fn replay_stored(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let generation = self
            .logs
            .generation(principal_id)
            .map_err(EngineError::Storage)?;
        let replayed = self
            .replay_generation(principal_id, genesis.clone(), generation)
            .await;
        if !log_is_stale(&replayed) {
            return replayed;
        }
        // The log is not a cache of the canonical chain: a resolved fork
        // re-pointed the chain under it, or it was written before the
        // two-phase commit. It is a cache of the blob store (I1), so it is
        // regenerated into a fresh generation from the blobs, one
        // regeneration at a time (the write lock may already be held by
        // this caller, so this one is separate).
        let lock = self.principal_lock(&format!("eml-generation\0{principal_id}"));
        let _regenerating = lock.lock().await;
        let current = self
            .logs
            .generation(principal_id)
            .map_err(EngineError::Storage)?;
        if current != generation {
            return self.replay_generation(principal_id, genesis, current).await;
        }
        let next = generation + 1;
        let storage = self
            .logs
            .open(principal_id, next)
            .map_err(EngineError::Storage)?;
        let regenerated = self
            .replay_onto(principal_id, genesis, storage, None)
            .await?;
        self.logs
            .retire_below(principal_id, next)
            .map_err(EngineError::Storage)?;
        Ok(regenerated)
    }

    /// Replay `principal_id`'s canonical chain onto generation
    /// `generation` of its log.
    async fn replay_generation(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        generation: u64,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let storage = self
            .logs
            .open(principal_id, generation)
            .map_err(EngineError::Storage)?;
        self.replay_onto(principal_id, genesis, storage, None).await
    }

    /// Replay the first `through` stored commits (all of them for `None`)
    /// of `principal_id` onto a principal built from `genesis` over
    /// `storage`.
    ///
    /// The storage is the caller's so a retention check can replay over a
    /// private in-memory Commit Tree: a rival verified at an earlier
    /// position must never read, append to or mismatch the principal's
    /// durable log.
    ///
    /// The stored action-only bundles are held once the commits are in. An
    /// action the key history does not authorize at its own `now` (SPEC 6.2,
    /// 6.5), as when a commit dated before it removes its key, is held but
    /// not shown in DT, and shown again if a later commit restores its key;
    /// its blobs stay stored (I1). The naked revokes the engine holds are
    /// taken in with them.
    async fn replay_onto<T: cyphr::eml::Storage>(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        storage: T,
        through: Option<u64>,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        let mut principal = Self::principal_from_genesis(genesis.clone(), storage).await?;

        let stored = self.stored_entries(principal_id, through).await?;
        self.commits_replayed.fetch_add(
            stored.entries.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let source = PinSource::stored();
        for (position, (entry, pins)) in stored.entries.iter().zip(&stored.pins).enumerate() {
            self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                .await?;
        }
        // Held actions are held as they are, with no verdict: whether one
        // counts is read from the key timeline, the naked revokes included,
        // whatever order they are taken in.
        for held in self.action_history(principal_id).await? {
            if let Err(why) = self
                .apply_pins(&mut principal, &source, &held.embedded, EMBED_DEPTH)
                .await
            {
                tracing::warn!(
                    principal = %principal_id,
                    manifest = %held.manifest,
                    error = %why,
                    "an embedded principal a stored action bundle was judged through does not replay; left out of DT"
                );
                continue;
            }
            match cyphr::replay::replay_held(&mut principal, &held.bundle).await {
                Ok(_) => {},
                Err(refused) => tracing::warn!(
                    principal = %principal_id,
                    manifest = %held.manifest,
                    error = %refused,
                    "a stored action bundle does not replay; left out of DT"
                ),
            }
        }

        note_revokes(&mut principal, &self.revoked());
        Ok(principal)
    }

    /// The action-only bundles accepted for `principal_id`, read back from
    /// the blob store, in replay order.
    async fn action_history(&self, principal_id: &str) -> Result<ActionHistory, EngineError> {
        let held = self
            .actions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default();
        let mut history = ActionHistory::new();
        for stored in held {
            let blobs = self.read_blobs(&stored.blobs).await?;
            let bundle = action_bundle(blobs).map_err(|why| {
                EngineError::MalformedBlob(format!("action manifest {}: {why}", stored.manifest))
            })?;
            history.push(ActionBundle {
                manifest: stored.manifest,
                blobs: stored.blobs,
                embedded: stored.embedded,
                bundle,
            });
        }
        replay_order(&mut history);
        Ok(history)
    }

    /// A principal holding only its genesis key, over `storage`.
    async fn principal_from_genesis<T: cyphr::eml::Storage>(
        genesis: crate::Genesis,
        storage: T,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        let key = genesis
            .key()
            .ok_or_else(|| EngineError::InvalidInput("genesis requires at least one key".into()))?;
        Ok(cyphr::Principal::open(key.clone(), storage).await?)
    }

    /// The first `through` stored commits (all for `None`) of
    /// `principal_id` as replayable entries: each commit's bundle read and
    /// parsed. No protocol check.
    async fn stored_entries(
        &self,
        principal_id: &str,
        through: Option<u64>,
    ) -> Result<StoredChain, EngineError> {
        let last = match through {
            Some(0) => return Ok(StoredChain::default()),
            Some(count) => Some(count - 1),
            None => None,
        };
        let chain = self.chain(principal_id, None, last).await?;
        let mut stored = StoredChain::default();
        for commit_ref in &chain {
            let bundle = self.commit_bundle(principal_id, commit_ref).await?;
            stored.entries.push(replay_entry(
                &bundle,
                &commit_ref.commit_id,
                &commit_ref.pr,
            )?);
            stored.prs.push(commit_ref.pr.clone());
            stored.pins.push(
                self.frame(principal_id, commit_ref)
                    .map(|f| f.embedded)
                    .unwrap_or_default(),
            );
        }

        Ok(stored)
    }

    /// Replay `entry`, the `position`-th commit of a chain, onto
    /// `principal`, first pinning each embedded principal the commit was
    /// admitted through at the state it was admitted against (SPEC 6.2,
    /// 10.7: a commit once admitted is never judged against a later state).
    async fn replay_pinned<T: cyphr::eml::Storage>(
        &self,
        principal: &mut cyphr::Principal<T>,
        source: &PinSource<'_>,
        entry: &crate::CommitEntry,
        pins: &[EmbeddedPin],
        position: usize,
        depth: u8,
    ) -> Result<(), EngineError> {
        self.apply_pins(principal, source, pins, depth).await?;
        crate::import::replay_commit(principal, entry, position).await?;
        Ok(())
    }

    /// Pin each of `pins` on `principal`: replay the embedded principal to
    /// the PR the admission recorded, and hold that as its tip. `b` was held
    /// before the commit was admitted, so a pin depends only on earlier
    /// admissions; `depth` bounds the walk for a store that says otherwise.
    async fn apply_pins<T: cyphr::eml::Storage>(
        &self,
        principal: &mut cyphr::Principal<T>,
        source: &PinSource<'_>,
        pins: &[EmbeddedPin],
        depth: u8,
    ) -> Result<(), EngineError> {
        for pin in pins {
            let b = self.state_at(source, &pin.member, &pin.b, depth).await?;
            principal
                .reveal_embedded(
                    &pin.member,
                    cyphr::Tracking::Pin(Box::new(cyphr::Tip::new(&b, 0))),
                )
                .map_err(EngineError::Protocol)?;
        }
        Ok(())
    }

    /// The state of the principal `member` names at the commit that left it
    /// at PR `b`, each of its own commits replayed against the embedded
    /// states it was admitted through. A `b` on B's canonical chain is read
    /// from one forward pass over it per call, resumed for a later `b`
    /// ([`PinSource`]). A `b` B has since reorganized away from is read from
    /// the ancestry of that commit alone ([`Self::ancestry`]). Boxed: it
    /// recurses through [`Self::apply_pins`].
    fn state_at<'a>(
        &'a self,
        source: &'a PinSource<'a>,
        member: &'a str,
        b: &'a str,
        depth: u8,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<cyphr::PrincipalState, EngineError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(depth) = depth.checked_sub(1) else {
                return Err(EngineError::MalformedBlob(format!(
                    "embedded principals nest deeper than {EMBED_DEPTH} replaying {member}"
                )));
            };
            // A chain that pins itself (only a forged store can) finds its
            // own slot held: refused, not waited on.
            let cycle =
                || EngineError::MalformedBlob(format!("embedded principal {member} pins itself"));
            // The canonical pass over `member` is held further up this call
            // when `member` and the principal being replayed embed each
            // other (SPEC 10.7): the state asked for here is an earlier one
            // than that pass has reached, so it is read from its own
            // ancestry below. A true self-pin finds that line held as well.
            let slot = source.slot(member);
            if let Ok(mut canonical) = slot.try_lock() {
                if canonical.is_none()
                    && let Some(chain) = self.embedded_chain(source, member).await?
                {
                    *canonical = Some(Self::chain_memo(chain, member).await?);
                }
                if let Some(memo) = canonical.as_mut() {
                    match self.advance(memo, source, b, depth).await {
                        Ok(Some(state)) => return Ok(state),
                        Ok(None) => {},
                        Err(e) => {
                            *canonical = None;
                            return Err(e);
                        },
                    }
                }
            }
            let line = source.slot(&format!("{member}\0{b}"));
            let mut line = line.try_lock().map_err(|_| cycle())?;
            if line.is_none() {
                let chain = self.ancestry(source, member, b).await?;
                *line = Some(Self::chain_memo(chain, member).await?);
            }
            let Some(memo) = line.as_mut() else {
                return Err(EngineError::EmbeddedPinLost {
                    member: member.to_string(),
                    b: b.to_string(),
                });
            };
            let found = self.advance(memo, source, b, depth).await;
            if found.is_err() {
                *line = None;
            }
            found?.ok_or_else(|| EngineError::EmbeddedPinLost {
                member: member.to_string(),
                b: b.to_string(),
            })
        })
    }

    /// Replay `memo`'s chain forward until it stands at PR `b`, taking the
    /// state at every PR passed; `None` when `b` is not on this chain.
    async fn advance(
        &self,
        memo: &mut ChainMemo,
        source: &PinSource<'_>,
        b: &str,
        depth: u8,
    ) -> Result<Option<cyphr::PrincipalState>, EngineError> {
        if let Some(state) = memo.at.get(b) {
            return Ok(Some(state.clone()));
        }
        if !memo.chain.prs.iter().any(|pr| pr == b) {
            return Ok(None);
        }
        while let (Some(entry), Some(pins)) = (
            memo.chain.entries.get(memo.next),
            memo.chain.pins.get(memo.next),
        ) {
            self.replay_pinned(&mut memo.principal, source, entry, pins, memo.next, depth)
                .await?;
            memo.next += 1;
            let pr = memo.principal.pr_tagged().map_err(EngineError::Protocol)?;
            let state = (*memo.principal).clone();
            let done = pr == b;
            memo.at.insert(pr, state.clone());
            if done {
                return Ok(Some(state));
            }
        }
        Ok(None)
    }

    /// A principal at the genesis `chain` begins with, to replay it onto.
    async fn chain_memo(chain: StoredChain, member: &str) -> Result<ChainMemo, EngineError> {
        let first = chain.entries.first().ok_or_else(|| {
            EngineError::NotFound(format!("embedded principal {member} has no commits"))
        })?;
        let first = first
            .bundle()
            .map_err(|e| EngineError::MalformedBlob(e.to_string()))?;
        let genesis = Self::genesis_from_bundle(Some(&first))?;
        let principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new()).await?;
        Ok(ChainMemo {
            chain,
            principal,
            next: 0,
            at: HashMap::new(),
        })
    }

    /// The principal `member` names (SPEC 10.3: B's PG or a PR B held), by
    /// the PG alias or the index's PR holders: the stored key. `None` when
    /// it names no principal held, or several, which no verifier can follow
    /// to one tip. The index is a locator only: what B's key history says
    /// is replayed from B's blobs.
    async fn principal_named(&self, member: &str) -> Result<Option<String>, EngineError> {
        if let Some(id) = self.stored_id(member).await? {
            return Ok(Some(id));
        }
        let Ok(digest) = member.parse::<TaggedDigest>() else {
            return Ok(None);
        };
        let mut holders: Vec<String> = self
            .indexer
            .resolve_digest_holders(&digest)
            .await?
            .into_iter()
            .filter(|h| h.principal_root)
            .filter_map(|h| h.principal_id)
            .collect();
        holders.sort_unstable();
        holders.dedup();
        match holders.as_slice() {
            [one] => self.stored_id(one).await,
            _ => Ok(None),
        }
    }

    /// The stored commits of the principal `member` (its PG or a PR it
    /// held) names, or `None` when `source` holds no such principal.
    async fn embedded_chain(
        &self,
        source: &PinSource<'_>,
        member: &str,
    ) -> Result<Option<StoredChain>, EngineError> {
        let Some((manifests, _)) = source.manifests else {
            let Some(id) = self.principal_named(member).await? else {
                return Ok(None);
            };
            return self.stored_entries(&id, None).await.map(Some);
        };
        let Some(named) = manifest_principal(source, member) else {
            return Ok(None);
        };
        let mut chain = StoredChain::default();
        for (_, manifest) in manifests
            .iter()
            .filter(|(_, m)| m.commit.principal_id == named)
        {
            let (entry, pins) = self.manifest_entry(manifest).await?;
            chain.prs.push(entry.pr.clone());
            chain.entries.push(entry);
            chain.pins.push(pins);
        }
        Ok(Some(chain))
    }

    async fn manifest_entry(
        &self,
        manifest: &CommitManifest,
    ) -> Result<(crate::CommitEntry, Vec<EmbeddedPin>), EngineError> {
        let bundle = self.manifest_bundle(manifest).await?;
        let entry = replay_entry(
            &bundle,
            manifest
                .commit
                .commit_ids
                .first()
                .map_or("", String::as_str),
            manifest.commit.prs.first().map_or("", String::as_str),
        )?;
        Ok((entry, manifest.embedded.clone()))
    }

    /// The commits of B's that lead to the one at PR `b`, oldest first,
    /// walked back by `pre` over every commit B holds, canonical and
    /// retained alike (SPEC 2.3.2, 14.12: B choosing another branch undoes
    /// nothing A did through it). The commit at `b` is the last.
    ///
    /// # Errors
    ///
    /// [`EngineError::EmbeddedPinLost`] when the ancestry has a gap: held
    /// blobs were lost, and a pin never degrades to an opaque digest.
    async fn ancestry(
        &self,
        source: &PinSource<'_>,
        member: &str,
        b: &str,
    ) -> Result<StoredChain, EngineError> {
        let lost = || EngineError::EmbeddedPinLost {
            member: member.to_string(),
            b: b.to_string(),
        };
        let (id, held) = match source.manifests {
            Some((canonical, rest)) => {
                let id = manifest_principal(source, member)
                    .or_else(|| manifest_principal(source, b))
                    .ok_or_else(lost)?;
                let held = canonical
                    .iter()
                    .chain(rest)
                    .filter(|(_, m)| m.commit.principal_id == id)
                    .map(|(_, m)| HeldCommit {
                        sequence: m.commit.sequence,
                        pr: m.commit.prs.first().cloned().unwrap_or_default(),
                        pre: m.commit.pre.clone(),
                        origin: HeldOrigin::Manifest(m),
                    })
                    .collect::<Vec<_>>();
                (id, held)
            },
            None => {
                let retained_of = |pr: &str| {
                    self.branches
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .iter()
                        .find(|(_, rs)| rs.iter().any(|r| r.pr == pr))
                        .map(|(id, _)| id.clone())
                };
                let id = match self.principal_named(member).await? {
                    Some(id) => id,
                    None => retained_of(member)
                        .or_else(|| retained_of(b))
                        .ok_or_else(lost)?,
                };
                let mut held: Vec<HeldCommit<'_>> = self
                    .chain(&id, None, None)
                    .await?
                    .into_iter()
                    .map(|c| HeldCommit {
                        sequence: c.sequence,
                        pr: c.pr.clone(),
                        pre: c.pre.clone(),
                        origin: HeldOrigin::Canonical(c),
                    })
                    .collect();
                let retained = self
                    .branches
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&id)
                    .cloned()
                    .unwrap_or_default();
                held.extend(retained.into_iter().map(|r| HeldCommit {
                    sequence: r.tip.sequence,
                    pr: r.pr.clone(),
                    pre: r.tip.pre.clone(),
                    origin: HeldOrigin::Retained(Box::new(r)),
                }));
                (id, held)
            },
        };
        let mut at = held.iter().find(|h| h.pr == b).ok_or_else(lost)?;
        let mut line = vec![at];
        while let Some(pre) = &at.pre {
            at = held
                .iter()
                .find(|h| h.pr == *pre && h.sequence + 1 == at.sequence)
                .ok_or_else(lost)?;
            line.push(at);
        }
        let mut chain = StoredChain::default();
        for h in line.into_iter().rev() {
            let (entry, pins) = match &h.origin {
                HeldOrigin::Canonical(c) => {
                    let bundle = self.commit_bundle(&id, c).await?;
                    let pins = self.frame(&id, c).map(|f| f.embedded).unwrap_or_default();
                    (replay_entry(&bundle, &c.commit_id, &c.pr)?, pins)
                },
                HeldOrigin::Retained(r) => {
                    let blobs = self.read_blobs(&r.blobs).await?;
                    let bundle = r.shape.group(blobs, r.keys.clone()).ok_or_else(|| {
                        EngineError::MalformedBlob(format!(
                            "retained commit {}: its shape groups a different number of blobs",
                            r.tip.tip
                        ))
                    })?;
                    (
                        replay_entry(&bundle, &r.tip.tip, &r.pr)?,
                        r.embedded.clone(),
                    )
                },
                HeldOrigin::Manifest(m) => self.manifest_entry(m).await?,
            };
            chain.prs.push(h.pr.clone());
            chain.entries.push(entry);
            chain.pins.push(pins);
        }
        Ok(chain)
    }

    /// Submit a commit for protocol validation and persistence.
    ///
    /// This is the **validated write path** — the engine's primary API for
    /// authority-mode operation. Each incoming raw coz blob is
    /// cryptographically verified via [`CommitScope`] before any
    /// persistence occurs.
    ///
    /// # Flow
    ///
    /// 1. Resolve genesis (from argument, storage, or submitted blobs)
    /// 2. Load existing principal from storage (or construct from genesis)
    /// 3. Open a `CommitScope`
    /// 4. Record the bundle's actions; for each transaction, verify its cozies (`{pay, sig}`, the
    ///    key a coz introduces taken from the bundle's `keys`) and apply them as one transaction
    ///    (`scope.apply_tx()`)
    /// 5. Finalize the scope → immutable `Commit`
    /// 6. Extract state digests from the finalized `Commit`
    /// 7. Store blobs + index via `ingest_commit`
    ///
    /// # Arguments
    ///
    /// * `principal_id` — The principal's id: its PG (SPEC 5.1 step 3; for a principal that never
    ///   committed, its genesis PR, the `tmb` by singleton promotion, SPEC 3.1), labelled
    ///   (`ALG:digest`, the stored spelling) or bare; a stored principal is also addressed by any
    ///   variant of its PG. Any other id is refused with [`EngineError::InvalidInput`]. The storage
    ///   key, and the id reported back, is the PG in the labelled spelling ([`record_key`]).
    /// * `genesis` — How this principal was originally created, or `None` to auto-detect from
    ///   storage (existing principal) or from the submitted blobs (new principal).
    /// * `bundle` — The pushed bundle (SPEC 4.6.2): `txs`, each transaction's raw coz JSON
    ///   envelopes (`{pay, sig}`), the commit transaction last; `keys`; and `actions`, data actions
    ///   recorded before the transactions.
    ///
    /// # Errors
    ///
    /// Any protocol violation (bad signature, broken chain, unknown signer,
    /// etc.) causes the entire submit to fail with no side effects — blobs
    #[tracing::instrument(
        skip(self, genesis, bundle),
        fields(blob_count = bundle.cozies().count())
    )]
    pub async fn submit_commit(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        bundle: &WireBundle,
    ) -> Result<IngestResult, EngineError> {
        self.ensure_healed().await?;

        if bundle.is_empty() {
            return Err(EngineError::InvalidInput("empty commit bundle".into()));
        }

        // Everything below, storage included, sees only the canonical
        // bundle, never the caller's bytes.
        let canonical = canonical_bundle(bundle)?;
        let bundle = &canonical;

        // 1. Resolve the principal's storage key.
        //
        // The key is a function of the record, never of the spelling the
        // caller used, so a rebuild from blobs reproduces it (I1): it is
        // [`record_key`] of the principal's first commit, its genesis
        // commit (SPEC 5.1). The key is also the id a response reports. An
        // id addresses a stored principal by its key or its PG (any
        // variant).
        let claimed = principal_id;
        let stored = self.stored_id(claimed).await?;
        let not_genesis_id = || {
            EngineError::InvalidInput(format!(
                "principal_id is not the genesis-derived id: {claimed}"
            ))
        };
        let (genesis, new_key) = match stored.as_deref() {
            // The record decides a stored principal's genesis: its first
            // commit, whatever genesis the caller names.
            Some(stored_id) => (self.genesis_of_stored(stored_id).await?, None),
            None => {
                // A new principal: these blobs are its genesis commit, and
                // the keys their `key/create`s disclose are its genesis.
                // Only when they disclose none does the caller's genesis
                // stand, for the core to refuse the commit with its reason.
                let genesis = match (disclosed_genesis(bundle), genesis) {
                    (Some(disclosed), _) => disclosed?,
                    (None, Some(given)) => given,
                    // Actions alone are not a genesis that failed to
                    // disclose its keys: the principal has no genesis
                    // commit yet (be0663f 2.3.2).
                    (None, None) if bundle.txs.is_empty() => {
                        return Err(EngineError::Protocol(cyphr::Error::GenesisIncomplete));
                    },
                    (None, None) => return Err(no_disclosed_genesis()),
                };
                let key = record_key(&genesis, bundle).await;
                let names_key = key
                    .as_ref()
                    .is_some_and(|key| claimed == key || claimed == bare_digest(key));
                // A commit that is no genesis commit derives no key; the
                // core refuses it with its own reason below.
                if key.is_some() && !names_key {
                    return Err(not_genesis_id());
                }
                let key = match key {
                    Some(key) => key,
                    None => genesis_principal_id(&genesis)?,
                };
                (genesis, Some(key))
            },
        };
        let canonical = stored.or(new_key).ok_or_else(not_genesis_id)?;
        let principal_id = canonical.as_str();

        // Serialize the whole sequence-resolution-through-ingest critical
        // section per principal_id: two concurrent callers for the SAME
        // principal must never both resolve `next_seq` before either has
        // ingested. Held for the remainder of this function; a concurrent
        // caller for a DIFFERENT principal_id never contends on this lock.
        let lock = self.principal_lock(principal_id);
        let write = Self::lock_writes(&lock, principal_id).await;

        // 2. Determine the tip this write extends, then load (or
        // construct) the principal at it: from the state kept after the
        // last write when everything it was folded from is unchanged,
        // else by replaying the stored chain.
        let tip_before = self.indexer.get_tip(principal_id).await?;
        let next_seq = tip_before.as_ref().map_or(0, |tip| tip.commit_count);
        // Taken before the load, so a revoke recorded during it can only
        // make the kept key differ, never match a state that lacks it.
        let revoked_at_load = self.revoked();
        let kept = self
            .resume_kept(
                principal_id,
                &genesis,
                tip_before.as_ref(),
                &revoked_at_load,
                &write,
            )
            .await?;
        let resumed = kept.is_some();
        let mut principal = match kept {
            Some(principal) => principal,
            None => self.replay_stored(principal_id, genesis.clone()).await?,
        };
        // The key a resumed state goes back under if the bundle is refused.
        let restore = tip_before
            .as_ref()
            .map(|tip| KeptKey::at(&tip.commit_id, revoked_at_load.clone()));
        // Set once the write has changed the state past what a refusal can
        // leave as it was (a stored bundle, an embedded principal followed).
        let mut changed = false;

        // The write itself. Its refusals leave `principal` as it was, so a
        // resumed state goes back to the cache and the next write is served
        // from it: a refused bundle is free to send, and must cost no replay.
        let written: Result<(IngestResult, bool), EngineError> = async {
            // Key death (SPEC 6.4), read under the lock. A revoke recorded
            // concurrently is not serialized with it (it takes no principal
            // lock), so it acts as one that arrived just after this bundle.
            if let Some(dead) = dead_key_in(bundle, &self.revoked()) {
                return Err(dead);
            }

            // SPEC 15.5: while the principal is in Error, only a bundle that
            // leaves Error is processed; what it would leave is `in_error` of
            // the held commits plus the candidate. A fixed protocol rule, never
            // a recovery strategy's.
            let held = self.held(principal_id).await?;
            let errored = in_error(&held).then_some(held.as_slice());

            // Whether every action the bundle carries is one the principal
            // already holds, before the bundle is applied to it: a client
            // cannot tell which actions a peer holds, so a push repeats them.
            let repeats =
                bundle_czds(bundle).map(|czds| czds.iter().all(|c| principal.has_included(c)));
            // A bundle may be signed through an embedded principal this node
            // holds (SPEC 10.3, 10.5); the manifest of what it forms, a commit
            // or the actions alone, records the state it was judged against.
            let embedded = self
                .follow_held(principal_id, &mut principal, bundle, &mut HeldCache::new())
                .await?;
            changed |= !embedded.is_empty();
            let mut build = match Self::build_staged(&mut principal, bundle, principal_id, next_seq)
                .await
            {
                Ok(Built::Commit(build))
                    if errored.is_some_and(|e| stays_errored(e, &build.commit)) =>
                {
                    // Refused, and kept as evidence: it verifies on the chain.
                    self.keep_evidence(bundle, build.commit, &embedded).await;
                    return Err(EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    });
                },
                Ok(Built::Commit(build)) => build,
                Ok(Built::Actions(_)) if errored.is_some() => {
                    return Err(EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    });
                },
                Ok(Built::Actions(staged)) => {
                    // An action is included only by a commit of its principal,
                    // and a principal's commits start at its genesis commit
                    // (be0663f 2.3.2): actions pushed ahead of it would be
                    // recorded under a key no chain includes.
                    if tip_before.is_none() {
                        return Err(EngineError::Protocol(cyphr::Error::GenesisIncomplete));
                    }
                    // Action-only bundle: no commit is formed and nothing is
                    // indexed, but its actions are in DT from now on, so every
                    // later replay records them. One whose every action DT
                    // already held is the same push repeated (a client cannot
                    // tell which actions a peer holds): it stores nothing
                    // (SPEC 7.6).
                    let blob_hashes = if repeats? {
                        bundle
                            .actions
                            .iter()
                            .map(|blob| Blake3Hash::from_bytes(*blake3::hash(blob).as_bytes()))
                            .collect()
                    } else {
                        changed = true;
                        let hashes = self
                            .store_actions(principal_id, &bundle.actions, &embedded)
                            .await?;
                        // Held on the state only once stored, so no refusal
                        // before this point leaves it holding an action the
                        // store does not. Verified when staged, so holding
                        // them checks nothing again, and holding actions in
                        // memory has no failure path: this `?` is the Commit
                        // variant's, which this one never takes.
                        staged
                            .commit()
                            .await
                            .map_err(|e| EngineError::Protocol(e.source))?;
                        hashes
                    };
                    // Built from the tip read before any write: once the blobs are
                    // durable this response cannot fail (an error would report a
                    // stored bundle as not stored).
                    let tip = tip_before.and_then(|t| {
                        Some(CommittedTip {
                            sequence: t.commit_count.checked_sub(1)?,
                            commit_id: t.commit_id,
                            pr: t.pr,
                            sr: t.sr,
                            ar: t.ar,
                            cr: t.cr,
                        })
                    });
                    // The actions are held on the state already: it is the
                    // kept state of the next write.
                    return Ok((
                        IngestResult {
                            principal_id: principal_id.to_string(),
                            blob_hashes,
                            manifest_hash: None,
                            tip,
                        },
                        embedded.is_empty(),
                    ));
                },
                Err(refused) => {
                    // A genesis commit pushed to a principal that has one is a
                    // rival at position 0: its arrow binds the genesis key, not
                    // this tip (SPEC 5.1 step 4), whatever transaction of it the
                    // replay happened to refuse first. A replay of the stored
                    // genesis itself stays the reuse it is (SPEC 7.6).
                    let reuse = matches!(refused, EngineError::Protocol(cyphr::Error::CozReuse));
                    let refused = if tip_before.is_some() && !reuse && is_genesis_bundle(bundle) {
                        EngineError::Protocol(cyphr::Error::CommitMismatch)
                    } else {
                        refused
                    };
                    // Only a verification failure can be a fork; a malformed
                    // or unreadable bundle is nothing to keep.
                    if matches!(refused, EngineError::Protocol(_)) {
                        // A bundle that extends a retained rival resolves the
                        // fork (SPEC 15.8) or, below the head, forks anew.
                        let canonical_len = tip_before.as_ref().map_or(0, |tip| tip.commit_count);
                        match self
                            .resolve_fork(principal_id, &genesis, bundle, canonical_len)
                            .await
                        {
                            Ok(Some(resolved)) => return Ok((resolved, false)),
                            Ok(None) => {},
                            Err(
                                refusal @ (EngineError::BranchLimit { .. }
                                | EngineError::Errored { .. }),
                            ) => return Err(refusal),
                            Err(err) => tracing::warn!(
                                principal = %principal_id,
                                error = %err,
                                "could not test a refused bundle as a resolution; retaining it"
                            ),
                        }
                        match self.retain_rival(principal_id, genesis, bundle).await {
                            // Held as a fork participant: the answer says so
                            // (the arrow does not fit the tip), whichever
                            // tip-state refusal the replay hit first, a
                            // duplicate key among them.
                            Ok(true) => {
                                return Err(EngineError::Protocol(cyphr::Error::CommitMismatch));
                            },
                            Ok(false) => {},
                            // The one retention outcome that is a refusal in
                            // its own right: no slot left for this key.
                            Err(full @ EngineError::BranchLimit { .. }) => return Err(full),
                            // Retention is best-effort evidence keeping: a
                            // storage fault must not turn the fork's own
                            // refusal (409/422) into a 500.
                            Err(err) => tracing::warn!(
                                principal = %principal_id,
                                error = %err,
                                "could not retain a refused rival; answering the original refusal"
                            ),
                        }
                    }
                    return Err(refused);
                },
            };
            let remembered = embedded.is_empty();
            build.embedded = embedded;
            changed = true;
            let result = self.ingest_commit(bundle, *build).await?;
            Ok((result, remembered))
        }
        .await;

        match written {
            Ok((result, remember)) => {
                if remember && let Some(tip) = &result.tip {
                    self.remember(
                        principal_id,
                        principal,
                        tip,
                        revoked_at_load,
                        resumed,
                        &write,
                    )
                    .await;
                }
                Ok(result)
            },
            Err(refused) => {
                if let (true, false, Some(key)) = (resumed, changed, restore) {
                    let state = principal.into_state();
                    self.kept.put(Kept { state, key }, &write);
                }
                Err(refused)
            },
        }
    }

    /// The principal at the tip a write extends, resumed from the state
    /// kept after the previous write, or `None` for a replay: nothing is
    /// kept, or something it was folded from has changed.
    ///
    /// The kept state is moved out of the cache, never copied; the write
    /// applies to it in place, [`Self::remember`] stores it again once the
    /// write succeeds, and a refused bundle puts it back as it was. With
    /// shadow checking on, the state is also replayed cold and compared,
    /// and a difference fails the write.
    ///
    /// Boxed, as is [`Self::follow_held`]: the auto-trait proof that
    /// `submit_commit` is `Send` would otherwise run through the replay and
    /// exceed the compiler's recursion limit for a caller with a concrete
    /// storage type.
    fn resume_kept<'a>(
        &'a self,
        principal_id: &'a str,
        genesis: &'a crate::Genesis,
        tip: Option<&'a TipState>,
        revoked: &'a Revoked,
        write: &'a WriteLock<'_>,
    ) -> ResumeFuture<'a, S> {
        Box::pin(self.resume_kept_unboxed(principal_id, genesis, tip, revoked, write))
    }

    async fn resume_kept_unboxed(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        tip: Option<&TipState>,
        revoked: &Revoked,
        write: &WriteLock<'_>,
    ) -> Result<Option<cyphr::Principal<S>>, EngineError> {
        use std::sync::atomic::Ordering::Relaxed;

        let Some(tip) = tip else {
            return Ok(None);
        };
        let fresh = KeptKey::at(&tip.commit_id, revoked.clone());
        let resumed = match self.kept.take(write) {
            Some(kept) if kept.key == fresh => self.resume_over_log(principal_id, kept.state).await,
            _ => None,
        };
        let Some(resumed) = resumed else {
            // A stale entry can never match again, and a cold write is
            // about to replace it: it is already out of the cache.
            self.kept_misses.fetch_add(1, Relaxed);
            return Ok(None);
        };
        if self.kept_shadow {
            let cold = self.replay_stored(principal_id, genesis.clone()).await?;
            if cold.projection() != resumed.projection() {
                self.kept_divergences.fetch_add(1, Relaxed);
                let why = format!(
                    "kept state of {principal_id} at {} differs from the replay of its stored \
                     chain",
                    tip.commit_id
                );
                tracing::error!("{why}");
                // Loud on purpose: shadow checking exists to fail a run that
                // would otherwise be answered, correctly, from the replay.
                return Err(EngineError::Storage(why));
            }
        }
        self.kept_hits.fetch_add(1, Relaxed);
        if self.kept_shadow {
            // Under the server's own target so a run's log shows that the
            // check ran (the scenarios' `RUST_LOG` names `cyphr_server`).
            tracing::info!(
                target: "cyphr_server::kept_state",
                principal = %principal_id,
                "shadow check: kept state equals the replay"
            );
        }
        Ok(Some(resumed))
    }

    /// `state` over its principal's current commit log, or `None` if that
    /// log is not the one it was folded from (a regenerated or lagging log
    /// is the replay's to repair).
    async fn resume_over_log(
        &self,
        principal_id: &str,
        state: cyphr::PrincipalState,
    ) -> Option<cyphr::Principal<S>> {
        let generation = self.logs.generation(principal_id).ok()?;
        let storage = self.logs.open(principal_id, generation).ok()?;
        cyphr::Principal::resume(state, storage).await.ok()
    }

    /// Keep `principal`, which has just admitted the commit `tip` names,
    /// for the principal's next write, if it is one a replay would
    /// reproduce exactly.
    ///
    /// Not kept: a principal whose state is not at `tip` (the commit
    /// stored but its log append failed: the next load repairs it), or
    /// whose history carries an embedded principal's pin or Key Tree
    /// digest. The views of embedded principals in a state that admitted a
    /// commit follow the embedded principal's current tip, those of a
    /// replay are pinned at the tip each commit was admitted against, so
    /// the two differ and such a principal replays.
    async fn remember(
        &self,
        principal_id: &str,
        principal: cyphr::Principal<S>,
        tip: &CommittedTip,
        revoked: Revoked,
        resumed: bool,
        write: &WriteLock<'_>,
    ) {
        if self.kept.capacity == 0 {
            return;
        }
        let at_tip = tip
            .sequence
            .checked_add(1)
            .is_some_and(|count| principal.commits().count() as u64 == count);
        // A resumed principal's history was checked when it was first kept.
        let embeds = principal.has_kt_digests()
            || (!resumed && self.history_has_pins(principal_id).await.unwrap_or(true));
        if !at_tip || embeds {
            return;
        }
        let kept = Kept {
            state: principal.into_state(),
            key: KeptKey::at(&tip.commit_id, revoked),
        };
        self.kept.put(kept, write);
    }

    /// Whether any commit or held action bundle of `principal_id` was
    /// admitted through an embedded principal ([`EmbeddedPin`]).
    async fn history_has_pins(&self, principal_id: &str) -> Result<bool, EngineError> {
        let held_actions = self
            .actions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .is_some_and(|held| held.iter().any(|a| !a.embedded.is_empty()));
        if held_actions {
            return Ok(true);
        }
        let chain = self.chain(principal_id, None, None).await?;
        Ok(chain.iter().any(|commit| {
            self.frame(principal_id, commit)
                .is_none_or(|f| !f.embedded.is_empty())
        }))
    }

    /// Follow every Key Tree digest of `principal` that names a principal
    /// this node holds, to the tip held for it (SPEC 10.7: references
    /// trigger tip retrieval), so the verifier judges `bundle` against it
    /// (10.5: the signer is an active key of B at that tip). Returns the
    /// state of each embedded principal a signer of `bundle` was authorized
    /// through, to record in the commit's manifest. A digest naming nothing
    /// held stays opaque: it authorizes nothing (10.3).
    ///
    /// Boxed: the auto-trait proof that `submit_commit` is `Send` would
    /// otherwise run through the core's follow, the tip source and a replay
    /// of B, and exceed the compiler's recursion limit for a caller with a
    /// concrete storage type.
    fn follow_held<'a, T: cyphr::eml::Storage + Send>(
        &'a self,
        own_id: &'a str,
        principal: &'a mut cyphr::Principal<T>,
        bundle: &'a WireBundle,
        held: &'a mut HeldCache<S>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<EmbeddedPin>, EngineError>> + Send + 'a>,
    > {
        Box::pin(self.follow_held_unboxed(own_id, principal, bundle, held))
    }

    async fn follow_held_unboxed<T: cyphr::eml::Storage>(
        &self,
        own_id: &str,
        principal: &mut cyphr::Principal<T>,
        bundle: &WireBundle,
        held: &mut HeldCache<S>,
    ) -> Result<Vec<EmbeddedPin>, EngineError> {
        if !principal.has_kt_digests() {
            return Ok(Vec::new());
        }
        let decoded = decode_bundle(bundle)?;
        let outside = |p: &cyphr::Principal<T>, tmb: &coz::Thumbprint| {
            !(p.is_key_active(tmb) || decoded.introduced_keys().any(|k| k.tmb() == tmb))
        };
        // With every signer a key of the principal now, none can be an
        // embedded principal's and there is nothing to follow, which saves
        // every embedded principal's replay. A key the bundle introduces
        // does not count: one that signs before its own introduction is not
        // yet a key of the principal, and is judged through the embedded
        // views, which must be current (SPEC 10.5).
        if decoded
            .cozies()
            .all(|coz| principal.is_key_active(&coz.header().tmb))
        {
            return Ok(Vec::new());
        }
        // The core reports every Key Tree digest but offers no list of
        // them, and only a revealed digest is followed: a source with no
        // tips names them, then each is revealed as followed.
        let members: Vec<String> = principal
            .follow_embedded(&mut NoTips)
            .await
            .into_iter()
            .map(|report| report.member)
            .collect();
        for member in &members {
            principal
                .reveal_embedded(member, cyphr::Tracking::Follow)
                .map_err(EngineError::Protocol)?;
        }
        let mut tips = HeldTips {
            engine: self,
            own_id,
            cache: held,
            found: std::collections::BTreeSet::new(),
            failed: None,
        };
        principal.follow_embedded(&mut tips).await;
        if let Some(failed) = tips.failed {
            return Err(failed);
        }
        let found = tips.found;
        let mut pins: Vec<EmbeddedPin> = Vec::new();
        for coz in decoded.cozies() {
            let tmb = &coz.header().tmb;
            if !outside(principal, tmb) {
                continue;
            }
            for member in &found {
                let Some((_, b, state)) = held.get(member).and_then(Option::as_ref) else {
                    continue;
                };
                let pin = EmbeddedPin {
                    member: member.clone(),
                    b: b.clone(),
                };
                if state.held_key(tmb) && !pins.contains(&pin) {
                    pins.push(pin);
                }
            }
        }
        Ok(pins)
    }

    /// The public key the index holds for each signer of `bundle`: the keys a
    /// rival signed through an embedded principal can be authenticated by
    /// before anything is replayed.
    async fn outside_keys(
        &self,
        bundle: &WireBundle,
    ) -> Result<HashMap<String, (String, Vec<u8>)>, EngineError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let mut keys = HashMap::new();
        for blob in bundle.cozies() {
            let Some(tmb) = serde_json::from_slice::<serde_json::Value>(blob)
                .ok()
                .and_then(|v| Some(v.pointer("/pay/tmb")?.as_str()?.to_owned()))
            else {
                continue;
            };
            if keys.contains_key(&tmb) {
                continue;
            }
            if let Some(info) = self.indexer.get_key(&tmb).await?
                && let Ok(public) = Base64UrlUnpadded::decode_vec(&info.public_key)
            {
                keys.insert(tmb, (info.algorithm, public));
            }
        }
        Ok(keys)
    }

    /// The tip this node holds of the principal `member` names, with the PR
    /// it stands at and the principal itself: its stored chain replayed,
    /// the naked revokes held applied, `Error` marked.
    ///
    /// Boxed: it is the one way `follow_held` re-enters the engine, and a
    /// `Send` proof for `follow_held` otherwise runs through the whole
    /// replay call graph, past the compiler's recursion limit.
    fn held_tip<'a>(&'a self, member: &'a str, own_id: &'a str) -> HeldRead<'a, S> {
        Box::pin(async move {
            // A principal embedding itself names no other principal's tip; its
            // log is also the one the caller is writing.
            let Some(id) = self
                .principal_named(member)
                .await?
                .filter(|id| id != own_id)
            else {
                return Ok(None);
            };
            let genesis = self.genesis_of_stored(&id).await?;
            let state = self.replay_stored(&id, genesis).await?;
            let pr = state.pr_tagged().map_err(EngineError::Protocol)?;
            let revoked = self.revoked();
            let mut tip = cyphr::Tip::new(&state, unix_now().unwrap_or(0))
                .with_revoked(revoked.keys().map(String::as_str));
            if self.error_state_of(&id).await?.is_some() {
                tip = tip.in_error();
            }
            Ok(Some((tip, pr, state)))
        })
    }

    /// Store an accepted action-only bundle and its [`ActionManifest`],
    /// and list it for replay. Returns the blob hashes.
    async fn store_actions(
        &self,
        principal_id: &str,
        blobs: &[Vec<u8>],
        embedded: &[EmbeddedPin],
    ) -> Result<Vec<Blake3Hash>, EngineError> {
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            blob_hashes.push(self.blob_store.put(blob).await?);
        }
        let manifest = ActionManifest {
            kind: ACTION_MANIFEST_KIND.to_string(),
            principal_id: principal_id.to_string(),
            blob_hashes: blob_hashes.clone(),
            embedded: embedded.to_vec(),
        };
        let mut bytes = ACTION_MANIFEST_PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("action manifest serialize: {e}")))?;
        let hash = self.blob_store.put(&bytes).await?;
        let mut held = self.actions.lock().unwrap_or_else(|p| p.into_inner());
        let of_principal = held.entry(principal_id.to_string()).or_default();
        if !of_principal.iter().any(|a| a.manifest == hash) {
            of_principal.push(StoredActions {
                manifest: hash,
                blobs: blob_hashes.clone(),
                embedded: embedded.to_vec(),
            });
        }
        Ok(blob_hashes)
    }

    /// Verify `bundle` against `principal`'s current state and build the
    /// commit they would form at `next_seq`, staged: nothing is written,
    /// to storage or to the principal's commit log, until the caller
    /// commits the returned [`StagedBuild`]. `Ok(None)` is an action-only
    /// bundle: it forms no commit (its actions are recorded on
    /// `principal`, in memory).
    ///
    /// Storage-free so a refused fork can be re-verified against an earlier
    /// state ([`Self::retain_rival`]) by the same code that admits a tip.
    async fn build_commit<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &str,
        next_seq: u64,
    ) -> Result<Option<StagedBuild<'p, T>>, EngineError> {
        Ok(
            match Self::build_staged(principal, bundle, principal_id, next_seq).await? {
                Built::Commit(build) => Some(*build),
                Built::Actions(_) => None,
            },
        )
    }

    /// [`Self::build_commit`], keeping the stage of an action-only bundle
    /// for the caller that holds its actions once stored, so they are
    /// verified once.
    async fn build_staged<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &str,
        next_seq: u64,
    ) -> Result<Built<'p, T>, EngineError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let active_algs = principal.active_algs().to_vec();

        let decoded = decode_bundle(bundle)?;
        let cozies: Vec<&cyphr::replay::StoredCoz> = decoded.cozies().collect();
        let extracted_keys: Vec<crate::PublicKeyInfo> = decoded
            .introduced_keys()
            .map(|key| crate::PublicKeyInfo {
                thumbprint: key.tmb().to_b64(),
                algorithm: key.alg().to_string(),
                public_key: Base64UrlUnpadded::encode_string(key.pub_key()),
            })
            .collect();
        let last_timestamp = cozies.last().map_or(0, |c| c.header().now);

        // The principal's state BEFORE this bundle: the chain link (`pre`) is
        // the previous commit's PR, and a PG established by this bundle is
        // the PR held before the `principal/create` commit (SPEC §3.7.1).
        let commit_pre = if next_seq == 0 {
            None
        } else {
            format_multihash_all(principal.pr().as_multihash())?
                .first()
                .cloned()
        };
        let had_pg = principal.pg().is_some();
        let staged = cyphr::replay::stage_bundle(principal, &decoded)
            .await
            .map_err(|e| EngineError::Protocol(e.source))?;
        let cyphr::replay::StagedBundle::Commit { staged: stage, .. } = &staged else {
            return Ok(Built::Actions(staged));
        };
        let principal = stage.state();
        let commit = principal
            .commits()
            .last()
            .ok_or(EngineError::Protocol(cyphr::Error::MissingCommit))?;
        let commit_ids = format_multihash_all(&commit.tr().0)?;
        let ar = format_multihash_opt(commit.auth_root().map(|a| a.as_multihash()))?;
        let sr = format_multihash_opt(commit.sr().map(|s| s.as_multihash()))?;
        let pr = format_multihash_all(commit.pr().as_multihash())?;
        let cr = principal
            .cr()
            .map(|c| format_multihash_all(c.as_multihash()))
            .transpose()?
            .unwrap_or_default();

        let pg = match principal.pg() {
            Some(pg) if !had_pg => format_multihash_all(pg.as_multihash())?,
            _ => Vec::new(),
        };

        let mut indexed = Vec::with_capacity(cozies.len());
        for coz in cozies {
            let source_alg = coz.hash_alg();
            let tagged = cyphr::state::TaggedCzd::new(coz.czd(), source_alg);

            let post_active_algs = active_algs.clone();
            let primary_alg = post_active_algs.first().copied().unwrap_or(source_alg);
            let converted = tagged.convert_to(primary_alg);
            let primary_czd = format!(
                "{primary_alg}:{}",
                Base64UrlUnpadded::encode_string(&converted)
            );

            indexed.push(IndexableCoz {
                blob_hash: Blake3Hash::from_bytes([0; 32]), // filled in by ingest_commit
                czd: primary_czd,
                typ: coz.header().typ.clone(),
                tmb: coz.header().tmb.to_b64(),
                alg: coz.alg().to_string(),
                now: coz.header().now,
                payload: serde_json::to_string(coz.pay()).ok(),
            });
        }

        let commit = IndexableCommit {
            principal_id: principal_id.to_string(),
            commit_ids,
            sequence: next_seq,
            pre: commit_pre,
            prs: pr,
            srs: sr,
            ars: ar,
            crs: cr,
            blob_hashes: Vec::new(), // filled in by ingest_commit
            cozies: indexed,
            timestamp: last_timestamp,
            keys: extracted_keys,
            pg,
        };

        Ok(Built::Commit(Box::new(StagedBuild {
            commit,
            staged,
            embedded: Vec::new(),
        })))
    }

    /// Retain a refused bundle as a non-canonical branch if it is a fork:
    /// a bundle that verifies against the principal's state at an earlier
    /// position, where the chain already holds a different commit. The
    /// bundle is still refused as the tip by the caller (I2: a fork is
    /// detected, never merged); this only keeps the evidence.
    ///
    /// The refusal is attacker-reachable, so the search is bounded:
    ///
    /// 1. **Authenticate first, replaying nothing.** Every coz of the bundle must name a key this
    ///    principal has ever held (its genesis keys and every key a stored coz introduced) and
    ///    verify under that key's public key. Anyone else costs blob reads only.
    /// 2. **One forward pass.** The stored chain is replayed once onto a private in-memory Commit
    ///    Tree. At each position where the bundle's transaction signers are active, a clone of that
    ///    prefix state tries the bundle through [`Self::build_commit`], the admission path's own
    ///    verification. At most one replay per stored commit.
    ///
    /// A bundle that verifies at no position (a key not active at its
    /// `pre`, an arrow that fits no state) is not retained. The private
    /// tree matters: replaying a rival over the principal's durable log
    /// would hit `DurableLeafMismatch`.
    ///
    /// Returns whether the bundle verified at a position and is now held
    /// as a rival (a no-op for one already held counts), so the caller
    /// answers the retained-rival refusal; `false` keeps nothing.
    ///
    /// Caller holds the principal's write lock.
    async fn retain_rival(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        bundle: &WireBundle,
    ) -> Result<bool, EngineError> {
        // Pushed again, a held rival is answered as the fork it is; the
        // canonical commit pushed again is no rival.
        let hashes: Vec<Blake3Hash> = bundle
            .cozies()
            .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
            .collect();
        if self.is_retained(principal_id, &hashes, &Shape::of(bundle)) {
            return Ok(true);
        }
        if self.is_already_stored(principal_id, bundle).await? {
            return Ok(false);
        }
        let stored = self.stored_entries(principal_id, None).await?;
        let entries = &stored.entries;
        let outside = self.outside_keys(bundle).await?;
        let Some(signers) = authenticated_signers(bundle, &genesis, entries, &outside) else {
            return Ok(false);
        };
        let mut principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new()).await?;
        let source = PinSource::stored();
        let mut held = HeldCache::new();
        for (position, (entry, pins)) in entries.iter().zip(&stored.pins).enumerate() {
            // A signer A never held may be a key of an embedded principal:
            // tried only where A's Key Tree holds a digest to follow.
            let tried = |t: &coz::Thumbprint| {
                principal.is_key_active(t)
                    || (outside.contains_key(&t.to_b64()) && principal.has_kt_digests())
            };
            if signers.iter().all(tried) {
                self.retention_trials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Verified on a fork and never committed: the staged build
                // is dropped, and only its manifest is kept. The bundle is
                // an arrival, so the held revokes gate it as on the
                // canonical path (SPEC 6.4); the held history below it was
                // replayed without them and is not judged again.
                let mut candidate = principal.fork().await?;
                note_revokes(&mut candidate, &self.revoked());
                // The rival is authenticated against the tips held now (R3),
                // and its manifest records them.
                let Ok(embedded) = self
                    .follow_held(principal_id, &mut candidate, bundle, &mut held)
                    .await
                else {
                    continue;
                };
                if let Ok(Some(build)) =
                    Self::build_commit(&mut candidate, bundle, principal_id, position as u64).await
                {
                    return self
                        .keep_branch(bundle, build.commit, &embedded)
                        .await
                        .map(|()| true);
                }
            }
            // The last commit's own state is never a `pre` of a rival.
            if position + 1 < entries.len() {
                self.retention_replays
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                    .await?;
            }
        }
        Ok(false)
    }

    /// Test a refused `bundle` as the extension of a retained rival, the
    /// one record a fork resolution leaves (SPEC 15.8: a new commit whose
    /// `pre` is the chosen branch's tip; the engine keeps no other).
    ///
    /// The extension is verified by replaying the canonical prefix below
    /// the rival, then the rival, then `bundle` through the admission
    /// path's own [`Self::build_commit`], on a private in-memory Commit
    /// Tree. Then:
    ///
    /// * the rival is at the head position: `bundle` becomes the tip, the rival's branch becomes
    ///   the canonical chain ([`IndexerWrite::replace_chain_from`]) and the displaced head is
    ///   retained in its place. The durable commit log is a cache of the displaced chain and is
    ///   regenerated on the next load ([`Self::replay_stored`]).
    /// * the rival is below the head: `bundle` is one more fork, retained beside the commit it
    ///   competes with, and the principal is in Error. The engine never picks between two
    ///   resolutions.
    ///
    /// `Ok(None)` is a bundle extending no retained rival. Authenticated
    /// first, like [`Self::retain_rival`], so an unauthenticated bundle
    /// costs blob reads only. Caller holds the principal's write lock.
    ///
    /// Known cost: the canonical prefix is replayed once per retained
    /// rival, because a retained commit's `pre` is bound only inside its
    /// arrow, `MR(pre, fwd, TMR)`, and the engine stores no verifiable
    /// `pre` per retained commit to resume from. The pass is reached only
    /// by an authenticated bundle, so an unauthenticated one never pays it.
    async fn resolve_fork(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        bundle: &WireBundle,
        canonical_len: u64,
    ) -> Result<Option<IngestResult>, EngineError> {
        let rivals = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default();
        if rivals.is_empty() || self.is_already_stored(principal_id, bundle).await? {
            return Ok(None);
        }
        let stored = self.stored_entries(principal_id, None).await?;
        let outside = self.outside_keys(bundle).await?;
        if authenticated_signers(bundle, genesis, &stored.entries, &outside).is_none() {
            return Ok(None);
        }
        let by_pr: HashMap<(u64, &str), &Retained> = rivals
            .iter()
            .map(|r| ((r.tip.sequence, r.pr.as_str()), r))
            .collect();
        let mut held = HeldCache::new();
        for rival in &rivals {
            let at = rival.tip.sequence;
            // The retained line the rival ends: it and its retained
            // ancestors, down to the one whose parent is canonical.
            let line = retained_line(&by_pr, rival);
            let base = line.first().map_or(at, |r| r.tip.sequence);
            let upto = usize::try_from(base).unwrap_or(usize::MAX);
            let (Some(prefix), Some(prefix_pins)) =
                (stored.entries.get(..upto), stored.pins.get(..upto))
            else {
                continue;
            };
            let mut bundles = Vec::with_capacity(line.len());
            for r in &line {
                bundles.push(
                    r.shape
                        .group(self.read_blobs(&r.blobs).await?, r.keys.clone())
                        .ok_or_else(|| {
                            EngineError::MalformedBlob(
                                "a retained branch's shape groups a different number of blobs"
                                    .into(),
                            )
                        })?,
                );
            }
            let mut principal =
                Self::principal_from_genesis(genesis.clone(), cyphr::eml::MemoryStorage::new())
                    .await?;
            let source = PinSource::stored();
            for (position, (entry, pins)) in prefix.iter().zip(prefix_pins).enumerate() {
                self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                    .await?;
            }
            let mut line_commits = Vec::with_capacity(line.len());
            let mut built = true;
            for (r, b) in line.iter().zip(&bundles) {
                // The retained commit is replayed against the embedded
                // states it was admitted through.
                if self
                    .apply_pins(&mut principal, &source, &r.embedded, EMBED_DEPTH)
                    .await
                    .is_err()
                {
                    built = false;
                    break;
                }
                let Ok(Some(staged)) =
                    Self::build_commit(&mut principal, b, principal_id, r.tip.sequence).await
                else {
                    built = false;
                    break;
                };
                let commit = staged.commit.clone();
                if staged.staged.commit().await.is_err() {
                    built = false;
                    break;
                }
                line_commits.push(commit);
            }
            if !built {
                continue;
            }
            // `bundle` is an arrival: the held revokes gate it as on the
            // canonical path (SPEC 6.4); the held line above was replayed
            // without them and is not judged again.
            note_revokes(&mut principal, &self.revoked());
            let Ok(embedded) = self
                .follow_held(principal_id, &mut principal, bundle, &mut held)
                .await
            else {
                continue;
            };
            let Ok(Some(next)) =
                Self::build_commit(&mut principal, bundle, principal_id, at + 1).await
            else {
                continue;
            };
            let next_commit = next.commit;
            if at + 1 < canonical_len {
                self.keep_branch(bundle, next_commit, &embedded).await?;
                return Ok(None);
            }
            // `bundle` takes the position above the canonical head, which
            // no held commit reaches, so it is the one tallest commit: the
            // fork rule's head, Active, in Error or not ([`assessment`]).
            // It passed the revoke gate on arrival ([`dead_key_in`]).
            return self
                .promote_branch(
                    principal_id,
                    &line,
                    &mut line_commits,
                    bundle,
                    next_commit,
                    &embedded,
                )
                .await
                .map(Some);
        }
        Ok(None)
    }

    /// Make the retained `line`'s branch the canonical chain, extended by
    /// `next` (`bundle`): the tail of [`Self::resolve_fork`]. Each canonical
    /// commit it displaces is retained as a branch.
    async fn promote_branch(
        &self,
        principal_id: &str,
        line: &[Retained],
        line_commits: &mut [IndexableCommit],
        bundle: &WireBundle,
        next: IndexableCommit,
        next_embedded: &[EmbeddedPin],
    ) -> Result<IngestResult, EngineError> {
        let Some(base) = line.first().map(|r| r.tip.sequence) else {
            return Err(EngineError::InvalidInput(
                "a promotion names no retained commit".into(),
            ));
        };
        // The line's blobs are already stored behind its branch manifests;
        // only the chain index needs them named.
        for (r, commit) in line.iter().zip(line_commits.iter_mut()) {
            commit.blob_hashes = r.blobs.clone();
            for (coz, hash) in commit.cozies.iter_mut().zip(&r.blobs) {
                coz.blob_hash = *hash;
            }
        }
        let displaced_chain = self.chain(principal_id, Some(base), None).await?;
        if displaced_chain.is_empty() {
            return Err(EngineError::NotFound(format!(
                "no commit at {base} of {principal_id}"
            )));
        }
        let mut displaced = Vec::with_capacity(displaced_chain.len());
        for c in displaced_chain {
            let bundle = self.commit_bundle(principal_id, &c).await?;
            let Frame {
                shape,
                keys,
                signed,
                seen,
                embedded,
            } = self.frame(principal_id, &c).ok_or_else(|| {
                EngineError::Indexer(crate::index::IndexerError::Consistency(format!(
                    "index commit {} of {principal_id} has no commit manifest",
                    c.commit_id
                )))
            })?;
            displaced.push(Retained {
                pr: c.pr.clone(),
                tip: BranchTip {
                    tip: c.commit_id.clone(),
                    pre: c.pre.clone(),
                    sequence: c.sequence,
                    canonical: false,
                    seen,
                },
                signer: bundle_signer(&bundle)?,
                blobs: c.blob_hashes.clone(),
                shape,
                keys,
                signed,
                embedded,
            });
        }

        // The displaced commits are blobs already held, retained one for one
        // in the line's place (both span `base` to the head), so a promotion
        // never grows the retained set and never counts against a signer's
        // quota: a quota a thief can fill must never refuse the owner's
        // resolution.
        if displaced.len() != line.len() {
            return Err(EngineError::Indexer(
                crate::index::IndexerError::Consistency(format!(
                    "promotion of {principal_id} from {base} displaces {} commits for a line of {}",
                    displaced.len(),
                    line.len()
                )),
            ));
        }

        // Claims first, so a refusal leaves no manifest behind; the alias
        // locks make the check and the writes below one step. The line is
        // not checked: it was verified when retained and sits where the
        // displaced chain is, which `check_commit` refuses as a rival.
        let mut claimants: Vec<&IndexableCommit> = line_commits.iter().collect();
        claimants.push(&next);
        let alias_locks = self.alias_locks(&claimants);
        let mut _alias_guards = Vec::with_capacity(alias_locks.len());
        for lock in &alias_locks {
            _alias_guards.push(lock.lock().await);
        }
        let token = DeriveToken::new();
        self.indexer.check_commit(&next, &token).await?;

        // I1 order: the resolving commit is the one new record. A walk of
        // the blobs then picks the same chain this replaces.
        let next_seen = unix_now();
        let (next, manifest_hash) = self
            .store_blobs_and_manifest(bundle, next, next_seen, next_embedded)
            .await?;
        let mut chain = line_commits.to_vec();
        chain.push(next.clone());
        self.indexer
            .replace_chain_from(principal_id, base, &chain, &token)
            .await?;
        for (r, commit) in line.iter().zip(line_commits.iter()) {
            self.record_frame(commit, &r.shape, r.tip.seen, &r.embedded);
        }
        self.record_frame(&next, &Shape::of(bundle), next_seen, next_embedded);

        {
            let mut kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
            let of_principal = kept.entry(principal_id.to_string()).or_default();
            of_principal.retain(|b| {
                !line
                    .iter()
                    .any(|r| r.tip.tip == b.tip.tip && r.tip.sequence == b.tip.sequence)
            });
            of_principal.extend(displaced);
        }
        Ok(IngestResult {
            principal_id: principal_id.to_string(),
            blob_hashes: next.blob_hashes.clone(),
            manifest_hash: Some(manifest_hash),
            tip: Some(CommittedTip::of(&next)),
        })
    }

    /// Record a self-signed naked revoke (SPEC 6.4), received by this node
    /// at `wrt` (its Witness Receipt Timestamp, Unix seconds), as a revoke
    /// record in the blob store. `evidence` is the `{pay, sig, key}`
    /// envelope the revoke arrived in; it is verified here, since a
    /// rebuild re-verifies it. A Coz-valid revoke is always accepted,
    /// pushed or relayed, whatever its `now` or `rvk` (the spec author on
    /// #203: "Coz valid revokes are always accepted").
    ///
    /// The key's cutoff is `wrt`, never the revoke's own `now` or `rvk`
    /// (#203: "honor it from the witness's own receipt time"; SPEC 14.12).
    /// A revoke is an admission gate and nothing else: a message the key
    /// signs that arrives after it is refused iff its own `now` is at or
    /// after the cutoff ([`dead_key_in`]; data actions through the key
    /// timeline). A held message is never judged again, live or on
    /// rebuild (SPEC 14.12: "Principals must explicitly mutate their state
    /// forward"), so recording a revoke changes no answer about what is
    /// held. A relayed
    /// revoke gets this node's receipt time, never the relayer's. The
    /// caller supplies `wrt` from its clock.
    ///
    /// The first revoke of a key accepted stands and is never replaced: a
    /// later one stores nothing, so re-signing cannot grow the store and a
    /// clock stepping back cannot lower the cutoff. Key death is global by
    /// thumbprint, so the record names no principal.
    ///
    /// # Errors
    ///
    /// [`EngineError::InvalidInput`] for a revoke that is not Coz-valid or
    /// not self-signed; a storage error if the record cannot be written.
    pub async fn record_revoke(
        &self,
        evidence: &serde_json::Value,
        wrt: i64,
    ) -> Result<(), EngineError> {
        self.ensure_healed().await?;
        let tmb = verify_revoke(evidence).map_err(EngineError::InvalidInput)?;
        // Held across the write, so two revokes of one key store one record.
        let lock = self.principal_lock(&format!("revoke\0{tmb}"));
        let _one_record = lock.lock().await;
        if self
            .revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&tmb)
        {
            return Ok(());
        }
        let mut bytes = REVOKE_RECORD_PREFIX.to_vec();
        serde_json::to_writer(
            &mut bytes,
            &RevokeRecord {
                wrt,
                evidence: evidence.clone(),
            },
        )
        .map_err(|e| EngineError::MalformedBlob(format!("revoke record serialize: {e}")))?;
        let death = Death {
            wrt,
            record: *blake3::hash(&bytes).as_bytes(),
        };
        self.blob_store.put(&bytes).await?;
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tmb, death);
        Ok(())
    }

    /// Keep a commit refused because the principal is in Error, as
    /// evidence ([`Self::keep_branch`]), within the branch limits. The
    /// refusal stands for Error whether or not it is kept: a full quota or
    /// a storage fault is logged, never answered in its place.
    async fn keep_evidence(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        embedded: &[EmbeddedPin],
    ) {
        let principal_id = commit.principal_id.clone();
        if let Err(err) = self.keep_branch(bundle, commit, embedded).await {
            tracing::warn!(
                principal = %principal_id,
                error = %err,
                "could not keep a commit refused in Error; answering the Error refusal"
            );
        }
    }

    /// The per-alias locks guarding the PG claims of `commits`, in sorted
    /// order so contenders cannot deadlock. The caller locks each.
    fn alias_locks(&self, commits: &[&IndexableCommit]) -> Vec<Arc<tokio::sync::Mutex<()>>> {
        let mut aliases: Vec<String> = commits
            .iter()
            .flat_map(|c| &c.pg)
            .map(|pg| format!("pg-alias\0{pg}"))
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        aliases.iter().map(|a| self.principal_lock(a)).collect()
    }

    /// Whether a rival with these blobs and grouping is retained.
    fn is_retained(&self, principal_id: &str, hashes: &[Blake3Hash], shape: &Shape) -> bool {
        self.branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .is_some_and(|rs| rs.iter().any(|r| r.blobs == hashes && r.shape == *shape))
    }

    /// Whether `bundle` is, byte for byte and in its grouping, a commit this engine already
    /// holds: on the canonical chain or retained as a rival. Such a bundle
    /// is nobody's rival at any other position, since its arrow binds
    /// exactly one `pre`, so it settles with no replay and no clone. This
    /// is the cheap check made before any state is cloned: the arrow binds
    /// `pre` only through the post-state root, which cannot be recomputed
    /// without applying the bundle, so a hash identity is the one sound
    /// filter that needs no state.
    async fn is_already_stored(
        &self,
        principal_id: &str,
        bundle: &WireBundle,
    ) -> Result<bool, EngineError> {
        let hashes: Vec<Blake3Hash> = bundle
            .cozies()
            .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
            .collect();
        // The same cozies grouped otherwise are another commit (its arrow
        // binds another TMR), so the grouping is part of the identity.
        let shape = Shape::of(bundle);
        if self.is_retained(principal_id, &hashes, &shape) {
            return Ok(true);
        }
        let chain = self.chain(principal_id, None, None).await?;
        let frames = self.frames.lock().unwrap_or_else(|p| p.into_inner());
        Ok(chain.iter().any(|c| {
            c.blob_hashes == hashes
                && frames
                    .get(&(principal_id.to_string(), c.commit_id.clone()))
                    .is_some_and(|f| f.shape == shape)
        }))
    }

    /// Store a verified rival `commit` and its blobs behind
    /// [`BRANCH_MANIFEST_PREFIX`] and list it. A commit past the canonical
    /// head (one refused while the principal is in Error) is kept the same
    /// way. A rival that is the
    /// canonical commit or an already-kept branch is a no-op; the
    /// rival of a key past [`BRANCH_PER_KEY`], or past [`BRANCH_LIMIT`] in all,
    /// is [`EngineError::BranchLimit`] and stores nothing.
    async fn keep_branch(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        embedded: &[EmbeddedPin],
    ) -> Result<(), EngineError> {
        let tip = commit.commit_ids.first().cloned().unwrap_or_default();
        let canonical = self
            .chain(
                &commit.principal_id,
                Some(commit.sequence),
                Some(commit.sequence),
            )
            .await?;
        if canonical.first().is_some_and(|c| c.commit_id == tip) {
            return Ok(());
        }
        let signer = commit_signer(&commit);
        {
            let kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
            let of_principal = kept
                .get(&commit.principal_id)
                .map_or(&[][..], Vec::as_slice);
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                return Ok(());
            }
            if !has_slot(of_principal, &signer) {
                return Err(EngineError::BranchLimit { key: signer });
            }
        }
        let seen = unix_now();
        let branch = BranchTip {
            tip,
            pre: commit.pre.clone(),
            sequence: commit.sequence,
            canonical: false,
            seen,
        };
        let principal_id = commit.principal_id.clone();
        let pr = commit.prs.first().cloned().unwrap_or_default();
        let signed = signed_of(&commit);
        let (stored, _) = self
            .store_manifest(
                bundle,
                commit,
                BRANCH_MANIFEST_PREFIX,
                BRANCH_MANIFEST_KIND,
                seen,
                embedded,
            )
            .await?;
        self.branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(principal_id)
            .or_default()
            .push(Retained {
                tip: branch,
                pr,
                signer,
                keys: key_entries(&stored.keys),
                blobs: stored.blob_hashes,
                shape: Shape::of(bundle),
                signed,
                embedded: embedded.to_vec(),
            });
        Ok(())
    }

    /// How many stored commits retention has replayed so far: the cost
    /// refused bundles have put on this engine. Exposed so a test can pin
    /// that an unauthenticated bundle costs none.
    pub fn retention_replays(&self) -> u64 {
        self.retention_replays
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many positions retention has tried a bundle at so far (the
    /// positions where the bundle's signers were active).
    pub fn retention_trials(&self) -> u64 {
        self.retention_trials
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Every branch head of a principal: the canonical chain's tip
    /// (`canonical`, the commit [`Self::get_tip`] reports) and each
    /// retained rival, by position (the canonical head first at a shared
    /// position).
    ///
    /// A rival is a commit that verified at its `pre` but took a position
    /// the chain already held, so it was refused as the tip
    /// ([`Self::submit_commit`]) and kept as evidence of a fork. A
    /// principal that is not stored is [`EngineError::NotFound`].
    #[tracing::instrument(skip(self))]
    pub async fn list_branches(&self, principal_id: &str) -> Result<Vec<BranchTip>, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let not_stored = || EngineError::NotFound(format!("principal {principal_id} not found"));
        let tip = self
            .indexer
            .get_tip(&principal_id)
            .await?
            .ok_or_else(not_stored)?;
        let last = tip.commit_count.checked_sub(1).ok_or_else(not_stored)?;
        let head = self
            .chain(&principal_id, Some(last), Some(last))
            .await?
            .into_iter()
            .next()
            .ok_or_else(not_stored)?;
        let seen = self.frame(&principal_id, &head).and_then(|f| f.seen);
        let mut branches = vec![BranchTip {
            tip: head.commit_id,
            pre: head.pre,
            sequence: head.sequence,
            canonical: true,
            seen,
        }];
        if let Some(kept) = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&principal_id)
        {
            branches.extend(kept.iter().map(|r| r.tip.clone()));
        }
        branches.sort_by(|a, b| {
            (a.sequence, !a.canonical, &a.tip).cmp(&(b.sequence, !b.canonical, &b.tip))
        });
        Ok(branches)
    }

    /// Whether the principal is in Error by the protocol ([`in_error`]),
    /// computed from the commits the engine holds, canonical and retained,
    /// and the revocations it holds, so a live engine and one rebuilt from
    /// the blobs answer alike. `false` for a principal that is not stored.
    /// No [`Recovery`] is consulted: what the engine admits is the protocol
    /// alone.
    pub async fn is_errored(&self, principal_id: &str) -> Result<bool, EngineError> {
        Ok(self.assess(principal_id).await?.consensus == Consensus::Error)
    }

    /// The principal's forks by the protocol ([`Assessment`]), from the
    /// commits the engine holds, canonical and retained, and the
    /// revocations it holds: the rule [`Self::is_errored`] reads, with the
    /// live heads and settled forks a viewer reports. A principal that is
    /// not stored has no heads and no forks.
    pub async fn assess(&self, principal_id: &str) -> Result<Assessment, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let held = self.held(&principal_id).await?;
        Ok(assessment(&held))
    }

    /// The principal's fork point and tied heads while it is in Error, `None`
    /// while Active or not stored: what a reader is told in place of a tip.
    /// From the held commits alone, so a live engine and one rebuilt from
    /// the blobs answer alike (I1).
    pub async fn error_state(&self, principal_id: &str) -> Result<Option<ErrorState>, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        Ok(self
            .error_state_of(&principal_id)
            .await?
            .map(|(fork_point, heads)| ErrorState { fork_point, heads }))
    }

    /// Whether the engine holds the commit `commit_id` of `principal_id`,
    /// on its canonical chain or as a retained branch. `false` for a
    /// principal that is not stored.
    pub async fn holds_commit(
        &self,
        principal_id: &str,
        commit_id: &str,
    ) -> Result<bool, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        Ok(self
            .held(&principal_id)
            .await?
            .iter()
            .any(|h| h.id == commit_id))
    }

    async fn error_state_of(
        &self,
        principal_id: &str,
    ) -> Result<Option<(ForkPoint, Vec<HeldHead>)>, EngineError> {
        let held = self.held(principal_id).await?;
        let assessed = assessment(&held);
        let Some(fork_point) = assessed.fork_point else {
            return Ok(None);
        };
        let by_id: HashMap<&str, &Held> = held.iter().map(|h| (h.id.as_str(), h)).collect();
        let retained = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default();
        let mut heads = Vec::with_capacity(assessed.heads.len());
        for id in &assessed.heads {
            // Heads are drawn from `held` by `assessment`, so each is in
            // `by_id`; a miss is an inconsistency, reported, not a panic.
            let head = by_id.get(id.as_str()).ok_or_else(|| {
                EngineError::NotFound(format!("tied head {id} of {principal_id} is not held"))
            })?;
            let held_since = match retained.iter().find(|r| &r.tip.tip == id) {
                Some(r) => r.tip.seen,
                None => {
                    let at = head.sequence;
                    self.chain(principal_id, Some(at), Some(at))
                        .await?
                        .first()
                        .and_then(|c| self.frame(principal_id, c))
                        .and_then(|f| f.seen)
                },
            };
            heads.push(HeldHead {
                commit_id: id.clone(),
                sequence: head.sequence,
                held_since,
            });
        }
        Ok(Some((fork_point, heads)))
    }

    /// Each tied branch from the fork point to its head: a commit is read
    /// from the canonical chain when the index holds it, else from the
    /// retained rival of that id.
    async fn branches_of(
        &self,
        principal_id: &str,
        fork_point: &ForkPoint,
        heads: &[HeldHead],
    ) -> Result<Vec<PatchBranch>, EngineError> {
        let held = self.held(principal_id).await?;
        let by_pr: HashMap<(u64, &str), &Held> = held
            .iter()
            .map(|h| ((h.sequence, h.pr.as_str()), h))
            .collect();
        let chain = self
            .chain(principal_id, Some(fork_point.height), None)
            .await?;
        let retained = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default();
        let indexed_head = self
            .indexer
            .get_tip(principal_id)
            .await?
            .map(|tip| tip.commit_id);
        let mut branches = Vec::with_capacity(heads.len());
        for head in heads {
            // The line from the head down to the fork point, then flipped.
            let mut line: Vec<&Held> = Vec::new();
            let mut at = held.iter().find(|h| h.id == head.commit_id);
            while let Some(h) = at.filter(|h| h.sequence >= fork_point.height) {
                line.push(h);
                at = h
                    .pre
                    .as_deref()
                    .zip(h.sequence.checked_sub(1))
                    .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied());
            }
            line.reverse();
            let mut entries = Vec::with_capacity(line.len());
            for h in line {
                let bundle = match chain.iter().find(|c| c.commit_id == h.id) {
                    Some(c) => self.commit_bundle(principal_id, c).await?,
                    None => {
                        let r = retained.iter().find(|r| r.tip.tip == h.id).ok_or_else(|| {
                            EngineError::NotFound(format!(
                                "branch commit {} of {principal_id} is neither indexed nor \
                                 retained",
                                h.id
                            ))
                        })?;
                        r.shape
                            .group(self.read_blobs(&r.blobs).await?, r.keys.clone())
                            .ok_or_else(|| {
                                EngineError::MalformedBlob(
                                    "a retained branch's shape groups a different number of blobs"
                                        .into(),
                                )
                            })?
                    },
                };
                entries.push(BranchEntry {
                    commit_id: h.id.clone(),
                    sequence: h.sequence,
                    pr: h.pr.clone(),
                    bundle,
                });
            }
            branches.push(PatchBranch {
                head: head.commit_id.clone(),
                canonical: indexed_head.as_deref() == Some(head.commit_id.as_str()),
                entries,
            });
        }
        Ok(branches)
    }

    /// Whether the engine holds a revoke record for `tmb` (base64url).
    #[must_use]
    pub fn is_revoked(&self, tmb: &str) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(tmb)
    }

    /// The revocations in force (a cache of the revoke records, I1).
    fn revoked(&self) -> Revoked {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Every commit the engine holds for `principal_id`: its canonical
    /// chain and each retained branch.
    async fn held(&self, principal_id: &str) -> Result<Vec<Held>, EngineError> {
        let chain = self.chain(principal_id, None, None).await?;
        let mut held = Vec::with_capacity(chain.len());
        for c in chain {
            let frame = self.frame(principal_id, &c).ok_or_else(|| {
                EngineError::Indexer(crate::index::IndexerError::Consistency(format!(
                    "index commit {} of {principal_id} has no commit manifest",
                    c.commit_id
                )))
            })?;
            held.push(Held {
                sequence: c.sequence,
                id: c.commit_id,
                pre: c.pre,
                pr: c.pr,
                signed: frame.signed,
            });
        }
        if let Some(kept) = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
        {
            held.extend(kept.iter().map(|r| Held {
                sequence: r.tip.sequence,
                id: r.tip.tip.clone(),
                pre: r.tip.pre.clone(),
                pr: r.pr.clone(),
                signed: r.signed.clone(),
            }));
        }
        Ok(held)
    }

    /// Every fork of a principal the store can prove: for each retained
    /// rival, the canonical commit it took the position of and the rival
    /// itself, as wire blobs. A principal that is not stored is
    /// [`EngineError::NotFound`]; a principal never forked yields none.
    #[tracing::instrument(skip(self))]
    pub async fn fork_evidence(
        &self,
        principal_id: &str,
    ) -> Result<(String, Vec<ForkEvidence>), EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        if self.indexer.get_tip(&principal_id).await?.is_none() {
            return Err(EngineError::NotFound(format!(
                "principal {principal_id} not found"
            )));
        }
        let rivals = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&principal_id)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rivals.len());
        for rival in rivals {
            let at = rival.tip.sequence;
            let chain = self.chain(&principal_id, Some(at), Some(at)).await?;
            let Some(canonical) = chain.first() else {
                continue;
            };
            let rival_bundle = rival
                .shape
                .group(self.read_blobs(&rival.blobs).await?, rival.keys.clone())
                .ok_or_else(|| {
                    EngineError::MalformedBlob(
                        "a retained branch's shape groups a different number of blobs".into(),
                    )
                })?;
            out.push(ForkEvidence {
                sequence: at,
                pre: rival.tip.pre.clone(),
                canonical: self.commit_bundle(&principal_id, canonical).await?,
                rival: rival_bundle,
                canonical_seen: self.frame(&principal_id, canonical).and_then(|f| f.seen),
                rival_seen: rival.tip.seen,
            });
        }
        out.sort_by(|a, b| {
            let key = |e: &ForkEvidence| {
                (
                    e.sequence,
                    e.rival.cozies().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                )
            };
            key(a).cmp(&key(b))
        });
        Ok((principal_id, out))
    }

    async fn read_blobs(&self, hashes: &[Blake3Hash]) -> Result<Vec<Vec<u8>>, EngineError> {
        let mut blobs = Vec::with_capacity(hashes.len());
        for hash in hashes {
            blobs.push(
                self.blob_store
                    .get(hash)
                    .await?
                    .ok_or_else(|| EngineError::NotFound(format!("blob {hash} missing")))?,
            );
        }
        Ok(blobs)
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material from the first stored
    ///   commit's blobs.
    /// - If the principal is new, extracts key material from the first of the caller's `submitted`
    ///   bundles, its genesis commit.
    ///
    /// Both cases apply the identical genesis-discovery rule ([`disclosed_genesis`]) over their
    /// respective bundle.
    pub async fn resolve_genesis(
        &self,
        principal_id: &str,
        submitted: &[WireBundle],
    ) -> Result<crate::Genesis, EngineError> {
        self.ensure_healed().await?;

        if let Some(stored_id) = self.stored_id(principal_id).await? {
            // Existing principal: its genesis is in its first stored commit.
            self.genesis_of_stored(&stored_id).await
        } else {
            // New principal — the caller's own first bundle is its first commit.
            Self::genesis_from_bundle(submitted.first())
        }
    }

    /// Genesis of the principal stored under exactly `stored_id`, read from
    /// its first stored commit's blobs.
    async fn genesis_of_stored(&self, stored_id: &str) -> Result<crate::Genesis, EngineError> {
        let chain = self.chain(stored_id, Some(0), Some(0)).await?;
        let first_commit = chain.first().ok_or_else(|| {
            EngineError::NotFound(format!("principal {stored_id} has no stored commits"))
        })?;
        let bundle = self.commit_bundle(stored_id, first_commit).await?;
        Self::genesis_from_bundle(Some(&bundle))
    }

    /// The spelling under which `principal_id` is stored, if a principal is.
    ///
    /// A labelled id (`ALG:digest`) is its own spelling. A bare digest
    /// names whichever labelled spelling has a stored chain; at most one
    /// can, because [`submit_commit`](Self::submit_commit) stores only the
    /// canonical spelling. A Principal Root alias (the PG, or any other PR
    /// the principal has had) resolves to the principal's canonical id.
    async fn stored_id(&self, principal_id: &str) -> Result<Option<String>, EngineError> {
        let candidates: Vec<String> = if principal_id.contains(':') {
            vec![principal_id.to_string()]
        } else {
            ID_LABELS
                .iter()
                .map(|label| format!("{label}:{principal_id}"))
                .collect()
        };
        for candidate in candidates {
            // The index resolves a Principal Root alias to the stored id. A
            // tip with no stored chain is a corrupt index, not a stored
            // principal.
            let Some(tip) = self.indexer.get_tip(&candidate).await? else {
                continue;
            };
            let chain = self.chain(&candidate, Some(0), Some(0)).await?;
            if !chain.is_empty() {
                return Ok(Some(tip.principal_id));
            }
        }
        Ok(None)
    }

    /// The id a principal is stored and reported under (its key), or
    /// `principal_id` unchanged if no such principal is stored. Read paths
    /// resolve on the key, so every address (key, PG or PG variant) reaches
    /// one chain.
    pub async fn canonical_principal_id(&self, principal_id: &str) -> Result<String, EngineError> {
        self.ensure_healed().await?;
        Ok(self
            .resolve_key(principal_id)
            .await?
            .unwrap_or_else(|| principal_id.to_string()))
    }

    /// The storage key `principal_id` addresses, if any.
    async fn resolve_key(&self, principal_id: &str) -> Result<Option<String>, EngineError> {
        self.stored_id(principal_id).await
    }

    /// The genesis a principal's first commit bundle discloses
    /// ([`disclosed_genesis`]). Every chain begins with a genesis commit
    /// whose `key/create`s disclose its keys (SPEC 5.1), so a bundle that
    /// discloses none names no principal.
    fn genesis_from_bundle(bundle: Option<&WireBundle>) -> Result<crate::Genesis, EngineError> {
        let Some(bundle) = bundle.filter(|b| !b.is_empty()) else {
            return Err(EngineError::NotFound(
                "no blobs to resolve genesis from".into(),
            ));
        };
        disclosed_genesis(bundle).unwrap_or_else(|| Err(no_disclosed_genesis()))
    }

    /// Discard the index and rebuild it from every durable manifest.
    ///
    /// The full-recovery form of [`Self::rebuild_index_from_manifests`]
    /// ([recovery-reindex], [recovery-convergence]): the index is a
    /// rebuildable cache of the blob store (root `AGENTS.md` I1), so
    /// clearing it first also drops any entry no manifest backs. `clear`
    /// requires a [`DeriveToken`] that only this crate can mint, which is
    /// why the clear lives here rather than at the call site.
    ///
    /// Unlike the heal pass, this rebuild trusts no manifest it can check:
    /// each principal is replayed from genesis through the admission path
    /// ([`Self::build_commit`]), manifest by manifest in sequence order, and
    /// a manifest recording a commit its blobs do not yield is quarantined
    /// ([`QuarantineReason::Unreplayable`]) with the rest of its chain, as
    /// is a principal whose sequence-0 blobs disclose no genesis (every
    /// chain begins with a genesis commit, SPEC 5.1).
    ///
    /// Known cost: the rebuild replays the whole store twice, the first
    /// time into a throwaway in-memory index (the quarantine set is
    /// written before the index is cleared, so a crash between the clear
    /// and the re-index cannot re-admit a quarantined manifest), and holds
    /// that index until the first pass ends. It is an operator-run
    /// recovery, not a request path, so the cost is accepted.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch(&self) -> Result<usize, EngineError> {
        Ok(self.rebuild_index_from_scratch_with_report().await?.indexed)
    }

    /// [`Self::rebuild_index_from_scratch`], reporting what it quarantined.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch_with_report(
        &self,
    ) -> Result<RebuildReport, EngineError> {
        // The quarantine set is written before the index is cleared. It
        // derives from a replaying scan, which runs into a throwaway index
        // first: a failure after the clear and before the re-index then
        // leaves a store whose next heal, which trusts the manifests and
        // honours the set, keeps a quarantined manifest out.
        let scan = self
            .rebuild_pass_on(&crate::index::MemoryIndexer::new(), true)
            .await?;
        self.indexer
            .set_quarantined(&Self::quarantine_set(&scan), &DeriveToken::new())
            .await?;
        self.indexer.clear(&DeriveToken::new()).await?;
        let report = self.rebuild_pass(true).await?;
        self.indexer
            .set_quarantined(&Self::quarantine_set(&report), &DeriveToken::new())
            .await?;
        // This pass is a full heal: without marking it, the first read
        // would run the trusting heal pass and re-index the manifests this
        // one quarantined. Already set means a heal ran earlier, which the
        // clear above has superseded either way.
        let _already_healed = self.healed.set(());
        Ok(report)
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// The quarantine set a rebuild report records in the index.
    fn quarantine_set(report: &RebuildReport) -> Vec<(Blake3Hash, String)> {
        report
            .quarantined
            .iter()
            .map(|q| (q.manifest, format!("{:?}", q.reason)))
            .collect()
    }
}

/// Whether a replay over a principal's log shows the log is not a cache of
/// its canonical chain: a leaf differs, or the log holds leaves past the
/// chain's last commit.
fn log_is_stale<S: cyphr::eml::Storage>(
    replayed: &Result<cyphr::Principal<S>, EngineError>,
) -> bool {
    match replayed {
        Ok(principal) => {
            principal.commit_trees().global_size() > principal.commits().count() as u64
        },
        Err(EngineError::Load(crate::import::LoadError::Protocol(
            cyphr::Error::DurableLeafMismatch(_),
        ))) => true,
        Err(_) => false,
    }
}

/// Every PR a stored manifest records, by principal and position: the
/// commits a rebuild holds, canonical or not.
type HeldRoots = std::collections::HashSet<(String, u64, String)>;

/// The stored manifests split by [`walk_chains`].
struct Walk {
    /// Each principal's canonical commits, in canonical order (sequence,
    /// then principal id, then manifest hash).
    canonical: Vec<(Blake3Hash, CommitManifest)>,
    /// Every other manifest: candidates for a retained branch.
    rest: Vec<(Blake3Hash, CommitManifest)>,
}

/// A commit the engine holds, canonical or retained, as [`assessment`] reads it.
#[derive(Debug, Clone)]
struct Held {
    sequence: u64,
    id: String,
    pre: Option<String>,
    pr: String,
    signed: Signed,
}

impl Held {
    fn of(commit: &IndexableCommit) -> Self {
        Self {
            sequence: commit.sequence,
            id: commit.commit_ids.first().cloned().unwrap_or_default(),
            pre: commit.pre.clone(),
            pr: commit.prs.first().cloned().unwrap_or_default(),
            signed: signed_of(commit),
        }
    }
}

/// A naked revoke the engine keeps for one key: this node's receipt time
/// of it, the key's cutoff, and the hash of its revoke record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Death {
    wrt: i64,
    record: [u8; 32],
}

/// The naked-revoked thumbprints (base64url), each with the revoke the
/// engine keeps for it, the first it accepted: a cache of the revoke
/// records (I1).
type Revoked = HashMap<String, Death>;

/// Key death at admission (SPEC 6.4), the one check every path that hands
/// the engine a bundle passes (`/push`, gossip, witness sync, a verifier's
/// store): the refusal for `bundle` if a transaction coz in it is signed by
/// a revoked key, or introduces one, and is dated at or after the key's
/// cutoff, this node's receipt time of its revoke ([`Death::wrt`]; a coz
/// with no readable `now` is judged dated after it). Not retroactive:
/// history a key signed before the cutoff stands, so a node that learned
/// the revoke first still syncs it. A coz that revokes its own signer is
/// never refused: it can only end the key (SPEC 6.4: "sign a standard
/// revoke, a subsequent `key/delete` ... and commit").
///
/// The key's holder chooses `now`, so a holder of a compromised key can
/// date a commit below the cutoff. That is not prevented here: the owner
/// recovers by mutating the principal forward (SPEC 14.12), since Cyphr
/// does not use reversion.
///
/// Refusal-only: it reads each coz's declared `pay.tmb`, `pay.id`,
/// `pay.typ` and `pay.now` before any signature is checked, so a forgery
/// can at worst refuse the bundle it travels in. It must never admit or
/// authorize on these fields.
fn dead_key_in(bundle: &WireBundle, revoked: &Revoked) -> Option<EngineError> {
    if revoked.is_empty() {
        return None;
    }
    // A data action is judged by the core at its own `now` against the key
    // timeline, which holds the naked revokes ([`note_revokes`]); only the
    // transactions are gated here.
    for raw in bundle.txs.iter().flatten() {
        let Ok(coz) = serde_json::from_slice::<serde_json::Value>(raw) else {
            continue;
        };
        let pay = &coz["pay"];
        let dead_at = |tmb: &str| {
            revoked
                .get(tmb)
                .is_some_and(|death| pay["now"].as_i64().is_none_or(|now| now >= death.wrt))
        };
        let typ = pay["typ"].as_str().unwrap_or_default();
        if cyphr::parsed_coz::typ::is_key_introducing(typ)
            && let Some(id) = pay["id"].as_str().filter(|id| dead_at(id))
        {
            return Some(EngineError::DeadKey {
                key: id.to_owned(),
                introduced: true,
            });
        }
        let self_revoke =
            cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::KEY_REVOKE);
        if let Some(tmb) = pay["tmb"].as_str().filter(|t| dead_at(t))
            && !self_revoke
        {
            return Some(EngineError::DeadKey {
                key: tmb.to_owned(),
                introduced: false,
            });
        }
    }
    None
}

/// The forks of a principal as the protocol reads them (SPEC 15.5-15.8):
/// walk from genesis over the held commits and, where a position has more
/// than one child, follow the child whose
/// subtree is tallest; two equally tall subtrees are Error, and the walk
/// stops there. That is the spec's "the commit resolves the fork" made
/// deterministic: a fork is settled by out-extending the other branch,
/// and a malicious settlement is undone only by recovery (SPEC 14).
///
/// The walk ends at a commit of the greatest height, and two commits of
/// that height tie at the fork where their lines part, so the principal
/// is Active exactly when one held commit is the highest: the heads are
/// the held commits of the greatest height.
///
/// Every held commit counts: each was admitted when it arrived, a
/// revoke only gates what arrives after it ([`dead_key_in`]), and a held
/// message is never judged again (SPEC 14.12: "Cyphr does not use
/// reversion"; the spec author on #203: "Retrospection isn't
/// supported"). A signature from a key's active period stands after the
/// key is deleted or replaced too (SPEC 6.2), and a revoke inside a commit
/// is state of its own branch only (SPEC 6.4, 15.8).
///
/// A pure function of the held commits, so a live
/// engine and one rebuilt from the blobs answer alike (I1), whether a
/// candidate commit would leave Error is this function over the held
/// commits plus the candidate, and a verifier holding the same commits
/// reaches the same verdict, heads and settlements as a peer. "Tallest"
/// is a statement about what is held now; the forks are what stays true.
fn assessment(held: &[Held]) -> Assessment {
    use std::collections::{BTreeMap, BTreeSet};

    let top = held.iter().map(|h| h.sequence).max();
    let heads: Vec<&Held> = held.iter().filter(|h| Some(h.sequence) == top).collect();

    // The walked line: the commits every head descends from (each head's
    // own line while Active).
    let by_pr: HashMap<(u64, &str), &Held> = held
        .iter()
        .map(|h| ((h.sequence, h.pr.as_str()), h))
        .collect();
    fn line_of<'a>(h: &'a Held, by_pr: &HashMap<(u64, &str), &'a Held>) -> HashSet<&'a str> {
        let mut line = HashSet::new();
        let mut at = Some(h);
        while let Some(h) = at {
            line.insert(h.id.as_str());
            at = h
                .pre
                .as_deref()
                .zip(h.sequence.checked_sub(1))
                .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied());
        }
        line
    }
    let mut lines = heads.iter().map(|h| line_of(h, &by_pr));
    let first = lines.next().unwrap_or_default();
    let walked: HashSet<&str> = lines.fold(first, |acc, line| &acc & &line);

    // The distinct held commits over each (position, pre).
    type Over<'a> = (u64, Option<&'a str>);
    let mut over: BTreeMap<Over<'_>, BTreeMap<&str, &Held>> = BTreeMap::new();
    for h in held {
        over.entry((h.sequence, h.pre.as_deref()))
            .or_default()
            .entry(h.id.as_str())
            .or_insert(h);
    }
    let forks = over
        .iter()
        .filter(|(_, c)| c.len() > 1)
        .map(|(&(sequence, pre), commits)| {
            let kept = commits
                .values()
                .copied()
                .find(|h| walked.contains(h.id.as_str()));
            Contest {
                sequence,
                pre: pre.map(str::to_owned),
                commits: commits.keys().map(|id| (*id).to_owned()).collect(),
                kept: kept.map(|k| k.id.clone()),
                by: kept.and_then(|k| settled_by_extension(held, k, &walked)),
            }
        })
        .collect();
    let heads: BTreeSet<String> = heads.iter().map(|h| h.id.clone()).collect();
    let fork_point = (heads.len() > 1).then(|| {
        // The common chain's last commit; the branches part just above it.
        let last = held
            .iter()
            .filter(|h| walked.contains(h.id.as_str()))
            .max_by_key(|h| h.sequence);
        ForkPoint {
            height: last.map_or(0, |h| h.sequence + 1),
            pre: last.map(|h| h.pr.clone()),
        }
    });
    Assessment {
        consensus: if heads.len() > 1 {
            Consensus::Error
        } else {
            Consensus::Active
        },
        heads: heads.into_iter().collect(),
        forks,
        fork_point,
    }
}

/// Whether a principal is in Error: [`assessment`]'s consensus.
fn in_error(held: &[Held]) -> bool {
    assessment(held).consensus == Consensus::Error
}

/// The key that settled a fork by extending `kept`: the first signer of
/// the walked commit whose `pre` is `kept`'s PR.
fn settled_by_extension(held: &[Held], kept: &Held, walked: &HashSet<&str>) -> Option<String> {
    held.iter()
        .find(|c| {
            walked.contains(c.id.as_str())
                && c.sequence == kept.sequence + 1
                && c.pre.as_deref() == Some(kept.pr.as_str())
        })
        .and_then(|c| c.signed.first().cloned())
}

/// Whether the principal `held` describes, in Error, stays in Error once
/// `candidate` is held too as the new canonical head: the Error gate,
/// which admits a commit only if it extends one of the tied heads
/// ([`assessment`]).
fn stays_errored(held: &[Held], candidate: &IndexableCommit) -> bool {
    let mut after = held.to_vec();
    after.push(Held::of(candidate));
    in_error(&after)
}

/// The retained line `rival` ends, lowest first: `rival` and, while one is
/// retained, the commit its `pre` names one position down. `by_pr` indexes
/// the retained commits by (position, PR), so the walk is linear. The key
/// is unique: PR = MR(SR, CR) and CR covers every commit's TR (SPEC 3.7.6),
/// so two distinct commits never share a PR, and a commit already held is
/// never retained twice ([`Self::is_already_stored`]).
fn retained_line(by_pr: &HashMap<(u64, &str), &Retained>, rival: &Retained) -> Vec<Retained> {
    let mut line = vec![rival.clone()];
    let mut at = rival;
    while let Some(parent) = at
        .tip
        .pre
        .as_deref()
        .zip(at.tip.sequence.checked_sub(1))
        .and_then(|(pre, below)| by_pr.get(&(below, pre)))
    {
        line.push((*parent).clone());
        at = parent;
    }
    line.reverse();
    line
}

/// Choose each principal's canonical chain from its stored commit and
/// branch manifests, the blobs alone deciding (I1).
///
/// A fork is resolved by a commit whose `pre` is the tip of the chosen
/// branch (SPEC 15.8), recorded as an ordinary commit manifest while the
/// chosen rival keeps its branch manifest; no other record exists. So the
/// walk starts at the principal's highest commit manifest (the first in
/// hash order when several share it) and goes down: the canonical commit
/// at each position is the one whose PR the canonical successor's `pre`
/// names, a commit manifest before a branch manifest and then hash order
/// among equals. A position the successor names nothing at falls back to
/// its first commit manifest, as an unresolved chain always did.
///
/// Which of two branches that both continue is canonical is not decided
/// here (see [`in_error`]); the hash-order head stays served.
///
/// Principals in `unbound` are not walked: their commit manifests pass
/// through unchanged, to be quarantined by the caller.
fn walk_chains(
    commits: Vec<(Blake3Hash, CommitManifest)>,
    branches: Vec<(Blake3Hash, CommitManifest)>,
    unbound: &HashMap<String, String>,
) -> Walk {
    use std::collections::BTreeMap;

    type Position = Vec<(bool, Blake3Hash, CommitManifest)>;
    let mut by_principal: BTreeMap<String, BTreeMap<u64, Position>> = BTreeMap::new();
    let tagged = commits
        .into_iter()
        .map(|(h, m)| (false, h, m))
        .chain(branches.into_iter().map(|(h, m)| (true, h, m)));
    for (branch, hash, manifest) in tagged {
        by_principal
            .entry(manifest.commit.principal_id.clone())
            .or_default()
            .entry(manifest.commit.sequence)
            .or_default()
            .push((branch, hash, manifest));
    }

    let mut walk = Walk {
        canonical: Vec::new(),
        rest: Vec::new(),
    };
    let extends = |successor: &CommitManifest, held: &CommitManifest| {
        successor
            .commit
            .pre
            .as_ref()
            .is_some_and(|pre| held.commit.prs.contains(pre))
    };
    for (principal_id, mut positions) in by_principal {
        for held in positions.values_mut() {
            held.sort_by_key(|(branch, hash, _)| (*branch, *hash.as_bytes()));
        }
        let walked = !unbound.contains_key(&principal_id);
        let mut chosen: HashMap<u64, usize> = HashMap::new();
        if walked {
            let mut successor: Option<&CommitManifest> = None;
            for (&sequence, held) in positions.iter().rev() {
                let named = successor.filter(|s| s.commit.sequence == sequence + 1);
                let pick = named
                    .and_then(|s| held.iter().position(|(_, _, m)| extends(s, m)))
                    .or_else(|| held.iter().position(|(branch, ..)| !branch));
                if let Some(at) = pick {
                    chosen.insert(sequence, at);
                    successor = Some(&held[at].2);
                }
            }
        }
        for (sequence, held) in positions {
            for (at, (branch, hash, manifest)) in held.into_iter().enumerate() {
                let canonical = if walked {
                    chosen.get(&sequence) == Some(&at)
                } else {
                    !branch
                };
                if canonical {
                    walk.canonical.push((hash, manifest));
                } else {
                    walk.rest.push((hash, manifest));
                }
            }
        }
    }
    walk.canonical.sort_by(|(ha, a), (hb, b)| {
        (a.commit.sequence, &a.commit.principal_id, ha.as_bytes()).cmp(&(
            b.commit.sequence,
            &b.commit.principal_id,
            hb.as_bytes(),
        ))
    });
    walk
}

/// The principal the manifests name `member` as (its key, its PG or a PR
/// it held, in any manifest), if exactly one.
fn manifest_principal(source: &PinSource<'_>, member: &str) -> Option<String> {
    let (canonical, rest) = source.manifests?;
    let mut named: Vec<&str> = canonical
        .iter()
        .chain(rest)
        .filter(|(_, m)| {
            m.commit.principal_id == member
                || m.commit.prs.iter().chain(&m.commit.pg).any(|d| d == member)
        })
        .map(|(_, m)| m.commit.principal_id.as_str())
        .collect();
    named.sort_unstable();
    named.dedup();
    match named.as_slice() {
        [one] => Some((*one).to_string()),
        _ => None,
    }
}

/// The thumbprints that sign the transactions of `bundle`, if every coz
/// of the bundle is signed by a key the principal has ever held and its
/// signature verifies under that key; `None` otherwise, or if the bundle
/// has no transaction. Reads no principal state: `genesis` and the keys the
/// stored `entries` introduced are the whole key history.
fn authenticated_signers(
    bundle: &WireBundle,
    genesis: &crate::Genesis,
    entries: &[crate::CommitEntry],
    outside: &HashMap<String, (String, Vec<u8>)>,
) -> Option<Vec<coz::Thumbprint>> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut history: HashMap<String, (String, Vec<u8>)> = HashMap::new();
    let genesis_keys: &[cyphr::Key] = match genesis {
        crate::Genesis::Implicit(key) => std::slice::from_ref(key),
        crate::Genesis::Disclosed(keys) => keys,
    };
    for key in genesis_keys {
        history.insert(
            key.tmb().to_b64(),
            (key.alg().to_owned(), key.pub_key().to_vec()),
        );
    }
    for key in entries.iter().flat_map(|e| &e.keys) {
        if let Ok(public) = Base64UrlUnpadded::decode_vec(&key.pub_key) {
            history.insert(key.tmb.clone(), (key.alg.clone(), public));
        }
    }

    // A key the principal never held may be a key of an embedded principal
    // (SPEC 10.3): its signature is checked here against the key the index
    // holds for the thumbprint, which only a replay can tie to a principal.
    for (tmb, key) in outside {
        history.entry(tmb.clone()).or_insert_with(|| key.clone());
    }

    let mut signers = Vec::new();
    // Keys this bundle introduces: they are not held at any `pre`, so
    // they are not signers retention looks for there.
    let mut introduced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for blob in bundle.cozies() {
        let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
        let mut pay = value.get("pay")?.clone();
        crate::import::canonicalize_value(&mut pay);
        let header = cyphr::parsed_coz::CozHeader::parse(&pay).ok()?;
        let sig = Base64UrlUnpadded::decode_vec(value.get("sig")?.as_str()?).ok()?;
        let (alg, public) = history.get(&header.tmb.to_b64())?;
        let pay_json = serde_json::to_vec(&pay).ok()?;
        if coz::verify_json(&pay_json, &sig, alg, public) != Some(true) {
            return None;
        }
        // A key a verified coz of this bundle introduces (`key/create`,
        // `key/replace`) may sign the cozies after it, as its own commit
        // does when it finalizes a rotation; the bundle discloses it, bound
        // to the `id` by its thumbprint.
        if cyphr::parsed_coz::typ::is_key_introducing(&header.typ)
            && let Some(id) = pay.get("id").and_then(|v| v.as_str())
        {
            // A key the principal already held is no new signer.
            let disclosed = bundle
                .keys
                .iter()
                .find(|k| k.tmb == id && !history.contains_key(id));
            if let Some(k) = disclosed {
                let public = Base64UrlUnpadded::decode_vec(&k.pub_key).ok()?;
                let bound = coz::compute_thumbprint_for_alg(&k.alg, &public)
                    .is_some_and(|t| t.to_b64() == id);
                if bound {
                    history.insert(id.to_string(), (k.alg.clone(), public));
                    introduced.insert(id.to_string());
                }
            }
        }
        if cyphr::parsed_coz::typ::is_transaction(&header.typ)
            && !introduced.contains(&header.tmb.to_b64())
        {
            signers.push(header.tmb);
        }
    }
    (!signers.is_empty()).then_some(signers)
}

/// The genesis a principal's first commit discloses, in wire order: every
/// key a `key/create` transaction before the `principal/create` introduces
/// (the bundle's `keys` entry its `id` names), the genesis key first (SPEC
/// 5.1 steps 1-2, 5.3, 7.7 Example 1); with one such key it is that key's
/// genesis. `None` when the bundle carries no `principal/create`, or no
/// `key/create` before it: such a bundle is no genesis commit, so its
/// principal cannot be read from it. A key the genesis creates beyond its
/// first gives the same state whether it is read as a genesis key or as one
/// added in the genesis commit.
fn disclosed_genesis(bundle: &WireBundle) -> Option<Result<crate::Genesis, EngineError>> {
    use cyphr::parsed_coz::typ::{KEY_CREATE, PRINCIPAL_CREATE, has_suffix};

    let values: Vec<serde_json::Value> = bundle
        .txs
        .iter()
        .flatten()
        .filter_map(|b| serde_json::from_slice(b).ok())
        .collect();
    let typ = |v: &serde_json::Value| v.pointer("/pay/typ")?.as_str().map(str::to_owned);
    let to_key = |v: &serde_json::Value| -> Result<cyphr::Key, EngineError> {
        let id = v.pointer("/pay/id").and_then(serde_json::Value::as_str);
        let entry = bundle
            .keys
            .iter()
            .find(|k| Some(k.tmb.as_str()) == id)
            .ok_or_else(|| {
                EngineError::MalformedBlob("a genesis key/create discloses no key".into())
            })?;
        crate::import::key_entry_to_key(entry)
            .map_err(|e| EngineError::MalformedBlob(format!("genesis key conversion: {e}")))
    };
    if let Some(pc) = values
        .iter()
        .position(|v| typ(v).is_some_and(|t| has_suffix(&t, PRINCIPAL_CREATE)))
    {
        let keys = values[..pc]
            .iter()
            .filter(|v| typ(v).is_some_and(|t| has_suffix(&t, KEY_CREATE)))
            .map(to_key)
            .collect::<Result<Vec<_>, _>>();
        return match keys {
            Err(e) => Some(Err(e)),
            Ok(mut keys) if keys.len() == 1 => keys.pop().map(|k| Ok(crate::Genesis::Implicit(k))),
            Ok(keys) if keys.is_empty() => None,
            Ok(keys) => Some(Ok(crate::Genesis::Disclosed(keys))),
        };
    }
    None
}

/// The refusal of a first bundle that discloses no genesis.
fn no_disclosed_genesis() -> EngineError {
    EngineError::MalformedBlob(
        "the first commit is no genesis commit: no key/create before a principal/create discloses \
         its keys (SPEC 5.1)"
            .into(),
    )
}

/// The key that signed a stored commit's bundle: [`commit_signer`] of the
/// commit the bundle forms.
fn bundle_signer(bundle: &WireBundle) -> Result<String, EngineError> {
    let decoded = decode_bundle(bundle)?;
    let cozies: Vec<_> = decoded.cozies().collect();
    Ok(cozies
        .iter()
        .rev()
        .find(|c| is_commit_create_typ(&c.header().typ))
        .or(cozies.last())
        .map(|c| c.header().tmb.to_b64())
        .unwrap_or_default())
}

/// Whether `typ` is the protocol's `commit/create` (authority-qualified
/// suffix, SPEC 7.3), never a substring match: an application typ that
/// merely contains `/commit/create` is an ordinary coz.
fn is_commit_create_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::COMMIT_CREATE)
}

/// Take the naked revokes the engine holds into `principal`'s key
/// history, after its held history is replayed: each gates the data
/// actions that arrive next from this node's receipt time of it (SPEC 6.4;
/// #203), and judges none already held. A revoke of a key the principal
/// never held changes nothing.
fn note_revokes<T: cyphr::eml::Storage>(principal: &mut cyphr::Principal<T>, revoked: &Revoked) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    // The thumbprints come from verified revokes ([`verify_revoke`]), so
    // they decode.
    for (tmb, death) in revoked {
        if let Ok(bytes) = Base64UrlUnpadded::decode_vec(tmb) {
            principal.note_naked_revoke(&coz::Thumbprint::from_bytes(bytes), death.wrt);
        }
    }
}

/// The four roots of `principal`'s state.
fn roots_of<T: cyphr::eml::Storage>(
    principal: &cyphr::Principal<T>,
) -> Result<DerivedRoots, EngineError> {
    let pr = format_multihash_all(principal.pr().as_multihash())?
        .into_iter()
        .next()
        .ok_or_else(|| EngineError::InvalidInput("empty PR".into()))?;

    // SR and AR are absent for a Dead principal (SPEC 3.7: an empty
    // component is omitted).
    let sr = format_multihash_opt(principal.sr().map(|s| s.as_multihash()))?
        .into_iter()
        .next();

    let ar = format_multihash_opt(principal.auth_root().map(|a| a.as_multihash()))?
        .into_iter()
        .next();

    let cr = match principal.cr() {
        Some(cr_obj) => format_multihash_all(cr_obj.as_multihash())?
            .into_iter()
            .next()
            .unwrap_or_default(),
        None => String::new(),
    };

    Ok(DerivedRoots { pr, sr, ar, cr })
}

/// The czds of an action-only bundle's actions.
fn bundle_czds(bundle: &WireBundle) -> Result<Vec<Vec<u8>>, EngineError> {
    let decoded = WireBundle::actions(bundle.actions.clone())
        .decode()
        .map_err(|e| EngineError::MalformedBlob(e.to_string()))?;
    Ok(decoded
        .cozies()
        .map(|c| c.czd().as_bytes().to_vec())
        .collect())
}

/// The action-only bundle of an action manifest's stored blobs, or why
/// they are not one.
fn action_bundle(blobs: Vec<Vec<u8>>) -> Result<cyphr::replay::Bundle, String> {
    if blobs.is_empty() {
        return Err("not an action-only bundle".into());
    }
    WireBundle::actions(blobs)
        .decode()
        .map_err(|e| e.to_string())
}

/// Order action-only bundles by their earliest `now`, then manifest hash
/// (SPEC 4.8.1: actions are ordered by `now`, then lexically).
fn replay_order(bundles: &mut [ActionBundle]) {
    bundles.sort_by_cached_key(|b| {
        let first = b.bundle.cozies().map(|c| c.header().now).min();
        (first, *b.manifest.as_bytes())
    });
}

/// The [`CommitEntry`](crate::CommitEntry) replay reads from a stored
/// commit's bundle. State digest fields are inert during replay.
fn replay_entry(
    bundle: &WireBundle,
    commit_id: &str,
    pr: &str,
) -> Result<crate::CommitEntry, EngineError> {
    let entry = crate::CommitEntry::from_bundle(bundle).map_err(|e| {
        EngineError::MalformedBlob(format!("commit {commit_id} blob is not valid JSON: {e}"))
    })?;
    Ok(crate::CommitEntry {
        commit_id: commit_id.to_string(),
        pr: pr.to_string(),
        ..entry
    })
}

/// The principal `bundle` replays to as its first bundle, or `None` when
/// it does not replay from `genesis`.
async fn replay_first(genesis: &crate::Genesis, bundle: &WireBundle) -> Option<cyphr::Principal> {
    let mut principal = cyphr::Principal::implicit(genesis.key()?.clone())
        .await
        .ok()?;
    let entry = replay_entry(bundle, "", "").ok()?;
    crate::import::replay_commits(&mut principal, &[entry])
        .await
        .ok()?;
    Some(principal)
}

/// The storage key a principal's first bundle derives, a
/// function of the record alone (I1). A genesis commit (SPEC 5.1) keys it
/// by its PG, in the spelling of [`genesis_principal_id`] (the first active
/// algorithm); the PG is the state at `principal/create`, so a nonce in the
/// genesis commit already makes it unique (5.1: "a nonce embedding for a
/// unique PG"). A bundle of data actions alone forms no commit: a Level 1/2
/// principal is keyed by its genesis PR. `None` when the bundle does not
/// replay.
async fn record_key(genesis: &crate::Genesis, bundle: &WireBundle) -> Option<String> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let principal = replay_first(genesis, bundle).await?;
    let Some(pg) = principal.pg() else {
        return (principal.commits().next().is_none())
            .then(|| genesis_principal_id(genesis).ok())
            .flatten();
    };
    let alg = principal.active_algs().first().copied()?;
    let digest = pg.as_multihash().get(alg)?;
    Some(format!(
        "{alg}:{}",
        Base64UrlUnpadded::encode_string(digest)
    ))
}

/// Whether `bundle` carries a `principal/create`: a genesis commit (SPEC
/// 5.1).
fn is_genesis_bundle(bundle: &WireBundle) -> bool {
    bundle.txs.iter().flatten().any(|blob| {
        serde_json::from_slice::<serde_json::Value>(blob)
            .ok()
            .and_then(|v| v.pointer("/pay/typ")?.as_str().map(str::to_owned))
            .is_some_and(|typ| {
                cyphr::parsed_coz::typ::has_suffix(&typ, cyphr::parsed_coz::typ::PRINCIPAL_CREATE)
            })
    })
}

/// Whether `data` parses as the pre-keyspace manifest shape. Parsed, not
/// searched: JSON lets any member name be spelled with escapes.
fn is_legacy_manifest(data: &[u8]) -> bool {
    /// The pre-keyspace manifest's shape: a kind and a commit, whatever
    /// else it carried (it predates the recorded transaction shape).
    #[derive(serde::Deserialize)]
    struct Legacy {
        kind: String,
        #[serde(rename = "commit")]
        _commit: IndexableCommit,
    }
    serde_json::from_slice::<Legacy>(data).is_ok_and(|m| m.kind == COMMIT_MANIFEST_KIND)
}

/// The members of a stored wire coz: exactly what the signature and the
/// protocol need (`pay` and `sig`; key material travels in the bundle's
/// `keys`, SPEC 4.6.2). Coz allows
/// applications to add members, so extras are tolerated on the wire but
/// never stored; `cad`/`czd` are recalculatable, so a present value is
/// recomputed and a mismatch refused (and the value dropped, as any
/// consumer can recompute it).
///
/// One signed coz therefore has one blob address, and a stored wire blob
/// cannot be shaped like anything else the engine stores.
fn canonical_coz(blob: &[u8], i: usize) -> Result<Vec<u8>, EngineError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let bad = |why: String| EngineError::MalformedBlob(format!("blob {i}: {why}"));
    let value: serde_json::Value = serde_json::from_slice(blob).map_err(|e| bad(e.to_string()))?;
    let serde_json::Value::Object(members) = value else {
        return Err(bad("not a JSON object".into()));
    };
    let mut pay = members
        .get("pay")
        .cloned()
        .ok_or_else(|| bad("missing 'pay'".into()))?;
    let sig = members
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| bad("missing 'sig'".into()))?;
    crate::import::canonicalize_value(&mut pay);

    let present = |name: &str| -> Result<Option<&str>, EngineError> {
        members
            .get(name)
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| bad(format!("'{name}' is not a string")))
            })
            .transpose()
    };
    let (cad, czd) = (present("cad")?, present("czd")?);
    if cad.is_some() || czd.is_some() {
        let alg = pay
            .get("alg")
            .and_then(|a| a.as_str())
            .ok_or_else(|| bad("missing 'alg' in pay".into()))?;
        let pay_bytes = serde_json::to_vec(&pay).map_err(|e| bad(format!("pay serialize: {e}")))?;
        let sig_bytes =
            Base64UrlUnpadded::decode_vec(sig).map_err(|_| bad("invalid sig base64".into()))?;
        let recomputed = coz::canonical_hash_for_alg(&pay_bytes, alg, None)
            .ok_or_else(|| bad("cad computation failed".into()))?;
        if cad.is_some_and(|c| c != recomputed.to_b64()) {
            return Err(bad("'cad' does not match the pay".into()));
        }
        if let Some(claimed) = czd {
            let czd = coz::czd_for_alg(&recomputed, &sig_bytes, alg)
                .ok_or_else(|| bad("czd computation failed".into()))?;
            if claimed != czd.to_b64() {
                return Err(bad("'czd' does not match the pay and sig".into()));
            }
        }
    }

    let mut canonical = serde_json::Map::new();
    canonical.insert("pay".into(), pay);
    canonical.insert("sig".into(), sig.into());
    let mut canonical = serde_json::Value::Object(canonical);
    crate::import::canonicalize_value(&mut canonical);
    serde_json::to_vec(&canonical).map_err(|e| bad(format!("serialize: {e}")))
}

/// A pushed bundle in the form the engine verifies and stores: each coz
/// canonical ([`canonical_coz`]), and of `keys` exactly one entry per key a
/// coz of `txs` introduces, holding `alg`, `pub` and `tmb` once the core has
/// checked `tmb` is the thumbprint of `pub`. `tag` and `now` are unsigned
/// labels, and the protocol sets a key's first-seen time from the signed
/// `pay.now` when it applies the introducing coz; an entry no coz names is
/// not stored, so a commit has one stored form whatever unsigned material
/// travelled with it.
fn canonical_bundle(bundle: &WireBundle) -> Result<WireBundle, EngineError> {
    let mut canonical = bundle.try_map(|i, blob| canonical_coz(blob, i))?;
    let named: std::collections::HashSet<String> = canonical
        .txs
        .iter()
        .flatten()
        .filter_map(|blob| {
            let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
            let typ = value.pointer("/pay/typ")?.as_str()?;
            crate::import::is_key_introducing_typ(typ)
                .then(|| value.pointer("/pay/id")?.as_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    let mut keys: Vec<KeyEntry> = Vec::new();
    for entry in &bundle.keys {
        if !named.contains(&entry.tmb) || keys.iter().any(|k| k.tmb == entry.tmb) {
            continue;
        }
        crate::import::key_entry_to_key(entry).map_err(|e| match e {
            // e.g. `TmbMismatch`: a client-facing protocol refusal, not a
            // malformed bundle.
            crate::import::LoadError::Protocol(p) => EngineError::Protocol(p),
            other => {
                EngineError::MalformedBlob(format!("key {} is not a valid key: {other}", entry.tmb))
            },
        })?;
        keys.push(KeyEntry {
            tag: None,
            now: None,
            ..entry.clone()
        });
    }
    canonical.keys = keys;
    Ok(canonical)
}

/// A canonical bundle decoded for the core.
fn decode_bundle(bundle: &WireBundle) -> Result<cyphr::replay::Bundle, EngineError> {
    use cyphr::replay::WireError;
    bundle.decode().map_err(|e| match e.error {
        // e.g. `TmbMismatch`: a client-facing protocol refusal, not an
        // infrastructure failure.
        WireError::Key(p) | WireError::Protocol(p) => EngineError::Protocol(p),
        other => match e.coz {
            Some(i) => EngineError::MalformedBlob(format!("blob {i}: {other}")),
            None => EngineError::MalformedBlob(format!("keys: {other}")),
        },
    })
}

/// Hash labels an identifier may carry. A bare digest is mapped to one of
/// these only by finding which labelled spelling names a stored principal
/// (or, on first push, the one the genesis derives); the label is never
/// inferred from the digest's length.
const ID_LABELS: [&str; 3] = ["SHA-256", "SHA-384", "SHA-512"];

/// The digest part of a labelled id (`ALG:digest`); an unlabelled id is
/// returned as is. This is the wire spelling SPEC §2.2.3 gives identifiers
/// by default (the engine stores the labelled spelling).
pub fn bare_digest(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, digest)| digest)
}

/// The id `genesis` derives (SPEC §3.1): the Principal Root of its genesis
/// key, by singleton promotion that key's `tmb`, in the algorithm-labelled
/// `ALG:digest` form, the one canonical spelling every storage and index
/// key uses. It keys a principal with no commit (Levels 1 and 2); a
/// genesis commit keys its principal by PG instead (see `record_key`).
///
/// # Errors
///
/// `NoActiveKeys` for an explicit genesis listing no key; otherwise the
/// protocol error genesis construction raises.
pub fn genesis_principal_id(genesis: &crate::Genesis) -> Result<String, EngineError> {
    let key = genesis.key().ok_or(cyphr::Error::NoActiveKeys)?;
    Ok(cyphr::PrincipalState::genesis(key.clone())?.pr_tagged()?)
}

/// Format all variants of a [`MultihashDigest`] as tagged digest strings (`"alg:base64url"`).
fn format_multihash_all(
    mh: &cyphr::multihash::MultihashDigest,
) -> Result<Vec<String>, EngineError> {
    mh.algorithms()
        .map(|alg| Ok(mh.tagged(alg)?.to_string()))
        .collect()
}

/// [`format_multihash_all`] for a root that may be absent: an absent root
/// formats to no variants, which readers treat as "no such root".
fn format_multihash_opt(
    mh: Option<&cyphr::multihash::MultihashDigest>,
) -> Result<Vec<String>, EngineError> {
    mh.map_or_else(|| Ok(Vec::new()), format_multihash_all)
}

#[cfg(test)]
mod tests;
