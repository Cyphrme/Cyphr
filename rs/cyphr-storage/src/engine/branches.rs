//! # Branches and the fork read
//!
//! The retained rivals of each principal (a cache of the branch manifests
//! in the blob store, I1), the fork reads kept between uses, and the engine
//! methods that retain, resolve, promote and report forks. [`BranchStore`]
//! owns both maps; everything else reaches them only through its methods.

use std::collections::HashMap;

use super::*;
/// A commit that was ever canonical is never removed, by a cap or
/// otherwise: promotion retains each commit it displaces one for one and
/// without quota, and the caps below refuse a new rival at admission and
/// evict nothing. An embedding principal's pin names a state of this one
/// (SPEC 14.12), and finds it again only because nothing held is deleted.
///
/// Retained rival lines kept per principal. A line is a retained root and
/// the retained commits under it, at most [`BRANCH_DEPTH`] in all. A key
/// holder can mint any number of rivals at one position; the quotas bound
/// what one principal can make the store keep by offer: [`BRANCH_LIMIT`] *
/// [`BRANCH_DEPTH`] commits. An offer the quotas refuse is still kept when
/// it changes the principal's standing or fork point (rule X), which adds
/// at most two commits per chain position: the bound is 32 + 2h, h the
/// principal's chain length. A refused offer answers
/// [`EngineError::BranchLimit`] while the principal is Active and
/// [`EngineError::Errored`] in Error.
pub const BRANCH_LIMIT: usize = 16;

/// Retained lines one signer may open (the signer of a line's first
/// commit). The quota bounds what one key can have kept as junk, nothing
/// more: a key holder can fill it, and what it refuses is kept anyway when
/// it would change the standing or the fork point, so filling it keeps
/// nothing out that matters.
pub const BRANCH_PER_KEY: usize = 2;

/// Commits kept in one retained line, its root included. The fork rule
/// reads a line's root and whether one commit extends it; a further commit
/// changes no verdict, so a holder keeps a line to this size and refuses
/// what grows it.
pub const BRANCH_DEPTH: usize = 2;

/// A principal's canonical commits as the fork rule reads them
/// ([`StorageEngine::held`]), kept between uses: the chain from position
/// `from` to the tip of `count` commits. Commits are immutable and a commit
/// names its predecessor by Principal Root, so a cached prefix is still the
/// chain's whenever the next commit read links to its last, and a cache is
/// never trusted past that check. A cache of the index and the stored manifests (I1):
/// a rebuild clears it.
struct ForkCache {
    from: u64,
    count: u64,
    tip_id: String,
    tip_pr: String,
    canonical: Vec<Held>,
}

/// The [`ForkCache`]s, at most `capacity` of them, the least recently used
/// evicted first: losing one costs its principal one fork read.
struct ForkCaches {
    capacity: usize,
    entries: HashMap<String, ForkCache>,
    order: std::collections::VecDeque<String>,
}

impl ForkCaches {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn touch(&mut self, principal_id: &str) {
        self.order.retain(|id| id != principal_id);
        self.order.push_back(principal_id.to_string());
    }

    /// The entry of `principal_id`, marked as just used.
    fn get(&mut self, principal_id: &str) -> Option<&ForkCache> {
        if self.entries.contains_key(principal_id) {
            self.touch(principal_id);
        }
        self.entries.get(principal_id)
    }

    fn put(&mut self, principal_id: &str, cache: ForkCache) {
        if self.capacity == 0 {
            return;
        }
        self.entries.insert(principal_id.to_string(), cache);
        self.touch(principal_id);
        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => self.entries.remove(&oldest),
                None => break,
            };
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// A retained rival as the engine tracks it: the listed [`BranchTip`],
/// the key that signed its closing `commit/create`, and the stored blobs
/// the evidence route serves back.
#[derive(Debug, Clone)]
pub(super) struct Retained {
    pub(super) tip: BranchTip,
    /// The commit's Principal Root: what a commit extending it names as
    /// its `pre`.
    pub(super) pr: String,
    pub(super) signer: String,
    pub(super) blobs: Vec<Blake3Hash>,
    /// The manifest blob that records the commit, where its frame is read.
    pub(super) manifest: Blake3Hash,
    pub(super) shape: Shape,
    pub(super) keys: Vec<KeyEntry>,
    pub(super) signed: Signed,
    /// The embedded principals its signers were authorized through, as the
    /// branch manifest records them.
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// Whether a rival commit at `sequence` over `pre`, signed by `signer`,
/// may still be retained beside `kept` by the caps alone: an extension
/// needs its line (the retained commits under one root) below
/// [`BRANCH_DEPTH`] in all; a commit that opens a line needs a free line
/// for its signer and for the principal. The caps count lines, not
/// commits. They never refuse what would change the standing or the fork
/// point: that is [`StorageEngine::keep_branch`]'s rule X.
pub(super) fn has_slot(kept: &[Retained], pre: Option<&str>, sequence: u64, signer: &str) -> bool {
    use std::collections::HashMap;
    let by_pr: HashMap<(u64, &str), &Retained> = kept
        .iter()
        .map(|r| ((r.tip.sequence, r.pr.as_str()), r))
        .collect();
    let parent_of = |r: &Retained| {
        r.tip
            .pre
            .as_deref()
            .zip(r.tip.sequence.checked_sub(1))
            .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied())
    };
    let root_of = |r: &Retained| {
        let mut at = r;
        while let Some(up) = parent_of(at) {
            at = up;
        }
        (at.tip.sequence, at.pr.clone())
    };
    let parent = pre
        .zip(sequence.checked_sub(1))
        .and_then(|(pre, below)| by_pr.get(&(below, pre)).copied());
    if let Some(parent) = parent {
        let root = root_of(parent);
        return kept.iter().filter(|r| root_of(r) == root).count() < BRANCH_DEPTH;
    }
    let mut lines = 0;
    let mut by_signer = 0;
    for r in kept.iter().filter(|r| parent_of(r).is_none()) {
        lines += 1;
        by_signer += usize::from(r.signer == signer);
    }
    lines < BRANCH_LIMIT && by_signer < BRANCH_PER_KEY
}

/// A retained line replayed onto the canonical chain below it
/// ([`StorageEngine::replay_line`]).
pub(super) struct ReplayedLine {
    /// The principal after the line's last commit.
    pub(super) principal: cyphr::Principal,
    /// The retained commits of the line, lowest first.
    pub(super) line: Vec<Retained>,
    /// Each as the replay built it, for the index.
    pub(super) line_commits: Vec<IndexableCommit>,
}

/// A PoP's line replayed onto the held commit its first commit extends.
pub(super) struct Attached {
    /// The principal after the line's last commit.
    pub(super) principal: cyphr::Principal,
    /// Each commit as the replay built it, with the embedded principals it
    /// was authorized through.
    pub(super) commits: Vec<(IndexableCommit, Vec<EmbeddedPin>)>,
}

/// What `retain_pair` did with an offered pair.
pub(super) enum PairKept {
    /// Neither commit was kept: the pair verifies as no fork participant,
    /// or its root is already held.
    No,
    /// Both commits are retained.
    Kept,
    /// The fork rule selected the extension, and its line became the
    /// canonical chain.
    Promoted(Box<IngestResult>),
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

/// A head and when this engine first stored it.
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
/// every head, in place of a tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorState {
    /// Where the heads part.
    pub fork_point: ForkPoint,
    /// The heads, sorted by commit id.
    pub heads: Vec<HeldHead>,
}

/// One commit of a branch, as served.
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

/// One branch of an Error principal: the commits from the fork point
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

/// The commit as [`assessment`] reads it.
pub(super) fn held_of(commit: &IndexableCommit) -> Held {
    Held {
        sequence: commit.sequence,
        id: commit.commit_ids.first().cloned().unwrap_or_default(),
        pre: commit.pre.clone(),
        pr: commit.prs.first().cloned().unwrap_or_default(),
        signed: signed_of(commit),
    }
}

/// Whether a principal is in Error: [`assessment`]'s consensus.
pub(super) fn in_error(held: &[Held], asserted: &[String]) -> bool {
    assessment(held, asserted).consensus == Consensus::Error
}

/// Whether the principal `held` describes, in Error, stays in Error once
/// `candidate` is held too: the Error gate, which admits a commit only if
/// the fork rule over the held commits plus it is Active ([`assessment`]).
pub(super) fn stays_errored(
    held: &[Held],
    asserted: &[String],
    candidate: &IndexableCommit,
) -> bool {
    let mut after = held.to_vec();
    after.push(held_of(candidate));
    in_error(&after, asserted)
}

/// The retained line `rival` ends, lowest first: `rival` and, while one is
/// retained, the commit its `pre` names one position down. `by_pr` indexes
/// the retained commits by (position, PR), so the walk is linear. The key
/// is unique: PR = MR(SR, CR) and CR covers every commit's TR (SPEC 3.7.6),
/// so two distinct commits never share a PR, and a commit already held is
/// never retained twice ([`Self::is_already_stored`]).
pub(super) fn retained_line(
    by_pr: &HashMap<(u64, &str), &Retained>,
    rival: &Retained,
) -> Vec<Retained> {
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

/// A fork read kept for a principal ([`BranchStore::cached_fork`]).
pub(super) struct CachedFork {
    /// How many canonical commits the cache holds.
    pub(super) count: u64,
    /// Whether it stands at the tip the caller named.
    pub(super) same_tip: bool,
    /// The Principal Root of its last commit.
    pub(super) tip_pr: String,
    pub(super) canonical: Vec<Held>,
}

/// The retained non-canonical branches per canonical principal id, and the
/// fork reads kept between uses.
///
/// The branches are a cache of the branch manifests in the blob store (I1),
/// filled by the rebuild scan and by retention, at most
/// `min(`[`BRANCH_LIMIT`]`, `[`BRANCH_PER_KEY`]` * active keys)` per
/// principal. The fork reads are each principal's canonical commits as the
/// fork rule reads them ([`ForkCache`]): what keeps the fork read of a
/// principal with a retained rival from costing its length on every reader.
pub(super) struct BranchStore {
    branches: std::sync::Mutex<HashMap<String, Vec<Retained>>>,
    forks: std::sync::Mutex<ForkCaches>,
}

impl BranchStore {
    pub(super) fn new(fork_capacity: usize) -> Self {
        Self {
            branches: std::sync::Mutex::new(HashMap::new()),
            forks: std::sync::Mutex::new(ForkCaches::new(fork_capacity)),
        }
    }

    /// The deepest line retention keeps ([`BRANCH_DEPTH`]).
    pub(super) fn depth(&self) -> usize {
        BRANCH_DEPTH
    }

    /// Keep at most `capacity` fork reads, none held now.
    pub(super) fn resize_forks(&self, capacity: usize) {
        *self.forks.lock().unwrap_or_else(|p| p.into_inner()) = ForkCaches::new(capacity);
    }

    /// How many principals' fork reads are kept.
    pub(super) fn forks_cached(&self) -> usize {
        self.forks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .len()
    }

    /// Forget every fork read: a rebuild re-derives them.
    pub(super) fn clear_forks(&self) {
        self.forks.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    /// Replace every retained branch with `branches`: a rebuild re-derives
    /// them from the blobs.
    pub(super) fn replace(&self, branches: HashMap<String, Vec<Retained>>) {
        *self.branches.lock().unwrap_or_else(|p| p.into_inner()) = branches;
    }

    /// A copy of `principal_id`'s retained rivals.
    pub(super) fn retained(&self, principal_id: &str) -> Vec<Retained> {
        self.with(principal_id, <[Retained]>::to_vec)
    }

    /// Forget the retained rival `tip` at `sequence`, if held: the commit
    /// became canonical.
    pub(super) fn forget(&self, principal_id: &str, tip: &str, sequence: u64) {
        if let Some(kept) = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(principal_id)
        {
            kept.retain(|r| !(r.tip.tip == tip && r.tip.sequence == sequence));
        }
    }

    /// Read `principal_id`'s retained rivals under the lock.
    pub(super) fn with<R>(&self, principal_id: &str, read: impl FnOnce(&[Retained]) -> R) -> R {
        let kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
        read(kept.get(principal_id).map_or(&[][..], Vec::as_slice))
    }

    /// Change `principal_id`'s retained rivals under the lock.
    pub(super) fn update<R>(
        &self,
        principal_id: &str,
        change: impl FnOnce(&mut Vec<Retained>) -> R,
    ) -> R {
        let mut kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
        change(kept.entry(principal_id.to_string()).or_default())
    }

    /// The principal that retains the commit whose Principal Root is `pr`.
    pub(super) fn principal_of_pr(&self, pr: &str) -> Option<String> {
        self.branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(_, rs)| rs.iter().any(|r| r.pr == pr))
            .map(|(id, _)| id.clone())
    }

    /// The keys the principal's retained rivals disclose: a source of
    /// signers for a bundle extending one of them. O(retained), which
    /// [`BRANCH_LIMIT`] caps; nothing is read from the store.
    pub(super) fn keys(&self, principal_id: &str) -> Vec<KeyEntry> {
        self.with(principal_id, |rs| {
            rs.iter().flat_map(|r| r.keys.clone()).collect()
        })
    }

    /// Whether a rival with these blobs and grouping is retained.
    pub(super) fn is_retained(
        &self,
        principal_id: &str,
        hashes: &[Blake3Hash],
        shape: &Shape,
    ) -> bool {
        self.with(principal_id, |rs| {
            rs.iter().any(|r| r.blobs == hashes && r.shape == *shape)
        })
    }

    /// The retained rivals of `principal_id` as the fork rule reads them.
    pub(super) fn held(&self, principal_id: &str) -> Vec<Held> {
        self.with(principal_id, |rs| {
            rs.iter()
                .map(|r| Held {
                    sequence: r.tip.sequence,
                    id: r.tip.tip.clone(),
                    pre: r.tip.pre.clone(),
                    pr: r.pr.clone(),
                    signed: r.signed.clone(),
                })
                .collect()
        })
    }

    /// The fork read kept for `principal_id`, if it starts at or below
    /// `from` and holds at most `count` commits; marked as just used.
    pub(super) fn cached_fork(
        &self,
        principal_id: &str,
        from: u64,
        count: u64,
        tip_id: &str,
    ) -> Option<CachedFork> {
        self.forks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .filter(|c| c.from <= from && c.count <= count)
            .map(|c| CachedFork {
                count: c.count,
                same_tip: c.tip_id == tip_id,
                tip_pr: c.tip_pr.clone(),
                canonical: c.canonical.clone(),
            })
    }

    /// Keep `canonical`, the fork read of `principal_id` from position
    /// `from` to its tip `tip_id` of `count` commits.
    pub(super) fn cache_fork(
        &self,
        principal_id: &str,
        from: u64,
        count: u64,
        tip_id: &str,
        canonical: &[Held],
    ) {
        let Some(last) = canonical.last() else {
            return;
        };
        self.forks.lock().unwrap_or_else(|p| p.into_inner()).put(
            principal_id,
            ForkCache {
                from,
                count,
                tip_id: tip_id.to_string(),
                tip_pr: last.pr.clone(),
                canonical: canonical.to_vec(),
            },
        );
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// How many principals' fork reads are kept ([`ForkCache`]), at most
    /// the kept-state capacity.
    pub fn forks_cached(&self) -> usize {
        self.branches.forks_cached()
    }

    /// The most commits a retained line holds ([`BRANCH_DEPTH`]): what a
    /// peer's line is kept to.
    pub fn branch_depth(&self) -> usize {
        self.branches.depth()
    }

    /// Retain a refused bundle as a non-canonical branch if it is a fork:
    /// a bundle that verifies against the principal's state at an earlier
    /// position, where the chain already holds a different commit. The
    /// bundle is still refused as the tip by the caller (I2: a fork is
    /// detected, never merged); this only keeps the evidence.
    ///
    /// The refusal is attacker-reachable, so the search is bounded:
    ///
    /// 1. **Authenticate first, reading none of the chain.** Every coz of the bundle must name a
    ///    key this principal has ever held, or one a principal it embeds has held, by `tip` (its
    ///    verified state at its tip, with the views it holds of the principals it embeds), and
    ///    verify under that key's public key. Anyone else, a stranger whose key the store knows for
    ///    another principal included, costs the bundle's own size.
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
    pub(super) async fn retain_rival(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        bundle: &WireBundle,
        tip: &cyphr::PrincipalState,
    ) -> Result<bool, EngineError> {
        // Pushed again, a held rival is answered as the fork it is; the
        // canonical commit pushed again is no rival.
        let hashes: Vec<Blake3Hash> = bundle
            .cozies()
            .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
            .collect();
        if self
            .branches
            .is_retained(principal_id, &hashes, &Shape::of(bundle))
        {
            return Ok(true);
        }
        if self.is_already_stored(principal_id, bundle).await? {
            return Ok(false);
        }
        // Authenticated before any of the stored chain is read: a bundle
        // no key of the principal signed costs its own size.
        let retained = self.branches.keys(principal_id);
        let Some(signers) = authenticated_signers(bundle, tip, &retained) else {
            return Ok(false);
        };
        let stored = self.stored_entries(principal_id, None).await?;
        let entries = &stored.entries;
        let mut principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new()).await?;
        let source = PinSource::stored();
        let mut held = HeldCache::new();
        for (position, (entry, pins)) in entries.iter().zip(&stored.pins).enumerate() {
            // A signer A never held may be a key of an embedded principal:
            // tried only where A's Key Tree holds a digest to follow.
            let tried = |t: &coz::Thumbprint| {
                principal.is_key_active(t)
                    || (tip.key_ever_held(t).is_none() && principal.has_kt_digests())
            };
            if signers.iter().all(tried) {
                self.counters.bump(Counter::RetentionTrials);
                // Verified on a fork and never committed: the staged build
                // is dropped, and only its manifest is kept. The bundle is
                // an arrival, and passed the revoke gate as one
                // ([`dead_key_in`], SPEC 6.4); the held history below it is
                // not judged again.
                let mut candidate = principal.fork().await?;
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
                self.counters.bump(Counter::RetentionReplays);
                self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                    .await?;
            }
        }
        Ok(false)
    }

    /// A cap refusal as the engine answers it: [`EngineError::Errored`]
    /// while the principal is in Error (the Error refusal is true whether
    /// or not the commit is kept), the refusal itself otherwise.
    pub(super) async fn answer_in_error(
        &self,
        principal_id: &str,
        refusal: EngineError,
    ) -> EngineError {
        if matches!(refusal, EngineError::BranchLimit { .. })
            && self.is_errored(principal_id).await.unwrap_or(false)
        {
            return EngineError::Errored {
                principal_id: principal_id.to_string(),
            };
        }
        refusal
    }

    /// Test a refused `bundle` as the extension of the rival line root
    /// `parent`, neither held: verify the root as a rival (as
    /// [`Self::retain_rival`] does), then `bundle` over it, and keep both
    /// or neither. Both are kept when the caps allow them, and otherwise
    /// when the pair moves the principal's consensus or fork point (rule
    /// X); a pair that changes nothing is refused whole. `Ok(false)` is a
    /// pair that verifies as no fork participant (or a root already held).
    /// Caller holds the principal's write lock.
    pub(super) async fn retain_pair(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        parent: &WireBundle,
        bundle: &WireBundle,
        tip: &cyphr::PrincipalState,
    ) -> Result<PairKept, EngineError> {
        let hashes: Vec<Blake3Hash> = parent
            .cozies()
            .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
            .collect();
        if self
            .branches
            .is_retained(principal_id, &hashes, &Shape::of(parent))
            || self.is_already_stored(principal_id, parent).await?
        {
            return Ok(PairKept::No);
        }
        let retained = self.branches.keys(principal_id);
        // The extension may be signed by a key its root introduces, as one
        // over a held root is (it is authenticated against that root's
        // keys): the pair carries them.
        let mut with_root = retained.clone();
        with_root.extend(parent.keys.iter().cloned());
        let (Some(root_signers), Some(_)) = (
            authenticated_signers(parent, tip, &retained),
            authenticated_signers(bundle, tip, &with_root),
        ) else {
            return Ok(PairKept::No);
        };
        let stored = self.stored_entries(principal_id, None).await?;
        let entries = &stored.entries;
        let mut principal =
            Self::principal_from_genesis(genesis.clone(), cyphr::eml::MemoryStorage::new()).await?;
        let source = PinSource::stored();
        let mut held = HeldCache::new();
        for (position, (entry, pins)) in entries.iter().zip(&stored.pins).enumerate() {
            let tried = |t: &coz::Thumbprint| {
                principal.is_key_active(t)
                    || (tip.key_ever_held(t).is_none() && principal.has_kt_digests())
            };
            if root_signers.iter().all(tried) {
                self.counters.bump(Counter::RetentionTrials);
                let mut candidate = principal.fork().await?;
                let Ok(root_embedded) = self
                    .follow_held(principal_id, &mut candidate, parent, &mut held)
                    .await
                else {
                    continue;
                };
                if let Ok(Some(root)) =
                    Self::build_commit(&mut candidate, parent, principal_id, position as u64).await
                {
                    let root_commit = root.commit.clone();
                    if root.staged.commit().await.is_err() {
                        continue;
                    }
                    let Ok(ext_embedded) = self
                        .follow_held(principal_id, &mut candidate, bundle, &mut held)
                        .await
                    else {
                        continue;
                    };
                    let Ok(Some(ext)) = Self::build_commit(
                        &mut candidate,
                        bundle,
                        principal_id,
                        position as u64 + 1,
                    )
                    .await
                    else {
                        continue;
                    };
                    let ext_commit = ext.commit;
                    let signer = commit_signer(&root_commit);
                    let allowed = {
                        self.branches
                            .with(&root_commit.principal_id, |of_principal| {
                                has_slot(
                                    of_principal,
                                    root_commit.pre.as_deref(),
                                    root_commit.sequence,
                                    &signer,
                                )
                            })
                    };
                    if !allowed
                        && !self
                            .changes_verdict(principal_id, &[&root_commit, &ext_commit])
                            .await?
                    {
                        return Err(EngineError::BranchLimit { key: signer });
                    }
                    // Whether the fork rule over the held commits plus the
                    // pair selects the extension: the same two commits
                    // pushed one by one would promote it, so the pair does
                    // too (the served tip is the assessment's head).
                    let selects_extension = {
                        let lowest = Some(root_commit.sequence);
                        let mut after = self.held_with(principal_id, lowest).await?;
                        after.push(held_of(&root_commit));
                        after.push(held_of(&ext_commit));
                        let after = self.assessed(principal_id, &after);
                        after.consensus == Consensus::Active
                            && after.heads
                                == [ext_commit.commit_ids.first().cloned().unwrap_or_default()]
                    };
                    self.keep_branch_with(parent, root_commit, &root_embedded, true)
                        .await?;
                    if selects_extension
                        && let Some(resolved) = self
                            .resolve_fork(principal_id, genesis, bundle, tip)
                            .await?
                    {
                        return Ok(PairKept::Promoted(Box::new(resolved)));
                    }
                    self.keep_branch_with(bundle, ext_commit, &ext_embedded, true)
                        .await?;
                    return Ok(PairKept::Kept);
                }
            }
            if position + 1 < entries.len() {
                self.counters.bump(Counter::RetentionReplays);
                self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                    .await?;
            }
        }
        Ok(PairKept::No)
    }

    /// The retained line `rival` ends, replayed: the canonical prefix below
    /// its root, then each commit of the line, through the admission
    /// path's own [`Self::build_commit`] on a private in-memory Commit
    /// Tree. `None` when the stored prefix is shorter than the line's base
    /// or a retained commit no longer replays. The principal returned
    /// stands at `rival`.
    pub(super) async fn replay_line(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        stored: &StoredChain,
        by_pr: &HashMap<(u64, &str), &Retained>,
        rival: &Retained,
    ) -> Result<Option<ReplayedLine>, EngineError> {
        // The retained line the rival ends: it and its retained
        // ancestors, down to the one whose parent is canonical.
        let line = retained_line(by_pr, rival);
        let base = line.first().map_or(rival.tip.sequence, |r| r.tip.sequence);
        let upto = usize::try_from(base).unwrap_or(usize::MAX);
        let (Some(prefix), Some(prefix_pins)) =
            (stored.entries.get(..upto), stored.pins.get(..upto))
        else {
            return Ok(None);
        };
        let mut bundles = Vec::with_capacity(line.len());
        for r in &line {
            bundles.push(
                r.shape
                    .group(self.read_blobs(&r.blobs).await?, r.keys.clone())
                    .ok_or_else(|| {
                        EngineError::MalformedBlob(
                            "a retained branch's shape groups a different number of blobs".into(),
                        )
                    })?,
            );
        }
        let mut principal =
            Self::principal_from_genesis(genesis.clone(), cyphr::eml::MemoryStorage::new()).await?;
        let source = PinSource::stored();
        for (position, (entry, pins)) in prefix.iter().zip(prefix_pins).enumerate() {
            self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                .await?;
        }
        let mut line_commits = Vec::with_capacity(line.len());
        for (r, b) in line.iter().zip(&bundles) {
            // The retained commit is replayed against the embedded
            // states it was admitted through.
            if self
                .apply_pins(&mut principal, &source, &r.embedded, EMBED_DEPTH)
                .await
                .is_err()
            {
                return Ok(None);
            }
            let Ok(Some(staged)) =
                Self::build_commit(&mut principal, b, principal_id, r.tip.sequence).await
            else {
                return Ok(None);
            };
            let commit = staged.commit.clone();
            if staged.staged.commit().await.is_err() {
                return Ok(None);
            }
            line_commits.push(commit);
        }
        Ok(Some(ReplayedLine {
            principal,
            line,
            line_commits,
        }))
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
    /// first, like [`Self::retain_rival`], against the key history of
    /// `tip`, so an unauthenticated bundle reads nothing of the chain. Caller holds the principal's
    /// write lock.
    ///
    /// Known cost: the canonical prefix is replayed once per retained
    /// rival, because a retained commit's `pre` is bound only inside its
    /// arrow, `MR(pre, fwd, TMR)`, and the engine stores no verifiable
    /// `pre` per retained commit to resume from. The pass is reached only
    /// by an authenticated bundle, so an unauthenticated one never pays it.
    pub(super) async fn resolve_fork(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        bundle: &WireBundle,
        tip: &cyphr::PrincipalState,
    ) -> Result<Option<IngestResult>, EngineError> {
        let rivals = self.branches.retained(principal_id);
        if rivals.is_empty() || self.is_already_stored(principal_id, bundle).await? {
            return Ok(None);
        }
        let retained: Vec<KeyEntry> = rivals.iter().flat_map(|r| r.keys.clone()).collect();
        if authenticated_signers(bundle, tip, &retained).is_none() {
            return Ok(None);
        }
        let stored = self.stored_entries(principal_id, None).await?;
        let by_pr: HashMap<(u64, &str), &Retained> = rivals
            .iter()
            .map(|r| ((r.tip.sequence, r.pr.as_str()), r))
            .collect();
        let mut held = HeldCache::new();
        for rival in &rivals {
            let at = rival.tip.sequence;
            let Some(ReplayedLine {
                mut principal,
                line,
                mut line_commits,
            }) = self
                .replay_line(principal_id, genesis, &stored, &by_pr, rival)
                .await?
            else {
                continue;
            };
            // `bundle` is an arrival, and passed the revoke gate as one
            // ([`dead_key_in`], SPEC 6.4); the held line above is not
            // judged again.
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
            // `bundle` resolves the fork only where the fork rule over the
            // held commits plus it is Active on `bundle` ([`assessment`]);
            // otherwise its line is kept as evidence (an extended rival and
            // an extended canonical branch are both out of compliance).
            // It passed the revoke gate on arrival ([`dead_key_in`]).
            let before = self.held(principal_id).await?;
            let next_id = next_commit.commit_ids.first().cloned().unwrap_or_default();
            let mut after = before.clone();
            after.push(held_of(&next_commit));
            let after = self.assessed(principal_id, &after);
            if after.consensus == Consensus::Error || after.heads != [next_id] {
                if self.assessed(principal_id, &before).consensus == Consensus::Error {
                    // SPEC 15.5: it leaves nothing standing, so it is
                    // refused as the Error gate refuses; kept as evidence
                    // only where a slot is left.
                    self.keep_evidence(bundle, next_commit, &embedded).await;
                    return Err(EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    });
                }
                self.keep_branch(bundle, next_commit, &embedded).await?;
                return Ok(None);
            }
            return self
                .promote_branch(
                    principal_id,
                    &line,
                    &mut line_commits,
                    Some((bundle, next_commit, &embedded)),
                )
                .await
                .map(Some);
        }
        Ok(None)
    }

    /// Make the retained `line`'s branch the canonical chain, extended by
    /// `next` where there is one (a resolving commit, [`Self::resolve_fork`])
    /// or ending at the line's last commit (a resync PoP selected it,
    /// [`Self::submit_resync`]). Each canonical commit it displaces is
    /// retained as a branch, whether the displaced chain is longer or
    /// shorter than the line.
    pub(super) async fn promote_branch(
        &self,
        principal_id: &str,
        line: &[Retained],
        line_commits: &mut [IndexableCommit],
        next: Option<(&WireBundle, IndexableCommit, &[EmbeddedPin])>,
    ) -> Result<IngestResult, EngineError> {
        let Some(base) = line.first().map(|r| r.tip.sequence) else {
            return Err(EngineError::InvalidInput(
                "a promotion names no retained commit".into(),
            ));
        };
        // The line's blobs are already stored behind its branch manifests;
        // only the chain index needs them named.
        for (r, commit) in line.iter().zip(line_commits.iter_mut()) {
            commit.manifest = Some(r.manifest);
            commit.blob_hashes = r.blobs.clone();
            for (coz, hash) in commit.cozies.iter_mut().zip(&r.blobs) {
                coz.blob_hash = *hash;
            }
        }
        let displaced_chain = self.chain(principal_id, Some(base), None).await?;
        // A line that extends the chain's own tip displaces nothing.
        if displaced_chain.is_empty()
            && self
                .indexer
                .get_tip(principal_id)
                .await?
                .is_none_or(|tip| tip.commit_count != base)
        {
            return Err(EngineError::NotFound(format!(
                "no commit at {base} of {principal_id}"
            )));
        }
        let mut displaced = Vec::with_capacity(displaced_chain.len());
        for c in displaced_chain {
            let (
                bundle,
                Frame {
                    shape,
                    keys,
                    signed,
                    seen,
                    embedded,
                },
            ) = self.commit_bundle_framed(principal_id, &c).await?;
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
                manifest: c.manifest.ok_or_else(|| {
                    EngineError::Indexer(crate::index::IndexerError::Consistency(format!(
                        "index commit {} of {principal_id} has no commit manifest",
                        c.commit_id
                    )))
                })?,
                shape,
                keys,
                signed,
                embedded,
            });
        }

        // The displaced commits are blobs already held, retained in the
        // line's place and never counted against a signer's quota: a quota
        // a thief can fill must never refuse the owner's resolution. A
        // chain and a line of unequal length trade places all the same;
        // what the retained set gains is commits the principal once had as
        // its chain.

        // Claims first, so a refusal leaves no manifest behind; the alias
        // locks make the check and the writes below one step. The line is
        // not checked: it was verified when retained and sits where the
        // displaced chain is, which `check_commit` refuses as a rival.
        let mut claimants: Vec<&IndexableCommit> = line_commits.iter().collect();
        claimants.extend(next.as_ref().map(|(_, commit, _)| commit));
        let alias_locks = self.alias_locks(&claimants);
        let mut _alias_guards = Vec::with_capacity(alias_locks.len());
        for lock in &alias_locks {
            _alias_guards.push(lock.lock().await);
        }
        let token = DeriveToken::new();
        if let Some((_, next, _)) = &next {
            self.indexer.check_commit(next, &token).await?;
        }

        // I1 order: the resolving commit is the one new record. A walk of
        // the blobs then picks the same chain this replaces.
        let next_seen = unix_now();
        let next = match next {
            Some((bundle, next, embedded)) => {
                let (next, manifest_hash) = self
                    .store_blobs_and_manifest(bundle, next, next_seen, embedded)
                    .await?;
                self.persist_record().await?;
                Some((bundle, next, manifest_hash, embedded))
            },
            None => None,
        };
        let mut chain = line_commits.to_vec();
        chain.extend(next.iter().map(|(_, next, ..)| next.clone()));
        self.indexer
            .replace_chain_from(principal_id, base, &chain, &token)
            .await?;

        self.branches.update(principal_id, |of_principal| {
            of_principal.retain(|b| {
                !line
                    .iter()
                    .any(|r| r.tip.tip == b.tip.tip && r.tip.sequence == b.tip.sequence)
            });
            of_principal.extend(displaced);
        });
        let head = chain.last().ok_or_else(|| {
            EngineError::InvalidInput("a promotion names no retained commit".into())
        })?;
        Ok(IngestResult {
            principal_id: principal_id.to_string(),
            blob_hashes: head.blob_hashes.clone(),
            manifest_hash: next.as_ref().map(|(_, _, hash, _)| *hash),
            tip: Some(CommittedTip::of(head)),
        })
    }

    /// Replay `line` onto the held commit its first commit extends, each
    /// commit through the admission path's own [`Self::build_commit`]: the
    /// canonical states in turn, then each retained rival's. The replay
    /// ends at the commit whose Principal Root is `target`; commits past
    /// it are not read, so a peer's whole chain from a fork can be offered
    /// as the line to any tip on it. `None` when no held commit takes it,
    /// the line never reaches `target`, or no key of the principal signed
    /// its first commit (checked first, so a stranger's line costs its own
    /// size). Caller holds the principal's write lock.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attach_line(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        stored: &StoredChain,
        rivals: &[Retained],
        by_pr: &HashMap<(u64, &str), &Retained>,
        tip: &cyphr::PrincipalState,
        line: &[WireBundle],
        target: &str,
    ) -> Result<Option<Attached>, EngineError> {
        let retained: Vec<KeyEntry> = rivals.iter().flat_map(|r| r.keys.clone()).collect();
        let Some(first) = line.first() else {
            return Ok(None);
        };
        let Some(signers) = authenticated_signers(first, tip, &retained) else {
            return Ok(None);
        };
        let source = PinSource::stored();
        let mut held = HeldCache::new();
        let mut principal =
            Self::principal_from_genesis(genesis.clone(), cyphr::eml::MemoryStorage::new()).await?;
        for position in 0..=stored.entries.len() {
            let tried = signers.iter().all(|t| {
                principal.is_key_active(t)
                    || (tip.key_ever_held(t).is_none() && principal.has_kt_digests())
            });
            if tried
                && let Some(attached) = self
                    .try_line(
                        principal_id,
                        &principal,
                        position as u64,
                        line,
                        target,
                        &mut held,
                    )
                    .await?
            {
                return Ok(Some(attached));
            }
            if let Some((entry, pins)) = stored.entries.get(position).zip(stored.pins.get(position))
            {
                self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                    .await?;
            }
        }
        for rival in rivals {
            let Some(replayed) = self
                .replay_line(principal_id, genesis, stored, by_pr, rival)
                .await?
            else {
                continue;
            };
            let sequence = rival.tip.sequence + 1;
            if let Some(attached) = self
                .try_line(
                    principal_id,
                    &replayed.principal,
                    sequence,
                    line,
                    target,
                    &mut held,
                )
                .await?
            {
                return Ok(Some(attached));
            }
        }
        Ok(None)
    }

    /// `line` replayed over `parent`, its first commit at `sequence`, up to
    /// the commit whose Principal Root is `target`: `None` at the first
    /// commit that does not verify, or when none reaches `target`.
    pub(super) async fn try_line(
        &self,
        principal_id: &str,
        parent: &cyphr::Principal,
        sequence: u64,
        line: &[WireBundle],
        target: &str,
        held: &mut HeldCache<S>,
    ) -> Result<Option<Attached>, EngineError> {
        let mut principal = parent.fork().await?;
        let mut commits = Vec::with_capacity(line.len());
        for (i, bundle) in line.iter().enumerate() {
            let Ok(embedded) = self
                .follow_held(principal_id, &mut principal, bundle, held)
                .await
            else {
                return Ok(None);
            };
            let Ok(Some(build)) =
                Self::build_commit(&mut principal, bundle, principal_id, sequence + i as u64).await
            else {
                return Ok(None);
            };
            let StagedBuild { commit, staged, .. } = build;
            if staged.commit().await.is_err() {
                return Ok(None);
            }
            commits.push((commit, embedded));
            if principal.pr_tagged().is_ok_and(|pr| pr == target) {
                return Ok(Some(Attached { principal, commits }));
            }
        }
        Ok(None)
    }

    /// Keep a commit refused because the principal is in Error, as
    /// evidence ([`Self::keep_branch`]), within the branch limits. The
    /// refusal stands for Error whether or not it is kept: a full quota or
    /// a storage fault is logged, never answered in its place.
    pub(super) async fn keep_evidence(
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

    /// Whether `bundle` is, byte for byte and in its grouping, a commit this engine already
    /// holds: on the canonical chain or retained as a rival. Such a bundle
    /// is nobody's rival at any other position, since its arrow binds
    /// exactly one `pre`, so it settles with no replay and no clone. This
    /// is the cheap check made before any state is cloned: the arrow binds
    /// `pre` only through the post-state root, which cannot be recomputed
    /// without applying the bundle, so a hash identity is the one sound
    /// filter that needs no state.
    pub(super) async fn is_already_stored(
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
        if self.branches.is_retained(principal_id, &hashes, &shape) {
            return Ok(true);
        }
        // A chain commit made of these blobs holds the bundle's last coz,
        // and the index names every position that coz is held at: those
        // commits are read, never the chain.
        let Some(last) = hashes.last() else {
            return Ok(false);
        };
        if !self.indexer.is_blob_indexed(last).await? {
            return Ok(false);
        }
        let Ok(decoded) = bundle.decode() else {
            return Ok(false);
        };
        let Some(coz) = decoded.cozies().last() else {
            return Ok(false);
        };
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let czd = cyphr::state::TaggedCzd::new(coz.czd(), coz.hash_alg());
        let mut positions = std::collections::BTreeSet::new();
        // The index files a coz under its digest in the principal's primary
        // algorithm at the time, which this does not know: each is asked.
        for label in ID_LABELS {
            let Ok(alg) = cyphr::state::hash_alg_named(label) else {
                continue;
            };
            let named = format!(
                "{alg}:{}",
                Base64UrlUnpadded::encode_string(&czd.convert_to(alg))
            );
            let Ok(digest) = named.parse::<TaggedDigest>() else {
                continue;
            };
            for holder in self.indexer.resolve_digest_holders(&digest).await? {
                if holder.principal_id.as_deref() == Some(principal_id)
                    && let Some(at) = holder.sequence
                {
                    positions.insert(at);
                }
            }
        }
        for at in positions {
            let there = self.chain(principal_id, Some(at), Some(at)).await?;
            for c in &there {
                if c.blob_hashes == hashes && self.frame(c).await?.is_some_and(|f| f.shape == shape)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Store a verified rival `commit` and its blobs behind
    /// [`BRANCH_MANIFEST_PREFIX`] and list it. A commit past the canonical
    /// head (one refused while the principal is in Error) is kept the same
    /// way. A rival that is the
    /// canonical commit or an already-kept branch is a no-op; one that
    /// opens a line past a key's [`BRANCH_PER_KEY`] or the principal's
    /// [`BRANCH_LIMIT`], or extends a line past [`BRANCH_DEPTH`], is
    /// [`EngineError::BranchLimit`] and stores nothing.
    pub(super) async fn keep_branch(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        embedded: &[EmbeddedPin],
    ) -> Result<(), EngineError> {
        self.keep_branch_with(bundle, commit, embedded, false).await
    }

    /// Whether retaining `commit` (and `also`, the extension offered with
    /// it) moves the principal's consensus or fork point: the test of
    /// rule X, run over the held commits plus the offer.
    pub(super) async fn changes_verdict(
        &self,
        principal_id: &str,
        offer: &[&IndexableCommit],
    ) -> Result<bool, EngineError> {
        let lowest = offer.iter().map(|c| c.sequence).min();
        let before = self.assessed(principal_id, &self.held_with(principal_id, lowest).await?);
        let mut held = self.held_with(principal_id, lowest).await?;
        held.extend(offer.iter().map(|c| held_of(c)));
        let after = self.assessed(principal_id, &held);
        Ok(after.consensus != before.consensus || after.fork_point != before.fork_point)
    }

    /// [`Self::keep_branch`], where `force` skips the caps (rule X has
    /// already found the offer changes the standing or the fork point). A
    /// single commit the caps would refuse is kept all the same when it
    /// changes either; a forced commit counts toward the quotas.
    pub(super) async fn keep_branch_with(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        embedded: &[EmbeddedPin],
        force: bool,
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
        // `None`: this very commit is already retained.
        let capped = self.branches.with(&commit.principal_id, |of_principal| {
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                return None;
            }
            Some(
                !force
                    && !has_slot(
                        of_principal,
                        commit.pre.as_deref(),
                        commit.sequence,
                        &signer,
                    ),
            )
        });
        let Some(capped) = capped else {
            return Ok(());
        };
        if capped
            && !self
                .changes_verdict(&commit.principal_id, &[&commit])
                .await?
        {
            return Err(EngineError::BranchLimit { key: signer });
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
        let (stored, manifest) = self
            .store_manifest(
                bundle,
                commit,
                BRANCH_MANIFEST_PREFIX,
                BRANCH_MANIFEST_KIND,
                seen,
                embedded,
            )
            .await?;
        // A retained rival makes the principal Error, and an attestor signs
        // a held statement over its heads (and their first-seen times) the
        // moment it is listed. A power cut that erased the rival would
        // restart the principal Active at the same height, to sign again
        // over different heads: durable before it is visible.
        self.persist_record().await?;
        self.branches.update(&principal_id, |of_principal| {
            of_principal.push(Retained {
                tip: branch,
                pr,
                signer,
                keys: key_entries(&stored.keys),
                manifest,
                blobs: stored.blob_hashes,
                shape: Shape::of(bundle),
                signed,
                embedded: embedded.to_vec(),
            });
        });
        // The retained set just changed, which can lower where the fork rule
        // reads from: read it now, under the write lock, so no reader pays
        // for it. A failure is the next reader's to meet.
        let _ = self.held(&principal_id).await;
        Ok(())
    }

    /// How many stored commits retention has replayed so far: the cost
    /// refused bundles have put on this engine. Exposed so a test can pin
    /// that an unauthenticated bundle costs none.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn retention_replays(&self) -> u64 {
        self.counters.get(Counter::RetentionReplays)
    }

    /// How many positions retention has tried a bundle at so far (the
    /// positions where the bundle's signers were active).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn retention_trials(&self) -> u64 {
        self.counters.get(Counter::RetentionTrials)
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
        let seen = self.frame(&head).await?.and_then(|f| f.seen);
        let mut branches = vec![BranchTip {
            tip: head.commit_id,
            pre: head.pre,
            sequence: head.sequence,
            canonical: true,
            seen,
        }];
        self.branches.with(&principal_id, |kept| {
            branches.extend(kept.iter().map(|r| r.tip.clone()));
        });
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
        Ok(self.assessed(&principal_id, &held))
    }

    /// The principal's fork point and heads while it is in Error, `None`
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

    /// Whether the held commit `child_id` extends the held commit
    /// `parent_id` of `principal_id` (its `pre` is the parent's Principal
    /// Root, one position up), read over the commits the fork rule reads.
    /// `None` when either is not among them, canonical or retained.
    pub async fn extends(
        &self,
        principal_id: &str,
        parent_id: &str,
        child_id: &str,
    ) -> Result<Option<bool>, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let held = self.held(&principal_id).await?;
        let find = |id: &str| held.iter().find(|h| h.id == id);
        let (Some(parent), Some(child)) = (find(parent_id), find(child_id)) else {
            return Ok(None);
        };
        Ok(Some(
            child.sequence == parent.sequence + 1
                && child.pre.as_deref() == Some(parent.pr.as_str()),
        ))
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
        let retained = self.branches.with(&principal_id, |kept| {
            kept.iter().any(|r| r.tip.tip == commit_id)
        });
        if retained {
            return Ok(true);
        }
        // On the canonical chain: the index names the position a commit id
        // is held at, and the commit there is read to confirm it.
        let Ok(digest) = commit_id.parse::<TaggedDigest>() else {
            return Ok(false);
        };
        for holder in self.indexer.resolve_digest_holders(&digest).await? {
            if holder.principal_id.as_deref() != Some(principal_id.as_str()) {
                continue;
            }
            let Some(at) = holder.sequence else { continue };
            let there = self.chain(&principal_id, Some(at), Some(at)).await?;
            if there.first().is_some_and(|c| c.commit_id == commit_id) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn error_state_of(
        &self,
        principal_id: &str,
    ) -> Result<Option<(ForkPoint, Vec<HeldHead>)>, EngineError> {
        let held = self.held(principal_id).await?;
        let assessed = self.assessed(principal_id, &held);
        let Some(fork_point) = assessed.fork_point else {
            return Ok(None);
        };
        let by_id: HashMap<&str, &Held> = held.iter().map(|h| (h.id.as_str(), h)).collect();
        let retained = self.branches.retained(principal_id);
        let mut heads = Vec::with_capacity(assessed.heads.len());
        for id in &assessed.heads {
            // Heads are drawn from `held` by `assessment`, so each is in
            // `by_id`; a miss is an inconsistency, reported, not a panic.
            let head = by_id.get(id.as_str()).ok_or_else(|| {
                EngineError::NotFound(format!("head {id} of {principal_id} is not held"))
            })?;
            let held_since = match retained.iter().find(|r| &r.tip.tip == id) {
                Some(r) => r.tip.seen,
                None => {
                    let at = head.sequence;
                    let there = self.chain(principal_id, Some(at), Some(at)).await?;
                    match there.first() {
                        Some(c) => self.frame(c).await?.and_then(|f| f.seen),
                        None => None,
                    }
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

    /// Each branch from the fork point to its head: a commit is read
    /// from the canonical chain when the index holds it, else from the
    /// retained rival of that id.
    pub(super) async fn branches_of(
        &self,
        principal_id: &str,
        fork_point: &ForkPoint,
        heads: &[HeldHead],
    ) -> Result<Vec<PatchBranch>, EngineError> {
        // Each line is walked down to the fork point and no further.
        let held = self.held_from(principal_id, fork_point.height).await?;
        let by_pr: HashMap<(u64, &str), &Held> = held
            .iter()
            .map(|h| ((h.sequence, h.pr.as_str()), h))
            .collect();
        let chain = self
            .chain(principal_id, Some(fork_point.height), None)
            .await?;
        let retained = self.branches.retained(principal_id);
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

    /// [`assessment`] of `held` with the PoPs this engine holds for
    /// `principal_id`: the one rule every fork read here applies.
    pub(super) fn assessed(&self, principal_id: &str, held: &[Held]) -> Assessment {
        assessment(held, &self.resyncs.asserted(principal_id))
    }

    /// The commits the engine holds for `principal_id` that its forks are
    /// read from ([`assessment`]): every retained branch, and the canonical
    /// chain from one position below the lowest of them, or its tip alone
    /// when none is retained.
    ///
    /// The canonical chain below that has one commit at each position and
    /// no retained commit beside or above it, so it holds no head, no fork,
    /// and no point where two lines part: [`assessment`] over this is its
    /// answer over every held commit, whose fork point, where the lines
    /// share anything, is at or above the first commit read here. Reading
    /// the fork state so costs the depth of the fork, not the length of the
    /// history, on every write and every read of a tip or a proof. Both
    /// inputs are caches rebuilt from the blobs (I1), and nothing else is
    /// kept for it.
    pub(super) async fn held(&self, principal_id: &str) -> Result<Vec<Held>, EngineError> {
        self.held_with(principal_id, None).await
    }

    /// [`Self::held`] read as if a commit at position `offer` were
    /// retained too: the window reaches one below it, so the fork rule can
    /// be run over the held commits plus that offer.
    pub(super) async fn held_with(
        &self,
        principal_id: &str,
        offer: Option<u64>,
    ) -> Result<Vec<Held>, EngineError> {
        let lowest_retained = self
            .branches
            .with(principal_id, |kept| {
                kept.iter().map(|r| r.tip.sequence).min()
            })
            .into_iter()
            .chain(offer)
            .min();
        let Some(tip) = self.indexer.get_tip(principal_id).await? else {
            return self.held_from(principal_id, 0).await;
        };
        let last = tip.commit_count.saturating_sub(1);
        let from = assessed_from(lowest_retained, last);
        let mut held = self
            .canonical_held(
                principal_id,
                from,
                tip.commit_count,
                &tip.commit_id,
                lowest_retained.is_some(),
            )
            .await?;
        held.extend(self.branches.held(principal_id));
        if self.kept.shadow() {
            let fresh = self.held_from(principal_id, from).await?;
            if format!("{:?}", self.assessed(principal_id, &held))
                != format!("{:?}", self.assessed(principal_id, &fresh))
            {
                self.counters.bump(Counter::KeptDivergences);
                let why = format!(
                    "kept fork assessment of {principal_id} at {} differs from a fresh read",
                    tip.commit_id
                );
                tracing::error!("{why}");
                return Err(EngineError::Storage(why));
            }
        }
        Ok(held)
    }

    /// The canonical commits of `principal_id` from position `from` to its
    /// tip (`count` commits, the last `tip_id`), from the [`ForkCache`] where
    /// it still holds them (only for a principal with a retained rival, `keep`): the tip itself, or
    /// a prefix the new commits link to, which then reads only those. Anything else is read whole.
    pub(super) async fn canonical_held(
        &self,
        principal_id: &str,
        from: u64,
        count: u64,
        tip_id: &str,
        keep: bool,
    ) -> Result<Vec<Held>, EngineError> {
        // With no retained rival the read is the head alone, one row: not
        // worth an entry, which an anonymous reader of every principal could
        // otherwise fill.
        if !keep {
            return self.held_canonical_from(principal_id, from).await;
        }
        let cached = self.branches.cached_fork(principal_id, from, count, tip_id);
        let mut canonical = match cached {
            Some(c) if c.count == count && c.same_tip => c.canonical,
            Some(c) if c.count < count => {
                let new = self.held_canonical_from(principal_id, c.count).await?;
                if new
                    .first()
                    .is_some_and(|h| h.pre.as_deref() == Some(c.tip_pr.as_str()))
                {
                    let mut canonical = c.canonical;
                    canonical.extend(new);
                    canonical
                } else {
                    self.held_canonical_from(principal_id, from).await?
                }
            },
            _ => self.held_canonical_from(principal_id, from).await?,
        };
        // Only what the fork rule reads is kept: a principal with no rival
        // holds its head alone.
        let skip = canonical
            .iter()
            .position(|h| h.sequence >= from)
            .unwrap_or(canonical.len());
        canonical.drain(..skip);
        self.branches
            .cache_fork(principal_id, from, count, tip_id, &canonical);
        Ok(canonical)
    }

    /// The canonical commits from position `from` up, as read from the
    /// index.
    pub(super) async fn held_canonical_from(
        &self,
        principal_id: &str,
        from: u64,
    ) -> Result<Vec<Held>, EngineError> {
        let chain = self.chain(principal_id, Some(from), None).await?;
        let mut held = Vec::with_capacity(chain.len());
        for c in chain {
            let frame = self.frame(&c).await?.ok_or_else(|| {
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
        Ok(held)
    }

    /// Every retained branch of `principal_id`, and its canonical chain
    /// from position `from` up.
    pub(super) async fn held_from(
        &self,
        principal_id: &str,
        from: u64,
    ) -> Result<Vec<Held>, EngineError> {
        let mut held = self.held_canonical_from(principal_id, from).await?;
        held.extend(self.branches.held(principal_id));
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
        let rivals = self.branches.retained(&principal_id);
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
                canonical_seen: self.frame(canonical).await?.and_then(|f| f.seen),
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
}
