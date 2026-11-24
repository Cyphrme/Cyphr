//! # Read path
//!
//! Serving what the engine holds: tips, patches, entities and derived
//! roots, and the replay of a stored principal that every read and write
//! stands on.

use std::collections::HashMap;

use super::*;

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
    /// each branch from it; `entries` then end below the fork point.
    /// `None` while Active, and always for `get_patch`.
    pub fork: Option<PatchFork>,
}

/// An Error principal's patch beyond the common chain.
#[derive(Debug, Clone)]
pub struct PatchFork {
    /// Where the branches part.
    pub fork_point: ForkPoint,
    /// Each branch, ordered by head commit id.
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

/// Stored commits of one principal, replayable: each commit's entry and
/// the embedded principals it was admitted through, by position.
#[derive(Default)]
pub(super) struct StoredChain {
    pub(super) entries: Vec<crate::CommitEntry>,
    pub(super) pins: Vec<Vec<EmbeddedPin>>,
    /// Each commit's PR, the first (primary) spelling.
    pub(super) prs: Vec<String>,
}

/// A commit B holds, canonical or retained: what walking a PR's ancestry by
/// `pre` needs to know before loading it.
pub(super) struct HeldCommit<'m> {
    pub(super) sequence: u64,
    pub(super) pr: String,
    pub(super) pre: Option<String>,
    pub(super) origin: HeldOrigin<'m>,
}

pub(super) enum HeldOrigin<'m> {
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
pub(super) struct PinSource<'m> {
    /// The canonical manifests and the rest (displaced and retained).
    pub(super) manifests: Option<ManifestLists<'m>>,
    pub(super) memo: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<ChainMemo>>>>>,
}

pub(super) type ManifestLists<'m> = (
    &'m [(Blake3Hash, CommitManifest)],
    &'m [(Blake3Hash, CommitManifest)],
);

/// An embedded principal's chain replayed as far as the call needed, with
/// the state at each PR passed.
pub(super) struct ChainMemo {
    pub(super) chain: StoredChain,
    pub(super) principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    pub(super) next: usize,
    pub(super) at: HashMap<String, cyphr::PrincipalState>,
}

impl<'m> PinSource<'m> {
    pub(super) fn stored() -> Self {
        Self {
            manifests: None,
            memo: std::sync::Mutex::default(),
        }
    }

    pub(super) fn manifests(
        canonical: &'m [(Blake3Hash, CommitManifest)],
        rest: &'m [(Blake3Hash, CommitManifest)],
    ) -> Self {
        Self {
            manifests: Some((canonical, rest)),
            memo: std::sync::Mutex::default(),
        }
    }

    pub(super) fn slot(&self, member: &str) -> Arc<tokio::sync::Mutex<Option<ChainMemo>>> {
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
pub(super) type HeldCache<S> = HashMap<String, Option<HeldTip<S>>>;

/// A held embedded principal: the tip it gives, the PR it stands at, and the
/// principal itself.
pub(super) type HeldTip<S> = (cyphr::Tip, String, cyphr::Principal<S>);

/// What reading a held tip yields, boxed ([`StorageEngine::held_tip`]).
pub(super) type HeldRead<'a, S> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<HeldTip<S>>, EngineError>> + Send + 'a>,
>;

/// The tips of embedded principals this engine holds, for the core to
/// follow ([`StorageEngine::follow_held`]): the engine's own store, never a
/// network. A failure to read a held principal is kept, not swallowed, and
/// the digest meanwhile has no tip (fails closed).
pub(super) struct HeldTips<'e, B, I, S: cyphr::eml::Storage> {
    pub(super) engine: &'e StorageEngine<B, I, S>,
    pub(super) own_id: &'e str,
    pub(super) cache: &'e mut HeldCache<S>,
    /// The followed digests that name a held principal, read from `cache`.
    pub(super) found: std::collections::BTreeSet<String>,
    pub(super) failed: Option<EngineError>,
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
pub(super) struct NoTips;

impl cyphr::TipSource for NoTips {
    async fn tip(&mut self, _member: &str) -> Option<cyphr::Tip> {
        None
    }
}

/// How many embedded principals may nest when a pin is replayed. A pin
/// names a state held before its commit was admitted, so the real depth is
/// finite; the bound is for a store that forged a cycle.
pub(super) const EMBED_DEPTH: u8 = 16;

/// What the index's commit record lacks for a stored chain commit: how its
/// blobs group into its bundle and the keys it introduced (to serve the
/// bundle), who signed it when (to judge it against a revocation), and
/// when it was first seen.
#[derive(Debug, Clone)]
pub(super) struct Frame {
    pub(super) shape: Shape,
    pub(super) keys: Vec<KeyEntry>,
    pub(super) signed: Signed,
    pub(super) seen: Option<i64>,
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// How each stored chain commit's blobs group into its bundle, and the keys
/// it introduced, by principal id and commit id: a cache of the commit
/// manifests in the blob store (I1), filled by the rebuild scan and by
/// ingest. The index's commit records name blobs only.
#[derive(Debug, Default)]
pub(super) struct Frames(std::sync::Mutex<HashMap<(String, String), Frame>>);

impl Frames {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn get(&self, principal_id: &str, commit_id: &str) -> Option<Frame> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(principal_id.to_string(), commit_id.to_string()))
            .cloned()
    }

    pub(super) fn record(&self, principal_id: &str, commit_id: &str, frame: Frame) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((principal_id.to_string(), commit_id.to_string()), frame);
    }

    /// Whether the commit is held with exactly this grouping.
    pub(super) fn has_shape(&self, principal_id: &str, commit_id: &str, shape: &Shape) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(principal_id.to_string(), commit_id.to_string()))
            .is_some_and(|f| f.shape == *shape)
    }
}

/// Accepted action-only bundles per principal id: a cache of the action
/// manifests in the blob store (I1), filled by the rebuild scan and by
/// ingest.
#[derive(Debug, Default)]
pub(super) struct ActionStore(std::sync::Mutex<HashMap<String, Vec<StoredActions>>>);

impl ActionStore {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Replace every held bundle with `actions`: a rebuild re-derives them
    /// from the blobs.
    pub(super) fn replace(&self, actions: HashMap<String, Vec<StoredActions>>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = actions;
    }

    /// The bundles held for `principal_id`, in acceptance order.
    pub(super) fn of(&self, principal_id: &str) -> Vec<StoredActions> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether any held bundle of `principal_id` was admitted through an
    /// embedded principal.
    pub(super) fn has_pins(&self, principal_id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .is_some_and(|held| held.iter().any(|a| !a.embedded.is_empty()))
    }

    /// List `stored` for `principal_id`, unless its manifest is listed.
    pub(super) fn add(&self, principal_id: &str, stored: StoredActions) {
        let mut held = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let of_principal = held.entry(principal_id.to_string()).or_default();
        if !of_principal.iter().any(|a| a.manifest == stored.manifest) {
            of_principal.push(stored);
        }
    }
}

/// The thumbprints that signed a commit's cozies, in coz order: who
/// settled a fork ([`Contest::by`]).
pub(super) type Signed = Vec<String>;

pub(super) fn signed_of(commit: &IndexableCommit) -> Signed {
    commit.cozies.iter().map(|c| c.tmb.clone()).collect()
}

/// An action-only bundle read back for replay.
pub(super) struct ActionBundle {
    pub(super) manifest: Blake3Hash,
    pub(super) blobs: Vec<Blake3Hash>,
    pub(super) embedded: Vec<EmbeddedPin>,
    pub(super) bundle: cyphr::replay::Bundle,
}

impl ActionBundle {
    /// The engine's record of this bundle.
    pub(super) fn stored(self) -> StoredActions {
        StoredActions {
            manifest: self.manifest,
            blobs: self.blobs,
            embedded: self.embedded,
        }
    }
}

/// A principal's action-only bundles, in replay order ([`replay_order`]).
pub(super) type ActionHistory = Vec<ActionBundle>;

/// Whether a replay over a principal's log shows the log is not a cache of
/// its canonical chain: a leaf differs, or the log holds leaves past the
/// chain's last commit.
pub(super) fn log_is_stale<S: cyphr::eml::Storage>(
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

/// The principal the manifests name `member` as (its key, its PG or a PR
/// it held, in any manifest), if exactly one.
pub(super) fn manifest_principal(source: &PinSource<'_>, member: &str) -> Option<String> {
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

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
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
    /// and [`PatchResponse::fork`] carries each branch, so no one
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

    pub(super) async fn patch(
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
        // the index serves past it is one branch among several.
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
    pub(super) async fn resolve_anchor_position(
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
    pub(super) async fn commit_bundle(
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
    pub(super) fn frame(&self, principal_id: &str, commit: &CommitRef) -> Option<Frame> {
        self.frames.get(principal_id, &commit.commit_id)
    }

    /// Record a chain commit's [`Frame`], in the `frames` cache.
    pub(super) fn record_frame(
        &self,
        commit: &IndexableCommit,
        shape: &Shape,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) {
        let Some(id) = commit.commit_ids.first() else {
            return;
        };
        self.frames.record(
            &commit.principal_id,
            id,
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

    /// The roots `tip` names, read from the roots the index stored for that
    /// commit when it was admitted: nothing is replayed. A commit landing
    /// after `tip` was read changes nothing here, so what comes back is a
    /// statement about the commit `tip` names whatever the principal does
    /// meanwhile. `None` if the chain no longer has that commit at that
    /// position (a fork resolved under the read).
    ///
    /// Memoized by (principal, commit).
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the index read fails.
    #[tracing::instrument(skip(self))]
    pub async fn derive_roots_at(
        &self,
        tip: &TipState,
    ) -> Result<Option<DerivedRoots>, EngineError> {
        self.ensure_healed().await?;
        let key = (tip.principal_id.clone(), tip.commit_id.clone());
        if let Some(hit) = self.roots_at.get(&key) {
            return Ok(Some(hit));
        }
        let Some(position) = tip.commit_count.checked_sub(1) else {
            return Ok(None);
        };
        let chain = self
            .indexer
            .get_commit_chain(&tip.principal_id, Some(position), Some(position))
            .await?;
        let Some(stored) = chain
            .into_iter()
            .find(|c| c.sequence == position && c.commit_id == tip.commit_id)
        else {
            return Ok(None);
        };
        let roots = DerivedRoots {
            pr: stored.pr,
            sr: stored.sr,
            ar: stored.ar,
            cr: stored.cr,
        };
        self.roots_at.insert(key, roots.clone());
        Ok(Some(roots))
    }

    /// Reconstruct a principal by replaying stored commits, as a read-only
    /// [`AtTip`]: it holds the engine's durable log but hands out only a
    /// shared reference, so the caller cannot append to it. Writes go
    /// through [`Self::submit_commit`].
    ///
    /// Fetches the full commit chain from the indexer, retrieves each
    /// blob from the blob store, and delegates to the existing
    /// [`import::replay_commits`] infrastructure, then holds the stored
    /// action-only bundles ([`Self::replay_onto`]).
    ///
    /// Always a replay, whatever state the engine keeps: for a caller that
    /// wants the replay itself (a store check, a one-shot tool). A reader
    /// that wants the principal's state takes [`Self::at_tip`].
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
    ) -> Result<AtTip<S>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let stored = key.as_deref().unwrap_or(principal_id);
        // The writer's lock: a push appends to the durable log before it
        // writes the index, and a load in that window sees a log one leaf
        // ahead of the chain and regenerates it for nothing.
        let lock = self.principal_lock(stored);
        let _no_write_in_flight = lock.lock().await;
        self.replay_stored(stored, genesis).await.map(AtTip::new)
    }

    /// [`load_principal`](Self::load_principal) for an id already known to
    /// be the stored spelling.
    pub(super) async fn replay_stored(
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
    pub(super) async fn replay_generation(
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
    /// no part of the state: they gate each arriving bundle
    /// ([`dead_key_in`]).
    pub(super) async fn replay_onto<T: cyphr::eml::Storage>(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        storage: T,
        through: Option<u64>,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        let mut principal = Self::principal_from_genesis(genesis.clone(), storage).await?;

        let stored = self.stored_entries(principal_id, through).await?;
        let source = PinSource::stored();
        for (position, (entry, pins)) in stored.entries.iter().zip(&stored.pins).enumerate() {
            self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                .await?;
        }
        // Held actions are held as they are, with no verdict: whether one
        // counts is read from the key timeline, whatever order they are
        // taken in.
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

        Ok(principal)
    }

    /// The action-only bundles accepted for `principal_id`, read back from
    /// the blob store, in replay order.
    pub(super) async fn action_history(
        &self,
        principal_id: &str,
    ) -> Result<ActionHistory, EngineError> {
        let held = self.actions.of(principal_id);
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

    /// The active key `tmb` of `principal`, as a resync's signer is read
    /// at the state a line reaches.
    pub(super) fn active_key<T: cyphr::eml::Storage>(
        principal: &cyphr::Principal<T>,
        tmb: &coz::Thumbprint,
    ) -> Result<cyphr::Key, EngineError> {
        principal
            .state()
            .get_key(tmb)
            .filter(|_| principal.is_key_active(tmb))
            .cloned()
            .ok_or(EngineError::Protocol(cyphr::Error::UnknownKey))
    }

    /// A principal holding only its genesis key, over `storage`.
    pub(super) async fn principal_from_genesis<T: cyphr::eml::Storage>(
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
    pub(super) async fn stored_entries(
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
    pub(super) async fn replay_pinned<T: cyphr::eml::Storage>(
        &self,
        principal: &mut cyphr::Principal<T>,
        source: &PinSource<'_>,
        entry: &crate::CommitEntry,
        pins: &[EmbeddedPin],
        position: usize,
        depth: u8,
    ) -> Result<(), EngineError> {
        self.apply_pins(principal, source, pins, depth).await?;
        // The single count of replay: every commit of a chain re-applied
        // from stored blobs, on whichever path. Commits re-applied while
        // following an embedded principal (`depth` below the top) are part
        // of the commit that embeds it, not counted again.
        if depth == EMBED_DEPTH {
            self.counters.bump(Counter::CommitsReplayed);
        }
        crate::import::replay_commit(principal, entry, position).await?;
        Ok(())
    }

    /// Pin each of `pins` on `principal`: replay the embedded principal to
    /// the PR the admission recorded, and hold that as its tip. `b` was held
    /// before the commit was admitted, so a pin depends only on earlier
    /// admissions; `depth` bounds the walk for a store that says otherwise.
    pub(super) async fn apply_pins<T: cyphr::eml::Storage>(
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
    pub(super) fn state_at<'a>(
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
    pub(super) async fn advance(
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
    pub(super) async fn chain_memo(
        chain: StoredChain,
        member: &str,
    ) -> Result<ChainMemo, EngineError> {
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
    pub(super) async fn principal_named(
        &self,
        member: &str,
    ) -> Result<Option<String>, EngineError> {
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
    pub(super) async fn embedded_chain(
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

    pub(super) async fn manifest_entry(
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
    pub(super) async fn ancestry(
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
                let retained_of = |pr: &str| self.branches.principal_of_pr(pr);
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
                let retained = self.branches.retained(&id);
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

    /// How many leading commits of `chain`, a peer's chain oldest first,
    /// this engine holds (canonical or retained): a PoP is offered with the
    /// line that starts after them ([`Self::submit_resync`]). A commit
    /// whose id cannot be read ends the prefix. Zero for a principal that
    /// is not stored.
    pub async fn held_prefix(
        &self,
        principal_id: &str,
        chain: &[WireBundle],
    ) -> Result<usize, EngineError> {
        let Some(tip) = self.get_tip(principal_id).await? else {
            return Ok(0);
        };
        let Ok(alg) = tip.commit_id.parse::<TaggedDigest>().map(|d| d.alg()) else {
            return Ok(0);
        };
        for (i, bundle) in chain.iter().enumerate() {
            let Some(id) = bundle.decode().ok().and_then(|d| d.commit_id(alg)) else {
                return Ok(i);
            };
            if !self.holds_commit(principal_id, &id.to_string()).await? {
                return Ok(i);
            }
        }
        Ok(chain.len())
    }

    pub(super) async fn read_blobs(
        &self,
        hashes: &[Blake3Hash],
    ) -> Result<Vec<Vec<u8>>, EngineError> {
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
    pub(super) async fn genesis_of_stored(
        &self,
        stored_id: &str,
    ) -> Result<crate::Genesis, EngineError> {
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
    pub(super) async fn stored_id(
        &self,
        principal_id: &str,
    ) -> Result<Option<String>, EngineError> {
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
    pub(super) async fn resolve_key(
        &self,
        principal_id: &str,
    ) -> Result<Option<String>, EngineError> {
        self.stored_id(principal_id).await
    }

    /// The genesis a principal's first commit bundle discloses
    /// ([`disclosed_genesis`]). Every chain begins with a genesis commit
    /// whose `key/create`s disclose its keys (SPEC 5.1), so a bundle that
    /// discloses none names no principal.
    pub(super) fn genesis_from_bundle(
        bundle: Option<&WireBundle>,
    ) -> Result<crate::Genesis, EngineError> {
        let Some(bundle) = bundle.filter(|b| !b.is_empty()) else {
            return Err(EngineError::NotFound(
                "no blobs to resolve genesis from".into(),
            ));
        };
        disclosed_genesis(bundle).unwrap_or_else(|| Err(no_disclosed_genesis()))
    }
}
/// The four roots of `principal`'s state.
pub(super) fn roots_of<T: cyphr::eml::Storage>(
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
pub(super) fn bundle_czds(bundle: &WireBundle) -> Result<Vec<Vec<u8>>, EngineError> {
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
pub(super) fn action_bundle(blobs: Vec<Vec<u8>>) -> Result<cyphr::replay::Bundle, String> {
    if blobs.is_empty() {
        return Err("not an action-only bundle".into());
    }
    WireBundle::actions(blobs)
        .decode()
        .map_err(|e| e.to_string())
}

/// Order action-only bundles by their earliest `now`, then manifest hash
/// (SPEC 4.8.1: actions are ordered by `now`, then lexically).
pub(super) fn replay_order(bundles: &mut [ActionBundle]) {
    bundles.sort_by_cached_key(|b| {
        let first = b.bundle.cozies().map(|c| c.header().now).min();
        (first, *b.manifest.as_bytes())
    });
}

/// The [`CommitEntry`](crate::CommitEntry) replay reads from a stored
/// commit's bundle. State digest fields are inert during replay.
pub(super) fn replay_entry(
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
pub(super) async fn replay_first(
    genesis: &crate::Genesis,
    bundle: &WireBundle,
) -> Option<cyphr::Principal> {
    let mut principal = cyphr::Principal::implicit(genesis.key()?.clone())
        .await
        .ok()?;
    let entry = replay_entry(bundle, "", "").ok()?;
    crate::import::replay_commits(&mut principal, &[entry])
        .await
        .ok()?;
    Some(principal)
}
