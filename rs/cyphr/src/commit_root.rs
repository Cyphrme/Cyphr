use std::collections::BTreeMap;

use eml;

use crate::HashAlg;
use crate::multihash::MultihashDigest;
use crate::state::StateDigest;

/// The EML log type backing [`CommitTrees`], generic over its storage
/// backend `S`.
type Log<S> = eml::NaryMerkleLog<S>;

/// The storage-parameterised EML error, generic over the backing storage's
/// own error type.
type LogError<S> = eml::Error<<S as eml::Storage>::Error>;

/// The storage-parameterised EML result, generic over the backing storage's
/// own error type.
type LogResult<T, S> = eml::Result<T, <S as eml::Storage>::Error>;

/// A single-algorithm hasher for the Cyphr EML implementation.
#[derive(Clone, Debug)]
pub struct MaltHasher {
    alg: HashAlg,
}

impl MaltHasher {
    /// Create a new single-algorithm EML hasher.
    pub fn new(alg: HashAlg) -> Self {
        Self { alg }
    }
}

impl eml::Hasher for MaltHasher {
    /// Extract this hasher's own algorithm variant and return it **raw,
    /// unhashed** — no domain-separation prefix. A cell payload is already a
    /// serialized `BTreeMap<alg_id, digest>` of pre-computed per-algorithm
    /// digests (SR/CR variants, or a commit's TR variants); re-hashing would
    /// be redundant and would break genesis singleton promotion (PR would
    /// become `H(SR)` instead of `SR`).
    ///
    /// A missing own-algorithm variant means this algorithm was inactive at
    /// the leaf's position, and maps to EML's null constant (`H("null")`),
    /// never `empty()` (the empty-tree root) and never another algorithm's
    /// bytes (per-algorithm isolation). Leaves are produced only by
    /// [`commit_leaf`], which refuses a missing active-algorithm variant with
    /// a typed error; the infallible `eml::Hasher` seam cannot carry one.
    fn leaf(&self, data: &[u8]) -> Vec<u8> {
        let variants: BTreeMap<u64, Box<[u8]>> = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return self.null(),
        };
        let alg_id = hash_alg_to_u64(self.alg);
        match variants.get(&alg_id) {
            Some(bytes) => bytes.to_vec(),
            None => self.null(),
        }
    }

    fn node(&self, children: &[&[u8]]) -> Vec<u8> {
        let mut d = Vec::with_capacity(children.iter().map(|c| c.len()).sum::<usize>());
        for child in children {
            d.extend_from_slice(child);
        }
        crate::state::hash_bytes(self.alg, &d).to_vec()
    }

    fn empty(&self) -> Vec<u8> {
        crate::state::hash_bytes(self.alg, b"").to_vec()
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        crate::state::hash_bytes(self.alg, data).to_vec()
    }

    fn clone_box(&self) -> Box<dyn eml::Hasher> {
        Box::new(self.clone())
    }
}

/// Serialize a commit's TR as the commit-log leaf, requiring a variant for
/// every active algorithm. EML hashes each leaf under every active
/// algorithm, and a missing variant would hash to a constant (`H("null")`),
/// which collapses in the Merkle fold and freezes that algorithm's root.
///
/// # Errors
///
/// [`crate::error::Error::MissingVariant`] if `tr` lacks an active algorithm.
pub(crate) fn commit_leaf(
    tr: &MultihashDigest,
    active_algs: &[HashAlg],
) -> crate::error::Result<Vec<u8>> {
    for &alg in active_algs {
        tr.get_or_err(alg)?;
    }
    let mapped: BTreeMap<u64, Box<[u8]>> = tr
        .variants()
        .iter()
        .map(|(&alg, digest)| (hash_alg_to_u64(alg), digest.clone()))
        .collect();
    serde_json::to_vec(&mapped).map_err(|_| crate::error::Error::MalformedPayload)
}

/// Verify an inclusion proof for the leaf at `index` in a tree of size
/// `tree_size`.
///
/// `index` and `tree_size` are trusted parameters (see [`eml::verify_inclusion`]'s
/// trust contract): they must come from an authenticated source, never the proof.
#[must_use]
pub fn verify_inclusion(
    hasher: &dyn eml::Hasher,
    leaf_hash: &[u8],
    index: u64,
    tree_size: u64,
    proof: &eml::InclusionProof,
    root: &[u8],
) -> bool {
    let Some(skeleton) = eml::mountain_skeleton(eml::LOG_ARITY, tree_size, index) else {
        return false;
    };
    eml::verify_inclusion(hasher, leaf_hash, &skeleton, &proof.path, root)
}

/// Verify a consistency proof between `old_size` and `new_size`.
///
/// `old_size`, `new_size`, `old_root`, and `new_root` are trusted parameters
/// (see [`eml::verify_consistency`]'s trust contract): they must come from an
/// authenticated source, never the proof.
#[must_use]
pub fn verify_consistency(
    hasher: &dyn eml::Hasher,
    old_size: u64,
    new_size: u64,
    proof: &eml::ConsistencyProof,
    old_root: &[u8],
    new_root: &[u8],
) -> bool {
    eml::verify_consistency(
        hasher,
        old_size,
        new_size,
        eml::LOG_ARITY,
        &proof.boundary_hash,
        &proof.peak_path,
        &proof.new_peaks,
        proof.split_index,
        old_root,
        new_root,
    )
}

/// The Commit Root represents the finalized state of the verifiable log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRoot(pub MultihashDigest);

impl CommitRoot {
    /// Retrieves a reference to the computed multihash digest.
    pub fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

impl StateDigest for CommitRoot {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// A principal's commit log: the EML over storage backend `S`, owned by
/// exactly one [`crate::Principal`].
///
/// There is one writer of a principal's log and no alias to it: the
/// principal holds it by value and hands out only `&CommitTrees`, so every
/// mutation goes through the principal's own two-phase commit
/// ([`crate::commit::CommitScope::stage`] then
/// [`crate::commit::StagedCommit::commit`]). The free-standing mutators
/// ([`Self::add_algorithm`], [`Self::append`]) serve logs built outside a
/// principal, such as a verifier assembling proof material.
///
/// # Async boundary
///
/// Every call that reads nodes or leaves, or writes, is `async`: storage is
/// [`eml::Storage`], whose futures are `Send` (`Storage: Send + Sync`), so
/// these futures are `Send` whenever `S` is. Calls that read only the
/// in-memory frontier (roots at the tip, sizes) stay synchronous.
///
/// # Manual `Debug`
///
/// Implemented by hand: `#[derive(Debug)]` would add an `S: Debug` bound,
/// and `storage_fjall::FjallStorage` implements no `Debug`.
pub struct CommitTrees<S: eml::Storage = eml::MemoryStorage> {
    log: Log<S>,
}

impl<S: eml::Storage> std::fmt::Debug for CommitTrees<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitTrees")
            .field("size", &self.log.size())
            .finish_non_exhaustive()
    }
}

/// A storage backend that can be copied into an independent store: writes
/// to the copy never reach the original. Only such a backend lets a
/// principal be forked ([`crate::Principal::fork`]); a durable backend whose
/// handles share one physical store (e.g. `storage_fjall::FjallStorage`)
/// must not implement it, since a "copy" would be a second writer of the
/// same log.
pub trait ForkStorage: eml::Storage + Sized {
    /// An independent copy of this store's contents.
    ///
    /// # Errors
    ///
    /// The backend's own error when the copy cannot be made.
    fn fork(&self) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send;
}

impl ForkStorage for eml::MemoryStorage {
    async fn fork(&self) -> Result<Self, Self::Error> {
        Ok(self.clone())
    }
}

impl<S: eml::Storage> CommitTrees<S> {
    /// Open a log over `storage`, reconstructing from whatever algorithm
    /// metadata (and leaves) are already durably present, or starting an
    /// empty log if `storage` has none.
    ///
    /// Reads which algorithm IDs are registered and reconstructs the
    /// matching [`MaltHasher`] for each, the only hasher this crate's commit
    /// log uses, so reconstruction succeeds whether `storage` is fresh or
    /// already populated.
    ///
    /// # Errors
    ///
    /// A storage error, or `UnknownAlgorithm` for a registered ID this
    /// crate does not map.
    pub async fn open(storage: S) -> LogResult<Self, S> {
        let metas = storage
            .load_algorithm_metas()
            .await
            .map_err(LogError::<S>::Storage)?;
        let mut hashers: Vec<(u64, Box<dyn eml::Hasher>)> = Vec::with_capacity(metas.len());
        for (alg_id, _) in metas {
            let alg =
                u64_to_hash_alg(alg_id).map_err(|_| LogError::<S>::UnknownAlgorithm(alg_id))?;
            hashers.push((alg_id, Box::new(MaltHasher::new(alg))));
        }
        let log = eml::from_storage(storage, hashers).await?;
        Ok(Self { log })
    }

    /// This log as an in-memory log at the same size and with the same
    /// roots, seeded from the frontier alone: O(log n) nodes are read and
    /// no leaf is copied, whatever the backend. The result can append, so
    /// a commit staged on it never reaches this log's store.
    ///
    /// # Errors
    ///
    /// The backend's own error if a frontier node cannot be read, or the
    /// seed cannot be reopened.
    pub(crate) async fn detach(self) -> crate::error::Result<CommitTrees<eml::MemoryStorage>> {
        let storage = |e: String| crate::error::Error::Storage(e);
        let sealed = self.log.seal().await.map_err(|e| storage(e.to_string()))?;
        let mut hashers: Vec<(u64, Box<dyn eml::Hasher>)> = Vec::new();
        // Every registered algorithm, one that left included: the seal
        // carries a closed algorithm's frontier at its close, and resume
        // restores it so its return is the same algorithm.
        let registered = sealed
            .frontiers()
            .iter()
            .map(|(id, _)| id)
            .chain(sealed.dormant_frontiers().iter().map(|(id, _)| id));
        for alg_id in registered {
            let alg = u64_to_hash_alg(*alg_id)?;
            hashers.push((*alg_id, Box::new(MaltHasher::new(alg))));
        }
        let log = Log::resume(&sealed, eml::MemoryStorage::new(), hashers)
            .await
            .map_err(|e| storage(e.to_string()))?;
        Ok(CommitTrees { log })
    }

    /// An independent copy of this log over a forked store.
    pub(crate) async fn fork(&self) -> LogResult<Self, S>
    where
        S: ForkStorage,
    {
        let storage = self
            .log
            .storage()
            .fork()
            .await
            .map_err(LogError::<S>::Storage)?;
        Self::open(storage).await
    }

    /// Check if the algorithm is registered.
    pub fn has_algorithm(&self, alg_id: u64) -> bool {
        self.log.frontier_for(alg_id).is_some()
    }

    /// Register a new hasher algorithm, active from the current size.
    ///
    /// # Errors
    ///
    /// A duplicate registration or a storage error.
    pub async fn add_algorithm(
        &mut self,
        alg_id: u64,
        hasher: Box<dyn eml::Hasher>,
    ) -> LogResult<(), S> {
        self.log.add_algorithm(alg_id, hasher).await
    }

    /// Append a leaf payload.
    ///
    /// # Errors
    ///
    /// No active algorithm, or a storage error.
    pub async fn append(&mut self, data: &[u8]) -> LogResult<(), S> {
        self.log.append_leaf(data).await
    }

    /// Make the log's active algorithms exactly those of `wanted` that it
    /// already registers: close the open epoch of a registered algorithm
    /// absent from `wanted`, and reopen (not re-register) a closed one in
    /// it. Algorithms in `wanted` the log does not register are left to
    /// [`polydigest::Staged::add_algorithm`].
    ///
    /// `wanted` is the post-mutation key families of the commit being
    /// appended, so an algorithm the commit's own mutation retires closes
    /// before that commit's leaf, though the leaf (a TR carrying the
    /// signer's variant) still has a variant for it. Its epoch ends at the
    /// leaf's index, and the `CR` before that leaf is the last to carry it.
    ///
    /// The log needs this because a leaf with no variant for an algorithm
    /// hashes to its null constant: an algorithm left active across such
    /// leaves has null Merkle nodes the log never stores and then requires
    /// when reopened. Each change is one durable write, landing before the
    /// leaf it precedes; a crash between the two leaves an epoch boundary
    /// at the size the interrupted commit would have had, which the same
    /// call, made again for that commit, finds already in place.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub(crate) async fn set_active_algorithms(&mut self, wanted: &[u64]) -> LogResult<(), S> {
        for (alg_id, epochs) in self.log.committed_epochs_at(self.log.count()) {
            let active = epochs.last().is_some_and(|&(_, end)| end == u64::MAX);
            match (active, wanted.contains(&alg_id)) {
                (true, false) => self.log.remove_algorithm(alg_id).await?,
                (false, true) => self.log.resume_algorithm(alg_id).await?,
                _ => {},
            }
        }
        Ok(())
    }

    /// Snapshot the log into a [`polydigest::Staged`] that algorithm
    /// activations and an append are applied to in memory, written later by
    /// [`Self::commit`] in one atomic `Storage::apply`.
    pub(crate) fn stage(&self) -> polydigest::Staged<S> {
        self.log.stage()
    }

    /// Stage the append of the commit leaf `data`. A log reopened from a
    /// frontier ([`Self::detach`]) holds no leaves, only the digests the
    /// frontier names, so the leaf goes in as a one-leaf subtree, whose
    /// digest is the digest a flat append of it gives. (An empty log reads
    /// as subtree-kind but binds to whichever append comes first.)
    pub(crate) fn stage_leaf(
        &self,
        staged: &mut polydigest::Staged<S>,
        data: &[u8],
    ) -> LogResult<(), S> {
        if self.log.kind() == eml::LogKind::Subtree && self.log.count() > 0 {
            staged.append_subtree(&eml::Subtree::Leaf(data.to_vec()))
        } else {
            staged.append_leaf(data)
        }
    }

    /// Write `staged` in one atomic `Storage::apply` and adopt it. `staged`
    /// must come from [`Self::stage`] on this log with no mutation between;
    /// holding the principal by `&mut` across both makes that the only
    /// possible order.
    pub(crate) async fn commit(&mut self, staged: polydigest::Staged<S>) -> LogResult<(), S> {
        self.log.commit(staged).await
    }

    /// Read the raw leaf payload durably stored at `index`.
    ///
    /// Used on replay to check that a leaf already occupying a commit's
    /// position is that commit's own TR.
    ///
    /// # Errors
    ///
    /// A storage error, including an index past the stored leaves.
    pub async fn get_leaf(&self, index: u64) -> LogResult<Vec<u8>, S> {
        self.log
            .storage()
            .get_leaf(index)
            .await
            .map_err(LogError::<S>::Storage)
    }

    /// Get root hash for the algorithm.
    ///
    /// # Errors
    ///
    /// `UnknownAlgorithm` if `alg_id` is not registered.
    pub fn root(&self, alg_id: u64) -> LogResult<Vec<u8>, S> {
        self.log.root_for(alg_id)
    }

    /// Get the algorithm's root hash as of a historical tree size: the
    /// root the tree had immediately after its `size`-th leaf was
    /// appended, not the tree's current root.
    ///
    /// # Errors
    ///
    /// `UnknownAlgorithm`, an out-of-range size, or a storage error.
    pub async fn root_at(&self, alg_id: u64, size: u64) -> LogResult<Vec<u8>, S> {
        self.log.root_for_at(alg_id, size).await
    }

    /// Generate an inclusion proof for the leaf at `index`, against the
    /// log's current tree size.
    ///
    /// # Errors
    ///
    /// `UnknownAlgorithm`, `IndexOutOfBounds`, or a storage error.
    pub async fn inclusion_proof(
        &self,
        alg_id: u64,
        index: u64,
    ) -> LogResult<eml::InclusionProof, S> {
        let tree_size = self.log.size();
        self.log
            .inclusion_proof_for(alg_id, index, tree_size)
            .await?
            .ok_or(LogError::<S>::IndexOutOfBounds { index, tree_size })
    }

    /// Generate a consistency proof from `old_size` to the log's current
    /// tree size.
    ///
    /// # Errors
    ///
    /// `UnknownAlgorithm`, `IndexOutOfBounds`, or a storage error.
    pub async fn consistency_proof(
        &self,
        alg_id: u64,
        old_size: u64,
    ) -> LogResult<eml::ConsistencyProof, S> {
        let new_size = self.log.size();
        self.log
            .consistency_proof_for(alg_id, old_size, new_size)
            .await?
            .ok_or(LogError::<S>::IndexOutOfBounds {
                index: old_size,
                tree_size: new_size,
            })
    }

    /// Get the tree size for the algorithm.
    ///
    /// Node addressing is by global append position (not a per-algorithm
    /// local offset), so an active algorithm's tree size is always the log's
    /// current global size.
    ///
    /// # Errors
    ///
    /// `UnknownAlgorithm` if `alg_id` is not registered.
    pub fn tree_size(&self, alg_id: u64) -> LogResult<u64, S> {
        if !self.has_algorithm(alg_id) {
            return Err(LogError::<S>::UnknownAlgorithm(alg_id));
        }
        Ok(self.log.size())
    }

    /// Check if the log has no leaves appended yet, whatever algorithms are
    /// registered.
    pub fn is_empty(&self) -> bool {
        self.log.size() == 0
    }

    /// The log's total append count (leaves for a flat log), independent of
    /// any specific algorithm's registration: how many commits this log
    /// holds, including leaves written in a prior session to the same
    /// storage.
    pub fn global_size(&self) -> u64 {
        self.log.size()
    }
}

/// Maps HashAlg to algorithm ID for EML. A persisted value: never
/// renumber a row.
pub fn hash_alg_to_u64(alg: HashAlg) -> u64 {
    match alg {
        HashAlg::Sha256 => 1,
        HashAlg::Sha384 => 2,
        HashAlg::Sha512 => 3,
    }
}

/// Maps algorithm ID to HashAlg: the supported algorithm whose
/// [`hash_alg_to_u64`] is `id`.
pub fn u64_to_hash_alg(id: u64) -> crate::error::Result<HashAlg> {
    crate::state::HASH_ALGS
        .into_iter()
        .find(|&alg| hash_alg_to_u64(alg) == id)
        .ok_or_else(|| crate::error::Error::UnsupportedAlgorithm(id.to_string()))
}

/// Assemble a `CommitRoot` `MultihashDigest` from the EML Log.
pub fn commit_root_from_trees<S: eml::Storage>(
    log: &CommitTrees<S>,
    algs: &[HashAlg],
) -> crate::error::Result<CommitRoot> {
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let alg_id = hash_alg_to_u64(alg);
        let root = log
            .root(alg_id)
            .map_err(|e| crate::error::Error::Storage(e.to_string()))?;
        variants.insert(alg, root.into_boxed_slice());
    }
    let md = MultihashDigest::new(variants)?;
    Ok(CommitRoot(md))
}

/// Assemble a `CommitRoot` `MultihashDigest` from the EML Log as of a
/// historical size: the replay counterpart to [`commit_root_from_trees`],
/// which reads the live root. Used when finalizing a commit whose leaf a
/// prior durable session already appended, so the CR reflects the tree as
/// it stood right after that leaf rather than any leaves appended since.
///
/// # Errors
///
/// A storage error, or an algorithm the log does not hold.
pub async fn commit_root_from_trees_at<S: eml::Storage>(
    log: &CommitTrees<S>,
    algs: &[HashAlg],
    size: u64,
) -> crate::error::Result<CommitRoot> {
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let alg_id = hash_alg_to_u64(alg);
        let root = log
            .root_at(alg_id, size)
            .await
            .map_err(|e| crate::error::Error::Storage(e.to_string()))?;
        variants.insert(alg, root.into_boxed_slice());
    }
    let md = MultihashDigest::new(variants)?;
    Ok(CommitRoot(md))
}

/// Assemble a `CommitRoot` from a staged append: the CR the log will report
/// once `staged` is committed, read before anything is written.
pub(crate) fn commit_root_from_staged<S: eml::Storage>(
    staged: &polydigest::Staged<S>,
    algs: &[HashAlg],
) -> crate::error::Result<CommitRoot> {
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let root = staged
            .root_for(hash_alg_to_u64(alg))
            .map_err(|e| crate::error::Error::Storage(e.to_string()))?;
        variants.insert(alg, root.into_boxed_slice());
    }
    Ok(CommitRoot(MultihashDigest::new(variants)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backs the typed-error path of the commit-log leaf: a TR lacking an
    /// active algorithm's variant is refused with `MissingVariant`, never
    /// hashed to a constant. Unit test: `stage_commit` always computes TR
    /// over every active algorithm, so no scenario can reach the refusal.
    /// Turns red if `commit_leaf` serializes a partial TR.
    #[test]
    fn commit_leaf_refuses_a_missing_active_variant() {
        let tr = MultihashDigest::from_single(HashAlg::Sha256, vec![7; 32]).unwrap();
        assert!(commit_leaf(&tr, &[HashAlg::Sha256]).is_ok(), "control");
        assert!(matches!(
            commit_leaf(&tr, &[HashAlg::Sha256, HashAlg::Sha384]),
            Err(crate::error::Error::MissingVariant(HashAlg::Sha384))
        ));
    }

    /// F4 -- `CommitTrees::is_empty()` must report empty for an
    /// algorithm-registered zero-leaf log, not only for a log with no
    /// algorithms registered at all. Unit test: every principal registers
    /// and appends in one staged write, so no scenario observes a log with
    /// an algorithm and no leaf.
    #[tokio::test]
    async fn is_empty_true_for_registered_algorithm_zero_leaves() {
        let mut log = CommitTrees::open(eml::MemoryStorage::new()).await.unwrap();
        assert!(
            log.is_empty(),
            "a freshly constructed log with no algorithms must be empty"
        );

        log.add_algorithm(
            hash_alg_to_u64(HashAlg::Sha256),
            Box::new(MaltHasher::new(HashAlg::Sha256)),
        )
        .await
        .expect("add_algorithm failed");

        assert!(
            log.is_empty(),
            "a log with a registered algorithm but zero leaves must still report empty"
        );
    }
    /// A leaf carrying a variant for each of `ids`.
    fn leaf_of(ids: &[u64], n: u8) -> Vec<u8> {
        let v: BTreeMap<u64, Vec<u8>> = ids
            .iter()
            .map(|&i| (i, vec![n; if i == 1 { 32 } else { 64 }]))
            .collect();
        serde_json::to_vec(&v).expect("leaf")
    }

    /// Append `leaf` the way a commit does: set the active algorithms, stage
    /// the leaf, commit it.
    async fn commit_leaf_to<S: eml::Storage>(log: &mut CommitTrees<S>, ids: &[u64], n: u8) {
        log.set_active_algorithms(ids).await.expect("set active");
        for &id in ids {
            if !log.has_algorithm(id) {
                let alg = u64_to_hash_alg(id).expect("alg");
                log.add_algorithm(id, Box::new(MaltHasher::new(alg)))
                    .await
                    .expect("add");
            }
        }
        let mut staged = log.stage();
        log.stage_leaf(&mut staged, &leaf_of(ids, n))
            .expect("stage");
        log.commit(staged).await.expect("commit");
    }

    /// SHA-512 (3) from the start, SHA-256 (1) from leaf 1 to leaf 2: a log
    /// holding an algorithm that left.
    async fn log_with_a_closed_algorithm() -> CommitTrees<eml::MemoryStorage> {
        let mut log = CommitTrees::open(eml::MemoryStorage::new())
            .await
            .expect("open");
        commit_leaf_to(&mut log, &[3], 0).await;
        commit_leaf_to(&mut log, &[1, 3], 1).await;
        commit_leaf_to(&mut log, &[3], 2).await;
        log
    }

    /// Claim: a log detached to its frontier, and the same log reopened from
    /// the detached copy's own storage, each still knows an algorithm that
    /// left, so its return is the same algorithm over the same history: the
    /// roots after the return equal those of the log that was never
    /// detached. Turns red if a detached log forgets the closed algorithm
    /// (its return registers it afresh over nulls) or a reopen cannot find
    /// a hasher it needs.
    #[tokio::test]
    async fn a_detached_log_keeps_and_reopens_an_algorithm_that_left() {
        let mut whole = log_with_a_closed_algorithm().await;
        commit_leaf_to(&mut whole, &[1, 3], 3).await;

        let mut detached = log_with_a_closed_algorithm()
            .await
            .detach()
            .await
            .expect("detach");
        assert!(detached.has_algorithm(1), "the detached log forgot SHA-256");
        let reopened_from = log_with_a_closed_algorithm()
            .await
            .detach()
            .await
            .expect("detach");
        let mut reopened = CommitTrees::open(reopened_from.log.into_storage())
            .await
            .expect("a detached log's storage reopens with every hasher it needs");
        assert!(reopened.has_algorithm(1), "the reopened log forgot SHA-256");

        commit_leaf_to(&mut detached, &[1, 3], 3).await;
        commit_leaf_to(&mut reopened, &[1, 3], 3).await;
        for id in [1, 3] {
            let want = whole.root(id).expect("root");
            assert_eq!(detached.root(id).expect("root"), want, "detached, alg {id}");
            assert_eq!(reopened.root(id).expect("root"), want, "reopened, alg {id}");
        }
    }
}
