use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eml;
use futures;

use crate::HashAlg;
use crate::multihash::MultihashDigest;
use crate::state::StateDigest;

/// The EML log type backing [`CloneableLog`], generic over its storage
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
    /// A missing own-algorithm variant returns `empty()` rather than
    /// borrowing another algorithm's bytes — falling back across algorithms
    /// would mix one algorithm's digest into another's tree, violating
    /// per-algorithm isolation.
    fn leaf(&self, data: &[u8]) -> Vec<u8> {
        let variants: BTreeMap<u64, Box<[u8]>> = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return self.empty(),
        };
        let alg_id = hash_alg_to_u64(self.alg);
        match variants.get(&alg_id) {
            Some(bytes) => bytes.to_vec(),
            None => self.empty(),
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

/// A cloneable wrapper around [`Log`] to preserve `Clone` bounds on `Principal`,
/// generic over the storage backend `S`.
///
/// The inner mutex is only ever contended by the synchronous `block_on` bridge
/// below, on a single logical caller; a poisoned lock therefore means a prior
/// call already panicked mid-mutation, an unrecoverable state, so lock
/// acquisition here panics too rather than plumbing a synthetic storage error.
///
/// # Manual `Debug`/`Clone`
///
/// Both traits are implemented by hand rather than derived: `#[derive(...)]`
/// would add an `S: Debug`/`S: Clone` bound even though neither is actually
/// needed (`Clone` shares the `Arc`; `Debug` never inspects the inner log) —
/// and `storage_fjall::FjallStorage` deliberately implements neither, so a
/// derived bound would make `CloneableLog<FjallStorage>` uninstantiable.
pub struct CloneableLog<S: eml::Storage>(pub Arc<Mutex<Log<S>>>);

impl<S: eml::Storage> Clone for CloneableLog<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S: eml::Storage> std::fmt::Debug for CloneableLog<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloneableLog").finish_non_exhaustive()
    }
}

impl<S: eml::Storage> CloneableLog<S> {
    /// Create a new cloneable log with no algorithms registered, backed by
    /// `storage`.
    pub fn new(storage: S) -> Self {
        let log = futures::executor::block_on(eml::from_storage(storage, Vec::new()))
            .expect("fresh empty log construction cannot fail");
        Self(Arc::new(Mutex::new(log)))
    }

    /// Open a log over `storage`, reconstructing from whatever algorithm
    /// metadata (and leaves) are already durably present, or creating a
    /// fresh empty log if `storage` genuinely has none.
    ///
    /// Unlike [`Self::new`], safe to call against storage that may already
    /// carry state from a prior session at the same physical location —
    /// `new` always passes an empty hasher list to `eml::from_storage`,
    /// which only succeeds when the storage has zero registered algorithms;
    /// against real prior state it returns `OrphanedMetadata` (surfaced by
    /// `new` as a panic). `open` first reads which algorithm IDs are
    /// already registered and reconstructs the matching [`MaltHasher`] for
    /// each — the only hasher this crate's commit trees ever use — so
    /// reconstruction succeeds whether `storage` is fresh or already
    /// populated.
    pub fn open(storage: S) -> LogResult<Self, S> {
        let metas = futures::executor::block_on(storage.load_algorithm_metas())
            .map_err(LogError::<S>::Storage)?;
        let mut hashers: Vec<(u64, Box<dyn eml::Hasher>)> = Vec::with_capacity(metas.len());
        for (alg_id, _) in metas {
            let alg =
                u64_to_hash_alg(alg_id).map_err(|_| LogError::<S>::UnknownAlgorithm(alg_id))?;
            hashers.push((alg_id, Box::new(MaltHasher::new(alg))));
        }
        let log = futures::executor::block_on(eml::from_storage(storage, hashers))?;
        Ok(Self(Arc::new(Mutex::new(log))))
    }

    /// Check if the algorithm is registered.
    pub fn has_algorithm(&self, alg_id: u64) -> bool {
        self.0
            .lock()
            .expect("commit tree mutex poisoned")
            .frontier_for(alg_id)
            .is_some()
    }

    /// Add a new hasher algorithm.
    pub fn add_algorithm(&self, alg_id: u64, hasher: Box<dyn eml::Hasher>) -> LogResult<(), S> {
        let mut log = self.0.lock().expect("commit tree mutex poisoned");
        futures::executor::block_on(log.add_algorithm(alg_id, hasher))
    }

    /// Append a leaf payload.
    pub fn append(&self, data: &[u8]) -> LogResult<(), S> {
        let mut log = self.0.lock().expect("commit tree mutex poisoned");
        futures::executor::block_on(log.append_leaf(data))
    }

    /// Get root hash for the algorithm.
    pub fn root(&self, alg_id: u64) -> LogResult<Vec<u8>, S> {
        self.0
            .lock()
            .expect("commit tree mutex poisoned")
            .root_for(alg_id)
    }

    /// Get the algorithm's root hash as of a historical tree size — the
    /// root the tree had immediately after its `size`-th leaf was
    /// appended, not the tree's live/current root.
    ///
    /// Used by [`crate::principal::PrincipalCore::finalize_commit`] to
    /// make replay idempotent: a leaf durably present from a prior
    /// session must report the root as of its own position, not the
    /// live root of a tree that may already carry leaves beyond it.
    pub fn root_at(&self, alg_id: u64, size: u64) -> LogResult<Vec<u8>, S> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        futures::executor::block_on(log.root_for_at(alg_id, size))
    }

    /// Generate an inclusion proof for the leaf at `index`, against the
    /// log's current tree size.
    pub fn inclusion_proof(&self, alg_id: u64, index: u64) -> LogResult<eml::InclusionProof, S> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        let tree_size = log.size();
        futures::executor::block_on(log.inclusion_proof_for(alg_id, index, tree_size))?
            .ok_or(LogError::<S>::IndexOutOfBounds { index, tree_size })
    }

    /// Generate a consistency proof from `old_size` to the log's current
    /// tree size.
    pub fn consistency_proof(
        &self,
        alg_id: u64,
        old_size: u64,
    ) -> LogResult<eml::ConsistencyProof, S> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        let new_size = log.size();
        futures::executor::block_on(log.consistency_proof_for(alg_id, old_size, new_size))?.ok_or(
            LogError::<S>::IndexOutOfBounds {
                index: old_size,
                tree_size: new_size,
            },
        )
    }

    /// Get the tree size for the algorithm.
    ///
    /// Node addressing is by global append position (not a per-algorithm
    /// local offset), so an active algorithm's tree size is always the log's
    /// current global size.
    pub fn tree_size(&self, alg_id: u64) -> LogResult<u64, S> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        if log.frontier_for(alg_id).is_none() {
            return Err(LogError::<S>::UnknownAlgorithm(alg_id));
        }
        Ok(log.size())
    }

    /// Check if the log has no algorithms registered.
    pub fn is_empty(&self) -> bool {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        log.committed_epochs_at(log.count()).is_empty()
    }

    /// The log's total append count (leaves for a flat log), independent of
    /// any specific algorithm's registration.
    ///
    /// Used by [`crate::principal::PrincipalCore::finalize_commit`] to make
    /// a durable-backed log's append idempotent under replay: leaf
    /// addressing is global (shared by every registered algorithm — see
    /// [`Self::tree_size`]'s docs), so this count is exactly "how many
    /// commits this log has ever had appended to it", including leaves that
    /// arrived in a prior session against the same physical storage.
    pub fn global_size(&self) -> u64 {
        self.0.lock().expect("commit tree mutex poisoned").size()
    }
}

/// Type alias representing the EML commit trees, generic over the storage
/// backend `S`. Defaults to [`eml::MemoryStorage`] so every existing call
/// site that spells the bare `CommitTrees` continues to mean exactly what it
/// meant before this type became generic.
pub type CommitTrees<S = eml::MemoryStorage> = CloneableLog<S>;

/// Maps HashAlg to algorithm ID for EML.
pub fn hash_alg_to_u64(alg: HashAlg) -> u64 {
    match alg {
        HashAlg::Sha256 => 1,
        HashAlg::Sha384 => 2,
        HashAlg::Sha512 => 3,
    }
}

/// Maps algorithm ID to HashAlg.
pub fn u64_to_hash_alg(id: u64) -> crate::error::Result<HashAlg> {
    match id {
        1 => Ok(HashAlg::Sha256),
        2 => Ok(HashAlg::Sha384),
        3 => Ok(HashAlg::Sha512),
        _ => Err(crate::error::Error::UnsupportedAlgorithm(id.to_string())),
    }
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
            .map_err(|e| crate::error::Error::UnsupportedAlgorithm(e.to_string()))?;
        variants.insert(alg, root.into_boxed_slice());
    }
    let md = MultihashDigest::new(variants)?;
    Ok(CommitRoot(md))
}

/// Assemble a `CommitRoot` `MultihashDigest` from the EML Log as of a
/// historical size — the idempotent-replay counterpart to
/// [`commit_root_from_trees`], which always reads the tree's live/current
/// root. Used when finalizing a commit whose leaf a prior durable session
/// already appended, so the CR reflects the tree as it stood right after
/// that leaf rather than any leaves appended since.
pub fn commit_root_from_trees_at<S: eml::Storage>(
    log: &CommitTrees<S>,
    algs: &[HashAlg],
    size: u64,
) -> crate::error::Result<CommitRoot> {
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let alg_id = hash_alg_to_u64(alg);
        let root = log
            .root_at(alg_id, size)
            .map_err(|e| crate::error::Error::UnsupportedAlgorithm(e.to_string()))?;
        variants.insert(alg, root.into_boxed_slice());
    }
    let md = MultihashDigest::new(variants)?;
    Ok(CommitRoot(md))
}

/// Compute the CR incrementally over a list of TRs.
pub fn compute_cr(trs: &[&MultihashDigest], algs: &[HashAlg]) -> crate::error::Result<CommitRoot> {
    let log = CommitTrees::new(eml::MemoryStorage::new());
    for &alg in algs {
        let alg_id = hash_alg_to_u64(alg);
        let hasher = Box::new(MaltHasher::new(alg));
        log.add_algorithm(alg_id, hasher)
            .map_err(|e| crate::error::Error::UnsupportedAlgorithm(e.to_string()))?;
    }

    for tr in trs {
        let mut map = BTreeMap::new();
        for (&alg, digest) in tr.variants() {
            map.insert(hash_alg_to_u64(alg), digest.clone());
        }
        let serialized =
            serde_json::to_vec(&map).map_err(|_| crate::error::Error::MalformedPayload)?;
        log.append(&serialized)
            .map_err(|e| crate::error::Error::UnsupportedAlgorithm(e.to_string()))?;
    }

    commit_root_from_trees(&log, algs)
}
