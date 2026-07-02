use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eml;
use futures;

use crate::HashAlg;
use crate::multihash::MultihashDigest;
use crate::state::StateDigest;

/// The concrete EML log type backing [`CloneableLog`]: the core-split
/// combinator driver over an in-memory store.
type Log = eml::NaryMerkleLog<eml::MemoryStorage>;

/// The storage-parameterised EML error, concretized over [`eml::MemoryStorage`].
type LogError = eml::Error<eml::storage::MemoryStorageError>;

/// The storage-parameterised EML result, concretized over [`eml::MemoryStorage`].
type LogResult<T> = eml::Result<T, eml::storage::MemoryStorageError>;

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

/// A cloneable wrapper around [`Log`] to preserve `Clone` bounds on `Principal`.
///
/// The inner mutex is only ever contended by the synchronous `block_on` bridge
/// below, on a single logical caller; a poisoned lock therefore means a prior
/// call already panicked mid-mutation, an unrecoverable state, so lock
/// acquisition here panics too rather than plumbing a synthetic storage error.
#[derive(Debug)]
pub struct CloneableLog(pub Arc<Mutex<Log>>);

impl Clone for CloneableLog {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl CloneableLog {
    /// Create a new cloneable log with no algorithms registered.
    pub fn new(storage: eml::MemoryStorage) -> Self {
        let log = futures::executor::block_on(eml::from_storage(storage, Vec::new()))
            .expect("fresh empty log construction cannot fail");
        Self(Arc::new(Mutex::new(log)))
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
    pub fn add_algorithm(&self, alg_id: u64, hasher: Box<dyn eml::Hasher>) -> LogResult<()> {
        let mut log = self.0.lock().expect("commit tree mutex poisoned");
        futures::executor::block_on(log.add_algorithm(alg_id, hasher))
    }

    /// Append a leaf payload.
    pub fn append(&self, data: &[u8]) -> LogResult<()> {
        let mut log = self.0.lock().expect("commit tree mutex poisoned");
        futures::executor::block_on(log.append_leaf(data))
    }

    /// Get root hash for the algorithm.
    pub fn root(&self, alg_id: u64) -> LogResult<Vec<u8>> {
        self.0
            .lock()
            .expect("commit tree mutex poisoned")
            .root_for(alg_id)
    }

    /// Generate an inclusion proof for the leaf at `index`, against the
    /// log's current tree size.
    pub fn inclusion_proof(&self, alg_id: u64, index: u64) -> LogResult<eml::InclusionProof> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        let tree_size = log.size();
        futures::executor::block_on(log.inclusion_proof_for(alg_id, index, tree_size))?
            .ok_or(LogError::IndexOutOfBounds { index, tree_size })
    }

    /// Generate a consistency proof from `old_size` to the log's current
    /// tree size.
    pub fn consistency_proof(
        &self,
        alg_id: u64,
        old_size: u64,
    ) -> LogResult<eml::ConsistencyProof> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        let new_size = log.size();
        futures::executor::block_on(log.consistency_proof_for(alg_id, old_size, new_size))?.ok_or(
            LogError::IndexOutOfBounds {
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
    pub fn tree_size(&self, alg_id: u64) -> LogResult<u64> {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        if log.frontier_for(alg_id).is_none() {
            return Err(LogError::UnknownAlgorithm(alg_id));
        }
        Ok(log.size())
    }

    /// Check if the log has no algorithms registered.
    pub fn is_empty(&self) -> bool {
        let log = self.0.lock().expect("commit tree mutex poisoned");
        log.committed_epochs_at(log.count()).is_empty()
    }
}

/// Type alias representing the EML commit trees.
pub type CommitTrees = CloneableLog;

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
pub fn commit_root_from_trees(
    log: &CommitTrees,
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
