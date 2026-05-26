use eml;
use futures;

use crate::HashAlg;
use crate::multihash::MultihashDigest;
use crate::state::StateDigest;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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
    fn leaf(&self, data: &[u8]) -> Vec<u8> {
        let variants: BTreeMap<u64, Box<[u8]>> = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return self.empty(),
        };
        let alg_id = hash_alg_to_u64(self.alg);
        let bytes = match variants.get(&alg_id).or_else(|| variants.values().next()) {
            Some(b) => b,
            None => return self.empty(),
        };
        
        let mut prefix_data = Vec::with_capacity(1 + bytes.len());
        prefix_data.push(0x00);
        prefix_data.extend_from_slice(bytes);
        crate::state::hash_bytes(self.alg, &prefix_data).to_vec()
    }

    fn node(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut d = Vec::with_capacity(1 + left.len() + right.len());
        d.push(0x01);
        d.extend_from_slice(left);
        d.extend_from_slice(right);
        crate::state::hash_bytes(self.alg, &d).to_vec()
    }

    fn empty(&self) -> Vec<u8> {
        crate::state::hash_bytes(self.alg, b"").to_vec()
    }

    fn null(&self) -> Vec<u8> {
        crate::state::hash_bytes(self.alg, &[0x02]).to_vec()
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        crate::state::hash_bytes(self.alg, data).to_vec()
    }
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

/// A cloneable wrapper around `eml::Log` to preserve `Clone` bounds on `Principal`.
#[derive(Debug)]
pub struct CloneableLog(pub Arc<Mutex<eml::Log<eml::MemoryStorage>>>);

impl Clone for CloneableLog {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl CloneableLog {
    /// Create a new cloneable log.
    pub fn new(storage: eml::MemoryStorage) -> Self {
        Self(Arc::new(Mutex::new(eml::Log::new(storage))))
    }

    /// Check if the algorithm is registered.
    pub fn has_algorithm(&self, alg_id: u64) -> bool {
        self.0.lock()
            .map(|guard| guard.algorithm_ids().any(|id| id == alg_id))
            .unwrap_or(false)
    }

    /// Add a new hasher algorithm.
    pub fn add_algorithm(&self, alg_id: u64, hasher: Box<dyn eml::Hasher>) -> eml::Result<()> {
        let mut log = self.0.lock().map_err(|e| {
            eml::Error::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mutex poisoned: {e}"),
            )))
        })?;
        futures::executor::block_on(log.add_algorithm(alg_id, hasher))
    }

    /// Append a leaf payload.
    pub fn append(&self, data: &[u8]) -> eml::Result<u64> {
        let mut log = self.0.lock().map_err(|e| {
            eml::Error::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mutex poisoned: {e}"),
            )))
        })?;
        futures::executor::block_on(log.append(data))
    }

    /// Get root hash for the algorithm.
    pub fn root(&self, alg_id: u64) -> eml::Result<Vec<u8>> {
        self.0.lock()
            .map_err(|e| {
                eml::Error::Storage(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("mutex poisoned: {e}"),
                )))
            })?
            .root(alg_id)
    }

    /// Generate an inclusion proof.
    pub fn inclusion_proof(&self, alg_id: u64, index: u64) -> eml::Result<eml::InclusionProof> {
        let log = self.0.lock().map_err(|e| {
            eml::Error::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mutex poisoned: {e}"),
            )))
        })?;
        futures::executor::block_on(log.inclusion_proof(alg_id, index))
    }

    /// Generate a consistency proof.
    pub fn consistency_proof(&self, alg_id: u64, old_size: u64) -> eml::Result<eml::ConsistencyProof> {
        let log = self.0.lock().map_err(|e| {
            eml::Error::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mutex poisoned: {e}"),
            )))
        })?;
        futures::executor::block_on(log.consistency_proof(alg_id, old_size))
    }

    /// Get the tree size for the algorithm.
    pub fn tree_size(&self, alg_id: u64) -> eml::Result<u64> {
        let log = self.0.lock().map_err(|e| {
            eml::Error::Storage(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mutex poisoned: {e}"),
            )))
        })?;
        futures::executor::block_on(log.tree_size(alg_id))
    }

    /// Check if the log has no algorithms registered.
    pub fn is_empty(&self) -> bool {
        self.0.lock()
            .map(|guard| guard.algorithm_ids().next().is_none())
            .unwrap_or(true)
    }
}

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
        let root = log.root(alg_id)
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
        let serialized = serde_json::to_vec(&map)
            .map_err(|_| crate::error::Error::MalformedPayload)?;
        log.append(&serialized)
            .map_err(|e| crate::error::Error::UnsupportedAlgorithm(e.to_string()))?;
    }

    commit_root_from_trees(&log, algs)
}
