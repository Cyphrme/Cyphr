use crate::HashAlg;
use crate::multihash::MultihashDigest;
use malt::{Log, TreeHasher};
use std::collections::BTreeMap;

/// A single-algorithm hasher for the Cyphr MALT implementation.
///
/// Each MALT instance uses exactly one algorithm; multi-algorithm support is
/// achieved by maintaining one MALT per active algorithm at the `Principal`
/// level.
#[derive(Clone, Debug)]
pub struct CyphrHasher {
    alg: HashAlg,
}

impl CyphrHasher {
    /// Create a new single-algorithm MALT hasher.
    pub fn new(alg: HashAlg) -> Self {
        Self { alg }
    }
}

impl TreeHasher for CyphrHasher {
    type Digest = Vec<u8>;

    fn leaf(&self, data: &[u8]) -> Self::Digest {
        // H(0x00 || data)
        let mut prefix_data = Vec::with_capacity(1 + data.len());
        prefix_data.push(0x00);
        prefix_data.extend_from_slice(data);
        crate::state::hash_bytes(self.alg, &prefix_data).to_vec()
    }

    fn node(&self, left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        // H(0x01 || left || right)
        let mut d = Vec::with_capacity(1 + left.len() + right.len());
        d.push(0x01);
        d.extend_from_slice(left);
        d.extend_from_slice(right);
        crate::state::hash_bytes(self.alg, &d).to_vec()
    }

    fn empty(&self) -> Self::Digest {
        crate::state::hash_bytes(self.alg, b"").to_vec()
    }
}

/// The Commit Root represents the finalized state of the verifiable MALT log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRoot(pub MultihashDigest);

impl CommitRoot {
    /// Retrieves a reference to the computed multihash digest.
    pub fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// A single-algorithm MALT instance for CR computation.
pub type CommitLog = Log<CyphrHasher>;

/// Maps each active hash algorithm to its own MALT instance.
/// CR is assembled from the roots of all active MALTs.
pub type CommitTrees = BTreeMap<HashAlg, CommitLog>;

/// Assemble a `CommitRoot` `MultihashDigest` from the roots of per-algorithm MALTs.
pub fn commit_root_from_trees(trees: &CommitTrees) -> crate::error::Result<CommitRoot> {
    let mut variants = BTreeMap::new();
    for (&alg, log) in trees {
        variants.insert(alg, log.root().into_boxed_slice());
    }
    let md = MultihashDigest::new(variants)?;
    Ok(CommitRoot(md))
}

/// Compute the CR incrementally over a list of TRs.
pub fn compute_cr(trs: &[&MultihashDigest], algs: &[HashAlg]) -> crate::error::Result<CommitRoot> {
    let mut trees = CommitTrees::new();
    for &alg in algs {
        let mut log = Log::new(CyphrHasher::new(alg));
        for tr in trs {
            // [conversion]: if TR lacks this alg, get_or_err returns the
            // first available variant's bytes.
            let bytes = tr.get_or_err(alg)?;
            log.append(bytes);
        }
        trees.insert(alg, log);
    }

    commit_root_from_trees(&trees)
}
