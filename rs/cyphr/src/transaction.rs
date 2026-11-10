use crate::multihash::MultihashDigest;
use crate::parsed_coz::VerifiedCoz;
use crate::state::{HashAlg, TaggedCzd};

/// A sequence of one or more related mutation cozies.
/// In Cyphr, mutation cozies MUST be grouped by transaction.
#[derive(Debug, Clone)]
pub struct Transaction(pub Vec<VerifiedCoz>);

impl Transaction {
    /// Returns true if this transaction contains a commit finalizer cozy.
    pub fn is_commit(&self) -> bool {
        self.0.iter().any(|cz| cz.arrow().is_some())
    }

    /// The transaction's identifier `TX = MR(czd0, czd1?, ...)` over its
    /// cozies in signed order (SPEC 3.7.5), in each of `algs`; a single
    /// coz's czd is promoted unhashed. `None` for a transaction of no coz.
    #[must_use]
    pub fn id(&self, algs: &[HashAlg]) -> Option<MultihashDigest> {
        let czds: Vec<TaggedCzd<'_>> = self
            .0
            .iter()
            .map(|c| TaggedCzd::new(c.czd(), c.hash_alg()))
            .collect();
        crate::transaction_root::compute_tx(&czds, algs)
    }
}
