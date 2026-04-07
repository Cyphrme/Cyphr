use crate::multihash::MultihashDigest;
use crate::state::hash_concat_bytes;
use crate::state::{HashAlg, TaggedCzd};
use std::collections::BTreeMap;

/// The Transaction Mutation Root (TMR)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionMutationRoot(pub MultihashDigest);

impl Default for TransactionMutationRoot {
    fn default() -> Self {
        Self(MultihashDigest::default())
    }
}

/// The Transaction Commit Root (TCR)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionCommitRoot(pub MultihashDigest);

impl Default for TransactionCommitRoot {
    fn default() -> Self {
        Self(MultihashDigest::default())
    }
}

/// The Transaction Root (TR)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionRoot(pub MultihashDigest);

impl Default for TransactionRoot {
    fn default() -> Self {
        Self(MultihashDigest::default())
    }
}

impl TransactionRoot {
    /// Returns the raw sub-digest matching the algorithm if it exists.
    pub fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.0.get(alg)
    }
}

/// Compute a Transaction ID (TX) from its constituent cozies (SPEC §14.2).
pub fn compute_tx(czds: &[TaggedCzd<'_>], algs: &[HashAlg]) -> Option<MultihashDigest> {
    if czds.is_empty() {
        return None;
    }

    // Implicit promotion: single czd
    if czds.len() == 1 {
        let target_alg = algs.first().copied().unwrap_or(HashAlg::Sha256);
        let converted = czds[0].convert_to(target_alg);
        return Some(MultihashDigest::from_single(target_alg, converted));
    }

    let mut variants = BTreeMap::new();
    for &target_alg in algs {
        let converted: Vec<Vec<u8>> = czds.iter().map(|tc| tc.convert_to(target_alg)).collect();
        let refs: Vec<&[u8]> = converted.iter().map(|v| v.as_slice()).collect();
        let digest = hash_concat_bytes(target_alg, &refs);
        variants.insert(target_alg, digest.into_boxed_slice());
    }

    MultihashDigest::new(variants).ok()
}

/// Compute the Transaction Mutation Root from transaction identifiers.
pub fn compute_tmr(txs: &[&MultihashDigest], algs: &[HashAlg]) -> Option<TransactionMutationRoot> {
    if txs.is_empty() {
        return None;
    }

    // Implicit promotion for single transaction
    if txs.len() == 1 {
        return Some(TransactionMutationRoot(txs[0].clone()));
    }

    let mut variants = BTreeMap::new();
    for &alg in algs {
        let mut refs = Vec::with_capacity(txs.len());
        for &tx in txs {
            let digest = tx.get(alg)?;
            refs.push(digest);
        }
        let merged_digest = hash_concat_bytes(alg, &refs);
        variants.insert(alg, merged_digest.into_boxed_slice());
    }

    Some(TransactionMutationRoot(
        MultihashDigest::new(variants).ok()?,
    ))
}

/// Compute the Transaction Commit Root from the commit transaction's czds.
pub fn compute_tcr(czds: &[TaggedCzd<'_>], algs: &[HashAlg]) -> Option<TransactionCommitRoot> {
    let mh = compute_tx(czds, algs)?;
    Some(TransactionCommitRoot(mh))
}

/// Compute the Transaction Root from TMR and TCR.
pub fn compute_tr(
    tmr: Option<&TransactionMutationRoot>,
    tcr: &TransactionCommitRoot,
    algs: &[HashAlg],
) -> Option<TransactionRoot> {
    // If no mutation transactions, implicit promotion: TR = TCR
    let tmr = match tmr {
        Some(t) => t,
        None => return Some(TransactionRoot(tcr.0.clone())),
    };

    let mut variants = BTreeMap::new();
    for &alg in algs {
        let tmr_bytes = tmr.0.get(alg)?;
        let tcr_bytes = tcr.0.get(alg)?;

        let refs = vec![tmr_bytes, tcr_bytes];
        let merged_digest = hash_concat_bytes(alg, &refs);
        variants.insert(alg, merged_digest.into_boxed_slice());
    }

    Some(TransactionRoot(MultihashDigest::new(variants).ok()?))
}
