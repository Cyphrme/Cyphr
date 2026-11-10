use std::collections::BTreeMap;

use crate::multihash::MultihashDigest;
use crate::state::{HashAlg, TaggedCzd, hash_concat_bytes};

/// The Transaction Mutation Root (TMR)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TransactionMutationRoot(pub MultihashDigest);

/// The Transaction Commit Root (TCR)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TransactionCommitRoot(pub MultihashDigest);

/// The Transaction Root (TR)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TransactionRoot(pub MultihashDigest);

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

    // Implicit promotion: single czd.
    // Convert to all active target algorithms.
    if czds.len() == 1 {
        let mut variants = BTreeMap::new();
        for &target_alg in algs {
            let converted = czds[0].convert_to(target_alg);
            variants.insert(target_alg, converted.into_boxed_slice());
        }
        return MultihashDigest::new(variants).ok();
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

/// Compute the Transaction Root: the MR of every transaction's id in order,
/// the commit transaction last (SPEC 3.7.5,
/// `TR = MR(TXm0?, TXm1?, ..., TXc)`). With no mutation transaction the
/// commit transaction's id is promoted unhashed. TR is not built from TMR:
/// TMR promotes a lone mutation transaction, which would hide its grouping
/// from TR; TMR's role is the arrow (SPEC 4.2).
pub fn compute_tr(
    mutations: &[&MultihashDigest],
    tcr: &TransactionCommitRoot,
    algs: &[HashAlg],
) -> Option<TransactionRoot> {
    if mutations.is_empty() {
        return Some(TransactionRoot(tcr.0.clone()));
    }

    let mut variants = BTreeMap::new();
    for &alg in algs {
        let mut refs = Vec::with_capacity(mutations.len() + 1);
        for tx in mutations {
            refs.push(tx.get(alg)?);
        }
        refs.push(tcr.0.get(alg)?);
        variants.insert(alg, hash_concat_bytes(alg, &refs).into_boxed_slice());
    }

    Some(TransactionRoot(MultihashDigest::new(variants).ok()?))
}
