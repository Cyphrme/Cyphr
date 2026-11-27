//! Explicit merge (SPEC 11.5.1): a source signs `principal/merge`, the
//! target accepts by signing `principal/merge-ack` with the same fields.
//!
//! Each transaction is accepted into its own signer's chain on that
//! signer's authority alone; neither changes the other principal, adds
//! keys, or touches AT. A merge exists only for a verifier holding both
//! chains, and [`merge_status`] is where that is decided.

use crate::parsed_coz::CozKind;
use crate::principal::Principal;
use crate::state::PrincipalRoot;

/// The fields `principal/merge` and `principal/merge-ack` share.
///
/// An ack matches a merge exactly when both fields are equal; nothing
/// else (signer, time, order of commits) enters the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeClaim {
    /// `merge_from`: PRs the source held, naming what is being merged in.
    /// Never empty.
    pub from: Vec<PrincipalRoot>,
    /// `merge_to_pr`: a PR of the target, one the target held.
    pub to_pr: PrincipalRoot,
}

impl MergeClaim {
    /// Whether two claims name the same merge. PRs compare by value on
    /// every algorithm they share ([`crate::MultihashDigest::matches`]),
    /// since one PR may be spelled in any of its algorithms.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.from.len() == other.from.len()
            && self.to_pr.0.matches(&other.to_pr.0)
            && self
                .from
                .iter()
                .zip(&other.from)
                .all(|(a, b)| a.0.matches(&b.0))
    }
}

/// How far a merge from one principal into another has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MergeStatus {
    /// The source signed a merge naming a PR the target held, and the
    /// target signed an ack carrying the same fields.
    Merged,
    /// The source signed such a merge; the target has not matched it.
    Pending,
    /// The source signed no merge naming a PR the target held.
    None,
}

/// What `source`'s chain and `target`'s chain together say about a merge
/// of `source` into `target`.
///
/// Pure over the two chains: it reads no clock and no server. `Merged`
/// requires an ack in the target's chain equal to a merge in the source's
/// on both `merge_from` and `merge_to_pr` ([`MergeClaim::matches`]); an
/// ack with no equal merge, and a merge naming a PR the target never held
/// (which the target could not even ack), both yield no merge.
pub fn merge_status<S, T>(source: &Principal<S>, target: &Principal<T>) -> MergeStatus
where
    S: eml::Storage,
    T: eml::Storage,
{
    let acks: Vec<&MergeClaim> = target
        .iter_all_cozies()
        .filter_map(|c| match c.kind() {
            CozKind::MergeAck(claim) => Some(claim),
            _ => None,
        })
        .collect();

    let mut status = MergeStatus::None;
    for coz in source.iter_all_cozies() {
        let CozKind::Merge(merge) = coz.kind() else {
            continue;
        };
        if !target.has_held(&merge.to_pr) {
            continue;
        }
        if acks.iter().any(|ack| ack.matches(merge)) {
            return MergeStatus::Merged;
        }
        status = MergeStatus::Pending;
    }
    status
}
