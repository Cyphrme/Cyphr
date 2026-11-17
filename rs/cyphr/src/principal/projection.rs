//! A canonical reading of a verified state, to compare two derivations of
//! one record.

use super::PrincipalState;
use super::timeline::KeyTimeline;
use crate::commit_root::CommitRoot;
use crate::key::Key;
use crate::state::{AuthRoot, DataRoot, KeyRoot, PrincipalRoot, StateRoot};

/// What a [`PrincipalState`] is, with nothing in it that depends on the
/// order the record arrived in: the roots, the keys and their `last_used`,
/// the key timeline, every held action and the ones DT shows, and the
/// lifecycle. Two states of one record (a kept state and a replay of the
/// stored chain) are equal exactly when their projections are.
#[derive(Debug, PartialEq, Eq)]
pub struct StateProjection<'a> {
    pr: &'a PrincipalRoot,
    sr: Option<&'a StateRoot>,
    ar: Option<&'a AuthRoot>,
    kr: Option<&'a KeyRoot>,
    dr: Option<&'a DataRoot>,
    cr: Option<&'a CommitRoot>,
    commits: usize,
    keys: Vec<&'a Key>,
    revoked: Vec<&'a Key>,
    timeline: &'a KeyTimeline,
    /// Every held action, by `(now, czd)`.
    held: Vec<(i64, &'a [u8])>,
    /// The czds of the actions DT shows.
    shown: Vec<&'a [u8]>,
    included: Vec<&'a [u8]>,
    lifecycle: (bool, bool, bool),
    latest_timestamp: i64,
}

/// `keys` in thumbprint order: the map's own order is the order keys were
/// added in, which is the chain's, but a projection owes no one that.
fn sorted(keys: &indexmap::IndexMap<String, Key>) -> Vec<&Key> {
    let mut keys: Vec<&Key> = keys.values().collect();
    keys.sort_by(|a, b| a.tmb().as_bytes().cmp(b.tmb().as_bytes()));
    keys
}

impl PrincipalState {
    /// This state's [`StateProjection`].
    pub fn projection(&self) -> StateProjection<'_> {
        StateProjection {
            pr: &self.pr,
            sr: self.sr.as_ref(),
            ar: self.ar.as_ref(),
            kr: self.kr.as_ref(),
            dr: self.dr.as_ref(),
            cr: self.cr.as_ref(),
            commits: self.auth.commits.len(),
            keys: sorted(&self.auth.keys),
            revoked: sorted(&self.auth.revoked),
            timeline: &self.key_timeline,
            held: self
                .data
                .actions
                .iter()
                .map(|((now, czd), _)| (*now, czd.as_slice()))
                .collect(),
            shown: self.actions().map(|a| a.czd().as_bytes()).collect(),
            included: self.included_czds.iter().map(Vec::as_slice).collect(),
            lifecycle: (self.deleted, self.frozen, self.errored),
            latest_timestamp: self.latest_timestamp,
        }
    }
}
