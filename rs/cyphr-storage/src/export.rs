//! Export utilities for Principal storage.
//!
//! Bridges the `cyphr` Principal type with the storage layer by exporting
//! its history (finalized commits and the data actions between them) as
//! [`CommitEntry`] bundle lines.

use cyphr::state::StateDigest;
use cyphr::{Principal, eml};

use crate::{CommitEntry, KeyEntry};

/// Errors that can occur during export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// JSON serialization failed.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// State digest is empty (no algorithm variants).
    #[error("empty state digest: {0}")]
    EmptyDigest(#[from] cyphr::Error),
}

/// Export a Principal's history as bundle lines, in the order it was
/// recorded: each finalized commit, preceded by one action-only line per
/// data action recorded since the commit before, and the actions recorded
/// after the last commit on lines at the end.
///
/// Actions travel with the history because a `ds/create` includes exactly
/// the actions recorded before it (SPEC 4.8.2): replaying the lines with
/// [`load_principal_from_commits`](crate::load_principal_from_commits)
/// reaches the same DT, DR and PR.
///
/// A commit line holds its transactions as SPEC 4.6.2 `txs` (each an
/// array of its cozies, the commit transaction last), the keys they
/// introduce in `keys`, its TR as `commit_id`, and the roots after it.
///
/// An action-only line forms no commit: its `commit_id` is empty and its
/// roots are those it leaves, which an action does not change: the roots
/// of the commit before it, or, for a principal that has made no commit,
/// its roots. A line recorded before the first commit of a principal that
/// has since committed carries `null` roots and an empty `pr`: the roots it
/// left are not kept once the principal commits.
///
/// # Errors
///
/// Returns `ExportError` if serialization or state digest access fails.
///
/// # Example
///
/// ```ignore
/// // Ignored: requires initialized Principal with commits (external context)
/// let lines = export_commits(&principal)?;
/// for line in lines {
///     file.write_line(&line.to_json()?)?;
/// }
/// ```
pub fn export_commits<S: eml::Storage>(
    principal: &Principal<S>,
) -> Result<Vec<CommitEntry>, ExportError> {
    let mut lines = Vec::new();
    let mut actions = principal.actions().peekable();
    let mut before: Option<CommitEntry> = match principal.commits().next() {
        Some(_) => None,
        None => Some(roots_line(principal)?),
    };
    for (position, commit) in principal.commits().enumerate() {
        while let Some(action) = actions.next_if(|a| a.recorded_after() <= position) {
            lines.push(action_line(action, before.as_ref())?);
        }
        let line = commit_line(commit)?;
        lines.push(line.clone());
        before = Some(line);
    }
    for action in actions {
        lines.push(action_line(action, before.as_ref())?);
    }
    Ok(lines)
}

/// The line of one action recorded after `before` (none: before any
/// commit).
fn action_line(
    action: &cyphr::Action,
    before: Option<&CommitEntry>,
) -> Result<CommitEntry, ExportError> {
    Ok(CommitEntry {
        actions: vec![serde_json::to_value(action.raw())?],
        auth_root: before.and_then(|c| c.auth_root.clone()),
        sr: before.and_then(|c| c.sr.clone()),
        pr: before.map(|c| c.pr.clone()).unwrap_or_default(),
        ..CommitEntry::default()
    })
}

/// A line holding only `principal`'s current roots.
fn roots_line<S: eml::Storage>(principal: &Principal<S>) -> Result<CommitEntry, ExportError> {
    let tagged = |m: &cyphr::multihash::MultihashDigest| m.tagged_first().map(|t| t.to_string());
    Ok(CommitEntry {
        auth_root: principal
            .auth_root()
            .map(|a| tagged(a.as_multihash()))
            .transpose()?,
        sr: principal
            .sr()
            .map(|s| tagged(s.as_multihash()))
            .transpose()?,
        pr: tagged(principal.pr().as_multihash())?,
        ..CommitEntry::default()
    })
}

fn commit_line(commit: &cyphr::Commit) -> Result<CommitEntry, ExportError> {
    let txs = commit
        .transactions()
        .iter()
        .map(|tx| {
            tx.0.iter()
                .map(|cz| serde_json::to_value(cz.raw()))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys = commit
        .iter_all_cozies()
        .filter_map(|cz| cz.new_key())
        .map(KeyEntry::of)
        .collect();

    // Roots absent after a dying commit (SPEC 3.7) export as `None`,
    // which serializes as JSON `null`.
    let tagged = |m: &cyphr::multihash::MultihashDigest| m.tagged_first().map(|t| t.to_string());
    Ok(CommitEntry {
        actions: Vec::new(),
        txs,
        keys,
        commit_id: tagged(&commit.tr().0)?,
        auth_root: commit
            .auth_root()
            .map(|a| tagged(a.as_multihash()))
            .transpose()?,
        sr: commit.sr().map(|s| tagged(s.as_multihash())).transpose()?,
        pr: tagged(commit.pr().as_multihash())?,
    })
}
