//! Export utilities for Principal storage.
//!
//! Bridges the `cyphr` Principal type with the storage layer by exporting
//! its finalized commits as [`CommitEntry`] bundles.

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

/// Export commits from a Principal for commit-based storage.
///
/// Returns a vector of `CommitEntry` representing each finalized commit.
/// Each entry contains:
/// - `cozies`: Array of coz JSON values (with embedded key material)
/// - `commit_id`: Commit ID (Merkle root of coz czds, base64url)
/// - `as`: Auth State (base64url)
/// - `sr`: State Root (base64url)
/// - `pr`: Principal Root (base64url)
///
/// **Note**: Actions are not included in commits; they are stored separately
/// or handled by the caller.
///
/// # Errors
///
/// Returns `ExportError` if serialization or state digest access fails.
///
/// # Example
///
/// ```ignore
/// // Ignored: requires initialized Principal with commits (external context)
/// let commits = export_commits(&principal)?;
/// for commit in commits {
///     file.write_line(&commit.to_json()?)?;
/// }
/// ```
pub fn export_commits<S: eml::Storage>(
    principal: &Principal<S>,
) -> Result<Vec<CommitEntry>, ExportError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut commit_entries = Vec::new();

    for commit in principal.commits() {
        let mut cozies = Vec::new();
        let mut keys = Vec::new();

        for cz in commit.iter_all_cozies() {
            // Serialize complete CozJson {pay, sig} — no key embedding
            let raw = serde_json::to_value(cz.raw())?;
            cozies.push(raw);

            // Collect key material at commit level
            if let Some(key) = cz.new_key() {
                keys.push(KeyEntry {
                    alg: key.alg().to_owned(),
                    pub_key: Base64UrlUnpadded::encode_string(key.pub_key()),
                    tmb: key.tmb().to_b64(),
                    tag: key.tag().map(str::to_owned),
                    now: Some(key.first_seen()),
                });
            }
        }

        // Get state digests as algorithm-prefixed strings (alg:digest format)
        let commit_id = commit.tr().0.tagged_first()?.to_string();
        // Roots absent after a dying commit (SPEC 3.7) export as `None`,
        // which serializes as JSON `null`.
        let auth_root = commit
            .auth_root()
            .map(|a| a.as_multihash().tagged_first().map(|t| t.to_string()))
            .transpose()?;
        let sr = commit
            .sr()
            .map(|s| s.as_multihash().tagged_first().map(|t| t.to_string()))
            .transpose()?;
        let pr = commit.pr().as_multihash().tagged_first()?.to_string();

        commit_entries.push(CommitEntry::new(cozies, keys, commit_id, auth_root, sr, pr));
    }

    Ok(commit_entries)
}
