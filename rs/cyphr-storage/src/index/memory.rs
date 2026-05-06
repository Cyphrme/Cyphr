//! In-memory [`Indexer`] implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use cyphr::state::TaggedDigest;

use super::types::*;
use super::{Indexer, IndexerError};

/// Internal state for the memory indexer.
#[derive(Debug, Default)]
struct MemoryState {
    /// Principal summaries keyed by principal_id.
    principals: HashMap<String, PrincipalSummary>,
    /// Commit chains keyed by principal_id, ordered by sequence.
    commits: HashMap<String, Vec<CommitRef>>,
    /// Tip state keyed by principal_id.
    tips: HashMap<String, TipState>,
    /// Digest → entity reference lookup.
    digest_index: HashMap<String, EntityRef>,
}

/// In-memory indexer backed by `HashMap`.
///
/// Thread-safe via `RwLock`. Suitable for tests and short-lived processes.
/// Implements the same [`Indexer`] trait as production backends.
pub struct MemoryIndexer {
    state: RwLock<MemoryState>,
}

impl MemoryIndexer {
    /// Create an empty in-memory indexer.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(MemoryState::default()),
        }
    }
}

impl Default for MemoryIndexer {
    fn default() -> Self {
        Self::new()
    }
}

impl Indexer for MemoryIndexer {
    fn index_commit(&self, commit: &IndexableCommit) -> Result<(), IndexerError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;

        // Idempotency: skip if this commit_id is already indexed.
        if let Some(existing) = state.commits.get(&commit.principal_id) {
            if existing.iter().any(|c| c.commit_id == commit.commit_id) {
                return Ok(());
            }
        }

        // Build CommitRef.
        let commit_ref = CommitRef {
            commit_id: commit.commit_id.clone(),
            sequence: commit.sequence,
            blob_hashes: commit.blob_hashes.clone(),
            pr: commit.pr.clone(),
        };

        // Append to commit chain.
        state
            .commits
            .entry(commit.principal_id.clone())
            .or_default()
            .push(commit_ref);

        // Update or create principal summary.
        let commit_count = state
            .commits
            .get(&commit.principal_id)
            .map_or(0, |c| c.len() as u64);

        state
            .principals
            .entry(commit.principal_id.clone())
            .and_modify(|ps| {
                ps.pr = commit.pr.clone();
                ps.commit_count = commit_count;
                ps.last_updated = commit.timestamp;
            })
            .or_insert_with(|| PrincipalSummary {
                principal_id: commit.principal_id.clone(),
                pr: commit.pr.clone(),
                commit_count,
                created: commit.timestamp,
                last_updated: commit.timestamp,
            });

        // Update tip.
        state.tips.insert(
            commit.principal_id.clone(),
            TipState {
                principal_id: commit.principal_id.clone(),
                pr: commit.pr.clone(),
                sr: commit.sr.clone(),
                ar: commit.ar.clone(),
                commit_id: commit.commit_id.clone(),
                commit_count,
                last_updated: commit.timestamp,
            },
        );

        // Index each blob hash as a transaction entity reference.
        // In a full implementation, the engine would provide explicit
        // digest → blob mappings. For now, each blob is indexed by
        // its position in the commit.
        for (i, blob_hash) in commit.blob_hashes.iter().enumerate() {
            let tx_type = commit.transaction_types.get(i).cloned().unwrap_or_default();

            let entity_type = if tx_type.starts_with("cyphr/action") {
                EntityType::Action
            } else {
                EntityType::Transaction
            };

            // Use the blob hash hex as a synthetic digest key.
            // The real SQLite indexer will store tagged digests from
            // coz `czd` fields; this is a simplified approximation.
            let digest_key = blob_hash.to_string();
            state.digest_index.insert(
                digest_key.clone(),
                EntityRef {
                    digest: digest_key,
                    blob_hash: *blob_hash,
                    entity_type,
                },
            );
        }

        Ok(())
    }

    fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        Ok(state.tips.get(principal_id).cloned())
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Vec<CommitRef>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;

        let Some(commits) = state.commits.get(principal_id) else {
            return Ok(Vec::new());
        };

        let from_seq = from.unwrap_or(0);
        let to_seq = to.unwrap_or(u64::MAX);

        let chain: Vec<CommitRef> = commits
            .iter()
            .filter(|c| c.sequence >= from_seq && c.sequence <= to_seq)
            .cloned()
            .collect();

        Ok(chain)
    }

    fn resolve_digest(&self, digest: &TaggedDigest) -> Result<Option<EntityRef>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        let key = digest.to_string();
        Ok(state.digest_index.get(&key).cloned())
    }

    fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        Ok(state.principals.values().cloned().collect())
    }
}
