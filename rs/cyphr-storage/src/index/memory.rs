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
    fn index_commit(
        &self,
        commit: &IndexableCommit,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        async move {
            let mut state = self
                .state
                .write()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;

            // Idempotency: skip if this commit_id is already indexed.
            if let Some(existing) = state.commits.get(&commit.principal_id) {
                if existing
                    .iter()
                    .any(|c| commit.commit_ids.contains(&c.commit_id))
                {
                    return Ok(());
                }
            }

            let primary_cid = commit.commit_ids.first().cloned().unwrap_or_default();
            let primary_pr = commit.prs.first().cloned().unwrap_or_default();
            let primary_sr = commit.srs.first().cloned().unwrap_or_default();
            let primary_ar = commit.ars.first().cloned().unwrap_or_default();

            // Build CommitRef.
            let commit_ref = CommitRef {
                commit_id: primary_cid.clone(),
                sequence: commit.sequence,
                blob_hashes: commit.blob_hashes.clone(),
                pr: primary_pr.clone(),
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
                    ps.pr = primary_pr.clone();
                    ps.commit_count = commit_count;
                    ps.last_updated = commit.timestamp;
                })
                .or_insert_with(|| PrincipalSummary {
                    principal_id: commit.principal_id.clone(),
                    pr: primary_pr.clone(),
                    commit_count,
                    created: commit.timestamp,
                    last_updated: commit.timestamp,
                });

            // Update tip.
            state.tips.insert(
                commit.principal_id.clone(),
                TipState {
                    principal_id: commit.principal_id.clone(),
                    pr: primary_pr,
                    sr: primary_sr,
                    ar: primary_ar,
                    commit_id: primary_cid,
                    commit_count,
                    last_updated: commit.timestamp,
                },
            );

            // Index each blob hash as a transaction entity reference.
            for (i, blob_hash) in commit.blob_hashes.iter().enumerate() {
                let tx_type = commit.transaction_types.get(i).cloned().unwrap_or_default();

                let entity_type = if tx_type.starts_with("cyphr/action") {
                    EntityType::Action
                } else {
                    EntityType::Transaction
                };

                let digest_key = blob_hash.to_string();
                state.digest_index.insert(
                    digest_key.clone(),
                    EntityRef {
                        digest: digest_key,
                        blob_hash: *blob_hash,
                        entity_type,
                    },
                );

                if let Some(variants) = commit.transaction_ids.get(i) {
                    for variant in variants {
                        state.digest_index.insert(
                            variant.clone(),
                            EntityRef {
                                digest: variant.clone(),
                                blob_hash: *blob_hash,
                                entity_type,
                            },
                        );
                    }
                }
            }

            // Map all commit ID variants
            for cid in &commit.commit_ids {
                state.digest_index.insert(
                    cid.clone(),
                    EntityRef {
                        digest: cid.clone(),
                        blob_hash: commit.blob_hashes[0],
                        entity_type: EntityType::Commit,
                    },
                );
            }

            // Map all PR variants
            for pr in &commit.prs {
                state.digest_index.insert(
                    pr.clone(),
                    EntityRef {
                        digest: pr.clone(),
                        blob_hash: commit.blob_hashes[0],
                        entity_type: EntityType::Commit,
                    },
                );
            }

            // Map all SR variants
            for sr in &commit.srs {
                state.digest_index.insert(
                    sr.clone(),
                    EntityRef {
                        digest: sr.clone(),
                        blob_hash: commit.blob_hashes[0],
                        entity_type: EntityType::Commit,
                    },
                );
            }

            // Map all AR variants
            for ar in &commit.ars {
                state.digest_index.insert(
                    ar.clone(),
                    EntityRef {
                        digest: ar.clone(),
                        blob_hash: commit.blob_hashes[0],
                        entity_type: EntityType::Commit,
                    },
                );
            }

            Ok(())
        }
    }

    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.tips.get(&principal_id).cloned())
        }
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;

            let Some(commits) = state.commits.get(&principal_id) else {
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
    }

    fn resolve_digest(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<EntityRef>, IndexerError>> + Send {
        let key = digest.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.digest_index.get(&key).cloned())
        }
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        Ok(state.principals.values().cloned().collect())
    }
}
