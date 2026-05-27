//! Fjall-backed [`Indexer`] implementation.

use super::types::*;
use super::{Indexer, IndexerError};
use crate::blob::Blake3Hash;
use cyphr::state::TaggedDigest;
use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle};
use std::path::Path;

/// Persistent indexer backed by fjall.
pub struct FjallIndexer {
    #[allow(dead_code)]
    keyspace: Keyspace,
    principals: PartitionHandle,
    commits: PartitionHandle,
    tips: PartitionHandle,
    digest_index: PartitionHandle,
    public_keys: PartitionHandle,
}

impl FjallIndexer {
    /// Open or create a persistent indexer at `path`.
    pub fn open(path: &Path) -> Result<Self, IndexerError> {
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| IndexerError::Backend(format!("fjall keyspace open: {e}")))?;

        let principals = keyspace
            .open_partition("principals", PartitionCreateOptions::default())
            .map_err(|e| {
                IndexerError::Backend(format!("fjall open partition 'principals': {e}"))
            })?;

        let commits = keyspace
            .open_partition("commits", PartitionCreateOptions::default())
            .map_err(|e| IndexerError::Backend(format!("fjall open partition 'commits': {e}")))?;

        let tips = keyspace
            .open_partition("tips", PartitionCreateOptions::default())
            .map_err(|e| IndexerError::Backend(format!("fjall open partition 'tips': {e}")))?;

        let digest_index = keyspace
            .open_partition("digest_index", PartitionCreateOptions::default())
            .map_err(|e| {
                IndexerError::Backend(format!("fjall open partition 'digest_index': {e}"))
            })?;

        let public_keys = keyspace
            .open_partition("public_keys", PartitionCreateOptions::default())
            .map_err(|e| {
                IndexerError::Backend(format!("fjall open partition 'public_keys': {e}"))
            })?;

        Ok(Self {
            keyspace,
            principals,
            commits,
            tips,
            digest_index,
            public_keys,
        })
    }
}

impl Indexer for FjallIndexer {
    fn index_commit(
        &self,
        commit: &IndexableCommit,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        let principals = self.principals.clone();
        let commits = self.commits.clone();
        let tips = self.tips.clone();
        let digest_index = self.digest_index.clone();
        let public_keys = self.public_keys.clone();

        async move {
            let primary_cid = commit
                .commit_ids
                .first()
                .ok_or_else(|| IndexerError::Consistency("no commit IDs".into()))?;

            let primary_blob_hash = commit
                .blob_hashes
                .first()
                .copied()
                .ok_or_else(|| IndexerError::Consistency("no blob hashes".into()))?;

            // Idempotency: skip if already indexed
            let exists = digest_index
                .contains_key(primary_cid.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            if exists {
                return Ok(());
            }

            let primary_pr = commit.prs.first().cloned().unwrap_or_default();
            let primary_sr = commit.srs.first().cloned().unwrap_or_default();
            let primary_ar = commit.ars.first().cloned().unwrap_or_default();

            // Save CommitRef
            let commit_ref = CommitRef {
                commit_id: primary_cid.clone(),
                sequence: commit.sequence,
                blob_hashes: commit.blob_hashes.clone(),
                pr: primary_pr.clone(),
            };
            let commit_key = format!("{}/{:016x}", commit.principal_id, commit.sequence);
            let commit_val = serde_json::to_vec(&commit_ref)
                .map_err(|e| IndexerError::Consistency(e.to_string()))?;
            commits
                .insert(commit_key.as_bytes(), commit_val)
                .map_err(|e| IndexerError::Backend(e.to_string()))?;

            // Save PrincipalSummary
            let ps = if let Some(existing_bytes) = principals
                .get(commit.principal_id.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?
            {
                let mut existing: PrincipalSummary = serde_json::from_slice(&existing_bytes)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                existing.pr = primary_pr.clone();
                existing.commit_count = commit.sequence + 1;
                existing.last_updated = commit.timestamp;
                existing
            } else {
                PrincipalSummary {
                    principal_id: commit.principal_id.clone(),
                    pr: primary_pr.clone(),
                    commit_count: commit.sequence + 1,
                    created: commit.timestamp,
                    last_updated: commit.timestamp,
                }
            };
            let ps_val =
                serde_json::to_vec(&ps).map_err(|e| IndexerError::Consistency(e.to_string()))?;
            principals
                .insert(commit.principal_id.as_bytes(), ps_val)
                .map_err(|e| IndexerError::Backend(e.to_string()))?;

            // Save TipState
            let tip = TipState {
                principal_id: commit.principal_id.clone(),
                pr: primary_pr,
                sr: primary_sr,
                ar: primary_ar,
                commit_id: primary_cid.clone(),
                commit_count: commit.sequence + 1,
                last_updated: commit.timestamp,
            };
            let tip_val =
                serde_json::to_vec(&tip).map_err(|e| IndexerError::Consistency(e.to_string()))?;
            tips.insert(commit.principal_id.as_bytes(), tip_val)
                .map_err(|e| IndexerError::Backend(e.to_string()))?;

            // Save entities in digest_index
            for (i, blob_hash) in commit.blob_hashes.iter().enumerate() {
                let tx_type = commit.transaction_types.get(i).cloned().unwrap_or_default();
                let entity_type = if tx_type.starts_with("cyphr/action") {
                    EntityType::Action
                } else {
                    EntityType::Transaction
                };

                let digest_key = blob_hash.to_string();
                let ent = EntityRef {
                    digest: digest_key.clone(),
                    blob_hash: *blob_hash,
                    entity_type,
                };
                let ent_val = serde_json::to_vec(&ent)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                digest_index
                    .insert(digest_key.as_bytes(), ent_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;

                if let Some(variants) = commit.transaction_ids.get(i) {
                    for variant in variants {
                        let ent = EntityRef {
                            digest: variant.clone(),
                            blob_hash: *blob_hash,
                            entity_type,
                        };
                        let ent_val = serde_json::to_vec(&ent)
                            .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                        digest_index
                            .insert(variant.as_bytes(), ent_val)
                            .map_err(|e| IndexerError::Backend(e.to_string()))?;
                    }
                }
            }

            for cid in &commit.commit_ids {
                let ent = EntityRef {
                    digest: cid.clone(),
                    blob_hash: primary_blob_hash,
                    entity_type: EntityType::Commit,
                };
                let ent_val = serde_json::to_vec(&ent)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                digest_index
                    .insert(cid.as_bytes(), ent_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;
            }

            for pr in &commit.prs {
                let ent = EntityRef {
                    digest: pr.clone(),
                    blob_hash: primary_blob_hash,
                    entity_type: EntityType::Commit,
                };
                let ent_val = serde_json::to_vec(&ent)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                digest_index
                    .insert(pr.as_bytes(), ent_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;
            }

            for sr in &commit.srs {
                let ent = EntityRef {
                    digest: sr.clone(),
                    blob_hash: primary_blob_hash,
                    entity_type: EntityType::Commit,
                };
                let ent_val = serde_json::to_vec(&ent)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                digest_index
                    .insert(sr.as_bytes(), ent_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;
            }

            for ar in &commit.ars {
                let ent = EntityRef {
                    digest: ar.clone(),
                    blob_hash: primary_blob_hash,
                    entity_type: EntityType::Commit,
                };
                let ent_val = serde_json::to_vec(&ent)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                digest_index
                    .insert(ar.as_bytes(), ent_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;
            }

            // Save public keys
            for key in &commit.keys {
                let key_val = serde_json::to_vec(key)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                public_keys
                    .insert(key.thumbprint.as_bytes(), key_val)
                    .map_err(|e| IndexerError::Backend(e.to_string()))?;
            }

            Ok(())
        }
    }

    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let tips = self.tips.clone();
        async move {
            let val = tips
                .get(principal_id.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            if let Some(bytes) = val {
                let tip: TipState = serde_json::from_slice(&bytes)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                Ok(Some(tip))
            } else {
                Ok(None)
            }
        }
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let commits = self.commits.clone();
        async move {
            let from_key = format!("{}/{:016x}", principal_id, from.unwrap_or(0));
            let to_key = format!("{}/{:016x}", principal_id, to.unwrap_or(u64::MAX));
            let range_iter = commits.range(from_key.as_bytes()..=to_key.as_bytes());

            let mut chain = Vec::new();
            for item in range_iter {
                let (_key, val) = item.map_err(|e| IndexerError::Backend(e.to_string()))?;
                let commit_ref: CommitRef = serde_json::from_slice(&val)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                chain.push(commit_ref);
            }
            Ok(chain)
        }
    }

    fn resolve_digest(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<EntityRef>, IndexerError>> + Send {
        let key = digest.to_string();
        let digest_index = self.digest_index.clone();
        async move {
            let val = digest_index
                .get(key.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            if let Some(bytes) = val {
                let ent: EntityRef = serde_json::from_slice(&bytes)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                Ok(Some(ent))
            } else {
                Ok(None)
            }
        }
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send {
        let principals = self.principals.clone();
        async move {
            let mut summaries = Vec::new();
            for item in principals.iter() {
                let (_key, val) = item.map_err(|e| IndexerError::Backend(e.to_string()))?;
                let summary: PrincipalSummary = serde_json::from_slice(&val)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                summaries.push(summary);
            }
            Ok(summaries)
        }
    }

    fn clear(&self) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let principals = self.principals.clone();
        let commits = self.commits.clone();
        let tips = self.tips.clone();
        let digest_index = self.digest_index.clone();
        let public_keys = self.public_keys.clone();

        async move {
            let clear_partition = |partition: PartitionHandle| -> Result<(), IndexerError> {
                let mut keys = Vec::new();
                for result in partition.iter() {
                    let (key, _) = result.map_err(|e| IndexerError::Backend(e.to_string()))?;
                    keys.push(key.to_vec());
                }
                for key in keys {
                    partition
                        .remove(key)
                        .map_err(|e| IndexerError::Backend(e.to_string()))?;
                }
                Ok(())
            };

            clear_partition(principals)?;
            clear_partition(commits)?;
            clear_partition(tips)?;
            clear_partition(digest_index)?;
            clear_partition(public_keys)?;

            Ok(())
        }
    }

    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send {
        let key = hash.to_string();
        let digest_index = self.digest_index.clone();
        async move {
            let exists = digest_index
                .contains_key(key.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            Ok(exists)
        }
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send {
        let thumbprint = thumbprint.to_string();
        let public_keys = self.public_keys.clone();
        async move {
            let val = public_keys
                .get(thumbprint.as_bytes())
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            if let Some(bytes) = val {
                let info: PublicKeyInfo = serde_json::from_slice(&bytes)
                    .map_err(|e| IndexerError::Consistency(e.to_string()))?;
                Ok(Some(info))
            } else {
                Ok(None)
            }
        }
    }
}
