//! In-memory [`Indexer`] implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use cyphr::state::TaggedDigest;

use super::types::*;
use super::{
    DeriveToken, Indexer, IndexerError, IndexerWrite, check_replacement, digest_entries,
    merge_holder,
};
use crate::blob::Blake3Hash;

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
    digest_index: HashMap<String, Vec<EntityRef>>,
    /// Public keys keyed by thumbprint.
    public_keys: HashMap<String, PublicKeyInfo>,
    /// Alias table: Principal Root variant → the principal id it names.
    /// Derived state; see [`Indexer::get_tip`] for the resolution rule.
    aliases: HashMap<String, String>,
    /// Principals whose PG is established (see [`Indexer::is_pg_established`]).
    established: std::collections::HashSet<String>,
    /// See [`IndexerWrite::set_quarantined`]; survives [`IndexerWrite::clear`].
    quarantined: Vec<(crate::blob::Blake3Hash, String)>,
    /// What each indexed commit wrote, by `(principal_id, sequence)`, so
    /// [`IndexerWrite::replace_chain_from`] can withdraw it.
    written: HashMap<(String, u64), Written>,
}

/// The digest holders and PG aliases one indexed commit contributed.
#[derive(Debug)]
struct Written {
    entries: Vec<(String, EntityRef)>,
    pg: Vec<String>,
}

impl MemoryState {
    /// The stored principal id `id` names: itself if a principal is stored
    /// under it, else the principal its alias names, else `id` unchanged.
    fn canonical<'a>(&'a self, id: &'a str) -> &'a str {
        if self.tips.contains_key(id) {
            id
        } else {
            self.aliases.get(id).map_or(id, String::as_str)
        }
    }
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
            Ok(state.tips.get(state.canonical(&principal_id)).cloned())
        }
    }

    fn is_pg_established(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.established.contains(&principal_id))
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

            let Some(commits) = state.commits.get(state.canonical(&principal_id)) else {
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
            Ok(state
                .digest_index
                .get(&key)
                .and_then(|h| h.first().cloned()))
        }
    }

    fn resolve_digest_holders(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Vec<EntityRef>, IndexerError>> + Send {
        let key = digest.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.digest_index.get(&key).cloned().unwrap_or_default())
        }
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError> {
        let state = self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        Ok(state.principals.values().cloned().collect())
    }

    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send {
        let key = hash.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.digest_index.contains_key(&key))
        }
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send {
        let thumbprint = thumbprint.to_string();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            Ok(state.public_keys.get(&thumbprint).cloned())
        }
    }
}

/// Whether this commit is already indexed at its chain position
/// `(principal_id, sequence)`. A different commit at an indexed position is
/// fork evidence (I2: one writer, one linear chain), never a no-op.
fn is_indexed(state: &MemoryState, commit: &IndexableCommit) -> Result<bool, IndexerError> {
    let Some(held) = state
        .commits
        .get(&commit.principal_id)
        .and_then(|chain| chain.iter().find(|c| c.sequence == commit.sequence))
    else {
        return Ok(false);
    };
    if commit.commit_ids.first().map_or("", String::as_str) == held.commit_id {
        return Ok(true);
    }
    Err(IndexerError::Consistency(format!(
        "principal {} already has commit {} at sequence {}; refusing a rival commit there",
        commit.principal_id, held.commit_id, commit.sequence
    )))
}

/// Refuse a commit whose PG alias claim would re-point an existing alias:
/// such a write names no new truth, it rewrites an old one. The only
/// exclusive claim; digests name sets of holders.
fn claims_conflict(state: &MemoryState, commit: &IndexableCommit) -> Result<(), IndexerError> {
    for pr in commit.pg.iter().filter(|pr| **pr != commit.principal_id) {
        let owner = state
            .aliases
            .get(pr)
            .map(String::as_str)
            .or_else(|| state.principals.contains_key(pr).then_some(pr.as_str()));
        if owner.is_some_and(|o| o != commit.principal_id) {
            return Err(IndexerError::Conflict(format!(
                "PG alias {pr} already names another principal; refusing to re-point it to {}",
                commit.principal_id
            )));
        }
    }
    Ok(())
}

/// Index `commit`, which no indexed commit holds the position of.
fn index_one(state: &mut MemoryState, commit: &IndexableCommit) -> Result<(), IndexerError> {
    claims_conflict(state, commit)?;
    let entries = digest_entries(commit)?;

    let primary_cid = commit.commit_ids.first().cloned().unwrap_or_default();
    let primary_pr = commit.prs.first().cloned().unwrap_or_default();
    let primary_sr = commit.srs.first().cloned();
    let primary_ar = commit.ars.first().cloned();
    let primary_cr = commit.crs.first().cloned().unwrap_or_default();

    // Build CommitRef.
    let commit_ref = CommitRef {
        commit_id: primary_cid.clone(),
        sequence: commit.sequence,
        pre: commit.pre.clone(),
        pr: primary_pr.clone(),
        sr: primary_sr.clone(),
        ar: primary_ar.clone(),
        cr: primary_cr.clone(),
        blob_hashes: commit.blob_hashes.clone(),
        manifest: commit.manifest,
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

    // Alias each PG variant to the principal. The conflict check
    // above guarantees none names anyone else.
    for pr in &commit.pg {
        if *pr != commit.principal_id {
            state
                .aliases
                .insert(pr.clone(), commit.principal_id.clone());
        }
    }

    if !commit.pg.is_empty() {
        state.established.insert(commit.principal_id.clone());
    }

    // Update tip.
    state.tips.insert(
        commit.principal_id.clone(),
        TipState {
            principal_id: commit.principal_id.clone(),
            pr: primary_pr,
            sr: primary_sr,
            ar: primary_ar,
            cr: primary_cr,
            commit_id: primary_cid,
            commit_count,
            last_updated: commit.timestamp,
        },
    );

    // Every digest names its set of holders; arrival order is
    // invisible in the result (see `merge_holder`).
    for (digest, holder) in &entries {
        merge_holder(
            state.digest_index.entry(digest.clone()).or_default(),
            holder.clone(),
        );
    }

    // Index public keys.
    for key in &commit.keys {
        state
            .public_keys
            .insert(key.thumbprint.clone(), key.clone());
    }

    state.written.insert(
        (commit.principal_id.clone(), commit.sequence),
        Written {
            entries,
            pg: commit
                .pg
                .iter()
                .filter(|pr| **pr != commit.principal_id)
                .cloned()
                .collect(),
        },
    );
    Ok(())
}

impl IndexerWrite for MemoryIndexer {
    fn check_commit(
        &self,
        commit: &IndexableCommit,
        _token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        async move {
            let state = self
                .state
                .read()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
            if is_indexed(&state, &commit)? {
                return Ok(());
            }
            claims_conflict(&state, &commit)
        }
    }

    fn index_commit(
        &self,
        commit: &IndexableCommit,
        _token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        async move {
            let mut state = self
                .state
                .write()
                .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;

            // Idempotency: keyed by chain position, not commit id.
            if is_indexed(&state, &commit)? {
                return Ok(());
            }

            index_one(&mut state, &commit)
        }
    }

    async fn replace_chain_from(
        &self,
        principal_id: &str,
        sequence: u64,
        commits: &[IndexableCommit],
        _token: &DeriveToken,
    ) -> Result<(), IndexerError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        let held = state
            .commits
            .get(principal_id)
            .map_or(0, |c| c.len() as u64);
        check_replacement(principal_id, sequence, held, commits)?;
        for commit in commits {
            claims_conflict(&state, commit)?;
        }

        let state = &mut *state;
        let mut touched = std::collections::HashSet::new();
        for at in sequence..held {
            let Some(written) = state.written.remove(&(principal_id.to_string(), at)) else {
                continue;
            };
            for (digest, holder) in written.entries {
                if let Some(holders) = state.digest_index.get_mut(&digest) {
                    holders.retain(|h| {
                        h.principal_id != holder.principal_id
                            || h.entity_type != holder.entity_type
                            || h.sequence < Some(sequence)
                    });
                }
                touched.insert((digest, holder.entity_type as u8));
            }
            for pr in &written.pg {
                state.aliases.remove(pr);
            }
            if !written.pg.is_empty() {
                state.established.remove(principal_id);
            }
        }
        // A kept commit may hold a withdrawn digest too (a repeated root):
        // the holder falls back to it.
        for at in 0..sequence {
            for (digest, holder) in state
                .written
                .get(&(principal_id.to_string(), at))
                .map_or(&[][..], |w| w.entries.as_slice())
            {
                if touched.contains(&(digest.clone(), holder.entity_type as u8)) {
                    merge_holder(
                        state.digest_index.entry(digest.clone()).or_default(),
                        holder.clone(),
                    );
                }
            }
        }
        state.digest_index.retain(|_, holders| !holders.is_empty());
        if let Some(chain) = state.commits.get_mut(principal_id) {
            chain.truncate(sequence as usize);
        }
        if sequence == 0 {
            state.principals.remove(principal_id);
        }
        for commit in commits {
            index_one(state, commit)?;
        }
        Ok(())
    }

    async fn clear(&self, _token: &DeriveToken) -> Result<(), IndexerError> {
        let mut state = self
            .state
            .write()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?;
        state.principals.clear();
        state.commits.clear();
        state.tips.clear();
        state.digest_index.clear();
        state.public_keys.clear();
        state.aliases.clear();
        state.established.clear();
        state.written.clear();
        Ok(())
    }

    async fn set_quarantined(
        &self,
        manifests: &[(crate::blob::Blake3Hash, String)],
        _token: &DeriveToken,
    ) -> Result<(), IndexerError> {
        self.state
            .write()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?
            .quarantined = manifests.to_vec();
        Ok(())
    }

    async fn quarantined(&self) -> Result<Vec<(crate::blob::Blake3Hash, String)>, IndexerError> {
        Ok(self
            .state
            .read()
            .map_err(|e| IndexerError::Backend(format!("lock poisoned: {e}")))?
            .quarantined
            .clone())
    }
}
