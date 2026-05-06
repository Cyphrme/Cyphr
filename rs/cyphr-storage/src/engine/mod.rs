//! # Storage Engine
//!
//! Coordination layer that joins [`BlobStore`] and [`Indexer`] into
//! coherent read and write paths.
//!
//! The engine does not own storage or indexing logic — it orchestrates
//! both to serve assembled responses. This is the layer that the HTTP
//! server (Phase 4) programs against.
//!
//! ## Read Path
//!
//! - [`StorageEngine::get_tip`] — current principal state (index only)
//! - [`StorageEngine::get_patch`] — commit chain + blob content (index → blobs)
//! - [`StorageEngine::get_entity`] — digest resolution + blob fetch (index → blob)
//!
//! ## Write Path
//!
//! - [`StorageEngine::ingest_commit`] — store blobs, build index entry

mod error;

pub use error::EngineError;

use cyphr::state::TaggedDigest;

use crate::blob::{Blake3Hash, BlobStore};
use crate::index::{CommitRef, IndexableCommit, Indexer, TipState};

/// A commit's metadata paired with its blob contents.
///
/// Each entry in `blobs` corresponds positionally to a
/// `CommitRef::blob_hashes` entry.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// Commit metadata from the index.
    pub commit: CommitRef,
    /// Raw blob contents, ordered to match `commit.blob_hashes`.
    pub blobs: Vec<Vec<u8>>,
}

/// Response from [`StorageEngine::get_patch`].
#[derive(Debug, Clone)]
pub struct PatchResponse {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Ordered commit entries with their blob contents.
    pub entries: Vec<PatchEntry>,
}

/// Metadata for ingesting a pre-validated commit.
///
/// The engine does not validate protocol-level signatures or state
/// transitions — that responsibility belongs to the protocol layer
/// (Phase 3b). This struct carries the metadata needed to store
/// blobs and build an index entry.
#[derive(Debug, Clone)]
pub struct IngestMeta {
    /// Principal genesis identifier (tagged digest string).
    pub principal_id: String,
    /// Commit ID (tagged digest string).
    pub commit_id: String,
    /// Commit sequence number within this principal (0-indexed).
    pub sequence: u64,
    /// Principal Root after this commit.
    pub pr: String,
    /// State Root after this commit.
    pub sr: String,
    /// Auth Root after this commit.
    pub ar: String,
    /// Transaction type identifiers (e.g., "key/create").
    pub transaction_types: Vec<String>,
    /// Timestamp of the commit.
    pub timestamp: i64,
}

/// Result from [`StorageEngine::ingest_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
}

/// Coordinated storage engine joining blob and index layers.
///
/// Generic over backend implementations. Use `MemoryBlobStore` +
/// `MemoryIndexer` for tests, production backends for deployment.
pub struct StorageEngine<B, I> {
    blob_store: B,
    indexer: I,
}

impl<B: BlobStore, I: Indexer> StorageEngine<B, I> {
    /// Create a new engine wrapping the given backends.
    pub fn new(blob_store: B, indexer: I) -> Self {
        Self {
            blob_store,
            indexer,
        }
    }

    // ========================================================================
    // Read path
    // ========================================================================

    /// Retrieve the current tip state for a principal.
    ///
    /// Delegates directly to the indexer.
    pub fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, EngineError> {
        Ok(self.indexer.get_tip(principal_id)?)
    }

    /// Retrieve a patch: commit chain metadata joined with blob content.
    ///
    /// For each commit in the range, fetches the raw blob bytes from
    /// the blob store. This is the engine's primary coordination value —
    /// neither trait can serve this alone.
    pub fn get_patch(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        let chain = self.indexer.get_commit_chain(principal_id, from, to)?;

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash)?.ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "blob {hash} referenced by commit {} not found in store",
                        commit_ref.commit_id
                    ))
                })?;
                blobs.push(data);
            }
            entries.push(PatchEntry {
                commit: commit_ref,
                blobs,
            });
        }

        Ok(PatchResponse {
            principal_id: principal_id.to_string(),
            entries,
        })
    }

    /// Resolve a tagged digest to its raw blob content.
    ///
    /// Two-step: resolve digest → entity ref (index), then
    /// fetch blob content (blob store).
    pub fn get_entity(&self, digest: &TaggedDigest) -> Result<Option<Vec<u8>>, EngineError> {
        let entity = match self.indexer.resolve_digest(digest)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let data = self.blob_store.get(&entity.blob_hash)?;
        Ok(data)
    }

    // ========================================================================
    // Write path
    // ========================================================================

    /// Ingest a pre-validated commit: store blobs and index metadata.
    ///
    /// Each entry in `blobs` is a raw coz byte slice. The engine:
    /// 1. Puts each blob into the blob store (content-addressed)
    /// 2. Builds an `IndexableCommit` from the metadata + blob hashes
    /// 3. Calls the indexer to record relational data
    ///
    /// Returns the BLAKE3 hashes of the stored blobs.
    ///
    /// **Note:** This method does NOT validate protocol-level
    /// signatures or state transitions. That responsibility belongs
    /// to the protocol validation layer (Phase 3b).
    pub fn ingest_commit(
        &self,
        blobs: &[&[u8]],
        metadata: IngestMeta,
    ) -> Result<IngestResult, EngineError> {
        // Store each blob.
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let hash = self.blob_store.put(blob)?;
            blob_hashes.push(hash);
        }

        // Build and submit index entry.
        let indexable = IndexableCommit {
            principal_id: metadata.principal_id,
            commit_id: metadata.commit_id,
            sequence: metadata.sequence,
            pr: metadata.pr,
            sr: metadata.sr,
            ar: metadata.ar,
            blob_hashes: blob_hashes.clone(),
            transaction_types: metadata.transaction_types,
            timestamp: metadata.timestamp,
        };
        self.indexer.index_commit(&indexable)?;

        Ok(IngestResult { blob_hashes })
    }
}

#[cfg(test)]
mod tests;
