//! # Cyphr Storage
//!
//! Storage backends for the Cyphr identity protocol.
//!
//! This crate provides a storage API for persisting Cyphr principals, cozies, and actions
//! using a modern asynchronous storage engine design.
//!
//! ## Design Principles
//!
//! - **Storage is dumb**: The storage layer only handles bytes. All semantic operations
//!   (verification, state computation) are handled by `cyphr`.
//! - **Immutable history**: Entries are append-only; past entries are never modified.
//! - **Order from the commit manifest**: Intra-commit order is retained at ingest, not recovered
//!   from storage order.
//! - **Bit-perfect preservation**: Original JSON bytes are stored to ensure correct `czd`
//!   computation.
//!
//! ## Included Backends
//!
//! - [`engine::StorageEngine`]: The unified storage engine that coordinates persistent blobs and
//!   indexers.
//! - `cyphr_blob_fjall::FjallBlobStore` (in the `cyphr-blob-fjall` crate): A persistent blob store
//!   backed by the Fjall LSM-tree storage engine.
//! - `cyphr_index_fjall::FjallIndexer` (in the `cyphr-index-fjall` crate): A persistent KV indexer
//!   backed by the Fjall LSM-tree storage engine.
//! - [`index::memory::MemoryIndexer`]: An in-memory indexer for testing.

#![forbid(unsafe_code)]

pub mod blob;
pub mod engine;
mod export;
mod import;
pub mod index;

pub use export::{ExportError, export_commits};
pub use import::{Genesis, LoadError, load_principal_from_commits};
pub use index::PublicKeyInfo;

/// Key material for a commit (SPEC §6).
///
/// Keys are stored at commit level per SPEC §5.2/§5.3, not embedded
/// per-coz. Optional fields (`tag`, `now`) are semantically
/// optional — not all keys have human-readable labels or creation
/// timestamps at export time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyEntry {
    /// Algorithm identifier (e.g., "ES256").
    pub alg: String,
    /// Public key (base64url-encoded).
    #[serde(rename = "pub")]
    pub pub_key: String,
    /// Key thumbprint (base64url-encoded).
    pub tmb: String,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Optional creation timestamp (maps to Key.first_seen).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,
}

/// A stored commit bundle for the commit-based JSONL format.
///
/// Each line in the JSONL file represents one finalized commit containing:
/// - `cozies`: Array of coz entries (signed coz messages)
/// - `keys`: Key material introduced in this commit (SPEC §5.2/§5.3)
/// - `commit_id`: Commit ID (Merkle root of commit's coz czds)
/// - `ar`: Auth Root (derived from KR)
/// - `sr`: State Root (derived from AR and DR?)
/// - `pr`: Principal Root (derived from SR and CR)
///
/// The derived state digests enable efficient indexing and verification
/// without replaying the full coz history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitEntry {
    /// ParsedCoz entries in this commit bundle.
    #[serde(rename = "txs")]
    pub cozies: Vec<serde_json::Value>,
    /// Key material introduced in this commit.
    pub keys: Vec<KeyEntry>,
    /// Commit ID (per-commit Merkle root of coz czds).
    pub commit_id: String,
    /// Auth Root after this commit.
    #[serde(rename = "ar")]
    pub auth_root: String,
    /// State Root: root of the principal's StateTree (SPEC §3.7.2);
    /// promotes from AR when no Data Root is present, otherwise the
    /// tree root over AR and DR.
    pub sr: String,
    /// Principal Root after this commit.
    pub pr: String,
}

impl CommitEntry {
    /// Create a new commit entry from components.
    pub fn new(
        cozies: Vec<serde_json::Value>,
        keys: Vec<KeyEntry>,
        commit_id: String,
        auth_root: String,
        sr: String,
        pr: String,
    ) -> Self {
        Self {
            cozies,
            keys,
            commit_id,
            auth_root,
            sr,
            pr,
        }
    }

    /// Get the raw JSON string for this commit entry.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a commit entry from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}
