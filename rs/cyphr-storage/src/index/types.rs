//! Domain types for the relational index.
//!
//! These types live at the storage boundary — they carry serialized
//! representations of protocol state (strings, blob hashes), not live
//! protocol objects. The engine (Phase 3) bridges protocol types to
//! these index-level representations.

use crate::blob::Blake3Hash;

/// Input to [`super::Indexer::index_commit`].
///
/// Constructed by the engine from a validated `cyphr::Commit`.
/// All digest fields are pre-serialized (base64url or tagged digest
/// strings) — the indexer stores them verbatim.
#[derive(Debug, Clone)]
pub struct IndexableCommit {
    /// Principal genesis identifier (tagged digest string).
    pub principal_id: String,
    /// Commit ID (tagged digest string).
    pub commit_id: String,
    /// Commit sequence number within this principal (0-indexed).
    pub sequence: u64,
    /// Principal Root after this commit (tagged digest string).
    pub pr: String,
    /// State Root after this commit (tagged digest string).
    pub sr: String,
    /// Auth Root after this commit (tagged digest string).
    pub ar: String,
    /// BLAKE3 hashes of individual coz blobs stored for this commit.
    pub blob_hashes: Vec<Blake3Hash>,
    /// Transaction type identifiers (e.g., "key/create", "key/revoke").
    pub transaction_types: Vec<String>,
    /// Timestamp of the commit (from the commit transaction's `now` field).
    pub timestamp: i64,
}

/// Current tip state for a principal.
///
/// Returned by [`super::Indexer::get_tip`]. Represents the latest
/// known state without replaying the full commit history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipState {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Current Principal Root.
    pub pr: String,
    /// Current State Root.
    pub sr: String,
    /// Current Auth Root.
    pub ar: String,
    /// Most recent Commit ID.
    pub commit_id: String,
    /// Total number of commits for this principal.
    pub commit_count: u64,
    /// Timestamp of the most recent commit.
    pub last_updated: i64,
}

/// Reference to a commit in the chain.
///
/// Returned by [`super::Indexer::get_commit_chain`]. Contains
/// enough metadata to locate and order commits without fetching
/// full blob content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRef {
    /// Commit ID (tagged digest string).
    pub commit_id: String,
    /// Commit sequence number (0-indexed).
    pub sequence: u64,
    /// BLAKE3 hashes of blobs belonging to this commit.
    pub blob_hashes: Vec<Blake3Hash>,
    /// Principal Root after this commit.
    pub pr: String,
}

/// Reference to an entity resolved by digest.
///
/// Returned by [`super::Indexer::resolve_digest`]. Maps a
/// protocol-level tagged digest to a storage-level blob hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRef {
    /// The tagged digest string that was resolved.
    pub digest: String,
    /// BLAKE3 hash of the blob containing this entity.
    pub blob_hash: Blake3Hash,
    /// What kind of entity this digest refers to.
    pub entity_type: EntityType,
}

/// Classification of indexed entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityType {
    /// A finalized commit bundle.
    Commit,
    /// An individual transaction (coz) within a commit.
    Transaction,
    /// A data action entry.
    Action,
}

/// Summary of a principal for listing.
///
/// Returned by [`super::Indexer::list_principals`]. Lightweight
/// overview without full state details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSummary {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Current Principal Root.
    pub pr: String,
    /// Total number of commits.
    pub commit_count: u64,
    /// Timestamp of the genesis commit.
    pub created: i64,
    /// Timestamp of the most recent commit.
    pub last_updated: i64,
}
