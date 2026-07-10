//! Domain types for the relational index.
//!
//! These types live at the storage boundary — they carry serialized
//! representations of protocol state (strings, blob hashes), not live
//! protocol objects. The engine (Phase 3) bridges protocol types to
//! these index-level representations.

use crate::blob::Blake3Hash;

/// Per-Coz metadata for the canonical event log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct IndexableCoz {
    /// BLAKE3 hash of the coz blob.
    pub blob_hash: Blake3Hash,
    /// Tagged protocol digest (primary czd variant).
    pub czd: String,
    /// Action type (e.g., "cyphr.me/cyphr/key/create").
    pub typ: String,
    /// Signer thumbprint.
    pub tmb: String,
    /// Algorithm.
    pub alg: String,
    /// Timestamp (Unix seconds).
    pub now: i64,
    /// Raw JSON pay object (for unstructured data queries).
    pub payload: Option<String>,
}

/// Input to [`super::Indexer::index_commit`].
///
/// Constructed by the engine from a validated `cyphr::Commit`.
/// All digest fields are pre-serialized (base64url or tagged digest
/// strings) — the indexer stores them verbatim.
///
/// Serializable so the engine can embed a full copy of it inside a
/// durable, content-addressed commit-manifest blob (see
/// `engine::CommitManifest`) — the index-rebuild signal that keeps the
/// blob store the sole source of truth for a commit's ingest order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexableCommit {
    /// Principal genesis identifier (tagged digest string).
    pub principal_id: String,
    /// Commit ID variants (tagged digest strings).
    pub commit_ids: Vec<String>,
    /// Commit sequence number within this principal (0-indexed).
    pub sequence: u64,
    /// Prior PR variants (tagged digest strings, None for genesis).
    pub pre: Option<String>,
    /// Principal Root variants after this commit (tagged digest strings).
    pub prs: Vec<String>,
    /// State Root variants after this commit (tagged digest strings).
    pub srs: Vec<String>,
    /// Auth Root variants after this commit (tagged digest strings).
    pub ars: Vec<String>,
    /// Commit Root variants after this commit (tagged digest strings).
    ///
    /// Empty for commits that predate any CR (there is none at genesis —
    /// PR = SR until the first commit populates the EML log).
    pub crs: Vec<String>,
    /// BLAKE3 hashes of individual coz blobs stored for this commit.
    pub blob_hashes: Vec<Blake3Hash>,
    /// Per-coz metadata for the event log.
    pub cozies: Vec<IndexableCoz>,
    /// Timestamp of the commit (from the commit transaction's `now` field).
    pub timestamp: i64,
    /// Public keys extracted from key-introducing transactions.
    pub keys: Vec<PublicKeyInfo>,
}

/// Public key metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Public key thumbprint.
    pub thumbprint: String,
    /// Cryptographic algorithm (e.g., "ED25519").
    pub algorithm: String,
    /// Base64url-encoded public key.
    pub public_key: String,
}

/// Current tip state for a principal.
///
/// Returned by [`super::Indexer::get_tip`]. Represents the latest
/// known state without replaying the full commit history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TipState {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Current Principal Root.
    pub pr: String,
    /// Current State Root.
    pub sr: String,
    /// Current Auth Root.
    pub ar: String,
    /// Current Commit Root (empty string if no commit has populated the EML
    /// log yet).
    pub cr: String,
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CommitRef {
    /// Commit ID (tagged digest string).
    pub commit_id: String,
    /// Commit sequence number (0-indexed).
    pub sequence: u64,
    /// Prior PR (chain link, None for genesis).
    pub pre: Option<String>,
    /// Principal Root after this commit.
    pub pr: String,
    /// State Root after this commit.
    pub sr: String,
    /// Auth Root after this commit.
    pub ar: String,
    /// Commit Root after this commit (empty string if none yet).
    pub cr: String,
    /// BLAKE3 hashes of blobs belonging to this commit.
    pub blob_hashes: Vec<Blake3Hash>,
}

/// Reference to an entity resolved by digest.
///
/// Returned by [`super::Indexer::resolve_digest`]. Maps a
/// protocol-level tagged digest to a storage-level blob hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EntityRef {
    /// The tagged digest string that was resolved.
    pub digest: String,
    /// BLAKE3 hash of the blob containing this entity.
    pub blob_hash: Blake3Hash,
    /// What kind of entity this digest refers to.
    pub entity_type: EntityType,
}

/// Classification of indexed entities.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
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
