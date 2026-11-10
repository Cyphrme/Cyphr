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
///
/// Serialized with a top-level `v` (the bundle format version). A reader
/// takes a line without `v` (from before versions) as v1 and refuses any
/// other version as [`BundleError::UnsupportedVersion`].
#[derive(Debug, Clone)]
pub struct CommitEntry {
    /// ParsedCoz entries in this commit bundle.
    pub cozies: Vec<serde_json::Value>,
    /// Key material introduced in this commit.
    pub keys: Vec<KeyEntry>,
    /// Commit ID (per-commit Merkle root of coz czds).
    pub commit_id: String,
    /// Auth Root after this commit; `None` when the commit left the
    /// principal with no key (Dead, SPEC §3.7), written as JSON `null`.
    pub auth_root: Option<String>,
    /// State Root: root of the principal's StateTree (SPEC §3.7.2);
    /// promotes from AR when no Data Root is present, otherwise the
    /// tree root over AR and DR. `None` (JSON `null`) when the commit left
    /// no key and the principal holds no data.
    pub sr: Option<String>,
    /// Principal Root after this commit.
    pub pr: String,
}

/// The one bundle-line format version this build reads and writes.
const BUNDLE_VERSION: u64 = 1;

/// Why a bundle line could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    /// The line states a format version this build does not read. The text
    /// names the variant so the refusal stays identifiable when it crosses
    /// a plain serde boundary (flattened to a message).
    #[error("UnsupportedVersion: bundle version {found} is not the supported {supported}")]
    UnsupportedVersion {
        /// The version the line states.
        found: u64,
        /// The one version this build reads.
        supported: u64,
    },
    /// The line is not a bundle entry of the expected shape.
    #[error("malformed bundle line: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// A bundle line as it appears on the wire (the version is checked by
/// [`CommitEntry::from_value`] before the body is read).
#[derive(serde::Serialize, serde::Deserialize)]
struct Line {
    #[serde(default, skip_deserializing)]
    v: u64,
    #[serde(rename = "txs")]
    cozies: Vec<serde_json::Value>,
    keys: Vec<KeyEntry>,
    commit_id: String,
    // No `default`: an absent root is `null`, and a missing field is a
    // malformed line, not an absent root.
    #[serde(rename = "ar", deserialize_with = "required_nullable")]
    auth_root: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    sr: Option<String>,
    pr: String,
}

/// Read a field that must be present but may be `null`.
fn required_nullable<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    <Option<String> as serde::Deserialize>::deserialize(deserializer)
}

impl serde::Serialize for CommitEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Cloning keeps `Line` one owned shape for both directions; a
        // bundle line is exported once, not on a hot path.
        Line {
            v: BUNDLE_VERSION,
            cozies: self.cozies.clone(),
            keys: self.keys.clone(),
            commit_id: self.commit_id.clone(),
            auth_root: self.auth_root.clone(),
            sr: self.sr.clone(),
            pr: self.pr.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CommitEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let doc = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        Self::from_value(doc).map_err(serde::de::Error::custom)
    }
}

impl CommitEntry {
    /// Create a new commit entry from components.
    pub fn new(
        cozies: Vec<serde_json::Value>,
        keys: Vec<KeyEntry>,
        commit_id: String,
        auth_root: Option<String>,
        sr: Option<String>,
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
    ///
    /// # Errors
    ///
    /// [`BundleError::UnsupportedVersion`] for a line stating a version
    /// other than the supported one, checked before the rest of the line is
    /// interpreted; [`BundleError::Malformed`] otherwise.
    pub fn from_json(json: &str) -> Result<Self, BundleError> {
        Self::from_value(serde_json::from_str(json)?)
    }

    fn from_value(doc: serde_json::Value) -> Result<Self, BundleError> {
        // Version first, so a future line's differently shaped body reads
        // as an unsupported version, never as a malformed one.
        if let Some(v) = doc.get("v") {
            let found = v.as_u64().ok_or_else(|| {
                <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
            })?;
            if found != BUNDLE_VERSION {
                return Err(BundleError::UnsupportedVersion {
                    found,
                    supported: BUNDLE_VERSION,
                });
            }
        }
        let line: Line = serde_json::from_value(doc)?;
        Ok(Self {
            cozies: line.cozies,
            keys: line.keys,
            commit_id: line.commit_id,
            auth_root: line.auth_root,
            sr: line.sr,
            pr: line.pr,
        })
    }
}
