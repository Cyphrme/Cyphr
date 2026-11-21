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

/// Key material for a commit (SPEC 4.6.2 `keys`, 5.2): the public keys
/// the commit's key-introducing cozies name by thumbprint.
pub use cyphr::replay::KeyEntry;
pub use export::{ExportError, export_commits};
pub use import::{Genesis, LoadError, load_principal_from_commits};
pub use index::PublicKeyInfo;

/// A stored bundle line: one finalized commit, or the data actions
/// recorded between two commits.
///
/// Each line holds, in the SPEC 4.6.2 JSON wire form:
/// - `txs`: the commit's transactions, each an array of its cozies in signed order, the commit
///   transaction last (empty on an action-only line)
/// - `keys`: the public keys the commit's key-introducing cozies name (SPEC 5.2)
/// - `actions`: data actions recorded before the transactions (an action-only line holds only
///   these)
/// - `commit_id`: the commit's TR
/// - `ar`, `sr`, `pr`: the roots after the line
///
/// The derived state digests enable efficient indexing and verification
/// without replaying the full coz history.
///
/// Serialized with a top-level `v` (the bundle format version). A reader
/// takes a line without `v` (from before versions) as v1 and refuses any
/// version but the supported one as [`BundleError::UnsupportedVersion`].
#[derive(Debug, Clone, Default)]
pub struct CommitEntry {
    /// Data actions recorded before the transactions.
    pub actions: Vec<serde_json::Value>,
    /// The commit's transactions, each its cozies in signed order.
    pub txs: Vec<Vec<serde_json::Value>>,
    /// Key material introduced in this commit.
    pub keys: Vec<KeyEntry>,
    /// Commit ID: the commit's TR (empty on an action-only line).
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

/// The one bundle-line format version this build reads and writes. Version
/// 2 nests `txs` by transaction (SPEC 4.6.2) and carries data actions in
/// `actions`; a version 1 line's flat `txs` is not read as either.
const BUNDLE_VERSION: u64 = 2;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<serde_json::Value>,
    txs: Vec<Vec<serde_json::Value>>,
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
            actions: self.actions.clone(),
            txs: self.txs.clone(),
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

    /// The line's bundle in the wire form a push carries.
    ///
    /// # Errors
    ///
    /// A coz value that does not serialize (never, for parsed JSON).
    pub fn bundle(&self) -> Result<cyphr::replay::WireBundle, serde_json::Error> {
        Ok(cyphr::replay::WireBundle {
            actions: self
                .actions
                .iter()
                .map(serde_json::to_vec)
                .collect::<Result<_, _>>()?,
            txs: self
                .txs
                .iter()
                .map(|tx| tx.iter().map(serde_json::to_vec).collect())
                .collect::<Result<_, _>>()?,
            keys: self.keys.clone(),
        })
    }

    /// The line of `bundle` (its roots left empty): each coz parsed as
    /// JSON.
    ///
    /// # Errors
    ///
    /// A coz that is not JSON.
    pub fn from_bundle(bundle: &cyphr::replay::WireBundle) -> Result<Self, serde_json::Error> {
        let value = |blob: &Vec<u8>| serde_json::from_slice(blob);
        Ok(Self {
            actions: bundle.actions.iter().map(value).collect::<Result<_, _>>()?,
            txs: bundle
                .txs
                .iter()
                .map(|tx| tx.iter().map(value).collect())
                .collect::<Result<_, _>>()?,
            keys: bundle.keys.clone(),
            ..Self::default()
        })
    }

    fn from_value(doc: serde_json::Value) -> Result<Self, BundleError> {
        // Version first, so a line of another version reads as an
        // unsupported version, never as a malformed one.
        let found = match doc.get("v") {
            None => 1,
            Some(v) => v.as_u64().ok_or_else(|| {
                <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
            })?,
        };
        if found != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion {
                found,
                supported: BUNDLE_VERSION,
            });
        }
        let line: Line = serde_json::from_value(doc)?;
        Ok(Self {
            actions: line.actions,
            txs: line.txs,
            keys: line.keys,
            commit_id: line.commit_id,
            auth_root: line.auth_root,
            sr: line.sr,
            pr: line.pr,
        })
    }
}
