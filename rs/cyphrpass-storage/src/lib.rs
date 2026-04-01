//! # Cyphrpass Storage
//!
//! Storage backends for the Cyphrpass identity protocol.
//!
//! This crate provides a backend-agnostic storage API for persisting
//! Cyphrpass principals, cozies, and actions. The core `Store` trait
//! defines the minimal interface that any storage backend must implement.
//!
//! ## Design Principles
//!
//! - **Storage is dumb**: The storage layer only handles bytes. All semantic
//!   operations (verification, state computation) are handled by `cyphrpass`.
//! - **Immutable history**: Entries are append-only; past entries are never modified.
//! - **Order via `pre` chain**: Canonical order is derived from coz `pre`
//!   field chaining, not storage order.
//! - **Bit-perfect preservation**: Entries store original JSON bytes to ensure
//!   correct `czd` computation. See `Entry` for details.
//!
//! ## Included Backends
//!
//! - [`FileStore`]: File-based storage using JSONL format (one file per principal).

#![forbid(unsafe_code)]

mod export;
mod file;
mod import;

pub use export::{ExportError, PersistError, export_commits, export_entries, persist_entries};
pub use file::{FileStore, FileStoreError};
pub use import::{
    Checkpoint, Genesis, LoadError, load_from_checkpoint, load_principal,
    load_principal_from_commits,
};

use cyphrpass::state::PrincipalGenesis;
use serde_json::value::RawValue;

/// Storage backend trait.
///
/// Implementations provide persistence for signed Cyphrpass entries
/// (cozies and actions). The trait is intentionally minimal:
/// storage backends need only handle append and retrieval operations.
pub trait Store {
    /// The error type for this store implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Append a signed entry to the log.
    fn append_entry(&self, pr: &PrincipalGenesis, entry: &Entry) -> Result<(), Self::Error>;

    /// Retrieve all entries for a principal.
    fn get_entries(&self, pr: &PrincipalGenesis) -> Result<Vec<Entry>, Self::Error>;

    /// Retrieve entries with filtering (supports coz patches).
    fn get_entries_range(
        &self,
        pr: &PrincipalGenesis,
        opts: &QueryOpts,
    ) -> Result<Vec<Entry>, Self::Error>;

    /// Check if principal exists in storage.
    fn exists(&self, pr: &PrincipalGenesis) -> Result<bool, Self::Error>;
}

/// Query options for filtered retrieval.
#[derive(Default, Debug, Clone)]
pub struct QueryOpts {
    /// Only include entries with `now` > this timestamp.
    pub after: Option<i64>,
    /// Only include entries with `now` < this timestamp.
    pub before: Option<i64>,
    /// Maximum number of entries to return.
    pub limit: Option<usize>,
}

/// A stored entry preserving bit-perfect JSON bytes.
///
/// **CRITICAL INVARIANT**: The original JSON string is preserved exactly as received.
/// This ensures correct `czd` computation, which hashes the exact bytes of `pay`.
///
/// ## The Re-serialization Trap
///
/// A naive approach would parse JSON into `serde_json::Value`, then re-serialize
/// for `czd` computation. This breaks signatures because re-serialization can change:
/// - Field ordering
/// - Whitespace
/// - Number representation (e.g., `1.0` → `1`)
///
/// By storing `Box<RawValue>`, we preserve the original bytes and extract `pay`
/// from the same source, ensuring bit-perfect fidelity.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw JSON string (bit-perfect, used for czd computation).
    raw_json: Box<RawValue>,
    /// The `now` timestamp extracted from pay.now (for filtering).
    pub now: i64,
}

impl Entry {
    /// Create an entry from a raw JSON string.
    ///
    /// This is the primary constructor for entries loaded from storage.
    /// The original bytes are preserved exactly.
    ///
    /// # Errors
    ///
    /// Returns `EntryError::InvalidJson` if the string is not valid JSON.
    /// Returns `EntryError::MissingNow` if `pay.now` is missing or not an integer.
    pub fn from_json(json: String) -> Result<Self, EntryError> {
        // Validate and convert to RawValue
        let raw_json: Box<RawValue> =
            serde_json::from_str(&json).map_err(|_| EntryError::InvalidJson)?;

        // Extract timestamp for filtering
        let now = Self::extract_now(&json)?;

        Ok(Self { raw_json, now })
    }

    /// Create an entry from an owned RawValue.
    ///
    /// Useful when deserializing from a format that already provides RawValue.
    pub fn from_raw_value(raw: Box<RawValue>) -> Result<Self, EntryError> {
        let now = Self::extract_now(raw.get())?;
        Ok(Self { raw_json: raw, now })
    }

    /// Create an entry from a serde_json::Value.
    ///
    /// **Warning**: This serializes the Value, which may not preserve original
    /// byte ordering. Use only when creating new entries (e.g., during export),
    /// not when loading from storage.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, EntryError> {
        let json = serde_json::to_string(value).map_err(|_| EntryError::InvalidJson)?;
        Self::from_json(json)
    }

    /// Get the raw JSON string.
    ///
    /// This returns the exact bytes stored, suitable for I/O operations.
    pub fn raw_json(&self) -> &str {
        self.raw_json.get()
    }

    /// Parse the entry as a serde_json::Value.
    ///
    /// Use this for field access (e.g., extracting `typ`, `key`).
    /// **Do NOT use the resulting Value for czd computation** - use `pay_bytes()` instead.
    pub fn as_value(&self) -> Result<serde_json::Value, EntryError> {
        serde_json::from_str(self.raw_json.get()).map_err(|_| EntryError::InvalidJson)
    }

    /// Extract the `pay` field as raw bytes, preserving exact byte sequence.
    ///
    /// This is the critical method for `czd` computation. It extracts the `pay`
    /// field from the original JSON, preserving exact bytes including whitespace
    /// and field ordering.
    ///
    /// # Implementation Note
    ///
    /// We parse the raw JSON into a structure with RawValue for the pay field,
    /// then return those bytes. This ensures we're extracting from the preserved
    /// original, not re-serializing.
    pub fn pay_bytes(&self) -> Result<Vec<u8>, EntryError> {
        // Parse with pay as RawValue to preserve its exact bytes
        #[derive(serde::Deserialize)]
        struct PayExtractor<'a> {
            #[serde(borrow)]
            pay: &'a RawValue,
        }

        let extractor: PayExtractor =
            serde_json::from_str(self.raw_json.get()).map_err(|_| EntryError::MissingPay)?;

        Ok(extractor.pay.get().as_bytes().to_vec())
    }

    /// Extract `pay.now` timestamp from JSON string.
    fn extract_now(json: &str) -> Result<i64, EntryError> {
        #[derive(serde::Deserialize)]
        struct PayNow {
            now: i64,
        }
        #[derive(serde::Deserialize)]
        struct NowExtractor {
            pay: PayNow,
        }

        let extractor: NowExtractor =
            serde_json::from_str(json).map_err(|_| EntryError::MissingNow)?;
        Ok(extractor.pay.now)
    }
}

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
    pub cozies: Vec<serde_json::Value>,
    /// Key material introduced in this commit.
    pub keys: Vec<KeyEntry>,
    /// Commit ID (per-commit Merkle root of coz czds).
    #[serde(alias = "ts")]
    pub commit_id: String,
    /// Auth Root after this commit.
    #[serde(rename = "ar")]
    pub auth_root: String,
    /// State Root: MR(AR, DR?).
    #[serde(alias = "cs")]
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

/// Errors that can occur when working with entries.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// Entry is not valid JSON.
    #[error("invalid JSON")]
    InvalidJson,
    /// Entry is missing the required `pay.now` field.
    #[error("entry missing pay.now field")]
    MissingNow,
    /// Entry is missing the required `pay` field.
    #[error("entry missing pay field")]
    MissingPay,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_from_json_extracts_now() {
        let json = r#"{"pay":{"now":12345,"typ":"test"},"sig":"AAAA"}"#.to_string();
        let entry = Entry::from_json(json).unwrap();
        assert_eq!(entry.now, 12345);
    }

    #[test]
    fn entry_raw_json_preserves_bytes() {
        let json = r#"{"pay":{"now":12345,"typ":"test"},"sig":"AAAA"}"#.to_string();
        let entry = Entry::from_json(json.clone()).unwrap();
        assert_eq!(entry.raw_json(), json);
    }

    #[test]
    fn entry_pay_bytes_extracts_exact_bytes() {
        let json = r#"{"pay":{"now":12345,"typ":"test"},"sig":"AAAA"}"#.to_string();
        let entry = Entry::from_json(json).unwrap();
        let pay_bytes = entry.pay_bytes().unwrap();
        assert_eq!(
            String::from_utf8(pay_bytes).unwrap(),
            r#"{"now":12345,"typ":"test"}"#
        );
    }

    #[test]
    fn entry_missing_now_fails() {
        let json = r#"{"pay":{"typ":"test"},"sig":"AAAA"}"#.to_string();
        let result = Entry::from_json(json);
        assert!(matches!(result, Err(EntryError::MissingNow)));
    }

    #[test]
    fn entry_missing_pay_fails() {
        let json = r#"{"sig":"AAAA"}"#.to_string();
        let result = Entry::from_json(json);
        assert!(matches!(result, Err(EntryError::MissingNow)));
    }

    #[test]
    fn entry_invalid_json_fails() {
        let json = "not json".to_string();
        let result = Entry::from_json(json);
        assert!(matches!(result, Err(EntryError::InvalidJson)));
    }
}
