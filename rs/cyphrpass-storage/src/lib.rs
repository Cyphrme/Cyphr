//! # Cyphrpass Storage
//!
//! Storage backends for the Cyphrpass identity protocol.
//!
//! This crate provides a backend-agnostic storage API for persisting
//! Cyphrpass principals, transactions, and actions. The core `Store` trait
//! defines the minimal interface that any storage backend must implement.
//!
//! ## Design Principles
//!
//! - **Storage is dumb**: The storage layer only handles bytes. All semantic
//!   operations (verification, state computation) are handled by `cyphrpass`.
//! - **Immutable history**: Entries are append-only; past entries are never modified.
//! - **Order via `pre` chain**: Canonical order is derived from transaction `pre`
//!   field chaining, not storage order.
//!
//! ## Included Backends
//!
//! - [`FileStore`]: File-based storage using JSONL format (one file per principal).

mod file;

pub use file::FileStore;

use cyphrpass::state::PrincipalRoot;

/// Storage backend trait.
///
/// Implementations provide persistence for signed Cyphrpass entries
/// (transactions and actions). The trait is intentionally minimal:
/// storage backends need only handle append and retrieval operations.
pub trait Store {
    /// The error type for this store implementation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Append a signed entry to the log.
    fn append_entry(&self, pr: &PrincipalRoot, entry: &Entry) -> Result<(), Self::Error>;

    /// Retrieve all entries for a principal.
    fn get_entries(&self, pr: &PrincipalRoot) -> Result<Vec<Entry>, Self::Error>;

    /// Retrieve entries with filtering (supports transaction patches).
    fn get_entries_range(
        &self,
        pr: &PrincipalRoot,
        opts: &QueryOpts,
    ) -> Result<Vec<Entry>, Self::Error>;

    /// Check if principal exists in storage.
    fn exists(&self, pr: &PrincipalRoot) -> Result<bool, Self::Error>;
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

/// A stored entry (transaction or action as raw Coz message).
///
/// Entries are stored as raw JSON values to keep the storage layer simple.
/// Parsing and verification is handled by `cyphrpass::Principal`.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw JSON value of the signed Coz message.
    pub raw: serde_json::Value,
    /// The `now` timestamp extracted from the entry (for filtering).
    pub now: i64,
}

impl Entry {
    /// Create a new entry from a raw JSON value.
    ///
    /// Extracts the `now` timestamp from `pay.now`.
    pub fn from_value(raw: serde_json::Value) -> Result<Self, EntryError> {
        let now = raw
            .get("pay")
            .and_then(|p| p.get("now"))
            .and_then(|n| n.as_i64())
            .ok_or(EntryError::MissingNow)?;

        Ok(Self { raw, now })
    }
}

/// Errors that can occur when working with entries.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// Entry is missing the required `pay.now` field.
    #[error("entry missing pay.now field")]
    MissingNow,
}
