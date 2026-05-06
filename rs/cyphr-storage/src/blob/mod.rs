//! # Content-Addressed Blob Storage
//!
//! Backend-agnostic trait for content-addressed byte storage using BLAKE3.
//!
//! BLAKE3 is deliberately disjoint from the protocol's hash algorithms
//! (SHA-256, SHA-512). Storage hashes identify raw bytes for persistence;
//! protocol digests identify semantic objects for verification. Conflating
//! the two is a design error.
//!
//! ## Implementations
//!
//! - [`FjallBlobStore`] — LSM-tree backend (production)
//! - [`MemoryBlobStore`] — `HashMap`-backed (testing)

mod fjall_store;
mod memory;

pub use fjall_store::FjallBlobStore;
pub use memory::MemoryBlobStore;

use std::fmt;
use std::str::FromStr;

/// 32-byte BLAKE3 digest used as content address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Wrap a raw 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3Hash({self})")
    }
}

impl FromStr for Blake3Hash {
    type Err = Blake3HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(Blake3HashParseError::InvalidLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).map_err(|_| Blake3HashParseError::InvalidHex)?;
            bytes[i] = u8::from_str_radix(hex, 16).map_err(|_| Blake3HashParseError::InvalidHex)?;
        }
        Ok(Self(bytes))
    }
}

/// Error parsing a hex-encoded [`Blake3Hash`].
#[derive(Debug, thiserror::Error)]
pub enum Blake3HashParseError {
    #[error("expected 64 hex characters, got {0}")]
    InvalidLength(usize),
    #[error("invalid hex character")]
    InvalidHex,
}

/// Errors from [`BlobStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    /// I/O error from the underlying storage.
    #[error("blob store I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Backend-specific error (fjall, redb, etc.).
    #[error("blob store backend error: {0}")]
    Backend(String),

    /// Content did not match the expected BLAKE3 hash.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        expected: Blake3Hash,
        actual: Blake3Hash,
    },
}

/// Content-addressed blob storage.
///
/// Implementations store raw bytes keyed by their BLAKE3 digest.
/// The trait is synchronous — async boundaries belong at the engine
/// layer, not the storage layer.
pub trait BlobStore {
    /// Store raw bytes and return their BLAKE3 digest.
    ///
    /// Idempotent: storing identical content yields the same hash
    /// and does not duplicate data.
    fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError>;

    /// Retrieve raw bytes by their BLAKE3 digest.
    ///
    /// Returns `None` if the hash is not present.
    fn get(&self, hash: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError>;

    /// Check whether a blob exists without retrieving it.
    fn exists(&self, hash: &Blake3Hash) -> Result<bool, BlobStoreError>;

    /// Iterate over all stored blobs.
    ///
    /// Used for index recovery (Phase 2). The iterator yields
    /// `Result` per item because backends may encounter I/O errors
    /// mid-iteration.
    fn iter(
        &self,
    ) -> Result<
        Box<dyn Iterator<Item = Result<(Blake3Hash, Vec<u8>), BlobStoreError>> + '_>,
        BlobStoreError,
    >;
}

#[cfg(test)]
mod tests;
