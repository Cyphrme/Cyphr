//! # DAOLFMT
//!
//! Dense, Append-Only, Left-Filled Merkle Tree conforming to
//! [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1).
//!
//! This crate provides a generic, append-only Merkle tree parameterized by a
//! [`TreeHasher`] trait. It supports incremental construction, root extraction,
//! and (in future) inclusion and consistency proofs.
//!
//! The tree has **zero external dependencies** — callers provide their own hash
//! implementation via [`TreeHasher`].
//!
//! # Usage
//!
//! ```ignore
//! use daolfmt::{Log, TreeHasher};
//!
//! // Implement TreeHasher for your hash function, then:
//! let mut log = Log::new(my_hasher);
//! log.append(b"first entry");
//! log.append(b"second entry");
//! let root = log.root();
//! ```

mod error;
mod proof;
mod tree;

pub use error::Error;
pub use proof::{ConsistencyProof, InclusionProof, verify_consistency, verify_inclusion};
pub use tree::{Log, TreeHasher, mth};
