//! # DAOLFMT
//!
//! Dense, Append-Only, Left-Filled Merkle Tree conforming to
//! [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1).
//!
//! This crate provides a generic, append-only Merkle tree parameterized by a
//! [`TreeHasher`] trait. It supports incremental construction, root extraction,
//! inclusion proofs, and consistency proofs.
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
//!
//! # Panic Policy
//!
//! This crate uses `expect()` in two locations where the stack state is
//! guaranteed by structural invariants:
//!
//! - [`Log::append`] — merge pops are bounded by `count_trailing_ones(size)`,
//!   which guarantees sufficient stack depth by construction (A-STACK).
//! - [`Log::root`] — fold over a non-empty stack (guarded by `size > 0`).
//!
//! These are **not** input-validation panics. They guard invariants proven
//! correct by the formal model (§3.4 A-STACK, A-EQUIV). Converting them to
//! `Result` would impose API ergonomic cost for genuinely impossible errors.

mod error;
mod proof;
mod tree;

pub use error::Error;
pub use proof::{ConsistencyProof, InclusionProof, verify_consistency, verify_inclusion};
pub use tree::{Log, TreeHasher};
