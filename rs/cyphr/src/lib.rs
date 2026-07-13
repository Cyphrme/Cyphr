//! # Cyphr
//!
//! Self-sovereign identity protocol implementation.
//!
//! Cyphr enables password-free authentication via public key cryptography,
//! multi-device key management, and Authenticated Atomic Actions (AAA).
//!
//! Built on [Coz](https://github.com/Cyphrme/Coz) cryptographic messaging.
//!
//! ## Feature Levels
//!
//! - **Level 1**: Single static key
//! - **Level 2**: Key replacement
//! - **Level 3**: Multi-key management
//! - **Level 4**: Arbitrary data (AAA)

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod action;
pub mod commit;
/// Commit Root logic.
pub mod commit_root;
pub mod error;
pub mod hasher;
/// Portable inclusion-proof verification (F9) — free functions taking proof
/// material and a trusted root as plain parameters, with no `Principal`
/// dependency.
pub mod inclusion;
pub mod key;
/// Principal lifecycle state derivation (SPEC.md §11).
pub mod lifecycle;
pub mod multihash;
pub mod parsed_coz;
pub mod principal;
/// Principal Tree (PT) logic — the `EpochTree` backing the Principal Root.
pub mod principal_tree;
/// Semantic Tree nodes (KT, AR-node, SR-node) — generalizes `PrincipalTree`'s
/// pattern from "one instance at the root" to "one instance per semantic
/// node." See module docs for the full design.
pub mod semantic_tree;
pub mod state;
// ...
/// Transaction structure definitions.
pub mod transaction;
/// Transaction root (TR, TMR, TCR) computations.
pub mod transaction_root;

// Re-exports
pub use action::Action;
pub use commit::{Commit, CommitScope, PendingCommit};
pub use commit_root::{CommitRoot, CommitTrees, MaltHasher, verify_consistency, verify_inclusion};
// The full `eml` crate, re-exported so a durable-storage caller (e.g.
// `cyphr-storage`'s `StorageEngine<B, I, S>`) can name `eml::Storage` and
// `eml::MemoryStorage` — the bound and default for `Principal`'s storage
// type parameter — without taking its own direct dependency on `eml`.
pub use eml;
// EML/polydigest proof types.
// Re-exported so consumers can verify proofs without depending on `eml`/`polydigest` directly.
pub use eml::{ConsistencyProof, InclusionProof, LeafProof};
pub use error::Error;
pub use inclusion::{
    TransactionHop1, TransactionHop2, verify_key_inclusion, verify_transaction_inclusion,
};
pub use key::Key;
pub use multihash::MultihashDigest;
pub use parsed_coz::{CozKind, ParsedCoz, VerifiedCoz, compute_czd, verify_coz};
pub use principal::Principal;
#[cfg(any(test, feature = "test-utils"))]
pub use state::compute_pr;
pub use state::{
    AuthRoot, CommitID, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateDigest,
    StateRoot, compute_commit_id, compute_dr,
};
pub use transaction::Transaction;
pub use transaction_root::{TransactionCommitRoot, TransactionMutationRoot, TransactionRoot};
