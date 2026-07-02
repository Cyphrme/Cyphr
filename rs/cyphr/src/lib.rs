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
pub mod key;
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
// EML proof types.
// Re-exported so consumers can verify proofs without depending on `eml` directly.
pub use eml::{ConsistencyProof, InclusionProof};
pub use error::Error;
pub use key::Key;
pub use multihash::MultihashDigest;
pub use parsed_coz::{CozKind, ParsedCoz, VerifiedCoz, verify_coz};
pub use principal::Principal;
pub use state::{
    AuthRoot, CommitID, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateDigest,
    StateRoot, compute_ar, compute_commit_id, compute_dr, compute_kr, compute_pr, compute_sr,
};
pub use transaction::Transaction;
pub use transaction_root::{TransactionCommitRoot, TransactionMutationRoot, TransactionRoot};
