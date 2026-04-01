//! # Cyphrpass
//!
//! Self-sovereign identity protocol implementation.
//!
//! Cyphrpass enables password-free authentication via public key cryptography,
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
pub mod error;
pub mod key;
pub mod multihash;
pub mod parsed_coz;
pub mod principal;
pub mod state;
// ...
/// Transaction structure definitions.
pub mod transaction;
/// Transaction root (TR, TMR, TCR) computations.
pub mod transaction_root;

// Re-exports
pub use action::Action;
pub use commit::{Commit, CommitScope, PendingCommit};
pub use error::Error;
pub use key::Key;
pub use multihash::MultihashDigest;
pub use parsed_coz::{CozKind, ParsedCoz, VerifiedCoz, verify_coz};
pub use principal::Principal;
pub use state::{
    AuthRoot, CommitID, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot,
    compute_ar, compute_commit_id, compute_dr, compute_kr, compute_pr, compute_sr,
};
pub use transaction::{CommitTransaction, Transaction};
pub use transaction_root::{TransactionCommitRoot, TransactionMutationRoot, TransactionRoot};
