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
pub mod principal;
pub mod state;
pub mod transaction;

// Re-exports
pub use action::Action;
pub use commit::{Commit, PendingCommit};
pub use error::Error;
pub use key::Key;
pub use multihash::MultihashDigest;
pub use principal::Principal;
pub use state::{
    AuthState, DataState, HashAlg, KeyState, PrincipalRoot, PrincipalState, TransactionState,
    compute_as, compute_ds, compute_ks, compute_ps, compute_ts,
};
pub use transaction::{Transaction, TransactionKind, VerifiedTransaction, verify_transaction};
