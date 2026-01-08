//! Transaction types for Auth State mutations.
//!
//! Per SPEC §4.2.

use coz::{Czd, Thumbprint};

use crate::state::AuthState;

/// Transaction types (SPEC §4.2).
#[derive(Debug, Clone)]
pub enum TransactionKind {
    /// Add a new key (Level 3+) - SPEC §4.2.1
    KeyAdd {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key being added.
        id: Thumbprint,
    },

    /// Remove key without invalidation (Level 3+) - SPEC §4.2.2
    KeyDelete {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key being deleted.
        id: Thumbprint,
    },

    /// Atomic key swap (Level 2+) - SPEC §4.2.3
    KeyReplace {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of new key.
        id: Thumbprint,
    },

    /// Self-revoke (Level 1+) - SPEC §4.2.4
    SelfRevoke {
        /// Revocation timestamp.
        rvk: i64,
    },

    /// Other-revoke (Level 3+) - SPEC §4.2.5
    OtherRevoke {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key to revoke.
        id: Thumbprint,
        /// Revocation timestamp.
        rvk: i64,
    },
}

/// A verified transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction kind.
    pub kind: TransactionKind,
    /// Signer's thumbprint.
    pub signer: Thumbprint,
    /// Transaction timestamp.
    pub now: i64,
    /// Coz digest (unique identifier).
    pub czd: Czd,
}
