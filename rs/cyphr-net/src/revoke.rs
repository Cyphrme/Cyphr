//! Verification of a naked revoke (SPEC 6.4). The rule lives in core
//! ([`cyphr::revoke`]) so that this verifier, the server's `POST /revoke`
//! and the storage engine cannot disagree about what a valid revoke is.

pub use cyphr::revoke::{NakedRevoke, RevokeFailure, verify_naked_revoke};
