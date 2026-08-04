//! Error types for Cyphr.

use thiserror::Error;

/// Cyphr error type covering all error conditions from SPEC §17.
#[derive(Debug, Error)]
pub enum Error {
    // === ParsedCoz errors (§17.1) ===
    /// Signature does not verify against claimed key.
    #[error("invalid signature")]
    InvalidSignature,

    /// Referenced key (`tmb` or `id`) not in current KS.
    #[error("unknown key")]
    UnknownKey,

    /// Client doesn't know or support the algorithm.
    #[error("unknown algorithm")]
    UnknownAlg,

    /// `now` < the principal's latest known timestamp.
    #[error("timestamp in past")]
    TimestampPast,

    /// `now` > server time + tolerance.
    #[error("timestamp in future")]
    TimestampFuture,

    /// Signing key has `rvk` ≤ `now`.
    #[error("key revoked")]
    KeyRevoked,

    /// Missing required fields for coz type.
    #[error("malformed payload")]
    MalformedPayload,

    /// `key/create` for key already in KS.
    #[error("duplicate key")]
    DuplicateKey,

    // === State errors (§17.3) ===
    /// Computed PR does not match claimed PR.
    #[error("state mismatch")]
    StateMismatch,

    /// MultihashDigest contains no variants (internal invariant violation).
    #[error("empty multihash digest")]
    EmptyMultihash,

    /// Requested algorithm has no variant in this multihash.
    #[error("multihash has no variant for {0}")]
    MissingVariant(crate::state::HashAlg),

    // === Internal ===
    /// No active keys remain in principal.
    #[error("no active keys")]
    NoActiveKeys,

    // === Lifecycle errors (SPEC §11.4 Close, §14.9 Freeze) ===
    /// `principal/delete` or `freeze/create` signed against a principal that
    /// has already signed `principal/delete` ([no-transactions-on-deleted]).
    #[error("principal already deleted")]
    AlreadyDeleted,

    /// `freeze/create` signed against a principal that is already frozen.
    #[error("principal already frozen")]
    AlreadyFrozen,

    /// `freeze/delete` (Thaw) signed against a principal that is not frozen.
    #[error("principal not frozen")]
    NotFrozen,

    /// Algorithm not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// A backing storage/IO failure surfaced through the protocol layer
    /// (e.g. an `eml::Storage` backend error while reading or writing a
    /// commit tree root) — distinct from [`Error::UnsupportedAlgorithm`],
    /// which signals an algorithm-support question, not an infrastructure
    /// failure.
    #[error("storage failure: {0}")]
    Storage(String),

    /// A collection node (e.g. KT) was asked to hold more items than its
    /// 256-child collection-node arity boundary allows.
    ///
    /// A known, tracked gap deferred to future work — not resolved by
    /// silently extending arity or any other ad hoc handling.
    #[error("collection node exceeds 256-item arity boundary: {0} items")]
    CollectionArityExceeded(usize),

    // === Commit lifecycle errors ===
    /// Attempted to finalize an empty commit (no cozies).
    #[error("empty commit")]
    EmptyCommit,

    /// `commit` field appears on a non-terminal coz in the commit array.
    ///
    /// Per SPEC §4.4, `commit` MUST only appear on the last coz.
    #[error("commit field on non-terminal coz")]
    CommitNotLast,

    /// Terminal coz is missing the required `commit` field.
    ///
    /// Per SPEC §4.4, the last coz MUST include `"commit":<CS>`.
    #[error("missing commit field on terminal coz")]
    MissingCommit,

    /// `commit` field value does not match independently computed CS.
    ///
    /// Per SPEC §4.4, the `commit` value must equal `MR(AS, DS?)`.
    #[error("state root mismatch")]
    CommitMismatch,

    /// The leaf durably stored at a commit's position does not match the
    /// TR just computed for that commit.
    ///
    /// Signals a crash-window orphan leaf (a prior `finalize_commit` call
    /// durably appended its leaf but crashed before the index recorded the
    /// commit), not a genuine replay — the mismatched leaf's root must
    /// never be silently adopted as this commit's CR.
    #[error("durable leaf at index {0} does not match this commit's TR")]
    DurableLeafMismatch(u64),

    // === Digest parsing errors ===
    /// Malformed tagged digest string (missing separator, invalid base64).
    #[error("malformed digest: {0}")]
    MalformedDigest(&'static str),

    /// Digest length does not match the algorithm's expected output size.
    #[error("digest length mismatch for {alg}: expected {expected} bytes, got {actual}")]
    DigestLengthMismatch {
        /// The hash algorithm specified in the tagged digest.
        alg: crate::state::HashAlg,
        /// Expected digest length in bytes for this algorithm.
        expected: usize,
        /// Actual digest length in bytes received.
        actual: usize,
    },

    /// Underlying Coz error.
    #[error("coz: {0}")]
    Coz(#[from] coz::Error),
}

/// Result type for Cyphr operations.
pub type Result<T> = std::result::Result<T, Error>;
