//! Error types for Cyphrpass.

use thiserror::Error;

/// Cyphrpass error type covering all error conditions from SPEC §17.
#[derive(Debug, Error)]
pub enum Error {
    // === Transaction errors (§17.1) ===
    /// Signature does not verify against claimed key.
    #[error("invalid signature")]
    InvalidSignature,

    /// Referenced key (`tmb` or `id`) not in current KS.
    #[error("unknown key")]
    UnknownKey,

    /// Client doesn't know or support the algorithm.
    #[error("unknown algorithm")]
    UnknownAlg,

    /// `pre` does not match current AS.
    #[error("invalid prior state")]
    InvalidPrior,

    /// `now` < latest known PS timestamp.
    #[error("timestamp in past")]
    TimestampPast,

    /// `now` > server time + tolerance.
    #[error("timestamp in future")]
    TimestampFuture,

    /// Signing key has `rvk` ≤ `now`.
    #[error("key revoked")]
    KeyRevoked,

    /// Missing required fields for transaction type.
    #[error("malformed payload")]
    MalformedPayload,

    /// `key/create` for key already in KS.
    #[error("duplicate key")]
    DuplicateKey,

    /// Signing keys do not meet required weight (Level 5+).
    #[error("threshold not met")]
    ThresholdNotMet,

    // === Recovery errors (§17.2) ===
    /// Agent not registered via `recovery/designate`.
    #[error("recovery not designated")]
    RecoveryNotDesignated,

    /// Recovery attempted while regular keys are active.
    #[error("account recoverable")]
    AccountRecoverable,

    /// No active keys AND no designated recovery agents.
    #[error("unrecoverable principal")]
    UnrecoverablePrincipal,

    // === State errors (§17.3) ===
    /// Computed PS does not match claimed PS.
    #[error("state mismatch")]
    StateMismatch,

    /// `pre` references do not form valid chain to known state.
    #[error("chain broken")]
    ChainBroken,

    /// Multihash variant computed with wrong algorithm.
    #[error("hash algorithm mismatch")]
    HashAlgMismatch,

    // === Action errors (§17.4) ===
    /// Action `typ` not permitted for this key (Level 5+).
    #[error("unauthorized action")]
    UnauthorizedAction,

    // === Internal ===
    /// No active keys remain in principal.
    #[error("no active keys")]
    NoActiveKeys,

    /// Algorithm not supported.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    // === Commit lifecycle errors ===
    /// Attempted to begin a commit while one is already in progress.
    #[error("commit already in progress")]
    CommitInProgress,

    /// Attempted to finalize when no commit is pending.
    #[error("no pending commit")]
    NoPendingCommit,

    /// Attempted to finalize an empty commit (no transactions).
    #[error("empty commit")]
    EmptyCommit,

    /// Last transaction in commit missing `commit: true` marker.
    #[error("missing finalization marker")]
    MissingFinalizationMarker,

    /// External reference to transitory (unfinalized) commit state.
    ///
    /// Per SPEC §4.2.1, transitory state during a pending commit cannot
    /// be referenced by external transactions until the commit is finalized.
    #[error("transitory state reference")]
    TransitoryStateReference,

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

/// Result type for Cyphrpass operations.
pub type Result<T> = std::result::Result<T, Error>;
