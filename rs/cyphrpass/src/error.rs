//! Error types for Cyphrpass.

use thiserror::Error;

/// Cyphrpass error type covering all error conditions from SPEC §14.
#[derive(Debug, Error)]
pub enum Error {
    // === Transaction errors (§14.1) ===
    /// Signature does not verify against claimed key.
    #[error("invalid signature")]
    InvalidSignature,

    /// Referenced key (`tmb` or `id`) not in current KS.
    #[error("unknown key")]
    UnknownKey,

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

    /// `key/add` for key already in KS.
    #[error("duplicate key")]
    DuplicateKey,

    /// Signing keys do not meet required weight (Level 5+).
    #[error("threshold not met")]
    ThresholdNotMet,

    // === Recovery errors (§14.2) ===
    /// Agent not registered via `recovery/designate`.
    #[error("recovery not designated")]
    RecoveryNotDesignated,

    /// Recovery attempted while regular keys are active.
    #[error("account recoverable")]
    AccountRecoverable,

    /// No active keys AND no designated recovery agents.
    #[error("account unrecoverable")]
    AccountUnrecoverable,

    // === State errors (§14.3) ===
    /// Computed PS does not match claimed PS.
    #[error("state mismatch")]
    StateMismatch,

    /// `pre` references do not form valid chain to known state.
    #[error("chain broken")]
    ChainBroken,

    /// Derivation computed with wrong algorithm.
    #[error("derivation mismatch")]
    DerivationMismatch,

    // === Action errors (§14.4) ===
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

    /// Underlying Coz error.
    #[error("coz: {0}")]
    Coz(#[from] coz::Error),
}

/// Result type for Cyphrpass operations.
pub type Result<T> = std::result::Result<T, Error>;
