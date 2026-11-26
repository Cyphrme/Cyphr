//! Error types for Cyphr.

use thiserror::Error;

/// Cyphr error type covering all error conditions from SPEC §17.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The signing backend failed (see [`crate::signer`]).
    #[error(transparent)]
    Signer(#[from] crate::signer::SignerError),

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

    /// A key's `tmb` is not the thumbprint of its public key.
    #[error("key tmb does not match its public key")]
    TmbMismatch,

    /// `pay.alg` differs from the signing key's algorithm. An absent
    /// `alg` is [`Error::MalformedPayload`] (SPEC 2.3.1).
    #[error("pay alg does not match signing key alg")]
    AlgMismatch,

    /// The supplied `czd` is not the digest of the signed bytes.
    #[error("czd does not match signed bytes")]
    CzdMismatch,

    /// `key/create` for key already in KS.
    #[error("duplicate key")]
    DuplicateKey,

    /// `principal/create` for a principal that already exists (SPEC §7.6:
    /// `create` of an existing item fails with `DUPLICATE`).
    #[error("duplicate principal")]
    DuplicatePrincipal,

    /// `nonce/create` for a nonce already at that level (SPEC §7.6, §10.2).
    #[error("duplicate nonce")]
    DuplicateNonce,

    /// `nonce/delete` for a nonce not at that level.
    #[error("unknown nonce")]
    UnknownNonce,

    /// A transaction coz this principal already included is submitted
    /// again (SPEC §7.6). The first inclusion stays authoritative.
    #[error("COZ_REUSE: transaction coz already included by this principal")]
    CozReuse,

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

    /// A transaction other than the lifecycle ones, or a data action,
    /// against a frozen principal (SPEC §2.3.2, §11.2: no mutations until
    /// unfrozen).
    #[error("principal frozen: rejected until thawed")]
    Frozen,

    /// The signer is a key of an embedded principal that is in `Error`
    /// (SPEC §10.5, §11.1): authorization through it is `Error` too.
    #[error("embedded principal in error: authorization through it refused")]
    EmbeddedErrored,

    /// A transaction's cozies do not all carry one identical `typ`
    /// (SPEC §4.1).
    #[error("transaction cozies do not share one typ")]
    MixedTransactionTyp,

    /// A commit's only mutation transaction holds more than one coz. The
    /// signed `arrow` covers the mutation root, which a lone grouped
    /// transaction shares with the same cozies as separate transactions,
    /// so admitting both would give one signed commit two identities.
    #[error(
        "commit's only mutation transaction holds more than one coz: the grouping is ambiguous \
         with separate transactions"
    )]
    LoneGroupedTransaction,

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

    // === Commit lifecycle errors ===
    /// Attempted to finalize an empty commit (no cozies).
    #[error("empty commit")]
    EmptyCommit,

    /// The genesis is incomplete: a commit on a principal not yet created
    /// lacks its `principal/create` (a commit chain begins with the
    /// genesis commit, SPEC 5.1 steps 3-4), or a `principal/create` comes
    /// while a genesis key has no `key/create` (SPEC 5.1 step 1, 7.7
    /// Example 1).
    #[error("genesis incomplete")]
    GenesisIncomplete,

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
    /// Signals an orphan leaf: a log leaf with no commit behind it, which
    /// the mismatched leaf's root must never be adopted for. Reachable only
    /// for a log written before the two-phase commit, when a commit's leaf
    /// was appended before the commit was recorded and a crash or refusal
    /// in between left it behind; a commit's leaf is now written only after
    /// its commit is staged whole and, through the storage engine, recorded
    /// in the blob store.
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

impl Error {
    /// Whether the refusal is that the signer was not active at the
    /// signature's `now`: unknown to the key history then, revoked, or a
    /// key of an embedded principal in Error.
    #[must_use]
    pub fn is_inactive_signer(&self) -> bool {
        matches!(
            self,
            Self::UnknownKey | Self::KeyRevoked | Self::EmbeddedErrored
        )
    }

    /// The variant's own identifier, payload ignored. This is the one
    /// vocabulary for refusal names (golden corpus, fixture generator,
    /// storage tables). The `match` has no wildcard arm so that a new
    /// variant does not compile until it is named.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Signer(..) => "Signer",
            Self::InvalidSignature => "InvalidSignature",
            Self::UnknownKey => "UnknownKey",
            Self::UnknownAlg => "UnknownAlg",
            Self::TimestampPast => "TimestampPast",
            Self::TimestampFuture => "TimestampFuture",
            Self::KeyRevoked => "KeyRevoked",
            Self::MalformedPayload => "MalformedPayload",
            Self::TmbMismatch => "TmbMismatch",
            Self::AlgMismatch => "AlgMismatch",
            Self::CzdMismatch => "CzdMismatch",
            Self::DuplicateKey => "DuplicateKey",
            Self::DuplicatePrincipal => "DuplicatePrincipal",
            Self::DuplicateNonce => "DuplicateNonce",
            Self::UnknownNonce => "UnknownNonce",
            Self::CozReuse => "CozReuse",
            Self::StateMismatch => "StateMismatch",
            Self::EmptyMultihash => "EmptyMultihash",
            Self::MissingVariant(..) => "MissingVariant",
            Self::NoActiveKeys => "NoActiveKeys",
            Self::AlreadyDeleted => "AlreadyDeleted",
            Self::AlreadyFrozen => "AlreadyFrozen",
            Self::NotFrozen => "NotFrozen",
            Self::Frozen => "Frozen",
            Self::EmbeddedErrored => "EmbeddedErrored",
            Self::MixedTransactionTyp => "MixedTransactionTyp",
            Self::LoneGroupedTransaction => "LoneGroupedTransaction",
            Self::UnsupportedAlgorithm(..) => "UnsupportedAlgorithm",
            Self::Storage(..) => "Storage",
            Self::EmptyCommit => "EmptyCommit",
            Self::GenesisIncomplete => "GenesisIncomplete",
            Self::CommitNotLast => "CommitNotLast",
            Self::MissingCommit => "MissingCommit",
            Self::CommitMismatch => "CommitMismatch",
            Self::DurableLeafMismatch(..) => "DurableLeafMismatch",
            Self::MalformedDigest(..) => "MalformedDigest",
            Self::DigestLengthMismatch { .. } => "DigestLengthMismatch",
            Self::Coz(..) => "Coz",
        }
    }
}
