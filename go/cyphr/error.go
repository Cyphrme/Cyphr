package cyphr

import "errors"

// ParsedCoz errors (SPEC §14.1)
var (
	// ErrInvalidSignature indicates the signature does not verify against the claimed key.
	ErrInvalidSignature = errors.New("cyphr: invalid signature")

	// ErrUnknownKey indicates the referenced key (tmb or id) is not in current KS.
	ErrUnknownKey = errors.New("cyphr: unknown key")

	// ErrInvalidPrior indicates pre does not match current AS.
	ErrInvalidPrior = errors.New("cyphr: invalid prior state")

	// ErrTimestampPast indicates now < latest known PS timestamp.
	ErrTimestampPast = errors.New("cyphr: timestamp in past")

	// ErrTimestampFuture indicates now > server time + tolerance.
	ErrTimestampFuture = errors.New("cyphr: timestamp in future")

	// ErrKeyRevoked indicates the signing key has rvk ≤ now.
	ErrKeyRevoked = errors.New("cyphr: key revoked")

	// ErrMalformedPayload indicates missing required fields for coz type.
	ErrMalformedPayload = errors.New("cyphr: malformed payload")

	// ErrDuplicateKey indicates key/add for a key already in KS.
	ErrDuplicateKey = errors.New("cyphr: duplicate key")

	// ErrThresholdNotMet indicates signing keys do not meet required weight (Level 5+).
	ErrThresholdNotMet = errors.New("cyphr: threshold not met")
)

// Recovery errors (SPEC §14.2)
var (
	// ErrRecoveryNotDesignated indicates agent not registered via recovery/designate.
	ErrRecoveryNotDesignated = errors.New("cyphr: recovery not designated")

	// ErrAccountRecoverable indicates recovery attempted while regular keys are active.
	ErrAccountRecoverable = errors.New("cyphr: account recoverable")

	// ErrAccountUnrecoverable indicates no active keys AND no designated recovery agents.
	ErrAccountUnrecoverable = errors.New("cyphr: account unrecoverable")
)

// State errors (SPEC §14.3)
var (
	// ErrStateMismatch indicates computed PS does not match claimed PS.
	ErrStateMismatch = errors.New("cyphr: state mismatch")

	// ErrChainBroken indicates pre references do not form valid chain to known state.
	ErrChainBroken = errors.New("cyphr: chain broken")

	// ErrDerivationMismatch indicates derivation computed with wrong algorithm.
	ErrDerivationMismatch = errors.New("cyphr: derivation mismatch")
)

// Action errors (SPEC §14.4)
var (
	// ErrUnauthorizedAction indicates action typ not permitted for this key (Level 5+).
	ErrUnauthorizedAction = errors.New("cyphr: unauthorized action")
)

// Internal errors
var (
	// ErrNoActiveKeys indicates no active keys remain in principal.
	ErrNoActiveKeys = errors.New("cyphr: no active keys")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("cyphr: unsupported algorithm")

	// ErrEmptyCommit indicates an attempt to finalize a commit with no cozies.
	ErrEmptyCommit = errors.New("cyphr: empty commit")

	// ErrCommitNotLast indicates a commit field appeared on a non-terminal coz.
	// Per SPEC §4.4, commit MUST only appear on the last coz.
	ErrCommitNotLast = errors.New("cyphr: commit field on non-terminal coz")

	// ErrMissingCommit indicates the terminal coz is missing the required commit field.
	// Per SPEC §4.4, the last coz MUST include "commit":<CS>.
	ErrMissingCommit = errors.New("cyphr: missing commit field on terminal coz")

	// ErrCommitMismatch indicates the commit field value does not match independently computed CS.
	// Per SPEC §4.4, the commit value must equal MR(AS, DS?).
	ErrCommitMismatch = errors.New("cyphr: state root mismatch")

	// ErrEmptyMultihash indicates an attempt to create a MultihashDigest with no variants.
	ErrEmptyMultihash = errors.New("cyphr: empty multihash digest")

	// ErrMalformedDigest indicates a tagged digest string is malformed
	// (missing separator, wrong length, or invalid JSON encoding).
	ErrMalformedDigest = errors.New("cyphr: malformed digest")
)
