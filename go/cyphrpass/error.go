package cyphrpass

import "errors"

// Transaction errors (SPEC §14.1)
var (
	// ErrInvalidSignature indicates the signature does not verify against the claimed key.
	ErrInvalidSignature = errors.New("cyphrpass: invalid signature")

	// ErrUnknownKey indicates the referenced key (tmb or id) is not in current KS.
	ErrUnknownKey = errors.New("cyphrpass: unknown key")

	// ErrInvalidPrior indicates pre does not match current AS.
	ErrInvalidPrior = errors.New("cyphrpass: invalid prior state")

	// ErrTimestampPast indicates now < latest known PS timestamp.
	ErrTimestampPast = errors.New("cyphrpass: timestamp in past")

	// ErrTimestampFuture indicates now > server time + tolerance.
	ErrTimestampFuture = errors.New("cyphrpass: timestamp in future")

	// ErrKeyRevoked indicates the signing key has rvk ≤ now.
	ErrKeyRevoked = errors.New("cyphrpass: key revoked")

	// ErrMalformedPayload indicates missing required fields for transaction type.
	ErrMalformedPayload = errors.New("cyphrpass: malformed payload")

	// ErrDuplicateKey indicates key/add for a key already in KS.
	ErrDuplicateKey = errors.New("cyphrpass: duplicate key")

	// ErrThresholdNotMet indicates signing keys do not meet required weight (Level 5+).
	ErrThresholdNotMet = errors.New("cyphrpass: threshold not met")
)

// Recovery errors (SPEC §14.2)
var (
	// ErrRecoveryNotDesignated indicates agent not registered via recovery/designate.
	ErrRecoveryNotDesignated = errors.New("cyphrpass: recovery not designated")

	// ErrAccountRecoverable indicates recovery attempted while regular keys are active.
	ErrAccountRecoverable = errors.New("cyphrpass: account recoverable")

	// ErrAccountUnrecoverable indicates no active keys AND no designated recovery agents.
	ErrAccountUnrecoverable = errors.New("cyphrpass: account unrecoverable")
)

// State errors (SPEC §14.3)
var (
	// ErrStateMismatch indicates computed PS does not match claimed PS.
	ErrStateMismatch = errors.New("cyphrpass: state mismatch")

	// ErrChainBroken indicates pre references do not form valid chain to known state.
	ErrChainBroken = errors.New("cyphrpass: chain broken")

	// ErrDerivationMismatch indicates derivation computed with wrong algorithm.
	ErrDerivationMismatch = errors.New("cyphrpass: derivation mismatch")
)

// Action errors (SPEC §14.4)
var (
	// ErrUnauthorizedAction indicates action typ not permitted for this key (Level 5+).
	ErrUnauthorizedAction = errors.New("cyphrpass: unauthorized action")
)

// Internal errors
var (
	// ErrNoActiveKeys indicates no active keys remain in principal.
	ErrNoActiveKeys = errors.New("cyphrpass: no active keys")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("cyphrpass: unsupported algorithm")

	// ErrEmptyCommit indicates an attempt to finalize a commit with no transactions.
	ErrEmptyCommit = errors.New("cyphrpass: empty commit")

	// ErrEmptyMultihash indicates an attempt to create a MultihashDigest with no variants.
	ErrEmptyMultihash = errors.New("cyphrpass: empty multihash digest")

	// ErrMalformedDigest indicates a tagged digest string is malformed
	// (missing separator, wrong length, or invalid JSON encoding).
	ErrMalformedDigest = errors.New("cyphrpass: malformed digest")
)
