package storage

import "errors"

// Storage errors.
var (
	// ErrInvalidJSON indicates the entry is not valid JSON.
	ErrInvalidJSON = errors.New("invalid JSON")

	// ErrMissingPay indicates the entry is missing the required pay field.
	ErrMissingPay = errors.New("entry missing pay field")

	// ErrMissingSig indicates the entry is missing the required sig field.
	ErrMissingSig = errors.New("entry missing sig field")

	// ErrMissingNow indicates the entry is missing the required pay.now field.
	ErrMissingNow = errors.New("entry missing pay.now field")

	// ErrNoGenesisKeys indicates genesis was attempted with no keys.
	ErrNoGenesisKeys = errors.New("genesis requires at least one key")

	// ErrBrokenChain indicates a transaction's pre field doesn't match expected AS.
	ErrBrokenChain = errors.New("broken chain: pre mismatch")

	// ErrUnknownSigner indicates the signer key is not in the principal's key set.
	ErrUnknownSigner = errors.New("unknown signer")

	// ErrInvalidSignature indicates signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")
)
