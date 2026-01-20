package cyphrpass

import "github.com/cyphrme/coz"

// ApplyTransactionUnsafe applies a transaction without signature verification.
// This function is intended ONLY for testing where signatures are validated
// externally or cannot be generated (e.g., fixture-based tests).
//
// Production code should use VerifyTransaction + ApplyVerified instead.
//
// # Errors
//
//   - ErrTimestampPast: Transaction timestamp is older than latest seen
//   - ErrTimestampFuture: Transaction timestamp is too far in the future
//   - ErrInvalidPrior: Transaction's pre doesn't match current Auth State
//   - ErrNoActiveKeys: Would leave principal with no active keys
//   - ErrDuplicateKey: Adding key already in KS
func (p *Principal) ApplyTransactionUnsafe(tx *Transaction, newKey *coz.Key) error {
	return p.applyTransactionInternal(tx, newKey)
}
