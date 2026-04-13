package cyphr

import "github.com/cyphrme/coz"

// Revocation holds information about a revoked key.
type Revocation struct {
	// Rvk is the revocation timestamp (SPEC rvk field).
	// Signatures with now >= rvk are invalid.
	Rvk int64

	// By is the thumbprint of the key that performed the revocation.
	// nil for self-revoke, non-nil for other-revoke.
	By *coz.B64
}

// Key extends coz.Key with Cyphr lifecycle tracking.
type Key struct {
	*coz.Key

	// FirstSeen is when this key was first added to the principal.
	FirstSeen int64

	// LastUsed is the last time this key signed a valid coz/action.
	LastUsed int64

	// Revocation holds revocation info. nil if the key is active.
	Revocation *Revocation
}

// IsActive returns true if the key is not revoked.
func (k *Key) IsActive() bool {
	return k.Revocation == nil
}

// IsActiveAt returns true if the key was active at the given timestamp.
// This is critical for validating historical cozies.
// Per SPEC §11.3: Signatures with now >= rvk are invalid.
func (k *Key) IsActiveAt(timestamp int64) bool {
	if k.Revocation == nil {
		return true
	}
	return timestamp < k.Revocation.Rvk
}
