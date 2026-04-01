package cyphrpass

import "github.com/cyphrme/coz"

// ApplyTransactionUnsafe applies a coz without signature verification.
// This function is intended ONLY for testing where signatures are validated
// externally or cannot be generated (e.g., fixture-based tests).
//
// It computes commit_state post-mutation (per SPEC §4.4) since test
// cozies don't go through the signing path.
//
// # Errors
//
//   - ErrTimestampPast: ParsedCoz timestamp is older than latest seen
//   - ErrTimestampFuture: ParsedCoz timestamp is too far in the future
//   - ErrInvalidPrior: ParsedCoz's pre doesn't match current PS
//   - ErrNoActiveKeys: Would leave principal with no active keys
//   - ErrDuplicateKey: Adding key already in KS
func (p *Principal) ApplyTransactionUnsafe(cz *ParsedCoz, newKey *coz.Key) (*Commit, error) {
	// Apply mutation eagerly
	if err := p.applyCozInternal(cz, newKey); err != nil {
		return nil, err
	}

	// Compute SR from post-mutation state
	thumbprints := make([]coz.B64, len(p.auth.Keys))
	for i, k := range p.auth.Keys {
		thumbprints[i] = k.Tmb
	}
	kr, err := ComputeKR(thumbprints, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	ar, err := ComputeAR(kr, nil, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	sr, err := ComputeSR(ar, p.dr, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}

	// Inject state_root into coz
	cz.Arrow = sr.MultihashDigest

	// Finalize as single-cz commit
	pending := NewPendingCommit(p.hashAlg)
	pending.Push(cz)
	return p.finalizeCommit(pending)
}
