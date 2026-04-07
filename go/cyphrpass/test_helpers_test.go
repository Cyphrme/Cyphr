package cyphrpass

import "github.com/cyphrme/coz"

// ApplyTransactionUnsafe applies a coz without signature verification.
// This function is intended ONLY for testing where signatures are validated
// externally or cannot be generated (e.g., fixture-based tests).
//
// It computes the state_root post-mutation (per SPEC §4.4) since test
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

	// Push mutation coz to transactions (no arrow — that goes on commitTx)
	pending := NewPendingCommit(p.hashAlg)
	pending.PushTx(Transaction{cz})

	// Compute SR from post-mutation state
	// Compute SR from post-mutation state
	postAlgs := DeriveHashAlgs(p.auth.Keys)
	thumbprints := make([]coz.B64, len(p.auth.Keys))
	for i, k := range p.auth.Keys {
		thumbprints[i] = k.Tmb
	}
	kr, err := ComputeKR(thumbprints, nil, postAlgs)
	if err != nil {
		return nil, err
	}
	ar, err := ComputeAR(kr, nil, nil, postAlgs)
	if err != nil {
		return nil, err
	}
	sr, err := ComputeSR(ar, p.dr, nil, postAlgs)
	if err != nil {
		return nil, err
	}

	// Compute TMR from pending transactions
	// CZDs are single-algorithm, so TMR uses the signer's algorithm.
	txAlg := cz.HashAlg
	tmr, err := ComputeTMRFromPending(pending.transactions, []HashAlg{txAlg})
	if err != nil {
		return nil, err
	}

	// Ascertain Pre (previous PR) — p.pr is correctly initialized
	pre := p.pr

	// Compute Arrow = hash_sorted_concat(pre, sr, tmr) per SPEC
	components := [][]byte{
		pre.GetOrFirst(txAlg),
		sr.GetOrFirst(txAlg),
		tmr.GetOrFirst(txAlg),
	}
	arrowDigest, err := hashSortedConcatBytes(txAlg, components...)
	if err != nil {
		return nil, err
	}
	arrowMD := FromSingleDigest(txAlg, arrowDigest)

	// Create a synthetic commit coz with arrow for the commitTx slot.
	commitCoz := &ParsedCoz{
		Kind:    TxCommitCreate,
		Signer:  cz.Signer,
		Now:     cz.Now,
		Czd:     cz.Czd, // Synthetic — not used for real verification
		HashAlg: cz.HashAlg,
		Arrow:   &arrowMD,
	}
	pending.PushTx(Transaction{commitCoz})

	return p.finalizeCommit(pending)
}
