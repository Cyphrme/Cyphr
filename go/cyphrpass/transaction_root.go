package cyphrpass

import (
	"fmt"

	"github.com/cyphrme/coz"
)

// TransactionMutationRoot is the Merkle Root of all mutation transactions (TMR).
type TransactionMutationRoot struct {
	MultihashDigest
}

// TransactionCommitRoot is the Merkle Root of the commit transaction (TCR).
type TransactionCommitRoot struct {
	MultihashDigest
}

// TransactionRoot is the combined root of TMR and TCR.
type TransactionRoot struct {
	MultihashDigest
}

// ComputeTX computes the Transaction identifier from its constituent cozies (SPEC §14.2).
// This applies cross-algorithm conversion for inner czds.
func ComputeTX(czds []TaggedCzd, algs []HashAlg) (*MultihashDigest, error) {
	if len(czds) == 0 {
		return nil, nil // Error?
	}
	if len(algs) == 0 {
		algs = []HashAlg{HashSha256}
	}

	// Implicit promotion: single czd
	if len(czds) == 1 {
		targetAlg := algs[0]
		converted, err := czds[0].ConvertTo(targetAlg)
		if err != nil {
			return nil, err
		}
		mh := FromSingleDigest(targetAlg, converted)
		return &mh, nil
	}

	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, targetAlg := range algs {
		var buf []byte
		for _, tc := range czds {
			c, err := tc.ConvertTo(targetAlg)
			if err != nil {
				return nil, fmt.Errorf("failed to convert czd to %v: %w", targetAlg, err)
			}
			buf = append(buf, c...)
		}

		res, err := coz.Hash(coz.HshAlg(targetAlg), buf)
		if err != nil {
			return nil, err
		}
		variants[targetAlg] = res
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	return &mh, nil
}

// ComputeTMR computes the Transaction Mutation Root from transaction identifiers.
func ComputeTMR(txs []MultihashDigest, algs []HashAlg) (*TransactionMutationRoot, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	if len(algs) == 0 {
		algs = []HashAlg{HashSha256}
	}

	// Implicit promotion for single transaction
	if len(txs) == 1 {
		return &TransactionMutationRoot{txs[0].Clone()}, nil
	}

	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		var buf []byte
		for _, tx := range txs {
			digest := tx.Get(alg)
			if digest == nil {
				return nil, fmt.Errorf("transaction identifier missing variant for algorithm %v", alg)
			}
			buf = append(buf, digest...)
		}
		res, err := coz.Hash(coz.HshAlg(alg), buf)
		if err != nil {
			return nil, err
		}
		variants[alg] = res
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	return &TransactionMutationRoot{mh}, nil
}

// ComputeTCR computes the Transaction Commit Root from the commit transaction's czds.
func ComputeTCR(czds []TaggedCzd, algs []HashAlg) (*TransactionCommitRoot, error) {
	mh, err := ComputeTX(czds, algs)
	if err != nil || mh == nil {
		return nil, err
	}
	return &TransactionCommitRoot{*mh}, nil
}

// ComputeTR computes the Transaction Root from TMR and TCR.
func ComputeTR(tmr *TransactionMutationRoot, tcr *TransactionCommitRoot, algs []HashAlg) (*TransactionRoot, error) {
	if tcr == nil {
		return nil, ErrEmptyCommit
	}
	if len(algs) == 0 {
		algs = []HashAlg{HashSha256}
	}

	// If no mutation transactions, implicit promotion: TR = TCR
	if tmr == nil {
		return &TransactionRoot{tcr.Clone()}, nil
	}

	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		tmrBytes := tmr.Get(alg)
		if tmrBytes == nil {
			return nil, fmt.Errorf("TMR missing variant for algorithm %v", alg)
		}
		tcrBytes := tcr.Get(alg)
		if tcrBytes == nil {
			return nil, fmt.Errorf("TCR missing variant for algorithm %v", alg)
		}

		var buf []byte
		buf = append(buf, tmrBytes...)
		buf = append(buf, tcrBytes...)

		res, err := coz.Hash(coz.HshAlg(alg), buf)
		if err != nil {
			return nil, err
		}
		variants[alg] = res
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	return &TransactionRoot{mh}, nil
}
