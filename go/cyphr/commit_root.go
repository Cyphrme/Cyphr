package cyphr

import (
	"fmt"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/malt"
)

// CyphrHasher implements malt.TreeHasher for a single hash algorithm.
// Each MALT instance uses exactly one algorithm; multi-algorithm support is
// achieved by maintaining one MALT per active algorithm.
//
// The digest type is string (raw bytes cast to string) because Go's
// malt.TreeHasher requires a comparable type and []byte is not comparable.
type CyphrHasher struct {
	alg HashAlg
}

// NewCyphrHasher creates a hasher for a single hash algorithm.
func NewCyphrHasher(alg HashAlg) *CyphrHasher {
	return &CyphrHasher{alg: alg}
}

// Leaf computes H(0x00 || data).
func (h *CyphrHasher) Leaf(data []byte) string {
	prefixData := make([]byte, 1+len(data))
	prefixData[0] = 0x00
	copy(prefixData[1:], data)
	return string(hashBytesPanic(h.alg, prefixData))
}

func hashBytesPanic(alg HashAlg, data []byte) coz.B64 {
	b, err := hashConcatBytes(alg, data)
	if err != nil {
		panic(fmt.Sprintf("MALT invariant violation: hash failed %v", err))
	}
	return b
}

// Node computes H(0x01 || left || right).
func (h *CyphrHasher) Node(left, right string) string {
	l := []byte(left)
	r := []byte(right)
	d := make([]byte, 1+len(l)+len(r))
	d[0] = 0x01
	copy(d[1:], l)
	copy(d[1+len(l):], r)
	return string(hashBytesPanic(h.alg, d))
}

// Empty computes H("").
func (h *CyphrHasher) Empty() string {
	return string(hashBytesPanic(h.alg, []byte{}))
}

// CommitRoot represents the finalized state of the verifiable MALT log.
type CommitRoot struct {
	*MultihashDigest
}

// CommitLog is a single-algorithm MALT instance for CR computation.
type CommitLog = malt.Log[string]

// CommitTrees maps each active hash algorithm to its own MALT instance.
// CR is assembled from the roots of all active MALTs.
type CommitTrees map[HashAlg]*CommitLog

// NewCommitRootFromTrees assembles a CommitRoot MultihashDigest from the
// roots of per-algorithm MALTs.
func NewCommitRootFromTrees(trees CommitTrees) (*CommitRoot, error) {
	variants := make(map[HashAlg]coz.B64, len(trees))
	for alg, log := range trees {
		variants[alg] = coz.B64(log.Root())
	}
	md, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	return &CommitRoot{MultihashDigest: &md}, nil
}

// ComputeCR computes the CR incrementally over a list of TRs.
func ComputeCR(trs []*MultihashDigest, algs []HashAlg) (*CommitRoot, error) {
	trees := make(CommitTrees, len(algs))
	for _, alg := range algs {
		trees[alg] = malt.New[string](NewCyphrHasher(alg))
	}

	for _, tr := range trs {
		for _, alg := range algs {
			// [conversion]: if TR lacks this alg, GetOrFirst returns the
			// available variant's bytes. The MALT leaf hash H(0x00 || bytes)
			// provides the conversion naturally.
			trees[alg].Append(tr.GetOrFirst(alg))
		}
	}

	return NewCommitRootFromTrees(trees)
}
