package cyphrpass

import (
	"slices"
	"sort"

	"github.com/cyphrme/coz"
)

// MultihashDigest is a set of equivalent digests, one per hash algorithm.
// All variants are equivalent references to the same underlying state.
// Per SPEC §14: "No single algorithm is canonical."
type MultihashDigest struct {
	variants map[HashAlg]coz.B64
}

// NewMultihashDigest creates a MultihashDigest from a map of variants.
// Returns ErrEmptyMultihash if variants is empty.
func NewMultihashDigest(variants map[HashAlg]coz.B64) (MultihashDigest, error) {
	if len(variants) == 0 {
		return MultihashDigest{}, ErrEmptyMultihash
	}
	return MultihashDigest{variants: variants}, nil
}

// FromSingleDigest creates a single-variant MultihashDigest.
func FromSingleDigest(alg HashAlg, digest coz.B64) MultihashDigest {
	return MultihashDigest{
		variants: map[HashAlg]coz.B64{alg: slices.Clone(digest)},
	}
}

// Get returns the digest for a specific algorithm, or nil if not present.
func (m MultihashDigest) Get(alg HashAlg) coz.B64 {
	return m.variants[alg]
}

// Contains returns true if this multihash has a variant for the algorithm.
func (m MultihashDigest) Contains(alg HashAlg) bool {
	_, ok := m.variants[alg]
	return ok
}

// Algorithms returns all algorithms in this multihash, sorted.
func (m MultihashDigest) Algorithms() []HashAlg {
	algs := make([]HashAlg, 0, len(m.variants))
	for alg := range m.variants {
		algs = append(algs, alg)
	}
	sort.Slice(algs, func(i, j int) bool {
		return string(algs[i]) < string(algs[j])
	})
	return algs
}

// Len returns the number of algorithm variants.
func (m MultihashDigest) Len() int {
	return len(m.variants)
}

// IsEmpty returns true if the multihash has no variants.
func (m MultihashDigest) IsEmpty() bool {
	return len(m.variants) == 0
}

// First returns the digest for the first algorithm (by sort order).
// This implements "First-Variant Fallback" per SPEC §14.
func (m MultihashDigest) First() coz.B64 {
	algs := m.Algorithms()
	if len(algs) == 0 {
		return nil
	}
	return m.variants[algs[0]]
}

// GetOrFirst returns the digest for the given algorithm, or First() if not present.
func (m MultihashDigest) GetOrFirst(alg HashAlg) coz.B64 {
	if d := m.Get(alg); d != nil {
		return d
	}
	return m.First()
}

// Clone returns a deep copy of the MultihashDigest.
func (m MultihashDigest) Clone() MultihashDigest {
	variants := make(map[HashAlg]coz.B64, len(m.variants))
	for alg, digest := range m.variants {
		variants[alg] = slices.Clone(digest)
	}
	return MultihashDigest{variants: variants}
}

// Variants returns a copy of the underlying hash variant map.
func (m MultihashDigest) Variants() map[HashAlg]coz.B64 {
	out := make(map[HashAlg]coz.B64, len(m.variants))
	for alg, digest := range m.variants {
		out[alg] = digest
	}
	return out
}
