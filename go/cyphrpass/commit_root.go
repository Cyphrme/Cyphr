package cyphrpass

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/malt"
)

// CyphrpassMultiHasher implements malt.TreeHasher for Cyphrpass.
// It uses a canonical string representation of MultihashDigest as the comparable digest type.
type CyphrpassMultiHasher struct {
	activeAlgs []HashAlg
}

func NewCyphrpassMultiHasher(activeAlgs []HashAlg) *CyphrpassMultiHasher {
	return &CyphrpassMultiHasher{activeAlgs: activeAlgs}
}

// Leaf computes H(0x00 || data) for all active algorithms.
func (h *CyphrpassMultiHasher) Leaf(data []byte) string {
	prefixData := make([]byte, 1+len(data))
	prefixData[0] = 0x00
	copy(prefixData[1:], data)

	variants := make(map[HashAlg]coz.B64)
	for _, alg := range h.activeAlgs {
		variants[alg] = hashBytesPanic(alg, prefixData)
	}
	return serializeVariants(variants)
}

func hashBytesPanic(alg HashAlg, data []byte) coz.B64 {
	b, err := hashConcatBytes(alg, data)
	if err != nil {
		panic(fmt.Sprintf("MALT invariant violation: hash failed %v", err))
	}
	return b
}

// Node computes H(0x01 || left || right) for all active algorithms.
func (h *CyphrpassMultiHasher) Node(left, right string) string {
	lMap, err := deserializeVariants(left)
	if err != nil {
		panic(fmt.Sprintf("MALT invariant violation: left node invalid: %v", err))
	}
	rMap, err := deserializeVariants(right)
	if err != nil {
		panic(fmt.Sprintf("MALT invariant violation: right node invalid: %v", err))
	}

	variants := make(map[HashAlg]coz.B64)
	for _, alg := range h.activeAlgs {
		lDig := lMap[alg]
		rDig := rMap[alg]
		if lDig == nil || rDig == nil {
			panic(fmt.Sprintf("MALT invariant violation: missing variant %s", alg))
		}

		d := make([]byte, 1+len(lDig)+len(rDig))
		d[0] = 0x01
		copy(d[1:], lDig)
		copy(d[1+len(lDig):], rDig)

		variants[alg] = hashBytesPanic(alg, d)
	}
	return serializeVariants(variants)
}

// Empty computes H("") for all active algorithms.
func (h *CyphrpassMultiHasher) Empty() string {
	variants := make(map[HashAlg]coz.B64)
	for _, alg := range h.activeAlgs {
		variants[alg] = hashBytesPanic(alg, []byte{})
	}
	return serializeVariants(variants)
}

// -- Deterministic Serialization Helpers --

func serializeVariants(v map[HashAlg]coz.B64) string {
	algs := make([]string, 0, len(v))
	for a := range v {
		algs = append(algs, string(a))
	}
	sort.Strings(algs)

	var sb strings.Builder
	for i, a := range algs {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(a)
		sb.WriteByte(':')
		sb.WriteString(v[HashAlg(a)].String())
	}
	return sb.String()
}

func deserializeVariants(s string) (map[HashAlg]coz.B64, error) {
	out := make(map[HashAlg]coz.B64)
	if s == "" {
		return out, nil
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		idx := strings.IndexByte(p, ':')
		if idx == -1 {
			return nil, fmt.Errorf("invalid format")
		}
		alg := HashAlg(p[:idx])
		b64str := p[idx+1:]
		b64, err := coz.Decode(b64str)
		if err != nil {
			return nil, err
		}
		out[alg] = b64
	}
	return out, nil
}

// CommitRoot represents the finalized state of the verifiable MALT log.
type CommitRoot struct {
	*MultihashDigest
}

type CommitLog = malt.Log[string]

// NewCommitRootFromString rebuilds a CommitRoot from MALT tree root output.
func NewCommitRootFromString(s string) (*CommitRoot, error) {
	v, err := deserializeVariants(s)
	if err != nil {
		return nil, err
	}
	md, err := NewMultihashDigest(v)
	if err != nil {
		return nil, err
	}
	return &CommitRoot{MultihashDigest: &md}, nil
}

// ComputeCR computes the CR incrementally over a list of TRs.
func ComputeCR(trs []*MultihashDigest, algs []HashAlg) (*CommitRoot, error) {
	hasher := NewCyphrpassMultiHasher(algs)
	log := malt.New[string](hasher)

	for _, tr := range trs {
		// Concatenate the digests of all active algorithms deterministically
		var bytesData []byte
		for _, alg := range algs {
			bytesData = append(bytesData, tr.GetOrFirst(alg)...)
		}
		log.Append(bytesData)
	}

	rootStr := log.Root()
	v, err := deserializeVariants(rootStr)
	if err != nil {
		return nil, err
	}
	md, err := NewMultihashDigest(v)
	if err != nil {
		return nil, err
	}
	return &CommitRoot{MultihashDigest: &md}, nil
}
