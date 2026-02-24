package cyphrpass

import (
	"bytes"
	"fmt"
	"slices"
	"sort"

	"github.com/cyphrme/coz"
)

// State types wrap MultihashDigest for type safety. Each represents a Merkle digest
// at different levels of the Cyphrpass state tree per SPEC §7.
// Per SPEC §14, each state has one variant per active hash algorithm.

// KeyState (KS) is the digest of active key thumbprints (SPEC §7.2).
// Single key with no nonce: KS = tmb (implicit promotion).
type KeyState struct {
	MultihashDigest
}

// CommitID is the digest of transaction czds within a single commit (SPEC §8.5).
// Previously named TransactionState; renamed to reflect its role as the
// identity of a commit rather than a state-tree node.
type CommitID struct {
	MultihashDigest
}

// AuthState (AS) is the authentication state: MR(KS, RS?) or promoted (SPEC §8.4).
type AuthState struct {
	MultihashDigest
}

// CommitState (CS) binds an Auth State to a specific commit: MR(AS, CommitID) (SPEC §8.5).
type CommitState struct {
	MultihashDigest
}

// DataState (DS) is the state of user actions (SPEC §7.4).
// Currently single-algorithm (Cad-based), per Rust implementation.
type DataState struct {
	digest coz.B64
}

// NewDataState creates a DataState from a digest.
func NewDataState(digest coz.B64) DataState {
	return DataState{digest: slices.Clone(digest)}
}

// Bytes returns the raw digest bytes.
func (d DataState) Bytes() coz.B64 {
	return d.digest
}

// PrincipalState (PS) is the current top-level state: MR(CS, DS?) or promoted (SPEC §8.3).
type PrincipalState struct {
	MultihashDigest
}

// PrincipalRoot (PR) is the first PS ever computed. Permanent, never changes (SPEC §7.7).
// Frozen at genesis with only the genesis-time algorithm variants.
type PrincipalRoot struct {
	MultihashDigest
}

// NewPrincipalRoot creates a PrincipalRoot from the initial PrincipalState.
func NewPrincipalRoot(ps PrincipalState) PrincipalRoot {
	return PrincipalRoot{ps.Clone()}
}

// HashAlg is a hash algorithm used for state computation (SPEC §12).
type HashAlg coz.HshAlg

// String returns the hash algorithm name.
func (h HashAlg) String() string {
	return string(h)
}

// Common hash algorithms (re-exported for convenience).
const (
	HashSha256 HashAlg = "SHA-256"
	HashSha384 HashAlg = "SHA-384"
	HashSha512 HashAlg = "SHA-512"
)

// ParseHashAlg parses a hash algorithm name string (e.g., "SHA-256").
// Returns an error if the algorithm is not recognized.
func ParseHashAlg(s string) (HashAlg, error) {
	switch s {
	case "SHA-256":
		return HashSha256, nil
	case "SHA-384":
		return HashSha384, nil
	case "SHA-512":
		return HashSha512, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

// DigestLength returns the expected byte length for a hash algorithm.
func (h HashAlg) DigestLength() int {
	switch h {
	case HashSha256:
		return 32
	case HashSha384:
		return 48
	case HashSha512:
		return 64
	default:
		return 0
	}
}

// TaggedDigest is a digest with its algorithm explicitly specified.
// Format: "ALG:base64url" (e.g., "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg").
// This enforces "Parse, Don't Validate" at the wire boundary.
type TaggedDigest struct {
	Alg    HashAlg
	Digest coz.B64
}

// ParseTaggedDigest parses an "ALG:digest" string.
// Returns an error if:
// - Format is invalid (missing colon)
// - Algorithm is unsupported
// - Digest length doesn't match algorithm requirements
func ParseTaggedDigest(s string) (TaggedDigest, error) {
	idx := -1
	for i, c := range s {
		if c == ':' {
			idx = i
			break
		}
	}
	if idx == -1 {
		return TaggedDigest{}, ErrMalformedDigest
	}

	algStr := s[:idx]
	digestStr := s[idx+1:]

	alg, err := ParseHashAlg(algStr)
	if err != nil {
		return TaggedDigest{}, fmt.Errorf("invalid tagged digest: %w", err)
	}

	digest, err := coz.Decode(digestStr)
	if err != nil {
		return TaggedDigest{}, fmt.Errorf("invalid tagged digest: base64 decode failed: %w", err)
	}

	// Validate digest length matches algorithm
	expectedLen := alg.DigestLength()
	if len(digest) != expectedLen {
		return TaggedDigest{}, ErrMalformedDigest
	}

	return TaggedDigest{Alg: alg, Digest: digest}, nil
}

// String returns the canonical "ALG:base64url" representation.
func (td TaggedDigest) String() string {
	return fmt.Sprintf("%s:%s", td.Alg, td.Digest.String())
}

// MarshalJSON implements json.Marshaler.
func (td TaggedDigest) MarshalJSON() ([]byte, error) {
	return []byte(`"` + td.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (td *TaggedDigest) UnmarshalJSON(data []byte) error {
	// Remove quotes
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("invalid tagged digest JSON: %w", ErrMalformedDigest)
	}
	s := string(data[1 : len(data)-1])

	parsed, err := ParseTaggedDigest(s)
	if err != nil {
		return err
	}
	*td = parsed
	return nil
}

// String methods for state types (return base64 of first variant for compatibility).
func (s KeyState) String() string       { return s.First().String() }
func (s CommitID) String() string       { return s.First().String() }
func (s AuthState) String() string      { return s.First().String() }
func (s CommitState) String() string    { return s.First().String() }
func (s DataState) String() string      { return s.digest.String() }
func (s PrincipalState) String() string { return s.First().String() }
func (s PrincipalRoot) String() string  { return s.First().String() }

// Tagged returns the AuthState as an algorithm-prefixed digest string.
// Format: "ALG:base64url" (e.g., "SHA-256:digest...").
// Uses the lexicographically first algorithm for deterministic output.
func (s AuthState) Tagged() string {
	algs := s.Algorithms()
	if len(algs) == 0 {
		return ""
	}
	firstAlg := algs[0]
	digest := s.Get(firstAlg)
	return fmt.Sprintf("%s:%s", firstAlg, digest.String())
}

// Tagged returns the CommitState as an algorithm-prefixed digest string.
// Format: "ALG:base64url" (e.g., "SHA-256:digest...").
// Uses the lexicographically first algorithm for deterministic output.
// This is the canonical format for the `pre` field in transactions.
func (s CommitState) Tagged() string {
	algs := s.Algorithms()
	if len(algs) == 0 {
		return ""
	}
	firstAlg := algs[0]
	digest := s.Get(firstAlg)
	return fmt.Sprintf("%s:%s", firstAlg, digest.String())
}

// HashAlgFromSEAlg returns the hash algorithm for a given signing/encryption algorithm.
// Uses SEAlg.Hash() method per Coz API.
func HashAlgFromSEAlg(alg coz.SEAlg) HashAlg {
	return HashAlg(alg.Hash())
}

// DeriveHashAlgs extracts the set of hash algorithms from active keys (SPEC §14).
// Returns a sorted, deduplicated slice.
func DeriveHashAlgs(keys []*Key) []HashAlg {
	seen := make(map[HashAlg]bool)
	for _, k := range keys {
		if k.IsActive() {
			alg := HashAlgFromSEAlg(k.Alg)
			seen[alg] = true
		}
	}

	algs := make([]HashAlg, 0, len(seen))
	for alg := range seen {
		algs = append(algs, alg)
	}
	sort.Slice(algs, func(i, j int) bool {
		return string(algs[i]) < string(algs[j])
	})
	return algs
}

// isSupportedAlg checks if the algorithm is supported by Cyphrpass.
// Per SPEC §12: ES256, ES384, ES512, Ed25519.
func isSupportedAlg(alg coz.SEAlg) bool {
	switch string(alg) {
	case "ES256", "ES384", "ES512", "Ed25519":
		return true
	default:
		return false
	}
}

// hashSortedConcatBytes implements SPEC §7.1 canonical digest algorithm:
// 1. Collect component digests
// 2. Sort lexicographically (byte comparison)
// 3. Concatenate sorted digests
// 4. Hash using specified algorithm
func hashSortedConcatBytes(alg HashAlg, components ...[]byte) (coz.B64, error) {
	if len(components) == 0 {
		return nil, nil
	}

	// Sort lexicographically by byte comparison
	sorted := make([][]byte, len(components))
	copy(sorted, components)
	slices.SortFunc(sorted, bytes.Compare)

	// Concatenate
	var buf bytes.Buffer
	for _, c := range sorted {
		buf.Write(c)
	}

	// Hash using the specified algorithm
	return coz.Hash(coz.HshAlg(alg), buf.Bytes())
}

// ComputeKS computes Key State from thumbprints (SPEC §7.2).
// If only one thumbprint with no nonce, KS = tmb (implicit promotion).
// Computes one variant per algorithm in algs.
func ComputeKS(thumbprints []coz.B64, nonce coz.B64, algs []HashAlg) (KeyState, error) {
	if len(thumbprints) == 0 {
		return KeyState{}, ErrNoActiveKeys
	}
	if len(algs) == 0 {
		return KeyState{}, ErrNoActiveKeys
	}

	// Implicit promotion: single key, no nonce
	// Use first algorithm for single-variant multihash
	if len(thumbprints) == 1 && len(nonce) == 0 {
		return KeyState{FromSingleDigest(algs[0], thumbprints[0])}, nil
	}

	// Collect all components
	components := make([][]byte, 0, len(thumbprints)+1)
	for _, t := range thumbprints {
		components = append(components, t)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return KeyState{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return KeyState{}, err
	}
	return KeyState{mh}, nil
}

// ComputeCommitID computes the Commit ID (formerly Transaction State) from czds (SPEC §8.5).
// The Commit ID is the Merkle root of the czds within a single commit.
// If only one transaction with no nonce, CommitID = czd (implicit promotion).
// Returns nil if no transactions.
func ComputeCommitID(czds []coz.B64, nonce coz.B64, algs []HashAlg) (*CommitID, error) {
	if len(czds) == 0 {
		return nil, nil // No transactions = nil CommitID
	}
	if len(algs) == 0 {
		algs = []HashAlg{HashSha256} // Default fallback
	}

	// Implicit promotion: single transaction, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		cid := CommitID{FromSingleDigest(algs[0], czds[0])}
		return &cid, nil
	}

	components := make([][]byte, 0, len(czds)+1)
	for _, c := range czds {
		components = append(components, c)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return nil, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	cid := CommitID{mh}
	return &cid, nil
}

// ComputeAS computes Auth State from KS (SPEC §8.4).
// AS = MR(KS, RS?) — authentication state derived from the keyset.
// If no nonce (and no RS), AS = KS (implicit promotion).
func ComputeAS(ks KeyState, nonce coz.B64, algs []HashAlg) (AuthState, error) {
	// Implicit promotion: only KS, no nonce
	if len(nonce) == 0 {
		return AuthState{ks.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = ks.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		// Get KS variant for this algorithm, falling back to first available
		ksBytes := ks.GetOrFirst(alg)

		// Collect non-nil components
		components := [][]byte{ksBytes}
		// TODO: Level 5 — add RS component here when RuleState is implemented
		if len(nonce) > 0 {
			components = append(components, nonce)
		}

		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return AuthState{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return AuthState{}, err
	}
	return AuthState{mh}, nil
}

// ComputeCS computes Commit State (SPEC §8.5).
// CS = MR(AS, Commit ID) — binds an auth state to a specific commit.
// If commitID is nil (genesis / no transactions), CS promotes from AS.
func ComputeCS(as AuthState, commitID *CommitID, algs []HashAlg) (CommitState, error) {
	// Implicit promotion: no commit ID → CS = AS
	if commitID == nil {
		return CommitState{as.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = as.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		// Get AS variant for this algorithm, falling back to first available
		asBytes := as.GetOrFirst(alg)

		// Get CommitID variant for this algorithm, falling back to first available
		cidBytes := commitID.GetOrFirst(alg)

		components := [][]byte{asBytes, cidBytes}
		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return CommitState{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return CommitState{}, err
	}
	return CommitState{mh}, nil
}

// ComputeDS computes Data State from action czds (SPEC §7.4).
// If only one action with no nonce, DS = czd (implicit promotion).
// Returns nil DS if no actions.
// DataState is currently single-algorithm (per Rust).
func ComputeDS(czds []coz.B64, nonce coz.B64, alg HashAlg) (*DataState, error) {
	if len(czds) == 0 {
		return nil, nil // No actions = nil DS
	}

	// Implicit promotion: single action, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		ds := NewDataState(czds[0])
		return &ds, nil
	}

	components := make([][]byte, 0, len(czds)+1)
	for _, c := range czds {
		components = append(components, c)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := hashSortedConcatBytes(alg, components...)
	if err != nil {
		return nil, err
	}
	ds := NewDataState(digest)
	return &ds, nil
}

// ComputePS computes Principal State from CS and optional DS (SPEC §8.3).
// PS = MR(CS, DS?) — top-level state derived from commit state.
// If DS is nil with no nonce, PS = CS (implicit promotion).
func ComputePS(cs CommitState, ds *DataState, nonce coz.B64, algs []HashAlg) (PrincipalState, error) {
	// Implicit promotion: only CS, no DS, no nonce
	if ds == nil && len(nonce) == 0 {
		return PrincipalState{cs.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = cs.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		// Get CS variant for this algorithm, falling back to first available
		csBytes := cs.GetOrFirst(alg)

		// Collect non-nil components
		components := [][]byte{csBytes}
		if ds != nil {
			components = append(components, ds.Bytes())
		}
		if len(nonce) > 0 {
			components = append(components, nonce)
		}

		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return PrincipalState{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return PrincipalState{}, err
	}
	return PrincipalState{mh}, nil
}
