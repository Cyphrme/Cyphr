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

// KeyRoot (KS) is the digest of active key thumbprints (SPEC §7.2).
// Single key with no nonce: KS = tmb (implicit promotion).
type KeyRoot struct {
	MultihashDigest
}

// CommitID is the digest of transaction czds within a single commit (SPEC §8.5).
// Previously named TransactionState; renamed to reflect its role as the
// identity of a commit rather than a state-tree node.
type CommitID struct {
	MultihashDigest
}

// AuthRoot (AS) is the authentication state: MR(KS, RS?) or promoted (SPEC §8.4).
type AuthRoot struct {
	MultihashDigest
}

// StateRoot (SR) is the principal non-commit state: MR(AR, DR?, embedding?) (SPEC §3.7.2).
// SR excludes commit information (CR is a sibling of SR in PR, not a child).
// If DR is nil and no embedding, SR = AR (implicit promotion).
type StateRoot struct {
	MultihashDigest
}

// DataRoot (DS) is the state of user actions (SPEC §7.4).
// Currently single-algorithm (Cad-based), per Rust implementation.
type DataRoot struct {
	digest coz.B64
}

// NewDataRoot creates a DataRoot from a digest.
func NewDataRoot(digest coz.B64) DataRoot {
	return DataRoot{digest: slices.Clone(digest)}
}

// Bytes returns the raw digest bytes.
func (d DataRoot) Bytes() coz.B64 {
	return d.digest
}

// PrincipalRoot (PR) is the current top-level state: MR(SR, CR?, embedding?) (SPEC §3.7.1).
// When no CR exists (Levels 1-3), PR = SR (implicit promotion).
type PrincipalRoot struct {
	MultihashDigest
}

// PrincipalGenesis (PR) is the first PS ever computed. Permanent, never changes (SPEC §7.7).
// Frozen at genesis with only the genesis-time algorithm variants.
type PrincipalGenesis struct {
	MultihashDigest
}

// NewPrincipalGenesis creates a PrincipalGenesis from the initial PrincipalRoot.
func NewPrincipalGenesis(ps PrincipalRoot) PrincipalGenesis {
	return PrincipalGenesis{ps.Clone()}
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
func (s KeyRoot) String() string          { return s.First().String() }
func (s CommitID) String() string         { return s.First().String() }
func (s AuthRoot) String() string         { return s.First().String() }
func (s StateRoot) String() string        { return s.First().String() }
func (s DataRoot) String() string         { return s.digest.String() }
func (s PrincipalRoot) String() string    { return s.First().String() }
func (s PrincipalGenesis) String() string { return s.First().String() }

// Tagged returns the AuthRoot as an algorithm-prefixed digest string.
// Format: "ALG:base64url" (e.g., "SHA-256:digest...").
// Uses the lexicographically first algorithm for deterministic output.
func (s AuthRoot) Tagged() string {
	algs := s.Algorithms()
	if len(algs) == 0 {
		return ""
	}
	firstAlg := algs[0]
	digest := s.Get(firstAlg)
	return fmt.Sprintf("%s:%s", firstAlg, digest.String())
}

// Tagged returns the StateRoot as an algorithm-prefixed digest string.
// Format: "ALG:base64url" (e.g., "SHA-256:digest...").
// Uses the lexicographically first algorithm for deterministic output.
func (s StateRoot) Tagged() string {
	algs := s.Algorithms()
	if len(algs) == 0 {
		return ""
	}
	firstAlg := algs[0]
	digest := s.Get(firstAlg)
	return fmt.Sprintf("%s:%s", firstAlg, digest.String())
}

// Tagged returns the PrincipalRoot as an algorithm-prefixed digest string.
// Format: "ALG:base64url" (e.g., "SHA-256:digest...").
// Uses the lexicographically first algorithm for deterministic output.
// This is the canonical format for the `pre` field in transactions.
func (s PrincipalRoot) Tagged() string {
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

// hashConcatBytes implements array-order digest: concatenate in insertion order,
// then hash. Used for CommitID where transaction order is significant (SPEC §8.5).
func hashConcatBytes(alg HashAlg, components ...[]byte) (coz.B64, error) {
	if len(components) == 0 {
		return nil, nil
	}

	// Concatenate in array order (no sort)
	var buf bytes.Buffer
	for _, c := range components {
		buf.Write(c)
	}

	// Hash using the specified algorithm
	return coz.Hash(coz.HshAlg(alg), buf.Bytes())
}

// ComputeKR computes Key State from thumbprints (SPEC §7.2).
// If only one thumbprint with no nonce, KS = tmb (implicit promotion).
// Computes one variant per algorithm in algs.
func ComputeKR(thumbprints []coz.B64, nonce coz.B64, algs []HashAlg) (KeyRoot, error) {
	if len(thumbprints) == 0 {
		return KeyRoot{}, ErrNoActiveKeys
	}
	if len(algs) == 0 {
		return KeyRoot{}, ErrNoActiveKeys
	}

	// Implicit promotion: single key, no nonce
	// Use first algorithm for single-variant multihash
	if len(thumbprints) == 1 && len(nonce) == 0 {
		return KeyRoot{FromSingleDigest(algs[0], thumbprints[0])}, nil
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
			return KeyRoot{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return KeyRoot{}, err
	}
	return KeyRoot{mh}, nil
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
		digest, err := hashConcatBytes(alg, components...)
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

// TaggedCzd is a czd tagged with its source hash algorithm.
//
// Used for cross-algorithm state computation where czds from different
// signing algorithms need to be converted to a common hash algorithm
// (SPEC §14.2).
type TaggedCzd struct {
	Czd coz.B64 // Raw czd bytes.
	Alg HashAlg // Hash algorithm that produced this czd (from signing key).
}

// ConvertTo converts this czd to the target algorithm.
// If source and target algorithms match, returns the raw bytes.
// Otherwise, re-hashes the czd bytes with the target algorithm (SPEC §14.2).
func (tc TaggedCzd) ConvertTo(target HashAlg) (coz.B64, error) {
	if tc.Alg == target {
		return tc.Czd, nil
	}
	return coz.Hash(coz.HshAlg(target), tc.Czd)
}

// ComputeCommitIDTagged computes the Commit ID with cross-algorithm conversion (SPEC §14.2).
//
// Like ComputeCommitID, but accepts czds tagged with their source algorithm.
// When computing a target hash variant, czds from different algorithms are
// converted (re-hashed) to the target algorithm.
//
// Returns nil if no transactions.
func ComputeCommitIDTagged(czds []TaggedCzd, nonce coz.B64, algs []HashAlg) (*CommitID, error) {
	if len(czds) == 0 {
		return nil, nil
	}
	if len(algs) == 0 {
		algs = []HashAlg{HashSha256}
	}

	// Implicit promotion: single czd, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		targetAlg := algs[0]
		converted, err := czds[0].ConvertTo(targetAlg)
		if err != nil {
			return nil, err
		}
		cid := CommitID{FromSingleDigest(targetAlg, converted)}
		return &cid, nil
	}

	// Compute hash for each target algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, targetAlg := range algs {
		// Convert each czd to target algorithm
		converted := make([][]byte, 0, len(czds)+1)
		for _, tc := range czds {
			c, err := tc.ConvertTo(targetAlg)
			if err != nil {
				return nil, err
			}
			converted = append(converted, c)
		}

		// Add nonce if present
		if len(nonce) > 0 {
			converted = append(converted, nonce)
		}

		// Hash in array order (no sort — CommitID preserves transaction order)
		digest, err := hashConcatBytes(targetAlg, converted...)
		if err != nil {
			return nil, err
		}
		variants[targetAlg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return nil, err
	}
	cid := CommitID{mh}
	return &cid, nil
}

// ComputeAR computes Auth Root from KR (SPEC §3.7).
// AR = MR(KR, RR?, embedding?) — authentication state derived from the keyset.
// If no nonce (and no RS/RR), AR = KR (implicit promotion).
// embedding is reserved for future use; pass nil.
func ComputeAR(kr KeyRoot, nonce coz.B64, embedding coz.B64, algs []HashAlg) (AuthRoot, error) {
	// Implicit promotion: only KR, no nonce, no embedding
	if len(nonce) == 0 && len(embedding) == 0 {
		return AuthRoot{kr.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = kr.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		// Get KR variant for this algorithm, falling back to first available
		krBytes := kr.GetOrFirst(alg)

		// Collect non-nil components
		components := [][]byte{krBytes}
		// TODO: Level 5 — add RR component here when RuleRoot is implemented
		if len(nonce) > 0 {
			components = append(components, nonce)
		}
		if len(embedding) > 0 {
			components = append(components, embedding)
		}

		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return AuthRoot{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return AuthRoot{}, err
	}
	return AuthRoot{mh}, nil
}

// ComputeSR computes State Root (SPEC §3.7.2).
// SR = MR(AR, DR?, embedding?) — the principal non-commit state.
// If DR is nil and no embedding, SR = AR (implicit promotion).
// embedding is reserved for future use; pass nil.
func ComputeSR(ar AuthRoot, dr *DataRoot, embedding coz.B64, algs []HashAlg) (StateRoot, error) {
	// Implicit promotion: only AR, no DR, no embedding
	if dr == nil && len(embedding) == 0 {
		return StateRoot{ar.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = ar.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		arBytes := ar.GetOrFirst(alg)

		components := [][]byte{arBytes}
		if dr != nil {
			components = append(components, dr.Bytes())
		}
		if len(embedding) > 0 {
			components = append(components, embedding)
		}
		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return StateRoot{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return StateRoot{}, err
	}
	return StateRoot{mh}, nil
}

// ComputeDR computes Data State from action czds (SPEC §7.4).
// If only one action with no nonce, DS = czd (implicit promotion).
// Returns nil DS if no actions.
// DataRoot is currently single-algorithm (per Rust).
func ComputeDR(czds []coz.B64, nonce coz.B64, alg HashAlg) (*DataRoot, error) {
	if len(czds) == 0 {
		return nil, nil // No actions = nil DS
	}

	// Implicit promotion: single action, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		dr := NewDataRoot(czds[0])
		return &dr, nil
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
	dr := NewDataRoot(digest)
	return &dr, nil
}

// ComputePR computes Principal Root (SPEC §3.7.1).
// PR = MR(SR, CR?, embedding?) — top-level state.
// If CR is nil (Levels 1-3) and no embedding, PR = SR (implicit promotion).
// The cr parameter is temporarily *CommitID until CR replaces CommitID in Phase 5.
// embedding is reserved for future use; pass nil.
func ComputePR(sr StateRoot, cr *CommitID, embedding coz.B64, algs []HashAlg) (PrincipalRoot, error) {
	// Implicit promotion: only SR, no CR, no embedding
	if cr == nil && len(embedding) == 0 {
		return PrincipalRoot{sr.Clone()}, nil
	}

	if len(algs) == 0 {
		algs = sr.Algorithms()
	}

	// Compute hash for each algorithm variant
	variants := make(map[HashAlg]coz.B64, len(algs))
	for _, alg := range algs {
		srBytes := sr.GetOrFirst(alg)

		// Collect non-nil components
		components := [][]byte{srBytes}
		if cr != nil {
			components = append(components, cr.GetOrFirst(alg))
		}
		if len(embedding) > 0 {
			components = append(components, embedding)
		}

		digest, err := hashSortedConcatBytes(alg, components...)
		if err != nil {
			return PrincipalRoot{}, err
		}
		variants[alg] = digest
	}

	mh, err := NewMultihashDigest(variants)
	if err != nil {
		return PrincipalRoot{}, err
	}
	return PrincipalRoot{mh}, nil
}
