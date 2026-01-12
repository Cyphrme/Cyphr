package cyphrpass

import (
	"bytes"
	"slices"

	"github.com/cyphrme/coz"
)

// State types wrap coz.B64 for type safety. Each represents a Merkle digest
// at different levels of the Cyphrpass state tree per SPEC §7.

// KeyState (KS) is the digest of active key thumbprints (SPEC §7.2).
// Single key with no nonce: KS = tmb (implicit promotion).
type KeyState coz.B64

// TransactionState (TS) is the digest of transaction czds (SPEC §7.3).
type TransactionState coz.B64

// AuthState (AS) is the authentication state: H(sort(KS, TS?, RS?)) or promoted (SPEC §7.5).
type AuthState coz.B64

// DataState (DS) is the state of user actions (SPEC §7.4).
type DataState coz.B64

// PrincipalState (PS) is the current top-level state: H(sort(AS, DS?)) or promoted (SPEC §7.6).
type PrincipalState coz.B64

// PrincipalRoot (PR) is the first PS ever computed. Permanent, never changes (SPEC §7.7).
type PrincipalRoot coz.B64

// HashAlg is a hash algorithm used for state computation (SPEC §12).
type HashAlg coz.HshAlg

// String methods for state types (return base64 encoding)
func (s KeyState) String() string         { return coz.B64(s).String() }
func (s TransactionState) String() string { return coz.B64(s).String() }
func (s AuthState) String() string        { return coz.B64(s).String() }
func (s DataState) String() string        { return coz.B64(s).String() }
func (s PrincipalState) String() string   { return coz.B64(s).String() }
func (s PrincipalRoot) String() string    { return coz.B64(s).String() }

// HashAlgFromSEAlg returns the hash algorithm for a given signing/encryption algorithm.
// Uses SEAlg.Hash() method per Coz API.
func HashAlgFromSEAlg(alg coz.SEAlg) HashAlg {
	return HashAlg(alg.Hash())
}

// HashSortedConcat implements SPEC §7.1 canonical digest algorithm:
// 1. Collect component digests
// 2. Sort lexicographically (byte comparison)
// 3. Concatenate sorted digests
// 4. Hash using specified algorithm
func HashSortedConcat(alg HashAlg, components ...[]byte) (coz.B64, error) {
	if len(components) == 0 {
		return nil, nil
	}

	// Single component promotes without hashing (implicit promotion)
	if len(components) == 1 {
		return slices.Clone(components[0]), nil
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
func ComputeKS(thumbprints []coz.B64, nonce coz.B64, alg HashAlg) (KeyState, error) {
	if len(thumbprints) == 0 {
		return KeyState(nil), ErrNoActiveKeys
	}

	// Implicit promotion: single key, no nonce
	if len(thumbprints) == 1 && len(nonce) == 0 {
		return KeyState(slices.Clone(coz.B64(thumbprints[0]))), nil
	}

	// Collect all components
	components := make([][]byte, 0, len(thumbprints)+1)
	for _, t := range thumbprints {
		components = append(components, t)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := HashSortedConcat(alg, components...)
	if err != nil {
		return KeyState(nil), err
	}
	return KeyState(digest), nil
}

// ComputeTS computes Transaction State from czds (SPEC §7.3).
// If only one transaction with no nonce, TS = czd (implicit promotion).
// Returns nil TS if no transactions.
func ComputeTS(czds []coz.B64, nonce coz.B64, alg HashAlg) (TransactionState, error) {
	if len(czds) == 0 {
		return TransactionState(nil), nil // No transactions = nil TS
	}

	// Implicit promotion: single transaction, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		return TransactionState(slices.Clone(coz.B64(czds[0]))), nil
	}

	components := make([][]byte, 0, len(czds)+1)
	for _, c := range czds {
		components = append(components, c)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := HashSortedConcat(alg, components...)
	if err != nil {
		return TransactionState(nil), err
	}
	return TransactionState(digest), nil
}

// ComputeAS computes Auth State from KS and optional TS (SPEC §7.5).
// If TS is nil with no nonce, AS = KS (implicit promotion).
func ComputeAS(ks KeyState, ts TransactionState, nonce coz.B64, alg HashAlg) (AuthState, error) {
	// Implicit promotion: only KS, no TS, no nonce
	if len(ts) == 0 && len(nonce) == 0 {
		return AuthState(slices.Clone(coz.B64(ks))), nil
	}

	components := make([][]byte, 0, 3)
	components = append(components, ks)
	if len(ts) > 0 {
		components = append(components, ts)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := HashSortedConcat(alg, components...)
	if err != nil {
		return AuthState(nil), err
	}
	return AuthState(digest), nil
}

// ComputeDS computes Data State from action czds (SPEC §7.4).
// If only one action with no nonce, DS = czd (implicit promotion).
// Returns nil DS if no actions.
func ComputeDS(czds []coz.B64, nonce coz.B64, alg HashAlg) (DataState, error) {
	if len(czds) == 0 {
		return DataState(nil), nil // No actions = nil DS
	}

	// Implicit promotion: single action, no nonce
	if len(czds) == 1 && len(nonce) == 0 {
		return DataState(slices.Clone(coz.B64(czds[0]))), nil
	}

	components := make([][]byte, 0, len(czds)+1)
	for _, c := range czds {
		components = append(components, c)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := HashSortedConcat(alg, components...)
	if err != nil {
		return DataState(nil), err
	}
	return DataState(digest), nil
}

// ComputePS computes Principal State from AS and optional DS (SPEC §7.6).
// If DS is nil with no nonce, PS = AS (implicit promotion).
func ComputePS(as AuthState, ds DataState, nonce coz.B64, alg HashAlg) (PrincipalState, error) {
	// Implicit promotion: only AS, no DS, no nonce
	if len(ds) == 0 && len(nonce) == 0 {
		return PrincipalState(slices.Clone(coz.B64(as))), nil
	}

	components := make([][]byte, 0, 3)
	components = append(components, as)
	if len(ds) > 0 {
		components = append(components, ds)
	}
	if len(nonce) > 0 {
		components = append(components, nonce)
	}

	digest, err := HashSortedConcat(alg, components...)
	if err != nil {
		return PrincipalState(nil), err
	}
	return PrincipalState(digest), nil
}
