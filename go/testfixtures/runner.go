package testfixtures

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/cyphrpass/cyphrpass"
	"github.com/cyphrme/cyphrpass/storage"
)

// RunResult contains the result of running a golden test.
type RunResult struct {
	// Name is the test name.
	Name string
	// Passed is true if all assertions passed.
	Passed bool
	// Err is the error that occurred, if any.
	Err error
	// Failures lists individual assertion failures.
	Failures []string
}

// RunGolden executes a golden test and returns the result.
//
// The test flow is:
//  1. Resolve genesis keys from pool
//  2. Create entries from golden.Entries
//  3. Call storage.LoadPrincipal to replay with verification
//  4. Assert expected state matches actual state
//
// For error tests, the expected error is compared against the load error.
func RunGolden(pool *Pool, golden *Golden) *RunResult {
	result := &RunResult{Name: golden.Name}

	// Resolve genesis keys from golden.GenesisKeys (preferred) or pool
	genesisKeys, err := resolveGenesisKeys(pool, golden)
	if err != nil {
		// For error tests, genesis resolution failures may be the expected error
		if golden.IsErrorTest() && matchesExpectedError(err.Error(), golden.Expected.Error) {
			result.Passed = true
			return result
		}
		result.Err = fmt.Errorf("failed to resolve genesis keys: %w", err)
		return result
	}

	// Convert entries (flattening commits if present)
	entries, err := convertEntries(golden.FlattenEntries())
	if err != nil {
		result.Err = fmt.Errorf("failed to convert entries: %w", err)
		return result
	}

	// Build genesis
	var genesis storage.Genesis
	if len(genesisKeys) == 1 {
		genesis = storage.ImplicitGenesis{Key: genesisKeys[0]}
	} else {
		genesis = storage.ExplicitGenesis{Keys: genesisKeys}
	}

	// Load principal with optional setup
	var principal *cyphrpass.Principal
	var loadErr error

	if golden.Setup != nil && golden.Setup.RevokeKey != "" {
		// Need to apply setup between genesis and replay
		principal, loadErr = loadPrincipalWithSetup(pool, genesis, entries, golden.Setup)
	} else {
		// Standard load path
		principal, loadErr = storage.LoadPrincipal(genesis, entries)
	}

	// Handle error tests
	if golden.IsErrorTest() {
		if loadErr == nil {
			result.Err = fmt.Errorf("expected error %q but got none", golden.Expected.Error)
			return result
		}
		if !matchesExpectedError(loadErr.Error(), golden.Expected.Error) {
			result.Err = fmt.Errorf("expected error %q but got %q", golden.Expected.Error, loadErr.Error())
			return result
		}
		result.Passed = true
		return result
	}

	// Non-error test: load should succeed
	if loadErr != nil {
		result.Err = fmt.Errorf("load failed: %w", loadErr)
		return result
	}

	// Check assertions
	result.Failures = checkExpected(principal, golden.Expected)
	result.Passed = len(result.Failures) == 0
	if !result.Passed {
		result.Err = fmt.Errorf("assertion failures: %s", strings.Join(result.Failures, "; "))
	}

	return result
}

// resolveGenesisKeys resolves genesis keys, preferring embedded genesis_keys.
func resolveGenesisKeys(pool *Pool, golden *Golden) ([]*coz.Key, error) {
	// Prefer embedded genesis_keys (contains full material)
	if len(golden.GenesisKeys) > 0 {
		keys := make([]*coz.Key, len(golden.GenesisKeys))
		for i, gk := range golden.GenesisKeys {
			pub, err := coz.Decode(gk.Pub)
			if err != nil {
				return nil, fmt.Errorf("key %q: invalid pub: %w", gk.Alg, err)
			}
			// Create key with Alg and Pub only - let Thumbprint() compute Tmb
			key := &coz.Key{
				Alg: coz.SEAlg(gk.Alg),
				Pub: pub,
			}
			// Compute thumbprint (required for verification)
			if err := key.Thumbprint(); err != nil {
				return nil, fmt.Errorf("key %q: failed to compute tmb: %w", gk.Alg, err)
			}
			keys[i] = key
		}
		return keys, nil
	}

	// Fallback to pool lookup by name
	keys := make([]*coz.Key, len(golden.Principal))
	for i, name := range golden.Principal {
		poolKey := pool.Get(name)
		if poolKey == nil {
			return nil, fmt.Errorf("key %q not found in pool", name)
		}
		key, err := poolKey.ToCozKey()
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", name, err)
		}
		keys[i] = key
	}
	return keys, nil
}

// convertEntries converts golden entries to storage entries.
func convertEntries(rawEntries []json.RawMessage) ([]*storage.Entry, error) {
	entries := make([]*storage.Entry, len(rawEntries))
	for i, raw := range rawEntries {
		entry, err := storage.NewEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		entries[i] = entry
	}
	return entries, nil
}

// checkExpected verifies the principal matches expected state.
func checkExpected(p *cyphrpass.Principal, exp GoldenExpected) []string {
	var failures []string

	// Key count
	if exp.KeyCount != nil && p.ActiveKeyCount() != *exp.KeyCount {
		failures = append(failures, fmt.Sprintf("key_count: got %d, want %d", p.ActiveKeyCount(), *exp.KeyCount))
	}

	// Level
	if exp.Level != nil && int(p.Level()) != *exp.Level {
		failures = append(failures, fmt.Sprintf("level: got %d, want %d", p.Level(), *exp.Level))
	}

	// KS
	if exp.KS != "" && p.KS().String() != exp.KS {
		failures = append(failures, fmt.Sprintf("ks: got %s, want %s", p.KS().String(), exp.KS))
	}

	// AS
	if exp.AS != "" && p.AS().String() != exp.AS {
		failures = append(failures, fmt.Sprintf("as: got %s, want %s", p.AS().String(), exp.AS))
	}

	// PS
	if exp.PS != "" && p.PS().String() != exp.PS {
		failures = append(failures, fmt.Sprintf("ps: got %s, want %s", p.PS().String(), exp.PS))
	}

	// PR
	if exp.PR != "" && p.PR().String() != exp.PR {
		failures = append(failures, fmt.Sprintf("pr: got %s, want %s", p.PR().String(), exp.PR))
	}

	// DS (only for Level 4+)
	if exp.DS != "" {
		if p.DS() == nil {
			failures = append(failures, fmt.Sprintf("ds: got nil, want %s", exp.DS))
		} else if p.DS().String() != exp.DS {
			failures = append(failures, fmt.Sprintf("ds: got %s, want %s", p.DS().String(), exp.DS))
		}
	}

	return failures
}

// matchesExpectedError checks if the actual error matches the expected error pattern.
// Maps Rust error codes to Go error message patterns.
func matchesExpectedError(actual, expected string) bool {
	// Error code to Go message pattern mapping
	// Rust uses camelCase error codes, Go uses plain English messages
	codePatterns := map[string][]string{
		"KeyRevoked":           {"key revoked", "keyrevoked"},
		"UnknownKey":           {"unknown key", "unknown signer", "unknownkey"},
		"UnknownSigner":        {"unknown key", "unknown signer"}, // alias for UnknownKey
		"TimestampPast":        {"timestamp in past", "timestampinpast"},
		"DuplicateKey":         {"duplicate key", "duplicatekey"},
		"NoActiveKeys":         {"no active keys", "noactivekeys"},
		"NoGenesisKeys":        {"no active keys", "noactivekeys", "no genesis keys"}, // maps to same error
		"InvalidPrior":         {"invalid prior", "invalidprior"},
		"BrokenChain":          {"invalid prior", "invalidprior"}, // alias for InvalidPrior
		"UnsupportedAlgorithm": {"unsupported", "rs256", "unsupportedalgorithm"},
	}

	actualLower := strings.ToLower(actual)

	// Check if expected is a known error code with pattern mapping
	if patterns, ok := codePatterns[expected]; ok {
		for _, pattern := range patterns {
			if strings.Contains(actualLower, pattern) {
				return true
			}
		}
		return false
	}

	// Fallback: normalized substring match
	normalize := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, " ", ""))
	}
	return strings.Contains(normalize(actual), normalize(expected))
}

// loadPrincipalWithSetup creates a Principal from genesis, applies setup modifiers,
// then replays entries. This allows tests to set up state (like pre-revoked keys)
// before entry replay.
func loadPrincipalWithSetup(pool *Pool, genesis storage.Genesis, entries []*storage.Entry, setup *GoldenSetup) (*cyphrpass.Principal, error) {
	// Create principal from genesis (without entries)
	var principal *cyphrpass.Principal
	var err error

	switch g := genesis.(type) {
	case storage.ImplicitGenesis:
		principal, err = cyphrpass.Implicit(g.Key)
	case storage.ExplicitGenesis:
		if len(g.Keys) == 0 {
			return nil, fmt.Errorf("no genesis keys")
		}
		principal, err = cyphrpass.Explicit(g.Keys)
	default:
		return nil, fmt.Errorf("unknown genesis type: %T", genesis)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create principal from genesis: %w", err)
	}

	// Apply setup: pre-revoke key
	if setup != nil && setup.RevokeKey != "" {
		poolKey := pool.Get(setup.RevokeKey)
		if poolKey == nil {
			return nil, fmt.Errorf("setup.revoke_key %q not found in pool", setup.RevokeKey)
		}
		cozKey, err := poolKey.ToCozKey()
		if err != nil {
			return nil, fmt.Errorf("failed to convert pool key %q: %w", setup.RevokeKey, err)
		}
		principal.PreRevokeKey(cozKey.Tmb, setup.RevokeAt)
	}

	// Replay entries (we need to use storage package internals)
	// Use storage.LoadPrincipalWithEntries if available, or replay manually
	for i, entry := range entries {
		if err := storage.ReplayEntry(principal, entry, i); err != nil {
			return nil, err
		}
	}

	return principal, nil
}
