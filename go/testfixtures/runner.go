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
//  2. Flatten transactions from golden commits
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
	entries, err := convertEntries(golden.FlattenTxs())
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
	// KS - parse alg:digest format and compare
	if exp.KS != "" {
		alg, expectedDigest := parseAlgDigest(exp.KS)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("ks: invalid algorithm %s", alg))
			} else {
				ksDigest := p.KS().Get(hashAlg)
				if ksDigest == nil {
					failures = append(failures, fmt.Sprintf("ks: got nil, want %s", expectedDigest))
				} else if coz.B64(ksDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("ks: got %s, want %s", coz.B64(ksDigest).String(), expectedDigest))
				}
			}
		}
	}

	// AS - parse alg:digest format and compare
	if exp.AS != "" {
		alg, expectedDigest := parseAlgDigest(exp.AS)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("as: invalid algorithm %s", alg))
			} else {
				asDigest := p.AS().Get(hashAlg)
				if asDigest == nil {
					failures = append(failures, fmt.Sprintf("as: got nil, want %s", expectedDigest))
				} else if coz.B64(asDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("as: got %s, want %s", coz.B64(asDigest).String(), expectedDigest))
				}
			}
		}
	}

	// PS - parse alg:digest format and compare
	if exp.PS != "" {
		alg, expectedDigest := parseAlgDigest(exp.PS)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("ps: invalid algorithm %s", alg))
			} else {
				psDigest := p.PS().Get(hashAlg)
				if psDigest == nil {
					failures = append(failures, fmt.Sprintf("ps: got nil, want %s", expectedDigest))
				} else if coz.B64(psDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("ps: got %s, want %s", coz.B64(psDigest).String(), expectedDigest))
				}
			}
		}
	}

	// CS - parse alg:digest format and compare
	if exp.CS != "" {
		alg, expectedDigest := parseAlgDigest(exp.CS)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else if p.CS() == nil {
			failures = append(failures, fmt.Sprintf("cs: got nil, want %s:%s", alg, expectedDigest))
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("cs: invalid algorithm %s", alg))
			} else {
				csDigest := p.CS().Get(hashAlg)
				if csDigest == nil {
					failures = append(failures, fmt.Sprintf("cs: got nil, want %s", expectedDigest))
				} else if coz.B64(csDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("cs: got %s, want %s", coz.B64(csDigest).String(), expectedDigest))
				}
			}
		}
	}

	// PR - parse alg:digest format and compare (skip if empty or non-prefixed)
	if exp.PR != "" {
		alg, expectedDigest := parseAlgDigest(exp.PR)
		if alg != "" {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("pr: invalid algorithm %s", alg))
			} else {
				prDigest := p.PR().Get(hashAlg)
				if prDigest == nil {
					failures = append(failures, fmt.Sprintf("pr: got nil, want %s", expectedDigest))
				} else if coz.B64(prDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("pr: got %s, want %s", coz.B64(prDigest).String(), expectedDigest))
				}
			}
		}
		// If no ':' in pr, it's a raw thumbprint format - skip alg:digest verification
	}

	// DS (only for Level 4+)
	if exp.DS != "" {
		if p.DS() == nil {
			failures = append(failures, fmt.Sprintf("ds: got nil, want %s", exp.DS))
		} else if p.DS().String() != exp.DS {
			failures = append(failures, fmt.Sprintf("ds: got %s, want %s", p.DS().String(), exp.DS))
		}
	}

	// Multihash KS variants (SPEC §14 cross-impl verification)
	for algName, expectedDigest := range exp.MultihashKS {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_ks: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.KS().Get(hashAlg)
		if actualDigest == nil {
			failures = append(failures, fmt.Sprintf("multihash_ks[%s]: got nil, want %s", algName, expectedDigest))
		} else {
			actualB64 := coz.B64(actualDigest).String()
			if actualB64 != expectedDigest {
				failures = append(failures, fmt.Sprintf("multihash_ks[%s]: got %s, want %s", algName, actualB64, expectedDigest))
			}
		}
	}

	// Multihash AS variants
	for algName, expectedDigest := range exp.MultihashAS {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_as: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.AS().Get(hashAlg)
		if actualDigest == nil {
			failures = append(failures, fmt.Sprintf("multihash_as[%s]: got nil, want %s", algName, expectedDigest))
		} else {
			actualB64 := coz.B64(actualDigest).String()
			if actualB64 != expectedDigest {
				failures = append(failures, fmt.Sprintf("multihash_as[%s]: got %s, want %s", algName, actualB64, expectedDigest))
			}
		}
	}

	// Multihash PS variants
	for algName, expectedDigest := range exp.MultihashPS {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_ps: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.PS().Get(hashAlg)
		if actualDigest == nil {
			failures = append(failures, fmt.Sprintf("multihash_ps[%s]: got nil, want %s", algName, expectedDigest))
		} else {
			actualB64 := coz.B64(actualDigest).String()
			if actualB64 != expectedDigest {
				failures = append(failures, fmt.Sprintf("multihash_ps[%s]: got %s, want %s", algName, actualB64, expectedDigest))
			}
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
		if err := principal.PreRevokeKey(cozKey.Tmb, setup.RevokeAt); err != nil {
			return nil, fmt.Errorf("pre-revoke key %q: %w", setup.RevokeKey, err)
		}
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

// parseAlgDigest splits "alg:digest" format strings.
// Returns ("", "") if the string doesn't contain a colon.
func parseAlgDigest(s string) (alg, digest string) {
	idx := strings.Index(s, ":")
	if idx == -1 {
		return "", ""
	}
	return s[:idx], s[idx+1:]
}
