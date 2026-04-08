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
//  2. Flatten cozies from golden commits
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

	// Build storage entries directly from commits (commit-level keys → per-entry embedded keys)
	entries, err := entriesFromCommits(golden.Commits)
	if err != nil {
		result.Err = fmt.Errorf("failed to build entries from commits: %w", err)
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

// entriesFromCommits builds storage entries from golden commits.
// Commit-level keys are embedded into key-introducing cozies so the
// storage layer's Entry.KeyJSON() can extract them during replay.
func entriesFromCommits(commits []GoldenCommit) ([]*storage.Entry, error) {
	var entries []*storage.Entry
	for ci, c := range commits {
		keyIdx := 0
		for ti, cz := range c.Cozies {
			raw := cz
			// Embed commit-level key into key-introducing cozies
			if typ := txTyp(cz); isKeyIntroducingTyp(typ) && keyIdx < len(c.Keys) {
				injected, err := embedKey(cz, c.Keys[keyIdx])
				if err != nil {
					return nil, fmt.Errorf("commit %d cz %d: embed key: %w", ci, ti, err)
				}
				raw = injected
				keyIdx++
			}
			entry, err := storage.NewEntry(raw)
			if err != nil {
				return nil, fmt.Errorf("commit %d cz %d: %w", ci, ti, err)
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// txTyp extracts pay.typ from a raw JSON coz.
// Returns empty string on parse failure (non-fatal).
func txTyp(cz json.RawMessage) string {
	var ext struct {
		Pay struct {
			Typ string `json:"typ"`
		} `json:"pay"`
	}
	if err := json.Unmarshal(cz, &ext); err != nil {
		return ""
	}
	return ext.Pay.Typ
}

// isKeyIntroducingTyp returns true if the typ introduces new key material.
func isKeyIntroducingTyp(typ string) bool {
	return strings.HasSuffix(typ, "/key/create") || strings.HasSuffix(typ, "/key/replace")
}

// embedKey embeds a GoldenKey into a raw JSON coz as a "key" field.
func embedKey(cz json.RawMessage, key GoldenKey) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(cz, &obj); err != nil {
		return nil, err
	}
	keyJSON, err := json.Marshal(map[string]any{
		"alg": key.Alg,
		"pub": key.Pub,
		"tmb": key.Tmb,
	})
	if err != nil {
		return nil, err
	}
	obj["key"] = keyJSON
	return json.Marshal(obj)
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
	if exp.KR != "" {
		alg, expectedDigest := parseAlgDigest(exp.KR)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("ks: invalid algorithm %s", alg))
			} else {
				ksDigest := p.KR().Get(hashAlg)
				if ksDigest == nil {
					failures = append(failures, fmt.Sprintf("ks: got nil, want %s", expectedDigest))
				} else if coz.B64(ksDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("ks: got %s, want %s", coz.B64(ksDigest).String(), expectedDigest))
				}
			}
		}
	}

	// AS - parse alg:digest format and compare
	if exp.AR != "" {
		alg, expectedDigest := parseAlgDigest(exp.AR)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("as: invalid algorithm %s", alg))
			} else {
				asDigest := p.AR().Get(hashAlg)
				if asDigest == nil {
					failures = append(failures, fmt.Sprintf("as: got nil, want %s", expectedDigest))
				} else if coz.B64(asDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("as: got %s, want %s", coz.B64(asDigest).String(), expectedDigest))
				}
			}
		}
	}

	// PR - parse alg:digest format and compare
	if exp.PR != "" {
		alg, expectedDigest := parseAlgDigest(exp.PR)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
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
	}

	// SR - parse alg:digest format and compare
	if exp.SR != "" {
		alg, expectedDigest := parseAlgDigest(exp.SR)
		if alg == "" {
			// Legacy format without prefix - skip verification
		} else {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("sr: invalid algorithm %s", alg))
			} else {
				srDigest := p.SR().Get(hashAlg)
				if srDigest == nil {
					failures = append(failures, fmt.Sprintf("sr: got nil, want %s", expectedDigest))
				} else if coz.B64(srDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("sr: got %s, want %s", coz.B64(srDigest).String(), expectedDigest))
				}
			}
		}
	}

	// PR - parse alg:digest format and compare (skip if empty or non-prefixed)
	if exp.PG != "" {
		alg, expectedDigest := parseAlgDigest(exp.PG)
		if alg != "" {
			hashAlg, err := cyphrpass.ParseHashAlg(alg)
			if err != nil {
				failures = append(failures, fmt.Sprintf("pr: invalid algorithm %s", alg))
			} else if p.PG() == nil {
				failures = append(failures, fmt.Sprintf("pr: got nil, want %s:%s", alg, expectedDigest))
			} else {
				prDigest := p.PG().Get(hashAlg)
				if prDigest == nil {
					failures = append(failures, fmt.Sprintf("pr: got nil variant, want %s", expectedDigest))
				} else if coz.B64(prDigest).String() != expectedDigest {
					failures = append(failures, fmt.Sprintf("pr: got %s, want %s", coz.B64(prDigest).String(), expectedDigest))
				}
			}
		}
		// If no ':' in pr, it's a raw thumbprint format - skip alg:digest verification
	}

	// DS (only for Level 4+)
	if exp.DR != "" {
		if p.DR() == nil {
			failures = append(failures, fmt.Sprintf("ds: got nil, want %s", exp.DR))
		} else if p.DR().String() != exp.DR {
			failures = append(failures, fmt.Sprintf("ds: got %s, want %s", p.DR().String(), exp.DR))
		}
	}

	// Multihash KS variants (SPEC §14 cross-impl verification)
	for algName, expectedDigest := range exp.MultihashKR {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_ks: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.KR().Get(hashAlg)
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
	for algName, expectedDigest := range exp.MultihashAR {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_as: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.AR().Get(hashAlg)
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
	for algName, expectedDigest := range exp.MultihashPR {
		hashAlg, err := cyphrpass.ParseHashAlg(algName)
		if err != nil {
			failures = append(failures, fmt.Sprintf("multihash_ps: invalid algorithm %s", algName))
			continue
		}
		actualDigest := p.PR().Get(hashAlg)
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
// Maps Rust error codes and formal constraint tags to Go error message patterns.
func matchesExpectedError(actual, expected string) bool {
	// Constraint tag → error code mapping.
	// Allows TOML tests to use formal spec constraint tags (e.g., "[no-revoke-non-self]")
	// which get translated to the native error codes they should produce.
	constraintTags := map[string]string{
		// Transactions
		"[transaction-pre-required]":    "MalformedPayload",
		"[data-action-no-pre]":          "MalformedPayload",
		"[commit-pre-chain]":            "BrokenChain",
		"[no-orphan-pre]":               "BrokenChain",
		"[create-uniqueness]":           "DuplicateKey",
		"[no-unauthorized-transaction]": "UnknownKey",
		"[revoke-self-signed]":          "MalformedPayload",
		"[no-revoke-non-self]":          "MalformedPayload",
		"[naked-revoke-error]":          "NoActiveKeys",
		"[no-self-revoke-recovery]":     "NoActiveKeys",
		// Authentication
		"[verification-timestamp-order]": "TimestampPast",
		// Principal Lifecycle
		"[no-level-1-recovery]": "NoActiveKeys",
		"[dead-terminal]":       "NoActiveKeys",
	}

	// If expected is a constraint tag, resolve to error code first
	if resolved, ok := constraintTags[expected]; ok {
		expected = resolved
	}

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

	// Replay entries using the batch-aware ReplayEntries
	if err := storage.ReplayEntries(principal, entries); err != nil {
		return nil, err
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
