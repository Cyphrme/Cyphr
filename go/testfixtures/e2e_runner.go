package testfixtures

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/cyphrpass/cyphrpass"
	"github.com/cyphrme/cyphrpass/storage"
)

// E2EResult contains the result of running an e2e test.
type E2EResult struct {
	// Name is the test name.
	Name string
	// Passed is true if all assertions passed.
	Passed bool
	// Err is the error that occurred, if any.
	Err error
	// Failures contains specific assertion failures.
	Failures []string
}

// RunE2ETest runs a single e2e test case from an intent.
// Unlike golden tests which load pre-computed fixtures, e2e tests
// dynamically generate cozies, apply them, and verify round-trip.
func RunE2ETest(pool *Pool, test *TestIntent) *E2EResult {
	result := &E2EResult{Name: test.Name}

	// Build genesis keys from principal names
	genesisKeys, err := resolveGenesisFromNames(pool, test.Principal)
	if err != nil {
		result.Err = fmt.Errorf("failed to resolve genesis: %w", err)
		return result
	}

	// Create principal from genesis
	var principal *cyphrpass.Principal
	if len(genesisKeys) == 1 {
		principal, err = cyphrpass.Implicit(genesisKeys[0])
	} else if len(genesisKeys) > 1 {
		principal, err = cyphrpass.Explicit(genesisKeys)
	} else {
		// Empty genesis - will fail, but might be expected for error tests
		err = cyphrpass.ErrNoActiveKeys
	}

	// Handle genesis creation errors - might be expected for error tests
	if err != nil {
		if test.IsErrorTest() && matchesE2EError(err.Error(), test.Expected.Error) {
			result.Passed = true
			return result
		}
		result.Err = fmt.Errorf("failed to create principal: %w", err)
		return result
	}

	// Apply setup modifiers
	if test.Setup != nil && test.Setup.RevokeKey != "" {
		signingKey, err := pool.Get(test.Setup.RevokeKey).ToSigningKey()
		if err != nil {
			result.Err = fmt.Errorf("setup.revoke_key failed: %w", err)
			return result
		}
		if err := principal.PreRevokeKey(signingKey.Tmb, test.Setup.RevokeAt); err != nil {
			result.Err = fmt.Errorf("pre-revoke key failed: %w", err)
			return result
		}
	}

	// Build and apply cozies/actions based on intent type
	var applyErr error
	if len(test.Commit) > 1 {
		applyErr = applyMultiCommit(pool, principal, test)
	} else if len(test.Commit) == 1 {
		applyErr = applySingleCommit(pool, principal, &test.Commit[0].Tx[0][0], test.Override)
	}

	// Apply actions if present
	if applyErr == nil && test.HasAction() {
		if len(test.Action) > 1 {
			applyErr = applyMultiAction(pool, principal, test)
		} else {
			applyErr = applySingleAction(pool, principal, &test.Action[0])
		}
	}

	// Handle error tests
	if test.IsErrorTest() {
		if applyErr == nil {
			result.Err = fmt.Errorf("expected error %q but got none", test.Expected.Error)
			return result
		}
		if !matchesE2EError(applyErr.Error(), test.Expected.Error) {
			result.Err = fmt.Errorf("expected error %q but got %q", test.Expected.Error, applyErr.Error())
			return result
		}
		result.Passed = true
		return result
	}

	// Non-error test: apply should succeed
	if applyErr != nil {
		result.Err = fmt.Errorf("apply failed: %w", applyErr)
		return result
	}

	// Verify expected state
	result.Failures = verifyE2EExpected(principal, test.Expected)
	result.Passed = len(result.Failures) == 0
	if !result.Passed {
		result.Err = fmt.Errorf("assertion failures: %s", strings.Join(result.Failures, "; "))
	}

	return result
}

// resolveGenesisFromNames resolves key names to coz.Key slice.
func resolveGenesisFromNames(pool *Pool, names []string) ([]*coz.Key, error) {
	keys := make([]*coz.Key, len(names))
	for i, name := range names {
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

// applySingleCommit applies a single coz commit.
func applySingleCommit(pool *Pool, principal *cyphrpass.Principal, cz *TxIntent, override *OverrideIntent) error {
	batch := principal.BeginCommit()
	return applyTxToBatch(pool, principal, batch, cz, override, true)
}

// applyMultiCommit applies multiple commits.
// Each commit contains transactions, each transaction contains cozies.
func applyMultiCommit(pool *Pool, principal *cyphrpass.Principal, test *TestIntent) error {
	for i, commit := range test.Commit {
		batch := principal.BeginCommit()
		for j, tx := range commit.Tx {
			for k, cz := range tx {
				// Apply override only to the last cz of the last tx of the last commit
				var override *OverrideIntent
				isLastCommit := i == len(test.Commit)-1
				isLastTx := j == len(commit.Tx)-1
				isLastCz := k == len(tx)-1
				if isLastCommit && isLastTx && isLastCz {
					override = test.Override
				}
				isFinal := isLastTx && isLastCz
				if err := applyTxToBatch(pool, principal, batch, &cz, override, isFinal); err != nil {
					return fmt.Errorf("commit %d tx %d cz %d: %w", i, j, k, err)
				}
			}
		}
	}
	return nil
}

// applyTxToBatch builds a coz payload and applies it to the active commit batch.
// If isFinal is true, it finalizes the commit with the commit:<CS> injection.
func applyTxToBatch(pool *Pool, principal *cyphrpass.Principal, batch *cyphrpass.CommitBatch, cz *TxIntent, override *OverrideIntent, isFinal bool) error {
	// Get signer key
	signerPool := pool.Get(cz.Signer)
	if signerPool == nil {
		return fmt.Errorf("signer %q not found in pool", cz.Signer)
	}
	signerKey, err := signerPool.ToSigningKey()
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}

	// Build pay object (pre field will be overridden dynamically if we are in a batch,
	// but the test intent generator computes it before batch modifications are readable.
	// The cyphrpass Go implementation expects pre to be generated correctly by e2e runner)
	payObj := buildTransactionPay(cz, signerKey.Tmb, principal.PR())

	// Handle target key for key/create (SPEC verb naming)
	var targetKey *coz.Key
	if cz.Target != "" && (strings.Contains(cz.Typ, "key/create") || strings.Contains(cz.Typ, "key/add")) {
		targetPool := pool.Get(cz.Target)
		if targetPool == nil {
			return fmt.Errorf("target %q not found in pool", cz.Target)
		}
		targetKey, err = targetPool.ToCozKey()
		if err != nil {
			return fmt.Errorf("target key: %w", err)
		}
		payObj["id"] = targetKey.Tmb.String()
	}

	// Handle target key for key/delete or key/revoke
	if cz.Target != "" && (strings.Contains(cz.Typ, "key/delete") || strings.Contains(cz.Typ, "key/revoke")) {
		targetPool := pool.Get(cz.Target)
		if targetPool == nil {
			return fmt.Errorf("target %q not found in pool", cz.Target)
		}
		var targetCoz *coz.Key
		targetCoz, err = targetPool.ToCozKey()
		if err != nil {
			return fmt.Errorf("target key: %w", err)
		}
		payObj["id"] = targetCoz.Tmb.String()
	}

	// Apply override if present (for error tests)
	if override != nil {
		if override.Pre != "" {
			payObj["pre"] = override.Pre
		}
		if override.Tmb != "" {
			payObj["tmb"] = override.Tmb
		}
		if override.Now != nil {
			payObj["now"] = *override.Now
		}
	}

	// Handle principal/create: id is self-referential (current PS)
	if strings.Contains(cz.Typ, "principal/create") {
		payObj["id"] = principal.PR().Tagged()
	}

	// Inject 'alg' field for both final and non-final cozies
	payObj["alg"] = string(signerKey.Alg)

	// Non-final coz: sign normally without 'commit' field
	payBytes, err := json.Marshal(payObj)
	if err != nil {
		return fmt.Errorf("failed to marshal pay: %w", err)
	}

	digest, err := coz.Hash(signerKey.Alg.Hash(), payBytes)
	if err != nil {
		return fmt.Errorf("failed to hash pay: %w", err)
	}

	sig, err := signerKey.Sign(digest)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	signedCoz := &coz.Coz{
		Pay: payBytes,
		Sig: sig,
	}

	if err := batch.VerifyAndApply(signedCoz, targetKey); err != nil {
		return err
	}

	if isFinal {
		_, err := batch.FinalizeWithArrow(signerKey, cz.Now)
		return err
	}

	return nil
}

// applySingleAction applies a single action.
func applySingleAction(pool *Pool, principal *cyphrpass.Principal, action *ActionIntent) error {
	// Get signer key
	signerPool := pool.Get(action.Signer)
	if signerPool == nil {
		return fmt.Errorf("signer %q not found in pool", action.Signer)
	}
	signerKey, err := signerPool.ToSigningKey()
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}

	// Build action pay
	payObj := map[string]any{
		"alg": string(signerKey.Alg),
		"tmb": signerKey.Tmb.String(),
		"typ": action.Typ,
		"now": action.Now,
	}
	if action.Msg != "" {
		payObj["msg"] = action.Msg
	}

	return signAndApplyAction(signerKey, payObj, principal)
}

// applyMultiAction applies multiple actions.
func applyMultiAction(pool *Pool, principal *cyphrpass.Principal, test *TestIntent) error {
	for i := range test.Action {
		if err := applySingleAction(pool, principal, &test.Action[i]); err != nil {
			return fmt.Errorf("action %d: %w", i, err)
		}
	}
	return nil
}

// buildTransactionPay creates a pay map for a coz.
func buildTransactionPay(cz *TxIntent, signerTmb coz.B64, currentPS cyphrpass.PrincipalRoot) map[string]any {
	payObj := map[string]any{
		"alg": "ES256", // Will be overridden by signer
		"tmb": signerTmb.String(),
		"typ": cz.Typ,
		"now": cz.Now,
	}

	// Add pre field (current principal state) for cozies that need it
	if strings.Contains(cz.Typ, "key/create") ||
		strings.Contains(cz.Typ, "key/add") ||
		strings.Contains(cz.Typ, "key/delete") ||
		strings.Contains(cz.Typ, "key/replace") ||
		strings.Contains(cz.Typ, "key/revoke") ||
		strings.Contains(cz.Typ, "principal/create") {
		payObj["pre"] = currentPS.Tagged()
	}

	// Add rvk field if present
	if cz.Rvk != 0 {
		payObj["rvk"] = cz.Rvk
	}

	// Add msg field if present
	if cz.Msg != "" {
		payObj["msg"] = cz.Msg
	}

	return payObj
}

// (signAndApplyTransaction was removed and functionality merged into applyTxToBatch)

// signAndApplyAction signs an action and records it.
func signAndApplyAction(signerKey *coz.Key, payObj map[string]any, principal *cyphrpass.Principal) error {
	// Serialize pay to JSON - this is the exact bytes that will be signed
	payBytes, err := json.Marshal(payObj)
	if err != nil {
		return fmt.Errorf("failed to marshal pay: %w", err)
	}

	// Hash the payload
	digest, err := coz.Hash(signerKey.Alg.Hash(), payBytes)
	if err != nil {
		return fmt.Errorf("failed to hash pay: %w", err)
	}

	// Sign the digest
	sig, err := signerKey.Sign(digest)
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	// Create Coz with exact payload bytes
	signedCoz := &coz.Coz{
		Pay: payBytes,
		Sig: sig,
	}

	// Compute czd
	if err := signedCoz.Meta(); err != nil {
		return fmt.Errorf("failed to compute meta: %w", err)
	}

	// Parse pay for action creation
	var pay coz.Pay
	if err := json.Unmarshal(payBytes, &pay); err != nil {
		return fmt.Errorf("failed to parse pay: %w", err)
	}

	// Create action
	action, err := cyphrpass.ParseAction(&pay, signedCoz.Czd)
	if err != nil {
		return fmt.Errorf("failed to parse action: %w", err)
	}

	// Store raw bytes for export
	cozJSON := map[string]any{
		"pay": payObj,
		"sig": signedCoz.Sig.String(),
	}
	rawBytes, _ := json.Marshal(cozJSON)
	action.SetRaw(rawBytes)

	// Record action
	return principal.RecordAction(action)
}

// verifyE2EExpected checks if principal matches expected state.
func verifyE2EExpected(p *cyphrpass.Principal, exp *ExpectedAssertions) []string {
	if exp == nil {
		return nil
	}

	var failures []string

	if exp.KeyCount != nil && p.ActiveKeyCount() != *exp.KeyCount {
		failures = append(failures, fmt.Sprintf("key_count: got %d, want %d", p.ActiveKeyCount(), *exp.KeyCount))
	}

	if exp.Level != nil && int(p.Level()) != *exp.Level {
		failures = append(failures, fmt.Sprintf("level: got %d, want %d", p.Level(), *exp.Level))
	}

	if exp.KR != "" && p.KR().String() != exp.KR {
		failures = append(failures, fmt.Sprintf("ks: got %s, want %s", p.KR().String(), exp.KR))
	}

	if exp.AR != "" && p.AR().String() != exp.AR {
		failures = append(failures, fmt.Sprintf("as: got %s, want %s", p.AR().String(), exp.AR))
	}

	if exp.PR != "" && p.PR().String() != exp.PR {
		failures = append(failures, fmt.Sprintf("ps: got %s, want %s", p.PR().String(), exp.PR))
	}

	return failures
}

// matchesE2EError checks if actual error matches expected error pattern.
func matchesE2EError(actual, expected string) bool {
	// Use same matching logic as golden tests
	return matchesExpectedError(actual, expected)
}

// RunE2ERoundTrip runs an e2e test and also verifies round-trip export/import.
func RunE2ERoundTrip(pool *Pool, test *TestIntent) *E2EResult {
	result := &E2EResult{Name: test.Name}

	// Skip error tests for round-trip (they intentionally fail)
	if test.IsErrorTest() {
		return RunE2ETest(pool, test)
	}

	// Build genesis keys from principal names
	genesisKeys, err := resolveGenesisFromNames(pool, test.Principal)
	if err != nil {
		result.Err = fmt.Errorf("failed to resolve genesis: %w", err)
		return result
	}

	// Create principal from genesis
	var principal *cyphrpass.Principal
	if len(genesisKeys) == 1 {
		principal, err = cyphrpass.Implicit(genesisKeys[0])
	} else {
		principal, err = cyphrpass.Explicit(genesisKeys)
	}
	if err != nil {
		result.Err = fmt.Errorf("failed to create principal: %w", err)
		return result
	}

	// Apply all cozies/actions (same as RunE2ETest)
	var applyErr error
	if len(test.Commit) > 1 {
		applyErr = applyMultiCommit(pool, principal, test)
	} else if len(test.Commit) == 1 {
		applyErr = applySingleCommit(pool, principal, &test.Commit[0].Tx[0][0], nil)
	}

	if applyErr == nil && test.HasAction() {
		if len(test.Action) > 1 {
			applyErr = applyMultiAction(pool, principal, test)
		} else {
			applyErr = applySingleAction(pool, principal, &test.Action[0])
		}
	}

	if applyErr != nil {
		result.Err = fmt.Errorf("apply failed: %w", applyErr)
		return result
	}

	// Export entries
	exported := storage.ExportEntries(principal)

	// Rebuild genesis for reimport
	var genesis storage.Genesis
	if len(genesisKeys) == 1 {
		genesis = storage.ImplicitGenesis{Key: genesisKeys[0]}
	} else {
		genesis = storage.ExplicitGenesis{Keys: genesisKeys}
	}

	// Load from exported entries
	reimported, err := storage.LoadPrincipal(genesis, exported)
	if err != nil {
		result.Err = fmt.Errorf("reimport failed: %w", err)
		return result
	}

	// Compare state
	if principal.PR().String() != reimported.PR().String() {
		result.Failures = append(result.Failures, fmt.Sprintf(
			"round-trip PS mismatch: original=%s reimported=%s",
			principal.PR().String(), reimported.PR().String()))
	}

	if principal.ActiveKeyCount() != reimported.ActiveKeyCount() {
		result.Failures = append(result.Failures, fmt.Sprintf(
			"round-trip key_count mismatch: original=%d reimported=%d",
			principal.ActiveKeyCount(), reimported.ActiveKeyCount()))
	}

	// Also verify expected state
	if test.Expected != nil {
		result.Failures = append(result.Failures, verifyE2EExpected(principal, test.Expected)...)
	}

	result.Passed = len(result.Failures) == 0
	if !result.Passed {
		result.Err = fmt.Errorf("failures: %s", strings.Join(result.Failures, "; "))
	}

	return result
}

// RunE2EMultihashCoherence verifies multihash round-trip coherence (SPEC §14).
// Mirrors Rust's e2e_multihash_round_trip: after serialization and reimport,
// recomputed state values must match reimported values for ALL active algorithms.
func RunE2EMultihashCoherence(pool *Pool, test *TestIntent) *E2EResult {
	result := &E2EResult{Name: test.Name}

	// Build genesis keys from principal names
	genesisKeys, err := resolveGenesisFromNames(pool, test.Principal)
	if err != nil {
		result.Err = fmt.Errorf("failed to resolve genesis: %w", err)
		return result
	}

	// Create principal from genesis
	var principal *cyphrpass.Principal
	if len(genesisKeys) == 1 {
		principal, err = cyphrpass.Implicit(genesisKeys[0])
	} else {
		principal, err = cyphrpass.Explicit(genesisKeys)
	}
	if err != nil {
		result.Err = fmt.Errorf("failed to create principal: %w", err)
		return result
	}

	// Apply cozies if present
	var applyErr error
	if len(test.Commit) > 1 {
		applyErr = applyMultiCommit(pool, principal, test)
	} else if len(test.Commit) == 1 {
		applyErr = applySingleCommit(pool, principal, &test.Commit[0].Tx[0][0], nil)
	}

	if applyErr != nil {
		result.Err = fmt.Errorf("apply failed: %w", applyErr)
		return result
	}

	// Export entries
	exported := storage.ExportEntries(principal)

	// Rebuild genesis for reimport
	var genesis storage.Genesis
	if len(genesisKeys) == 1 {
		genesis = storage.ImplicitGenesis{Key: genesisKeys[0]}
	} else {
		genesis = storage.ExplicitGenesis{Keys: genesisKeys}
	}

	// Load from exported entries
	reimported, err := storage.LoadPrincipal(genesis, exported)
	if err != nil {
		result.Err = fmt.Errorf("reimport failed: %w", err)
		return result
	}

	// --- Multihash coherence verification ---

	// Step 1: Verify active_algs is not empty
	activeAlgs := reimported.ActiveAlgs()
	if len(activeAlgs) == 0 {
		result.Failures = append(result.Failures, "active_algs should not be empty")
	}

	// Step 2: Get thumbprints and recompute KS for each algorithm
	var thumbprints []coz.B64
	for _, k := range reimported.ActiveKeys() {
		thumbprints = append(thumbprints, k.Tmb)
	}

	recomputedKS, err := cyphrpass.ComputeKR(thumbprints, nil, activeAlgs)
	if err != nil {
		result.Err = fmt.Errorf("failed to recompute KS: %w", err)
		return result
	}

	// Step 3: Verify each algorithm variant matches for KS
	for _, alg := range activeAlgs {
		reimportedVariant := reimported.KR().Get(alg)
		recomputedVariant := recomputedKS.Get(alg)

		if reimportedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("KS missing variant for %s", alg))
			continue
		}
		if recomputedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("recomputed KS missing variant for %s", alg))
			continue
		}
		if string(reimportedVariant) != string(recomputedVariant) {
			result.Failures = append(result.Failures, fmt.Sprintf(
				"KS variant %s mismatch: reimported=%x recomputed=%x",
				alg, reimportedVariant[:8], recomputedVariant[:8]))
		}
	}

	// Step 4: Recompute AR and verify variants
	recomputedAR, err := cyphrpass.ComputeAR(recomputedKS, nil, nil, activeAlgs)
	if err != nil {
		result.Err = fmt.Errorf("failed to recompute AR: %w", err)
		return result
	}

	for _, alg := range activeAlgs {
		reimportedVariant := reimported.AR().Get(alg)
		recomputedVariant := recomputedAR.Get(alg)

		if reimportedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("AR missing variant for %s", alg))
			continue
		}
		if recomputedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("recomputed AR missing variant for %s", alg))
			continue
		}
		if string(reimportedVariant) != string(recomputedVariant) {
			result.Failures = append(result.Failures, fmt.Sprintf(
				"AR variant %s mismatch: reimported=%x recomputed=%x",
				alg, reimportedVariant[:8], recomputedVariant[:8]))
		}
	}

	// Step 5: Recompute SR = MR(AR, DR?) and verify variants
	recomputedSR, err := cyphrpass.ComputeSR(recomputedAR, reimported.DR(), nil, activeAlgs)
	if err != nil {
		result.Err = fmt.Errorf("failed to recompute SR: %w", err)
		return result
	}

	for _, alg := range activeAlgs {
		reimportedVariant := reimported.SR().Get(alg)
		recomputedVariant := recomputedSR.Get(alg)

		if reimportedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("SR missing variant for %s", alg))
			continue
		}
		if recomputedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("recomputed SR missing variant for %s", alg))
			continue
		}
		if string(reimportedVariant) != string(recomputedVariant) {
			result.Failures = append(result.Failures, fmt.Sprintf(
				"SR variant %s mismatch: reimported=%x recomputed=%x",
				alg, reimportedVariant[:8], recomputedVariant[:8]))
		}
	}

	// Step 6: Recompute PR = MR(SR, CR?) and verify variants
	recomputedPR, err := cyphrpass.ComputePR(recomputedSR, reimported.CR(), nil, activeAlgs)
	if err != nil {
		result.Err = fmt.Errorf("failed to recompute PR: %w", err)
		return result
	}

	for _, alg := range activeAlgs {
		reimportedVariant := reimported.PR().Get(alg)
		recomputedVariant := recomputedPR.Get(alg)

		if reimportedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("PR missing variant for %s", alg))
			continue
		}
		if recomputedVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf("recomputed PR missing variant for %s", alg))
			continue
		}
		if string(reimportedVariant) != string(recomputedVariant) {
			result.Failures = append(result.Failures, fmt.Sprintf(
				"PR variant %s mismatch: reimported=%x recomputed=%x",
				alg, reimportedVariant[:8], recomputedVariant[:8]))
		}
	}

	// Step 6: PR check — nil for L1/L2, has genesis variant for L3+
	if reimported.PG() != nil {
		genesisAlg := reimported.HashAlg()
		prVariant := reimported.PG().Get(genesisAlg)
		if prVariant == nil {
			result.Failures = append(result.Failures, fmt.Sprintf(
				"PR should have genesis algorithm %s variant", genesisAlg))
		}
	}

	// Also verify expected state if provided
	if test.Expected != nil {
		result.Failures = append(result.Failures, verifyE2EExpected(reimported, test.Expected)...)
	}

	result.Passed = len(result.Failures) == 0
	if !result.Passed {
		result.Err = fmt.Errorf("failures: %s", strings.Join(result.Failures, "; "))
	}

	return result
}
