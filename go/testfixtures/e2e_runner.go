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
// dynamically generate transactions, apply them, and verify round-trip.
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
		principal.PreRevokeKey(signingKey.Tmb, test.Setup.RevokeAt)
	}

	// Build and apply transactions/actions based on intent type
	var applyErr error
	if test.IsMultiStep() {
		applyErr = applyMultiStep(pool, principal, test)
	} else if test.Pay != nil && test.Crypto != nil {
		applyErr = applySingleStep(pool, principal, test)
	}

	// Apply actions if present
	if applyErr == nil && test.HasAction() {
		if test.IsMultiAction() {
			applyErr = applyMultiAction(pool, principal, test)
		} else if test.Action != nil {
			applyErr = applySingleAction(pool, principal, test)
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

// applySingleStep applies a single transaction from intent.
func applySingleStep(pool *Pool, principal *cyphrpass.Principal, test *TestIntent) error {
	pay := test.Pay
	crypto := test.Crypto

	// Get signer key
	signerPool := pool.Get(crypto.Signer)
	if signerPool == nil {
		return fmt.Errorf("signer %q not found in pool", crypto.Signer)
	}
	signerKey, err := signerPool.ToSigningKey()
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}

	// Build pay object
	payObj := buildTransactionPay(pay, signerKey.Tmb, principal.AS())

	// Handle target key for key/create (SPEC verb naming)
	var targetKey *coz.Key
	if crypto.Target != "" && (strings.Contains(pay.Typ, "key/create") || strings.Contains(pay.Typ, "key/add")) {
		targetPool := pool.Get(crypto.Target)
		if targetPool == nil {
			return fmt.Errorf("target %q not found in pool", crypto.Target)
		}
		targetKey, err = targetPool.ToCozKey()
		if err != nil {
			return fmt.Errorf("target key: %w", err)
		}
		// Set id field to target thumbprint
		payObj["id"] = targetKey.Tmb.String()
	}

	// Handle target key for key/delete or key/revoke
	if crypto.Target != "" && (strings.Contains(pay.Typ, "key/delete") || strings.Contains(pay.Typ, "key/revoke")) {
		targetPool := pool.Get(crypto.Target)
		if targetPool == nil {
			return fmt.Errorf("target %q not found in pool", crypto.Target)
		}
		var targetCoz *coz.Key
		targetCoz, err = targetPool.ToCozKey()
		if err != nil {
			return fmt.Errorf("target key: %w", err)
		}
		payObj["id"] = targetCoz.Tmb.String()
	}

	// Apply override if present
	if test.Override != nil {
		if test.Override.Pre != "" {
			payObj["pre"] = test.Override.Pre
		}
		if test.Override.Tmb != "" {
			payObj["tmb"] = test.Override.Tmb
		}
	}

	// Handle principal/create: id is self-referential (current AS)
	if strings.Contains(pay.Typ, "principal/create") {
		payObj["id"] = principal.AS().String()
	}

	// Sign and apply
	return signAndApplyTransaction(signerKey, payObj, targetKey, principal)
}

// applyMultiStep applies multiple transactions.
func applyMultiStep(pool *Pool, principal *cyphrpass.Principal, test *TestIntent) error {
	for i, step := range test.Step {
		// Create a temporary single-step test
		tempTest := &TestIntent{
			Name:     fmt.Sprintf("%s_step_%d", test.Name, i),
			Pay:      &step.Pay,
			Crypto:   &step.Crypto,
			Override: test.Override, // Apply override to last step if present
		}
		// Only apply override to last step
		if i < len(test.Step)-1 {
			tempTest.Override = nil
		}
		if err := applySingleStep(pool, principal, tempTest); err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	return nil
}

// applySingleAction applies a single action from intent.
func applySingleAction(pool *Pool, principal *cyphrpass.Principal, test *TestIntent) error {
	action := test.Action

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
	for i, action := range test.ActionStep {
		tempTest := &TestIntent{
			Name:   fmt.Sprintf("%s_action_%d", test.Name, i),
			Action: &action,
		}
		if err := applySingleAction(pool, principal, tempTest); err != nil {
			return fmt.Errorf("action %d: %w", i, err)
		}
	}
	return nil
}

// buildTransactionPay creates a pay map for a transaction.
func buildTransactionPay(pay *PayIntent, signerTmb coz.B64, currentAS cyphrpass.AuthState) map[string]any {
	payObj := map[string]any{
		"alg": "ES256", // Will be overridden by signer
		"tmb": signerTmb.String(),
		"typ": pay.Typ,
		"now": pay.Now,
	}

	// Add pre field (current auth state) for transactions that need it
	if strings.Contains(pay.Typ, "key/create") ||
		strings.Contains(pay.Typ, "key/add") ||
		strings.Contains(pay.Typ, "key/delete") ||
		strings.Contains(pay.Typ, "key/replace") ||
		strings.Contains(pay.Typ, "key/revoke") ||
		strings.Contains(pay.Typ, "principal/create") {
		payObj["pre"] = currentAS.String()
	}

	// Add rvk field if present
	if pay.Rvk != 0 {
		payObj["rvk"] = pay.Rvk
	}

	// Add msg field if present
	if pay.Msg != "" {
		payObj["msg"] = pay.Msg
	}

	return payObj
}

// signAndApplyTransaction signs a pay object and applies it to principal.
func signAndApplyTransaction(signerKey *coz.Key, payObj map[string]any, newKey *coz.Key, principal *cyphrpass.Principal) error {
	// Set correct alg from signer
	payObj["alg"] = string(signerKey.Alg)

	// Serialize pay to JSON - this is the exact bytes that will be signed
	payBytes, err := json.Marshal(payObj)
	if err != nil {
		return fmt.Errorf("failed to marshal pay: %w", err)
	}

	// Hash the payload using the key's hash algorithm
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

	// Verify and apply
	verifiedTx, err := principal.VerifyTransaction(signedCoz, newKey)
	if err != nil {
		return err
	}

	return principal.ApplyVerified(verifiedTx)
}

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
	action.Raw, _ = json.Marshal(cozJSON)

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

	if exp.KS != "" && p.KS().String() != exp.KS {
		failures = append(failures, fmt.Sprintf("ks: got %s, want %s", p.KS().String(), exp.KS))
	}

	if exp.AS != "" && p.AS().String() != exp.AS {
		failures = append(failures, fmt.Sprintf("as: got %s, want %s", p.AS().String(), exp.AS))
	}

	if exp.PS != "" && p.PS().String() != exp.PS {
		failures = append(failures, fmt.Sprintf("ps: got %s, want %s", p.PS().String(), exp.PS))
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

	// Apply all transactions/actions (same as RunE2ETest)
	var applyErr error
	if test.IsMultiStep() {
		applyErr = applyMultiStep(pool, principal, test)
	} else if test.Pay != nil && test.Crypto != nil {
		applyErr = applySingleStep(pool, principal, test)
	}

	if applyErr == nil && test.HasAction() {
		if test.IsMultiAction() {
			applyErr = applyMultiAction(pool, principal, test)
		} else if test.Action != nil {
			applyErr = applySingleAction(pool, principal, test)
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
	if principal.PS().String() != reimported.PS().String() {
		result.Failures = append(result.Failures, fmt.Sprintf(
			"round-trip PS mismatch: original=%s reimported=%s",
			principal.PS().String(), reimported.PS().String()))
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
