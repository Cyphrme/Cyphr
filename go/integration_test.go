package cyphrpass_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/cyphrpass"
)

// testVectorsDir is the relative path to test vectors from the go/ directory.
const testVectorsDir = "../test_vectors"

// =========================================================================
// Test Fixture Types
// =========================================================================

// TestFixture is the top-level structure of a test vector file.
type TestFixture struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Version     string     `json:"version"`
	Tests       []TestCase `json:"tests"`
}

// TestCase is an individual test case.
type TestCase struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Expected    ExpectedState   `json:"expected"`
}

// ExpectedState is the expected output state.
type ExpectedState struct {
	PR    *string `json:"pr"`
	PS    *string `json:"ps"`
	AS    *string `json:"as"`
	KS    *string `json:"ks"`
	TS    *string `json:"ts"`
	DS    *string `json:"ds"`
	Level *int    `json:"level"`
	Error *string `json:"error"`
}

// GenesisInput is input for genesis tests.
type GenesisInput struct {
	Type string     `json:"type"`
	Key  *KeyInput  `json:"key,omitempty"`
	Keys []KeyInput `json:"keys,omitempty"`
}

// KeyInput is a key definition in test vectors.
type KeyInput struct {
	Alg string `json:"alg"`
	Pub string `json:"pub"`
	Tmb string `json:"tmb"`
}

// =========================================================================
// Test Helpers
// =========================================================================

func loadFixture(t *testing.T, path string) *TestFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testVectorsDir, path))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	var fixture TestFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture %s: %v", path, err)
	}
	return &fixture
}

func makeKeyFromInput(t *testing.T, ki KeyInput) *coz.Key {
	t.Helper()
	pub, err := coz.Decode(ki.Pub)
	if err != nil {
		t.Fatalf("failed to decode pub: %v", err)
	}
	tmb, err := coz.Decode(ki.Tmb)
	if err != nil {
		t.Fatalf("failed to decode tmb: %v", err)
	}
	return &coz.Key{
		Alg: coz.SEAlg(ki.Alg),
		Pub: pub,
		Tmb: tmb,
	}
}

// =========================================================================
// Genesis Tests
// =========================================================================

func TestGenesisFixtures(t *testing.T) {
	fixture := loadFixture(t, "genesis/implicit.json")

	for _, tc := range fixture.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			var input GenesisInput
			if err := json.Unmarshal(tc.Input, &input); err != nil {
				t.Fatalf("failed to parse input: %v", err)
			}

			var p *cyphrpass.Principal
			var err error

			switch input.Type {
			case "implicit_genesis":
				if input.Key == nil {
					t.Fatal("implicit_genesis requires key")
				}
				key := makeKeyFromInput(t, *input.Key)
				p, err = cyphrpass.Implicit(key)

			case "explicit_genesis":
				if len(input.Keys) == 0 {
					t.Fatal("explicit_genesis requires keys")
				}
				keys := make([]*coz.Key, len(input.Keys))
				for i, ki := range input.Keys {
					keys[i] = makeKeyFromInput(t, ki)
				}
				p, err = cyphrpass.Explicit(keys)

			default:
				t.Fatalf("unknown input type: %s", input.Type)
			}

			// Check for expected error
			if tc.Expected.Error != nil {
				if err == nil {
					t.Errorf("expected error %s, got nil", *tc.Expected.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify state
			if tc.Expected.PR != nil {
				if p.PR().String() != *tc.Expected.PR {
					t.Errorf("PR: got %s, want %s", p.PR().String(), *tc.Expected.PR)
				}
			}
			if tc.Expected.PS != nil {
				if p.PS().String() != *tc.Expected.PS {
					t.Errorf("PS: got %s, want %s", p.PS().String(), *tc.Expected.PS)
				}
			}
			if tc.Expected.AS != nil {
				if p.AS().String() != *tc.Expected.AS {
					t.Errorf("AS: got %s, want %s", p.AS().String(), *tc.Expected.AS)
				}
			}
			if tc.Expected.KS != nil {
				if p.KS().String() != *tc.Expected.KS {
					t.Errorf("KS: got %s, want %s", p.KS().String(), *tc.Expected.KS)
				}
			}
			if tc.Expected.Level != nil {
				expectedLevel := cyphrpass.Level(*tc.Expected.Level)
				if p.Level() != expectedLevel {
					t.Errorf("Level: got %v, want %v", p.Level(), expectedLevel)
				}
			}
		})
	}
}

func TestGenesisExplicitFixtures(t *testing.T) {
	fixture := loadFixture(t, "genesis/explicit.json")

	for _, tc := range fixture.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			var input GenesisInput
			if err := json.Unmarshal(tc.Input, &input); err != nil {
				t.Fatalf("failed to parse input: %v", err)
			}

			var p *cyphrpass.Principal
			var err error

			switch input.Type {
			case "implicit_genesis":
				if input.Key == nil {
					t.Fatal("implicit_genesis requires key")
				}
				key := makeKeyFromInput(t, *input.Key)
				p, err = cyphrpass.Implicit(key)

			case "explicit_genesis":
				if len(input.Keys) == 0 {
					t.Fatal("explicit_genesis requires keys")
				}
				keys := make([]*coz.Key, len(input.Keys))
				for i, ki := range input.Keys {
					keys[i] = makeKeyFromInput(t, ki)
				}
				p, err = cyphrpass.Explicit(keys)

			default:
				t.Fatalf("unknown input type: %s", input.Type)
			}

			// Check for expected error
			if tc.Expected.Error != nil {
				if err == nil {
					t.Errorf("expected error %s, got nil", *tc.Expected.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify state
			if tc.Expected.PR != nil {
				if p.PR().String() != *tc.Expected.PR {
					t.Errorf("PR: got %s, want %s", p.PR().String(), *tc.Expected.PR)
				}
			}
			if tc.Expected.PS != nil {
				if p.PS().String() != *tc.Expected.PS {
					t.Errorf("PS: got %s, want %s", p.PS().String(), *tc.Expected.PS)
				}
			}
			if tc.Expected.AS != nil {
				if p.AS().String() != *tc.Expected.AS {
					t.Errorf("AS: got %s, want %s", p.AS().String(), *tc.Expected.AS)
				}
			}
			if tc.Expected.KS != nil {
				if p.KS().String() != *tc.Expected.KS {
					t.Errorf("KS: got %s, want %s", p.KS().String(), *tc.Expected.KS)
				}
			}
			if tc.Expected.Level != nil {
				expectedLevel := cyphrpass.Level(*tc.Expected.Level)
				if p.Level() != expectedLevel {
					t.Errorf("Level: got %v, want %v", p.Level(), expectedLevel)
				}
			}
		})
	}
}

// =========================================================================
// State Computation Tests
// =========================================================================

// StateTestFixture is the structure for state computation tests.
type StateTestFixture struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Keys        map[string]KeyInput `json:"keys"`
	Tests       []StateTestCase     `json:"tests"`
}

// StateTestCase is an individual state computation test.
type StateTestCase struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Setup       StateSetup    `json:"setup"`
	Expected    StateExpected `json:"expected"`
}

// StateSetup defines the test setup.
type StateSetup struct {
	Genesis     string   `json:"genesis"`
	InitialKey  string   `json:"initial_key,omitempty"`
	InitialKeys []string `json:"initial_keys,omitempty"`
}

// StateExpected defines expected state values.
type StateExpected struct {
	KS          *string `json:"ks,omitempty"`
	KSEqualsTmb *bool   `json:"ks_equals_tmb,omitempty"`
	KSIsHash    *bool   `json:"ks_is_hash,omitempty"`
	AS          *string `json:"as,omitempty"`
	ASEqualsKS  *bool   `json:"as_equals_ks,omitempty"`
	PS          *string `json:"ps,omitempty"`
	PSEqualsAS  *bool   `json:"ps_equals_as,omitempty"`
}

func TestStateComputationFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testVectorsDir, "state/computation.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixture StateTestFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	// Tests that only require genesis (no transactions)
	genesisOnlyTests := []string{
		"ks_single_key_promotion",
		"ks_two_keys_sorted",
		"as_only_ks_promotion",
		"ps_only_as_promotion",
	}

	for _, tc := range fixture.Tests {
		// Skip tests that require transactions/actions for now
		isGenesisOnly := false
		for _, name := range genesisOnlyTests {
			if tc.Name == name {
				isGenesisOnly = true
				break
			}
		}
		if !isGenesisOnly {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			var p *cyphrpass.Principal

			switch tc.Setup.Genesis {
			case "implicit":
				keyInput := fixture.Keys[tc.Setup.InitialKey]
				key := makeKeyFromInput(t, keyInput)
				p, err = cyphrpass.Implicit(key)
				if err != nil {
					t.Fatalf("Implicit failed: %v", err)
				}

			case "explicit":
				keys := make([]*coz.Key, len(tc.Setup.InitialKeys))
				for i, keyName := range tc.Setup.InitialKeys {
					keyInput := fixture.Keys[keyName]
					keys[i] = makeKeyFromInput(t, keyInput)
				}
				p, err = cyphrpass.Explicit(keys)
				if err != nil {
					t.Fatalf("Explicit failed: %v", err)
				}

			default:
				t.Fatalf("unknown genesis type: %s", tc.Setup.Genesis)
			}

			// Verify expected state
			if tc.Expected.KS != nil {
				if p.KS().String() != *tc.Expected.KS {
					t.Errorf("KS: got %s, want %s", p.KS().String(), *tc.Expected.KS)
				}
			}
			if tc.Expected.AS != nil {
				if p.AS().String() != *tc.Expected.AS {
					t.Errorf("AS: got %s, want %s", p.AS().String(), *tc.Expected.AS)
				}
			}
			if tc.Expected.PS != nil {
				if p.PS().String() != *tc.Expected.PS {
					t.Errorf("PS: got %s, want %s", p.PS().String(), *tc.Expected.PS)
				}
			}

			// Verify boolean assertions
			if tc.Expected.KSEqualsTmb != nil && *tc.Expected.KSEqualsTmb {
				keyInput := fixture.Keys[tc.Setup.InitialKey]
				if p.KS().String() != keyInput.Tmb {
					t.Errorf("KS should equal tmb: got %s, want %s", p.KS().String(), keyInput.Tmb)
				}
			}
			if tc.Expected.ASEqualsKS != nil && *tc.Expected.ASEqualsKS {
				if p.AS().String() != p.KS().String() {
					t.Errorf("AS should equal KS: got %s, want %s", p.AS().String(), p.KS().String())
				}
			}
			if tc.Expected.PSEqualsAS != nil && *tc.Expected.PSEqualsAS {
				if p.PS().String() != p.AS().String() {
					t.Errorf("PS should equal AS: got %s, want %s", p.PS().String(), p.AS().String())
				}
			}
		})
	}
}

// =========================================================================
// Edge Case Tests
// =========================================================================

// EdgeCaseFixture is the structure for edge case tests.
type EdgeCaseFixture struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Keys        map[string]KeyInput `json:"keys"`
	Tests       []EdgeCaseTest      `json:"tests"`
}

// EdgeCaseTest is an individual edge case test.
type EdgeCaseTest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Setup       StateSetup       `json:"setup"`
	Expected    EdgeCaseExpected `json:"expected"`
}

// EdgeCaseExpected defines expected values for edge cases.
type EdgeCaseExpected struct {
	KeyCount *int    `json:"key_count,omitempty"`
	KS       *string `json:"ks,omitempty"`
}

func TestEdgeCaseFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testVectorsDir, "edge_cases/ordering.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixture EdgeCaseFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	// Tests that only require genesis (key ordering tests)
	genesisOnlyTests := []string{
		"key_thumbprint_sort_order",
		"same_keys_different_order",
	}

	for _, tc := range fixture.Tests {
		// Skip tests that require transactions/actions
		isGenesisOnly := false
		for _, name := range genesisOnlyTests {
			if tc.Name == name {
				isGenesisOnly = true
				break
			}
		}
		if !isGenesisOnly {
			continue
		}

		t.Run(tc.Name, func(t *testing.T) {
			var p *cyphrpass.Principal

			switch tc.Setup.Genesis {
			case "implicit":
				keyInput := fixture.Keys[tc.Setup.InitialKey]
				key := makeKeyFromInput(t, keyInput)
				p, err = cyphrpass.Implicit(key)
				if err != nil {
					t.Fatalf("Implicit failed: %v", err)
				}

			case "explicit":
				keys := make([]*coz.Key, len(tc.Setup.InitialKeys))
				for i, keyName := range tc.Setup.InitialKeys {
					keyInput := fixture.Keys[keyName]
					keys[i] = makeKeyFromInput(t, keyInput)
				}
				p, err = cyphrpass.Explicit(keys)
				if err != nil {
					t.Fatalf("Explicit failed: %v", err)
				}

			default:
				t.Fatalf("unknown genesis type: %s", tc.Setup.Genesis)
			}

			// Verify expected values
			if tc.Expected.KeyCount != nil {
				if p.ActiveKeyCount() != *tc.Expected.KeyCount {
					t.Errorf("KeyCount: got %d, want %d", p.ActiveKeyCount(), *tc.Expected.KeyCount)
				}
			}
			if tc.Expected.KS != nil {
				if p.KS().String() != *tc.Expected.KS {
					t.Errorf("KS: got %s, want %s", p.KS().String(), *tc.Expected.KS)
				}
			}
		})
	}
}

// =========================================================================
// Transaction Tests
// =========================================================================

// TxTestFixture is the structure for transaction tests.
type TxTestFixture struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Keys        map[string]KeyInput `json:"keys"`
	Tests       []TxTestCase        `json:"tests"`
}

// TxTestCase is an individual transaction test.
type TxTestCase struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Setup       StateSetup   `json:"setup"`
	Coz         *CozMessage  `json:"coz,omitempty"`
	CozSequence []CozMessage `json:"coz_sequence,omitempty"`
	Expected    TxExpected   `json:"expected"`
}

// CozMessage represents a signed Coz message in tests.
type CozMessage struct {
	Pay json.RawMessage `json:"pay"`
	Key *KeyInput       `json:"key,omitempty"`
	Sig string          `json:"sig"`
	Czd string          `json:"czd"`
}

// TxPay represents the pay fields we need.
type TxPay struct {
	Alg string `json:"alg"`
	ID  string `json:"id,omitempty"`
	Now int64  `json:"now"`
	Pre string `json:"pre,omitempty"`
	Rvk int64  `json:"rvk,omitempty"`
	Tmb string `json:"tmb"`
	Typ string `json:"typ"`
}

// TxExpected defines expected values for transaction tests.
type TxExpected struct {
	KeyCount         *int     `json:"key_count,omitempty"`
	Level            *int     `json:"level,omitempty"`
	ActiveKeys       []string `json:"active_keys,omitempty"`
	RevokedKeys      []string `json:"revoked_keys,omitempty"`
	PRChanged        *bool    `json:"pr_changed,omitempty"`
	ASChanged        *bool    `json:"as_changed,omitempty"`
	PSChanged        *bool    `json:"ps_changed,omitempty"`
	SignerActive     *bool    `json:"signer_active,omitempty"`
	TransactionCount *int     `json:"transaction_count,omitempty"`
	PR               *string  `json:"pr,omitempty"`
	KS               *string  `json:"ks,omitempty"`
	AS               *string  `json:"as,omitempty"`
	PS               *string  `json:"ps,omitempty"`
}

func TestTransactionFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testVectorsDir, "transactions/mutations.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixture TxTestFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	for _, tc := range fixture.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			var p *cyphrpass.Principal

			// Setup genesis
			switch tc.Setup.Genesis {
			case "implicit":
				keyInput := fixture.Keys[tc.Setup.InitialKey]
				key := makeKeyFromInput(t, keyInput)
				p, err = cyphrpass.Implicit(key)
				if err != nil {
					t.Fatalf("Implicit failed: %v", err)
				}

			case "explicit":
				keys := make([]*coz.Key, len(tc.Setup.InitialKeys))
				for i, keyName := range tc.Setup.InitialKeys {
					keyInput := fixture.Keys[keyName]
					keys[i] = makeKeyFromInput(t, keyInput)
				}
				p, err = cyphrpass.Explicit(keys)
				if err != nil {
					t.Fatalf("Explicit failed: %v", err)
				}

			default:
				t.Fatalf("unknown genesis type: %s", tc.Setup.Genesis)
			}

			prBefore := p.PR().String()
			asBefore := p.AS().String()
			psBefore := p.PS().String()

			// Apply transactions
			if tc.Coz != nil {
				applyTestTransaction(t, p, tc.Coz)
			}
			for _, cozMsg := range tc.CozSequence {
				msg := cozMsg // avoid loop variable capture
				applyTestTransaction(t, p, &msg)
			}

			// Verify expected values
			if tc.Expected.KeyCount != nil {
				if p.ActiveKeyCount() != *tc.Expected.KeyCount {
					t.Errorf("KeyCount: got %d, want %d", p.ActiveKeyCount(), *tc.Expected.KeyCount)
				}
			}
			if tc.Expected.Level != nil {
				expectedLevel := cyphrpass.Level(*tc.Expected.Level)
				if p.Level() != expectedLevel {
					t.Errorf("Level: got %v, want %v", p.Level(), expectedLevel)
				}
			}
			if tc.Expected.KS != nil {
				if p.KS().String() != *tc.Expected.KS {
					t.Errorf("KS: got %s, want %s", p.KS().String(), *tc.Expected.KS)
				}
			}
			if tc.Expected.AS != nil {
				if p.AS().String() != *tc.Expected.AS {
					t.Errorf("AS: got %s, want %s", p.AS().String(), *tc.Expected.AS)
				}
			}
			if tc.Expected.PS != nil {
				if p.PS().String() != *tc.Expected.PS {
					t.Errorf("PS: got %s, want %s", p.PS().String(), *tc.Expected.PS)
				}
			}
			if tc.Expected.PR != nil {
				if p.PR().String() != *tc.Expected.PR {
					t.Errorf("PR: got %s, want %s", p.PR().String(), *tc.Expected.PR)
				}
			}

			// Verify change assertions
			if tc.Expected.PRChanged != nil {
				changed := p.PR().String() != prBefore
				if changed != *tc.Expected.PRChanged {
					t.Errorf("PR changed: got %v, want %v", changed, *tc.Expected.PRChanged)
				}
			}
			if tc.Expected.ASChanged != nil {
				changed := p.AS().String() != asBefore
				if changed != *tc.Expected.ASChanged {
					t.Errorf("AS changed: got %v, want %v", changed, *tc.Expected.ASChanged)
				}
			}
			if tc.Expected.PSChanged != nil {
				changed := p.PS().String() != psBefore
				if changed != *tc.Expected.PSChanged {
					t.Errorf("PS changed: got %v, want %v", changed, *tc.Expected.PSChanged)
				}
			}

			// Verify active keys
			for _, keyName := range tc.Expected.ActiveKeys {
				keyInput := fixture.Keys[keyName]
				tmb, _ := coz.Decode(keyInput.Tmb)
				if !p.IsKeyActive(tmb) {
					t.Errorf("expected key %s to be active", keyName)
				}
			}

			// Verify revoked keys
			for _, keyName := range tc.Expected.RevokedKeys {
				keyInput := fixture.Keys[keyName]
				tmb, _ := coz.Decode(keyInput.Tmb)
				if p.IsKeyActive(tmb) {
					t.Errorf("expected key %s to be revoked, but it's active", keyName)
				}
				// Check key exists in principal
				key := p.Key(tmb)
				if key == nil {
					t.Errorf("expected revoked key %s to exist", keyName)
				}
			}
		})
	}
}

func applyTestTransaction(t *testing.T, p *cyphrpass.Principal, cozMsg *CozMessage) {
	t.Helper()

	// Parse pay to get transaction fields
	var pay TxPay
	if err := json.Unmarshal(cozMsg.Pay, &pay); err != nil {
		t.Fatalf("failed to parse pay: %v", err)
	}

	// Decode czd
	czd, err := coz.Decode(cozMsg.Czd)
	if err != nil {
		t.Fatalf("failed to decode czd: %v", err)
	}

	// Decode signer tmb
	signer, err := coz.Decode(pay.Tmb)
	if err != nil {
		t.Fatalf("failed to decode tmb: %v", err)
	}

	// Build transaction - validate and use FIXTURE pre value
	// This validates both state machine correctness AND fixture data correctness
	tx := &cyphrpass.Transaction{
		Signer: signer,
		Now:    pay.Now,
		Czd:    czd,
		Rvk:    pay.Rvk,
	}

	// Parse and validate pre from fixture
	if pay.Pre != "" {
		pre, err := coz.Decode(pay.Pre)
		if err != nil {
			t.Fatalf("failed to decode pre: %v", err)
		}
		// Validate fixture pre matches current AS (catch fixture errors)
		if p.AS().String() != pay.Pre {
			t.Fatalf("fixture pre mismatch: fixture has %s, computed AS is %s", pay.Pre, p.AS().String())
		}
		tx.Pre = cyphrpass.AuthState(pre)
	} else {
		// For transactions like self-revoke that may not have pre, use current AS
		tx.Pre = p.AS()
	}

	// Parse id if present
	if pay.ID != "" {
		id, err := coz.Decode(pay.ID)
		if err != nil {
			t.Fatalf("failed to decode id: %v", err)
		}
		tx.ID = id
	}

	// Determine transaction kind from typ
	typ := pay.Typ
	suffix := typSuffix(typ)

	var newKey *coz.Key

	switch suffix {
	case "key/add":
		tx.Kind = cyphrpass.TxKeyAdd
		if cozMsg.Key != nil {
			newKey = makeKeyFromInput(t, *cozMsg.Key)
		}
	case "key/delete":
		tx.Kind = cyphrpass.TxKeyDelete
	case "key/replace":
		tx.Kind = cyphrpass.TxKeyReplace
		if cozMsg.Key != nil {
			newKey = makeKeyFromInput(t, *cozMsg.Key)
		}
	case "key/revoke":
		if pay.ID != "" {
			tx.Kind = cyphrpass.TxOtherRevoke
		} else {
			tx.Kind = cyphrpass.TxSelfRevoke
		}
	default:
		t.Fatalf("unknown transaction type: %s", typ)
	}

	// Apply transaction
	if err := p.ApplyTransaction(tx, newKey); err != nil {
		t.Fatalf("ApplyTransaction failed: %v", err)
	}
}

func typSuffix(typ string) string {
	for i := 0; i < len(typ); i++ {
		if typ[i] == '/' {
			return typ[i+1:]
		}
	}
	return typ
}

// =========================================================================
// Action Tests
// =========================================================================

// ActionTestFixture is the structure for action tests.
type ActionTestFixture struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Keys        map[string]KeyInput `json:"keys"`
	Tests       []ActionTestCase    `json:"tests"`
}

// ActionTestCase is an individual action test.
type ActionTestCase struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Setup       StateSetup      `json:"setup"`
	Actions     []ActionMessage `json:"actions"`
	Expected    ActionExpected  `json:"expected"`
}

// ActionMessage represents an action Coz message.
type ActionMessage struct {
	Pay ActionPay `json:"pay"`
	Sig string    `json:"sig"`
	Czd string    `json:"czd"`
}

// ActionPay represents action pay fields.
type ActionPay struct {
	Alg string `json:"alg"`
	Msg string `json:"msg"`
	Now int64  `json:"now"`
	Tmb string `json:"tmb"`
	Typ string `json:"typ"`
}

// ActionExpected defines expected values for action tests.
type ActionExpected struct {
	DSEqualsCzd    *bool   `json:"ds_equals_czd,omitempty"`
	DSIsHash       *bool   `json:"ds_is_hash,omitempty"`
	ActionCount    *int    `json:"action_count,omitempty"`
	DS             *string `json:"ds,omitempty"`
	PSChanged      *bool   `json:"ps_changed,omitempty"`
	PSIncludesDS   *bool   `json:"ps_includes_ds,omitempty"`
	SignerLastUsed *int64  `json:"signer_last_used,omitempty"`
	Level          *int    `json:"level,omitempty"`
	HasDataState   *bool   `json:"has_data_state,omitempty"`
}

func TestActionFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testVectorsDir, "actions/recording.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixture ActionTestFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	for _, tc := range fixture.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			var p *cyphrpass.Principal

			// Setup genesis
			keyInput := fixture.Keys[tc.Setup.InitialKey]
			key := makeKeyFromInput(t, keyInput)
			p, err = cyphrpass.Implicit(key)
			if err != nil {
				t.Fatalf("Implicit failed: %v", err)
			}

			psBefore := p.PS().String()

			// Apply actions
			for _, actMsg := range tc.Actions {
				czd, err := coz.Decode(actMsg.Czd)
				if err != nil {
					t.Fatalf("failed to decode czd: %v", err)
				}
				signer, err := coz.Decode(actMsg.Pay.Tmb)
				if err != nil {
					t.Fatalf("failed to decode tmb: %v", err)
				}

				action := &cyphrpass.Action{
					Typ:    actMsg.Pay.Typ,
					Signer: signer,
					Now:    actMsg.Pay.Now,
					Czd:    czd,
				}
				if err := p.RecordAction(action); err != nil {
					t.Fatalf("RecordAction failed: %v", err)
				}
			}

			// Verify expected values
			if tc.Expected.DS != nil {
				if p.DS().String() != *tc.Expected.DS {
					t.Errorf("DS: got %s, want %s", p.DS().String(), *tc.Expected.DS)
				}
			}
			if tc.Expected.DSEqualsCzd != nil && *tc.Expected.DSEqualsCzd {
				if len(tc.Actions) == 1 {
					if p.DS().String() != tc.Actions[0].Czd {
						t.Errorf("DS should equal czd: got %s, want %s", p.DS().String(), tc.Actions[0].Czd)
					}
				}
			}
			if tc.Expected.PSChanged != nil && *tc.Expected.PSChanged {
				if p.PS().String() == psBefore {
					t.Error("PS should have changed but didn't")
				}
			}
			if tc.Expected.Level != nil {
				expectedLevel := cyphrpass.Level(*tc.Expected.Level)
				if p.Level() != expectedLevel {
					t.Errorf("Level: got %v, want %v", p.Level(), expectedLevel)
				}
			}
			if tc.Expected.HasDataState != nil && *tc.Expected.HasDataState {
				if p.DS() == nil {
					t.Error("expected has_data_state but DS is nil")
				}
			}
			if tc.Expected.SignerLastUsed != nil {
				signer, _ := coz.Decode(tc.Actions[0].Pay.Tmb)
				key := p.Key(signer)
				if key == nil {
					t.Fatal("signer key not found")
				}
				if key.LastUsed != *tc.Expected.SignerLastUsed {
					t.Errorf("signer LastUsed: got %d, want %d", key.LastUsed, *tc.Expected.SignerLastUsed)
				}
			}
		})
	}
}

// =========================================================================
// Error Condition Tests
// =========================================================================

// ErrorTestFixture is the structure for error tests.
type ErrorTestFixture struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Version     string              `json:"version"`
	Keys        map[string]KeyInput `json:"keys"`
	Tests       []ErrorTestCase     `json:"tests"`
}

// ErrorTestCase is an individual error test.
type ErrorTestCase struct {
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Setup         ErrorSetup  `json:"setup"`
	Coz           *CozMessage `json:"coz,omitempty"`
	ExpectedError string      `json:"expected_error"`
}

// ErrorSetup defines the error test setup.
type ErrorSetup struct {
	Genesis        string   `json:"genesis"`
	InitialKey     string   `json:"initial_key,omitempty"`
	InitialKeys    []string `json:"initial_keys,omitempty"`
	RevokeKey      string   `json:"revoke_key,omitempty"`
	RevokeAt       int64    `json:"revoke_at,omitempty"`
	UnsupportedAlg bool     `json:"unsupported_alg,omitempty"`
}

func TestErrorFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testVectorsDir, "errors/conditions.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	var fixture ErrorTestFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	for _, tc := range fixture.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			var p *cyphrpass.Principal
			var genesisErr error

			// Setup genesis
			switch tc.Setup.Genesis {
			case "implicit":
				keyInput := fixture.Keys[tc.Setup.InitialKey]
				key := makeKeyFromInput(t, keyInput)
				p, genesisErr = cyphrpass.Implicit(key)

				// For tests expecting genesis to fail
				if tc.Coz == nil && tc.ExpectedError != "" {
					if genesisErr == nil {
						t.Fatalf("expected error %s but genesis succeeded", tc.ExpectedError)
					}
					switch tc.ExpectedError {
					case "UnsupportedAlgorithm":
						if genesisErr != cyphrpass.ErrUnsupportedAlgorithm {
							t.Errorf("expected UnsupportedAlgorithm, got %v", genesisErr)
						}
					default:
						t.Errorf("unknown expected error: %s", tc.ExpectedError)
					}
					return // Test complete
				}
				if genesisErr != nil {
					t.Fatalf("Implicit failed: %v", genesisErr)
				}

			case "explicit":
				keys := make([]*coz.Key, len(tc.Setup.InitialKeys))
				for i, keyName := range tc.Setup.InitialKeys {
					keyInput := fixture.Keys[keyName]
					keys[i] = makeKeyFromInput(t, keyInput)
				}
				p, err = cyphrpass.Explicit(keys)
				if err != nil {
					t.Fatalf("Explicit failed: %v", err)
				}

				// Handle pre-revoke setup
				if tc.Setup.RevokeKey != "" {
					revokeKeyInput := fixture.Keys[tc.Setup.RevokeKey]
					revokeTmb, _ := coz.Decode(revokeKeyInput.Tmb)

					// Apply self-revoke transaction to set up revoked state
					revokeTx := &cyphrpass.Transaction{
						Kind:   cyphrpass.TxSelfRevoke,
						Signer: revokeTmb,
						Now:    tc.Setup.RevokeAt,
						Rvk:    tc.Setup.RevokeAt,
						Czd:    []byte("fake-czd-for-setup"),
						Pre:    p.AS(),
					}
					if err := p.ApplyTransaction(revokeTx, nil); err != nil {
						t.Fatalf("failed to set up revoked key: %v", err)
					}
				}

			default:
				t.Fatalf("unknown genesis type: %s", tc.Setup.Genesis)
			}

			if tc.Coz == nil {
				t.Skip("no coz message to test")
			}

			// Try to apply the transaction (should fail)
			applyErr := applyTestTransactionForError(t, p, tc.Coz)

			if applyErr == nil {
				t.Fatalf("expected error %s but got nil", tc.ExpectedError)
			}

			// Check error type
			switch tc.ExpectedError {
			case "InvalidPrior":
				if applyErr != cyphrpass.ErrInvalidPrior {
					t.Errorf("expected InvalidPrior, got %v", applyErr)
				}
			case "UnknownKey":
				if applyErr != cyphrpass.ErrUnknownKey {
					t.Errorf("expected UnknownKey, got %v", applyErr)
				}
			case "KeyRevoked":
				if applyErr != cyphrpass.ErrKeyRevoked {
					t.Errorf("expected KeyRevoked, got %v", applyErr)
				}
			case "NoActiveKeys":
				if applyErr != cyphrpass.ErrNoActiveKeys {
					t.Errorf("expected NoActiveKeys, got %v", applyErr)
				}
			case "DuplicateKey":
				if applyErr != cyphrpass.ErrDuplicateKey {
					t.Errorf("expected DuplicateKey, got %v", applyErr)
				}
			default:
				t.Errorf("unknown expected error: %s", tc.ExpectedError)
			}
		})
	}
}

// applyTestTransactionForError is like applyTestTransaction but returns error instead of failing
func applyTestTransactionForError(t *testing.T, p *cyphrpass.Principal, cozMsg *CozMessage) error {
	t.Helper()

	var pay TxPay
	if err := json.Unmarshal(cozMsg.Pay, &pay); err != nil {
		t.Fatalf("failed to parse pay: %v", err)
	}

	czd, err := coz.Decode(cozMsg.Czd)
	if err != nil {
		t.Fatalf("failed to decode czd: %v", err)
	}

	signer, err := coz.Decode(pay.Tmb)
	if err != nil {
		t.Fatalf("failed to decode tmb: %v", err)
	}

	tx := &cyphrpass.Transaction{
		Signer: signer,
		Now:    pay.Now,
		Czd:    czd,
		Rvk:    pay.Rvk,
	}

	// Use fixture pre (to test invalid pre errors)
	if pay.Pre != "" {
		pre, err := coz.Decode(pay.Pre)
		if err != nil {
			t.Fatalf("failed to decode pre: %v", err)
		}
		tx.Pre = cyphrpass.AuthState(pre)
	}

	if pay.ID != "" {
		id, err := coz.Decode(pay.ID)
		if err != nil {
			t.Fatalf("failed to decode id: %v", err)
		}
		tx.ID = id
	}

	typ := pay.Typ
	suffix := typSuffix(typ)

	var newKey *coz.Key

	switch suffix {
	case "key/add":
		tx.Kind = cyphrpass.TxKeyAdd
		if cozMsg.Key != nil {
			newKey = makeKeyFromInput(t, *cozMsg.Key)
		}
	case "key/delete":
		tx.Kind = cyphrpass.TxKeyDelete
	case "key/replace":
		tx.Kind = cyphrpass.TxKeyReplace
		if cozMsg.Key != nil {
			newKey = makeKeyFromInput(t, *cozMsg.Key)
		}
	case "key/revoke":
		if pay.ID != "" {
			tx.Kind = cyphrpass.TxOtherRevoke
		} else {
			tx.Kind = cyphrpass.TxSelfRevoke
		}
	default:
		t.Fatalf("unknown transaction type: %s", typ)
	}

	return p.ApplyTransaction(tx, newKey)
}
