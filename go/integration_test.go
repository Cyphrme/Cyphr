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

func assertStateEquals(t *testing.T, name string, expected *string, actual cyphrpass.PrincipalState) {
	t.Helper()
	if expected == nil {
		if actual != nil {
			t.Errorf("%s: expected nil, got %s", name, actual.String())
		}
		return
	}
	if actual.String() != *expected {
		t.Errorf("%s: got %s, want %s", name, actual.String(), *expected)
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
