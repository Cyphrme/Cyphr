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
