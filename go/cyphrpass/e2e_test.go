package cyphrpass_test

import (
	"path/filepath"
	"testing"

	"github.com/cyphrme/cyphrpass/testfixtures"
)

// testsDir returns the path to tests/ directory.
func e2eIntentsDir() string {
	return filepath.Join("..", "..", "tests", "e2e")
}

// loadE2EPool loads the key pool for e2e tests.
func loadE2EPool(t *testing.T) *testfixtures.Pool {
	t.Helper()
	poolPath := filepath.Join("..", "..", "tests", "keys", "pool.toml")
	pool, err := testfixtures.LoadPool(poolPath)
	if err != nil {
		t.Fatalf("failed to load pool: %v", err)
	}
	return pool
}

// TestE2E_RoundTrip runs round-trip verification tests.
// These tests generate transactions dynamically, apply them, export, and reimport.
func TestE2E_RoundTrip(t *testing.T) {
	pool := loadE2EPool(t)

	intent, err := testfixtures.LoadIntent(filepath.Join(e2eIntentsDir(), "round_trip.toml"))
	if err != nil {
		t.Fatalf("failed to load intent: %v", err)
	}

	for _, test := range intent.Test {
		t.Run(test.Name, func(t *testing.T) {
			result := testfixtures.RunE2ERoundTrip(pool, &test)
			if !result.Passed {
				t.Errorf("test failed: %v", result.Err)
				for _, f := range result.Failures {
					t.Errorf("  - %s", f)
				}
			}
		})
	}
}

// TestE2E_GenesisLoad tests genesis creation and initial state.
func TestE2E_GenesisLoad(t *testing.T) {
	pool := loadE2EPool(t)

	intent, err := testfixtures.LoadIntent(filepath.Join(e2eIntentsDir(), "genesis_load.toml"))
	if err != nil {
		t.Fatalf("failed to load intent: %v", err)
	}

	for _, test := range intent.Test {
		t.Run(test.Name, func(t *testing.T) {
			result := testfixtures.RunE2ETest(pool, &test)
			if !result.Passed {
				t.Errorf("test failed: %v", result.Err)
				for _, f := range result.Failures {
					t.Errorf("  - %s", f)
				}
			}
		})
	}
}

// TestE2E_EdgeCases tests edge case scenarios.
func TestE2E_EdgeCases(t *testing.T) {
	pool := loadE2EPool(t)

	intent, err := testfixtures.LoadIntent(filepath.Join(e2eIntentsDir(), "edge_cases.toml"))
	if err != nil {
		t.Fatalf("failed to load intent: %v", err)
	}

	for _, test := range intent.Test {
		t.Run(test.Name, func(t *testing.T) {
			result := testfixtures.RunE2ERoundTrip(pool, &test)
			if !result.Passed {
				t.Errorf("test failed: %v", result.Err)
				for _, f := range result.Failures {
					t.Errorf("  - %s", f)
				}
			}
		})
	}
}

// TestE2E_ErrorConditions tests error handling scenarios.
func TestE2E_ErrorConditions(t *testing.T) {
	pool := loadE2EPool(t)

	intent, err := testfixtures.LoadIntent(filepath.Join(e2eIntentsDir(), "error_conditions.toml"))
	if err != nil {
		t.Fatalf("failed to load intent: %v", err)
	}

	for _, test := range intent.Test {
		t.Run(test.Name, func(t *testing.T) {
			result := testfixtures.RunE2ETest(pool, &test)
			if !result.Passed {
				t.Errorf("test failed: %v", result.Err)
				for _, f := range result.Failures {
					t.Errorf("  - %s", f)
				}
			}
		})
	}
}
