package tests

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cyphrme/cyphrpass/testfixtures"
)

// getTestsDir returns the path to the tests directory.
func getTestsDir() string {
	_, file, _, _ := runtime.Caller(0)
	// go/tests/golden_test.go -> go/ -> repo root -> tests/
	return filepath.Join(filepath.Dir(file), "..", "..", "tests")
}

// pool is lazily loaded and cached.
var pool *testfixtures.Pool

func getPool(t *testing.T) *testfixtures.Pool {
	t.Helper()
	if pool != nil {
		return pool
	}
	var err error
	pool, err = testfixtures.LoadPool(filepath.Join(getTestsDir(), "keys", "pool.toml"))
	if err != nil {
		t.Fatalf("failed to load pool: %v", err)
	}
	return pool
}

// runGoldenDir runs all golden tests in a directory.
func runGoldenDir(t *testing.T, dir string) {
	t.Helper()
	goldenDir := filepath.Join(getTestsDir(), "golden", dir)
	goldens, err := testfixtures.LoadGoldenDir(goldenDir)
	if err != nil {
		t.Fatalf("failed to load golden dir %s: %v", dir, err)
	}

	pool := getPool(t)
	for _, golden := range goldens {
		t.Run(golden.Name, func(t *testing.T) {
			result := testfixtures.RunGolden(pool, golden)
			if !result.Passed {
				t.Errorf("test failed: %v", result.Err)
				for _, failure := range result.Failures {
					t.Errorf("  - %s", failure)
				}
			}
		})
	}
}

// =========================================================================
// Golden Test Functions (one per directory)
// =========================================================================

// TestGolden_Mutations tests key mutation transactions.
//
// Covers:
//   - key_add_changes_state
//   - key_add_increases_count
//   - key_delete_decreases_count
//   - key_replace_single_key
//   - other_revoke_by_peer
//   - self_revoke_moves_to_revoked
//   - transaction_sequence_replay
func TestGolden_Mutations(t *testing.T) {
	runGoldenDir(t, "mutations")
}

// TestGolden_MultiKey tests multi-key principal operations.
//
// Covers:
//   - explicit_genesis_two_keys
//   - explicit_genesis_three_keys
//   - multi_key_add_from_second
//   - key_delete_in_multi_key
func TestGolden_MultiKey(t *testing.T) {
	runGoldenDir(t, "multi_key")
}

// TestGolden_AlgorithmDiversity tests different signing algorithms.
//
// Covers:
//   - es384_algorithm
//   - ed25519_algorithm
func TestGolden_AlgorithmDiversity(t *testing.T) {
	runGoldenDir(t, "algorithm_diversity")
}

// TestGolden_StateComputation tests state digest computation.
//
// Covers:
//   - implicit_genesis_state
//   - explicit_genesis_two_keys_state
//   - explicit_genesis_three_keys_state
//   - ks_sorting_invariant
//   - as_includes_ts
//   - ps_matches_as_at_level3
//   - ps_includes_ds_at_level4
//   - ts_empty_before_transactions
//   - ds_empty_before_actions
func TestGolden_StateComputation(t *testing.T) {
	runGoldenDir(t, "state_computation")
}

// TestGolden_EdgeCases tests edge case scenarios.
//
// Covers:
//   - key_thumbprint_sort_order
//   - same_keys_different_order
//   - transaction_replay_order
//   - action_after_key_add
func TestGolden_EdgeCases(t *testing.T) {
	runGoldenDir(t, "edge_cases")
}

// TestGolden_Actions tests action recording (Level 4).
//
// Covers:
//   - single_action_promotes_level
//   - action_increments_ds
//   - multiple_actions_sequence
//   - action_with_different_signer
//   - action_after_transaction
func TestGolden_Actions(t *testing.T) {
	runGoldenDir(t, "actions")
}

// TestGolden_Errors tests error conditions.
//
// Covers:
//   - invalid_signature_fails
//   - unknown_signer_fails
//   - revoked_key_cannot_sign
//   - duplicate_key_add_fails
//   - self_revoke_last_key_fails
//   - pre_mismatch_fails
//   - timestamp_past_fails
//   - action_timestamp_past_fails
//   - unsupported_algorithm_fails
//   - action_by_revoked_key_fails
func TestGolden_Errors(t *testing.T) {
	runGoldenDir(t, "errors")
}
