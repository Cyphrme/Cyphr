// Package testfixtures provides utilities for loading and running Cyphr test fixtures.
//
// This package supports the two-tiered test system:
//
//  1. Golden files (JSON): Pre-computed tests with real cryptographic values
//  2. Intent files (TOML): Human-readable test definitions (future)
//
// For now, only golden file consumption is implemented. Intent parsing will be
// added when E2E tests require it.
//
// # Usage
//
//	pool, _ := testfixtures.LoadPool("tests/keys/pool.toml")
//	golden, _ := testfixtures.LoadGolden("tests/golden/mutations/key_add.json")
//	result := testfixtures.RunGolden(pool, golden)
//	if result.Err != nil {
//	    t.Fatalf("golden test failed: %v", result.Err)
//	}
package testfixtures
