package testfixtures_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cyphrme/cyphrpass/testfixtures"
)

// getTestsDir returns the path to the tests directory.
func getTestsDir() string {
	_, file, _, _ := runtime.Caller(0)
	// go/testfixtures/testfixtures_test.go -> go/ -> ../tests
	return filepath.Join(filepath.Dir(file), "..", "..", "tests")
}

func TestLoadPool(t *testing.T) {
	poolPath := filepath.Join(getTestsDir(), "keys", "pool.toml")
	pool, err := testfixtures.LoadPool(poolPath)
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	if pool.Meta.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", pool.Meta.Version, "0.1.0")
	}

	// Check golden key exists
	golden := pool.Get("golden")
	if golden == nil {
		t.Fatal("golden key not found")
	}
	if golden.Alg != "ES256" {
		t.Errorf("golden.Alg = %q, want ES256", golden.Alg)
	}
}

func TestPoolKey_ToCozKey(t *testing.T) {
	poolPath := filepath.Join(getTestsDir(), "keys", "pool.toml")
	pool, err := testfixtures.LoadPool(poolPath)
	if err != nil {
		t.Fatalf("LoadPool failed: %v", err)
	}

	golden := pool.Get("golden")
	if golden == nil {
		t.Fatal("golden key not found")
	}

	cozKey, err := golden.ToCozKey()
	if err != nil {
		t.Fatalf("ToCozKey failed: %v", err)
	}

	// Expected tmb from pool.toml reference
	expectedTmb := "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
	if cozKey.Tmb.String() != expectedTmb {
		t.Errorf("tmb = %q, want %q", cozKey.Tmb.String(), expectedTmb)
	}
}

func TestLoadGolden(t *testing.T) {
	goldenPath := filepath.Join(getTestsDir(), "golden", "mutations", "key_add_changes_state.json")
	golden, err := testfixtures.LoadGolden(goldenPath)
	if err != nil {
		t.Fatalf("LoadGolden failed: %v", err)
	}

	if golden.Name != "key_add_changes_state" {
		t.Errorf("Name = %q, want key_add_changes_state", golden.Name)
	}

	if len(golden.Principal) != 1 || golden.Principal[0] != "golden" {
		t.Errorf("Principal = %v, want [golden]", golden.Principal)
	}

	// Check tx count using helper
	if golden.TxCount() != 1 {
		t.Errorf("TxCount = %d, want 1", golden.TxCount())
	}

	if !golden.IsGenesisOnly() == false {
		t.Error("expected non-genesis test")
	}

	if golden.IsErrorTest() {
		t.Error("expected non-error test")
	}
}

func TestLoadGoldenDir(t *testing.T) {
	mutationsDir := filepath.Join(getTestsDir(), "golden", "mutations")
	goldens, err := testfixtures.LoadGoldenDir(mutationsDir)
	if err != nil {
		t.Fatalf("LoadGoldenDir failed: %v", err)
	}

	// Should have 6 mutation tests
	if len(goldens) != 6 {
		t.Errorf("LoadGoldenDir returned %d goldens, want 6", len(goldens))
	}
}

func TestGolden_IsErrorTest(t *testing.T) {
	errorsDir := filepath.Join(getTestsDir(), "golden", "errors")
	goldens, err := testfixtures.LoadGoldenDir(errorsDir)
	if err != nil {
		t.Fatalf("LoadGoldenDir failed: %v", err)
	}

	// All error tests should have IsErrorTest() == true
	for _, g := range goldens {
		if !g.IsErrorTest() {
			t.Errorf("%s: expected error test but IsErrorTest() = false", g.Name)
		}
	}
}
