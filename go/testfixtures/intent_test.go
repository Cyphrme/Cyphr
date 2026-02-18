package testfixtures

import (
	"path/filepath"
	"testing"
)

func TestLoadIntent_RoundTrip(t *testing.T) {
	// Load the round_trip.toml intent file
	path := filepath.Join("..", "..", "tests", "e2e", "round_trip.toml")
	intent, err := LoadIntent(path)
	if err != nil {
		t.Fatalf("LoadIntent failed: %v", err)
	}

	if len(intent.Test) == 0 {
		t.Fatal("expected at least one test")
	}

	// Check first test has expected structure
	test := &intent.Test[0]
	if test.Name == "" {
		t.Error("test name should not be empty")
	}
	if len(test.Principal) == 0 {
		t.Error("principal should not be empty")
	}
}

func TestLoadIntent_ErrorConditions(t *testing.T) {
	// Load error_conditions.toml
	path := filepath.Join("..", "..", "tests", "e2e", "error_conditions.toml")
	intent, err := LoadIntent(path)
	if err != nil {
		t.Fatalf("LoadIntent failed: %v", err)
	}

	// All tests should be error tests
	for _, test := range intent.Test {
		if !test.IsErrorTest() {
			t.Errorf("test %q should be an error test", test.Name)
		}
	}
}

func TestLoadIntent_GenesisLoad(t *testing.T) {
	// Load genesis_load.toml
	path := filepath.Join("..", "..", "tests", "e2e", "genesis_load.toml")
	intent, err := LoadIntent(path)
	if err != nil {
		t.Fatalf("LoadIntent failed: %v", err)
	}

	// At least some tests should be genesis-only
	hasGenesisOnly := false
	for _, test := range intent.Test {
		if test.IsGenesisOnly() {
			hasGenesisOnly = true
		}
	}
	if !hasGenesisOnly {
		t.Error("expected at least one genesis-only test")
	}
}

func TestLoadIntentDir(t *testing.T) {
	dir := filepath.Join("..", "..", "tests", "e2e")
	intents, err := LoadIntentDir(dir)
	if err != nil {
		t.Fatalf("LoadIntentDir failed: %v", err)
	}

	// Should load all 5 intent files
	if len(intents) != 5 {
		t.Errorf("expected 5 intent files, got %d", len(intents))
	}
}

func TestTestIntent_Helpers(t *testing.T) {
	t.Run("HasCommits", func(t *testing.T) {
		test := TestIntent{Commit: []CommitIntent{{}, {}}}
		if !test.HasCommits() {
			t.Error("should have commits")
		}

		test2 := TestIntent{}
		if test2.HasCommits() {
			t.Error("should not have commits")
		}
	})

	t.Run("HasAction", func(t *testing.T) {
		test := TestIntent{Action: []ActionIntent{{}}}
		if !test.HasAction() {
			t.Error("should have action")
		}

		test2 := TestIntent{Action: []ActionIntent{{}, {}}}
		if !test2.HasAction() {
			t.Error("should have action via multiple actions")
		}

		test3 := TestIntent{}
		if test3.HasAction() {
			t.Error("should not have action")
		}
	})

	t.Run("IsErrorTest", func(t *testing.T) {
		test := TestIntent{Expected: &ExpectedAssertions{Error: "SomeError"}}
		if !test.IsErrorTest() {
			t.Error("should be error test")
		}

		test2 := TestIntent{Expected: &ExpectedAssertions{}}
		if test2.IsErrorTest() {
			t.Error("should not be error test")
		}
	})
}
