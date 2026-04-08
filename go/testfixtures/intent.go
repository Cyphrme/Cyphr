package testfixtures

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Intent is a test intent file containing one or more test cases.
// Intent files define test cases in human-editable TOML format.
type Intent struct {
	// Test contains test cases defined in this file.
	Test []TestIntent `toml:"test"`
}

// TestIntent is a single test case intent.
type TestIntent struct {
	// Name is the test identifier.
	Name string `toml:"name"`
	// Principal lists genesis key names from pool.
	Principal []string `toml:"principal"`
	// Setup contains optional modifiers (e.g., pre-revoke keys).
	Setup *SetupIntent `toml:"setup,omitempty"`

	// Commit is the commit sequence. Each commit contains one or more
	// cozies.
	Commit []CommitIntent `toml:"commit,omitempty"`
	// Action contains the action sequence (Level 4).
	Action []ActionIntent `toml:"action,omitempty"`

	// Override contains override fields for error tests.
	Override *OverrideIntent `toml:"override,omitempty"`
	// Expected contains assertions about final state.
	Expected *ExpectedAssertions `toml:"expected,omitempty"`
}

// CommitIntent is a single commit containing transactions.
// Each transaction is a list of cozies (list-of-lists per SPEC).
type CommitIntent struct {
	// Tx is a list of transactions within this commit.
	// Each transaction is a list of cozies.
	Tx [][]TxIntent `toml:"tx,omitempty"`
}

// TxIntent is a single coz within a commit.
// Flat struct merging the old PayIntent + CryptoIntent fields.
type TxIntent struct {
	// Typ is coz type (e.g., "cyphr.me/key/create").
	Typ string `toml:"typ"`
	// Now is timestamp.
	Now int64 `toml:"now"`
	// Signer is signer key name from pool.
	Signer string `toml:"signer"`
	// Target is target key name for key/add, key/revoke.
	Target string `toml:"target,omitempty"`
	// Msg is optional message.
	Msg string `toml:"msg,omitempty"`
	// Rvk is optional revocation timestamp.
	Rvk int64 `toml:"rvk,omitempty"`
}

// SetupIntent contains setup modifiers for a test.
type SetupIntent struct {
	// RevokeKey is key name to pre-revoke before test.
	RevokeKey string `toml:"revoke_key,omitempty"`
	// RevokeAt is timestamp for the revocation.
	RevokeAt int64 `toml:"revoke_at,omitempty"`
}

// ActionIntent is an action intent (Level 4).
type ActionIntent struct {
	// Typ is action type (e.g., "cyphr.me/action").
	Typ string `toml:"typ"`
	// Now is timestamp.
	Now int64 `toml:"now"`
	// Signer is signer key name from pool.
	Signer string `toml:"signer"`
	// Msg is optional message content.
	Msg string `toml:"msg,omitempty"`
}

// OverrideIntent contains override fields for error tests.
type OverrideIntent struct {
	// Pre overrides `pre` field value (for InvalidPrior tests).
	Pre string `toml:"pre,omitempty"`
	// Tmb overrides `tmb` field value (for UnknownKey tests).
	Tmb string `toml:"tmb,omitempty"`
	// Now overrides timestamp (for TimestampPast tests).
	Now *int64 `toml:"now,omitempty"`
	// InjectPre forces a `pre` field onto actions (for [data-action-no-pre] tests).
	InjectPre *bool `toml:"inject_pre,omitempty"`
}

// ExpectedAssertions contains expected state after test execution.
type ExpectedAssertions struct {
	// KeyCount is expected number of active keys.
	KeyCount *int `toml:"key_count,omitempty"`
	// Level is expected feature level.
	Level *int `toml:"level,omitempty"`
	// KR is expected key root digest.
	KR string `toml:"kr,omitempty"`
	// AR is expected auth root digest.
	AR string `toml:"ar,omitempty"`
	// SR is expected state root digest.
	SR string `toml:"sr,omitempty"`
	// PR is expected principal root digest.
	PR string `toml:"pr,omitempty"`
	// CommitID is expected commit ID digest.
	CommitID string `toml:"tr,omitempty"`
	// Error is expected error for error tests.
	Error string `toml:"error,omitempty"`
}

// LoadIntent loads an intent file from TOML.
func LoadIntent(path string) (*Intent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var intent Intent
	if err := toml.Unmarshal(data, &intent); err != nil {
		return nil, err
	}

	return &intent, nil
}

// LoadIntentDir loads all intent files from a directory.
func LoadIntentDir(dir string) ([]*Intent, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var intents []*Intent
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		intent, err := LoadIntent(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		intents = append(intents, intent)
	}

	return intents, nil
}

// ── Dispatch helpers ─────────────────────────────────────────────

// HasCommits returns true if this test has commits.
func (t *TestIntent) HasCommits() bool {
	return len(t.Commit) > 0
}

// HasAction returns true if this test has actions.
func (t *TestIntent) HasAction() bool {
	return len(t.Action) > 0
}

// IsGenesisOnly returns true if this is a genesis-only test.
func (t *TestIntent) IsGenesisOnly() bool {
	return len(t.Commit) == 0 && len(t.Action) == 0
}

// HasTxAndAction returns true if this test has both cozies and actions.
func (t *TestIntent) HasTxAndAction() bool {
	return len(t.Commit) > 0 && len(t.Action) > 0
}

// IsErrorTest returns true if this test expects an error.
func (t *TestIntent) IsErrorTest() bool {
	return t.Expected != nil && t.Expected.Error != ""
}
