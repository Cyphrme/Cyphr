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
//
// Supports both the new v2 format (Commit + unified Action) and the legacy
// format (Pay/Crypto/Step + Action/ActionStep). Legacy fields will be removed
// once all TOML files are migrated and the generator/runner are rewritten.
type TestIntent struct {
	// Name is the test identifier.
	Name string `toml:"name"`
	// Principal lists genesis key names from pool.
	Principal []string `toml:"principal"`
	// Setup contains optional modifiers (e.g., pre-revoke keys).
	Setup *SetupIntent `toml:"setup,omitempty"`

	// ── New canonical fields (v2) ──────────────────────────────

	// Commit is the commit sequence. Each commit contains one or more
	// transactions. Used by new [[test.commit]] / [[test.commit.tx]] format.
	Commit []CommitIntent `toml:"commit,omitempty"`

	// ── Legacy fields (bridge for runner + old TOML parsing) ───

	// Pay is payload intent for single-step tests.
	Pay *PayIntent `toml:"pay,omitempty"`
	// Crypto is crypto intent for single-step tests.
	Crypto *CryptoIntent `toml:"crypto,omitempty"`
	// Step contains steps for multi-step transaction tests.
	Step []StepIntent `toml:"step,omitempty"`
	// Action is single action for single-action tests ([test.action]).
	Action *ActionIntent `toml:"action,omitempty"`
	// ActionStep contains action sequence for multi-action tests.
	ActionStep []ActionIntent `toml:"action_step,omitempty"`

	// Override contains override fields for error tests.
	Override *OverrideIntent `toml:"override,omitempty"`
	// Expected contains assertions about final state.
	Expected *ExpectedAssertions `toml:"expected,omitempty"`
}

// ── New canonical types (v2) ──────────────────────────────────────

// CommitIntent is a single commit containing one or more transactions.
type CommitIntent struct {
	// Tx contains transactions within this commit.
	Tx []TxIntent `toml:"tx,omitempty"`
}

// TxIntent is a single transaction within a commit.
// Merges the old PayIntent + CryptoIntent into one flat struct.
type TxIntent struct {
	// Typ is transaction type (e.g., "cyphr.me/key/create").
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

// ── Legacy types (bridge for runner) ──────────────────────────────

// SetupIntent contains setup modifiers for a test.
type SetupIntent struct {
	// RevokeKey is key name to pre-revoke before test.
	RevokeKey string `toml:"revoke_key,omitempty"`
	// RevokeAt is timestamp for the revocation.
	RevokeAt int64 `toml:"revoke_at,omitempty"`
}

// PayIntent contains payload fields for a test step.
//
// Deprecated: use TxIntent instead. Kept for runner compatibility.
type PayIntent struct {
	// Typ is transaction/action type.
	Typ string `toml:"typ"`
	// Now is timestamp.
	Now int64 `toml:"now"`
	// Msg is optional message.
	Msg string `toml:"msg,omitempty"`
	// Rvk is optional revocation timestamp.
	Rvk int64 `toml:"rvk,omitempty"`
}

// CryptoIntent contains crypto fields for a test step.
//
// Deprecated: use TxIntent instead. Kept for runner compatibility.
type CryptoIntent struct {
	// Signer is signer key name from pool.
	Signer string `toml:"signer"`
	// Target is target key name for key/add, key/revoke.
	Target string `toml:"target,omitempty"`
}

// StepIntent is a single step in a multi-step test.
//
// Deprecated: use CommitIntent + TxIntent instead. Kept for runner compatibility.
type StepIntent struct {
	// Pay is payload intent.
	Pay PayIntent `toml:"pay"`
	// Crypto is crypto intent.
	Crypto CryptoIntent `toml:"crypto"`
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
}

// ExpectedAssertions contains expected state after test execution.
type ExpectedAssertions struct {
	// KeyCount is expected number of active keys.
	KeyCount *int `toml:"key_count,omitempty"`
	// Level is expected feature level.
	Level *int `toml:"level,omitempty"`
	// KS is expected key state digest.
	KS string `toml:"ks,omitempty"`
	// AS is expected auth state digest.
	AS string `toml:"as,omitempty"`
	// CS is expected commit state digest.
	CS string `toml:"cs,omitempty"`
	// PS is expected principal state digest.
	PS string `toml:"ps,omitempty"`
	// CommitID is expected commit ID digest.
	CommitID string `toml:"commit_id,omitempty"`
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

// HasCommits returns true if this test has commits (new v2 format).
func (t *TestIntent) HasCommits() bool {
	return len(t.Commit) > 0
}

// IsMultiStep returns true if this is a multi-step transaction test (legacy).
func (t *TestIntent) IsMultiStep() bool {
	return len(t.Step) > 0
}

// HasAction returns true if this test has actions.
func (t *TestIntent) HasAction() bool {
	return t.Action != nil || len(t.ActionStep) > 0
}

// IsMultiAction returns true if this test has multi-step actions.
func (t *TestIntent) IsMultiAction() bool {
	return len(t.ActionStep) > 0
}

// IsGenesisOnly returns true if this is a genesis-only test.
func (t *TestIntent) IsGenesisOnly() bool {
	return t.Pay == nil && len(t.Step) == 0 && t.Action == nil && len(t.ActionStep) == 0 && len(t.Commit) == 0
}

// HasTxAndAction returns true if this test has both transaction and action.
func (t *TestIntent) HasTxAndAction() bool {
	return (t.Pay != nil || len(t.Commit) > 0) && (t.Action != nil || len(t.ActionStep) > 0)
}

// IsErrorTest returns true if this test expects an error.
func (t *TestIntent) IsErrorTest() bool {
	return t.Expected != nil && t.Expected.Error != ""
}
