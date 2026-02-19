package storage

import (
	"encoding/json"
	"fmt"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/cyphrpass/cyphrpass"
)

// Genesis represents how a principal was created.
//
// Per SPEC §5, principals can be created implicitly (single key, no transaction)
// or explicitly (multiple keys with genesis transactions).
type Genesis interface {
	isGenesis()
}

// ImplicitGenesis represents implicit genesis: single key, no transaction required.
//
// Per SPEC §5.1: "Identity emerges from first key possession"
//   - PR = PS = AS = KS = tmb
//
// This is the Level 1/2 genesis path.
type ImplicitGenesis struct {
	Key *coz.Key
}

func (ImplicitGenesis) isGenesis() {}

// ExplicitGenesis represents explicit genesis: multiple keys established at creation.
//
// Per SPEC §5.1: "Multi-key accounts require explicit genesis"
//   - PR = H(sort(tmb₀, tmb₁, ...))
//
// This is the Level 3+ genesis path.
type ExplicitGenesis struct {
	Keys []*coz.Key
}

func (ExplicitGenesis) isGenesis() {}

// LoadPrincipal loads a principal by replaying entries from genesis.
//
// This performs full verification of the entire transaction history.
// Each entry's signature is verified before applying to ensure cryptographic
// integrity of the reconstructed state.
//
// # Arguments
//
//   - genesis: How the principal was created (implicit or explicit)
//   - entries: All transactions and actions to replay
//
// # Errors
//
// Returns error if:
//   - Signature verification fails
//   - Transaction chain is broken (pre mismatch)
//   - Unknown signer key
//   - Genesis has no keys
//
// # Example
//
//	genesis := storage.ImplicitGenesis{Key: myKey}
//	entries, _ := store.GetEntries(pr)
//	principal, err := storage.LoadPrincipal(genesis, entries)
func LoadPrincipal(genesis Genesis, entries []*Entry) (*cyphrpass.Principal, error) {
	// Create principal from genesis
	var principal *cyphrpass.Principal
	var err error

	switch g := genesis.(type) {
	case ImplicitGenesis:
		principal, err = cyphrpass.Implicit(g.Key)
	case ExplicitGenesis:
		if len(g.Keys) == 0 {
			return nil, ErrNoGenesisKeys
		}
		principal, err = cyphrpass.Explicit(g.Keys)
	default:
		return nil, fmt.Errorf("unknown genesis type: %T", genesis)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create principal from genesis: %w", err)
	}

	// Replay entries
	if err := replayEntries(principal, entries); err != nil {
		return nil, err
	}

	return principal, nil
}

// replayEntries replays entries onto a principal (shared logic).
func replayEntries(principal *cyphrpass.Principal, entries []*Entry) error {
	for i, entry := range entries {
		if err := ReplayEntry(principal, entry, i); err != nil {
			return err
		}
	}
	return nil
}

// ReplayEntry replays a single entry onto a principal.
// This is exported for use by testfixtures package for setup-aware loading.
func ReplayEntry(principal *cyphrpass.Principal, entry *Entry, index int) error {
	// Determine if transaction or action
	if entry.IsTransaction() {
		return replayTransaction(principal, entry, index)
	}
	return replayAction(principal, entry, index)
}

// replayTransaction replays a transaction entry.
func replayTransaction(principal *cyphrpass.Principal, entry *Entry, index int) error {
	// Extract pay and sig bytes
	payBytes, err := entry.PayBytes()
	if err != nil {
		return fmt.Errorf("entry %d: %w", index, err)
	}

	sigBytes, err := entry.SigBytes()
	if err != nil {
		return fmt.Errorf("entry %d: %w", index, err)
	}

	// Extract optional key material
	keyJSON, err := entry.KeyJSON()
	if err != nil {
		return fmt.Errorf("entry %d: failed to extract key: %w", index, err)
	}

	var newKey *coz.Key
	if keyJSON != nil {
		newKey, err = parseKeyJSON(keyJSON)
		if err != nil {
			return fmt.Errorf("entry %d: invalid key: %w", index, err)
		}
	}

	// Construct Coz message for verification
	cz := &coz.Coz{
		Pay: payBytes,
		Sig: sigBytes,
	}

	// Verify and apply transaction
	verifiedTx, err := principal.VerifyTransaction(cz, newKey)
	if err != nil {
		return &LoadError{
			Index:   index,
			Message: fmt.Sprintf("verification failed: %v", err),
		}
	}

	// Note: IsCommit is derived from the payload's commit field during parsing.
	// No external assignment needed - payload is source of truth (SPEC §4.2.1).

	if _, err := principal.ApplyTransaction(verifiedTx); err != nil {
		return &LoadError{
			Index:   index,
			Message: fmt.Sprintf("apply failed: %v", err),
		}
	}

	return nil
}

// replayAction replays an action entry.
func replayAction(principal *cyphrpass.Principal, entry *Entry, index int) error {
	// Extract pay and sig bytes
	payBytes, err := entry.PayBytes()
	if err != nil {
		return fmt.Errorf("entry %d: %w", index, err)
	}

	sigBytes, err := entry.SigBytes()
	if err != nil {
		return fmt.Errorf("entry %d: %w", index, err)
	}

	// Construct Coz message for verification
	cz := &coz.Coz{
		Pay: payBytes,
		Sig: sigBytes,
	}

	// Parse pay to get action fields
	var pay coz.Pay
	if err := json.Unmarshal(payBytes, &pay); err != nil {
		return fmt.Errorf("entry %d: invalid pay: %w", index, err)
	}

	// Get the signer key for verification
	signerKey := principal.Key(pay.Tmb)
	if signerKey == nil {
		return &LoadError{
			Index:   index,
			Message: fmt.Sprintf("unknown signer: %s", pay.Tmb.String()),
		}
	}

	// Verify signature
	valid, err := signerKey.Key.VerifyCoz(cz)
	if err != nil || !valid {
		return &LoadError{
			Index:   index,
			Message: "signature verification failed",
		}
	}

	// Compute czd
	if err := cz.Meta(); err != nil {
		return fmt.Errorf("entry %d: failed to compute meta: %w", index, err)
	}

	// Create and record action
	action, err := cyphrpass.ParseAction(&pay, cz.Czd)
	if err != nil {
		return fmt.Errorf("entry %d: invalid action: %w", index, err)
	}

	// Store raw bytes for future export
	action.Raw = entry.Raw

	if err := principal.RecordAction(action); err != nil {
		return &LoadError{
			Index:   index,
			Message: fmt.Sprintf("record failed: %v", err),
		}
	}

	return nil
}

// parseKeyJSON parses key material from JSON.
func parseKeyJSON(data json.RawMessage) (*coz.Key, error) {
	var keyData struct {
		Alg string `json:"alg"`
		Pub string `json:"pub"`
		Tmb string `json:"tmb"`
	}

	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, err
	}

	pub, err := coz.Decode(keyData.Pub)
	if err != nil {
		return nil, fmt.Errorf("invalid pub: %w", err)
	}

	tmb, err := coz.Decode(keyData.Tmb)
	if err != nil {
		return nil, fmt.Errorf("invalid tmb: %w", err)
	}

	return &coz.Key{
		Alg: coz.SEAlg(keyData.Alg),
		Pub: pub,
		Tmb: tmb,
	}, nil
}

// LoadError represents an error during entry replay.
type LoadError struct {
	Index   int
	Message string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("entry %d: %s", e.Index, e.Message)
}
