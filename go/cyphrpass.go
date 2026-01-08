// Package cyphrpass provides a decoupled, storage-agnostic implementation of
// Cyphrpass - a self-sovereign identity and authentication layer for the Internet.
//
// This package implements Cyphrpass feature levels 1-4:
//   - Level 1: Single static key per service
//   - Level 2: Single key with programmatic replacement
//   - Level 3: Multiple keys with equal authority
//   - Level 4: Arbitrary data (ALS, DLS, AS) - Actions and data layer
//
// The primary types are:
//   - Account: User account with keys and state
//   - Block: A point-in-time snapshot in the account chain
//   - Key: Extension of coz.Key with Cyphrpass-specific tracking
//   - Action: User-signed operations (comments, posts, etc.)
//   - Transaction: State-mutating auth operations (key add/revoke)
package cyphrpass

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/cyphrme/coz"
)

// Standard Cyphrpass action types.
const (
	// Authority for Cyphrpass types
	Authority = "cyphr.me"

	// Account transactions (auth layer)
	TypAccountCreate  = Authority + "/cyphrpass/account/create"
	TypAccountDelete  = Authority + "/cyphrpass/account/delete"
	TypKeyCreate      = Authority + "/cyphrpass/key/create"
	TypKeyRevoke      = Authority + "/cyphrpass/key/revoke"
	TypKeyOtherRevoke = Authority + "/cyphrpass/key/other-revoke"
	TypKeyDelete      = Authority + "/cyphrpass/key/delete"
	TypKeyUpsert      = Authority + "/cyphrpass/key/upsert"

	// Data layer actions (Level 4)
	TypComment  = Authority + "/comment/create"
	TypReaction = Authority + "/reaction/create"
	TypBookmark = Authority + "/bookmark/create"
)

// ErrKeyNotActive is returned when an operation requires an active key.
var ErrKeyNotActive = errors.New("cyphrpass: key is not active")

// ErrKeyRevoked is returned when attempting to use a revoked key.
var ErrKeyRevoked = errors.New("cyphrpass: key is revoked")

// ErrInvalidTransaction is returned for malformed transactions.
var ErrInvalidTransaction = errors.New("cyphrpass: invalid transaction")

// ErrNoActiveKeys is returned when an account has no active keys.
var ErrNoActiveKeys = errors.New("cyphrpass: no active keys")

////////////////////////////////////////////////////////////////////////////////
// Core Types
////////////////////////////////////////////////////////////////////////////////

// Dig is a labeled digest: the algorithm label and digest value.
// This is the fundamental unit for cryptographic identifiers.
type Dig struct {
	Alg coz.HshAlg `json:"alg"`
	Dig coz.B64    `json:"dig"`
}

// Derivations maps digest values (as B64 strings) to their full Dig info.
// Each entry represents the same abstract identity computed with a different
// hashing algorithm. The map key is the actual digest value.
//
// Example: An account root might have derivations for SHA-256 and SHA-384,
// allowing verification regardless of which algorithm a verifier prefers.
type Derivations map[coz.B64s]Dig

// Key extends coz.Key with Cyphrpass-specific tracking fields.
// These fields track key lifecycle within the Cyphrpass system.
type Key struct {
	*coz.Key

	// FirstSeen is when this key was first added to the account.
	FirstSeen int64 `json:"first_seen,omitempty"`

	// LastUsed is the last time this key signed a valid transaction/action.
	LastUsed int64 `json:"last_used,omitempty"`

	// RevokedAt is the timestamp when this key was revoked (0 if active).
	// This is the `rvk` time from the revoke transaction, not when it was seen.
	RevokedAt int64 `json:"revoked_at,omitempty"`

	// RevokedBy is the tmb of the key that revoked this key (nil for self-revoke).
	RevokedBy coz.B64 `json:"revoked_by,omitempty"`
}

// IsActive returns true if the key is not revoked.
func (k *Key) IsActive() bool {
	return k.RevokedAt == 0
}

// IsActiveAt returns true if the key was active at the given timestamp.
// This is critical for validating historical transactions.
func (k *Key) IsActiveAt(timestamp int64) bool {
	if k.RevokedAt == 0 {
		return true // Not revoked
	}
	return timestamp < k.RevokedAt
}

////////////////////////////////////////////////////////////////////////////////
// Account - The central identity type
////////////////////////////////////////////////////////////////////////////////

// Account represents a Cyphrpass user account (Levels 1-4).
//
// Terminology:
//   - AR (Account Root): Permanent account identifier (first initial state)
//   - AS (Account State): Current top-level Merkle root combining ALS and DLS
//   - ALS (Auth Ledger State): Merkle root of authentication data (keys, transactions)
//   - DLS (Data Ledger State): Merkle root of user data/actions (Level 4+)
type Account struct {
	// AR is the permanent Account Root - the initial state digest.
	// This never changes and uniquely identifies the account.
	AR Derivations `json:"ar"`

	// AS is the current Account State - top level combining ALS and DLS.
	AS Derivations `json:"as"`

	// Auth contains the authentication ledger (Level 3).
	Auth AuthLedger `json:"auth"`

	// Data contains the data ledger (Level 4+). Nil for Level 1-3.
	Data *DataLedger `json:"data,omitempty"`
}

// AuthLedger holds the authentication layer state (ALS).
// This tracks all keys and auth-related transactions.
type AuthLedger struct {
	// State is the current ALS Merkle root.
	State Derivations `json:"state"`

	// Keys maps thumbprint (as B64 string) to the key.
	// Only active keys are in this map.
	Keys map[coz.B64s]*Key `json:"keys,omitempty"`

	// RevokedKeys maps thumbprint to revoked keys.
	// Keeping revoked keys allows historical verification.
	RevokedKeys map[coz.B64s]*Key `json:"revoked_keys,omitempty"`

	// Transactions holds signed state-changing auth operations.
	// For storage efficiency, implementations may store only recent transactions
	// and checkpoint older ones into blocks.
	Transactions []*coz.Coz `json:"transactions,omitempty"`
}

// DataLedger holds the data layer state (DLS) for Level 4+.
// This tracks user actions like comments, posts, reactions, etc.
type DataLedger struct {
	// State is the current DLS Merkle root.
	State Derivations `json:"state"`

	// Actions holds signed user actions.
	// Like transactions, implementations may checkpoint these.
	Actions []*coz.Coz `json:"actions,omitempty"`
}

// Block represents a point-in-time snapshot of account state.
// Blocks form a chain enabling historical verification and efficient rebuilds.
type Block struct {
	// ID is the unique identifier(s) for this block.
	ID Derivations `json:"id"`

	// AS is the Account State at this block.
	AS Derivations `json:"as"`

	// PrevID references the previous block (nil for genesis).
	// Uses the primary algorithm of the account.
	PrevID coz.B64 `json:"prev,omitempty"`

	// CreatedAt is when this block was created.
	CreatedAt int64 `json:"created_at"`

	// Transactions in this block (since previous block).
	Transactions []*coz.Coz `json:"transactions,omitempty"`

	// Actions in this block - Level 4 (since previous block).
	Actions []*coz.Coz `json:"actions,omitempty"`

	// Checkpoint, if present, holds full account state for efficient rebuilds.
	// Not all blocks need checkpoints - perhaps every Nth block.
	Checkpoint *Account `json:"checkpoint,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// Account Lifecycle
////////////////////////////////////////////////////////////////////////////////

// NewAccount creates a new Cyphrpass account with one or more initial keys.
//
// The first key's algorithm determines the primary hashing algorithm for the account.
// All keys are added as active, and the initial Merkle root becomes both AR and AS.
//
// Returns error if no keys provided or if any key is invalid.
func NewAccount(initialKeys ...*coz.Key) (*Account, error) {
	if len(initialKeys) == 0 {
		return nil, errors.New("cyphrpass: at least one initial key required")
	}

	acc := &Account{
		Auth: AuthLedger{
			Keys:        make(map[coz.B64s]*Key),
			RevokedKeys: make(map[coz.B64s]*Key),
		},
	}

	now := time.Now().Unix()

	// Add all initial keys
	for _, k := range initialKeys {
		if k == nil {
			return nil, errors.New("cyphrpass: nil key provided")
		}
		if len(k.Tmb) == 0 {
			return nil, errors.New("cyphrpass: key missing thumbprint")
		}

		wrapped := &Key{
			Key:       k,
			FirstSeen: now,
		}
		acc.Auth.Keys[coz.B64s(k.Tmb.String())] = wrapped
	}

	// Compute initial state
	if err := acc.recomputeALS(); err != nil {
		return nil, err
	}

	// Initial state: ALS = AS = AR (no DLS yet)
	acc.AS = acc.Auth.State
	acc.AR = acc.Auth.State

	return acc, nil
}

// GetKey returns the key for a given thumbprint, checking both active and revoked.
// Returns nil if key not found.
func (a *Account) GetKey(tmb coz.B64) *Key {
	k := a.Auth.Keys[coz.B64s(tmb.String())]
	if k != nil {
		return k
	}
	return a.Auth.RevokedKeys[coz.B64s(tmb.String())]
}

// IsKeyActive returns true if the key is in the active keys map.
func (a *Account) IsKeyActive(tmb coz.B64) bool {
	_, ok := a.Auth.Keys[coz.B64s(tmb.String())]
	return ok
}

// IsKeyActiveAt returns true if the key was active at the given timestamp.
// This checks revocation time to enable historical verification.
func (a *Account) IsKeyActiveAt(tmb coz.B64, timestamp int64) bool {
	k := a.GetKey(tmb)
	if k == nil {
		return false
	}
	return k.IsActiveAt(timestamp)
}

// ActiveKeys returns all currently active keys.
func (a *Account) ActiveKeys() []*Key {
	keys := make([]*Key, 0, len(a.Auth.Keys))
	for _, k := range a.Auth.Keys {
		keys = append(keys, k)
	}
	return keys
}

////////////////////////////////////////////////////////////////////////////////
// State Computation
////////////////////////////////////////////////////////////////////////////////

// recomputeALS recalculates the Auth Ledger State from current active keys.
// It sorts thumbprints lexicographically, concatenates, and hashes.
func (a *Account) recomputeALS() error {
	if len(a.Auth.Keys) == 0 {
		return ErrNoActiveKeys
	}

	// Collect and sort thumbprint strings for determinism
	tmbStrs := make([]string, 0, len(a.Auth.Keys))
	for t := range a.Auth.Keys {
		tmbStrs = append(tmbStrs, string(t))
	}
	sort.Strings(tmbStrs)

	// Concatenate decoded thumbprint bytes
	var buf bytes.Buffer
	for _, s := range tmbStrs {
		b, err := coz.Decode(s)
		if err != nil {
			return err
		}
		buf.Write(b)
	}

	// Hash the concatenation (using SHA-256 as primary)
	// TODO: Support multiple algorithms based on key algs
	digest, err := coz.Hash(coz.SHA256, buf.Bytes())
	if err != nil {
		return err
	}

	// Update ALS with this derivation
	a.Auth.State = Derivations{
		coz.B64s(digest.String()): Dig{
			Alg: coz.SHA256,
			Dig: digest,
		},
	}

	return nil
}

// recomputeAS recalculates Account State from ALS and DLS.
// AS = Hash(ALS || DLS) if DLS exists, else AS = ALS.
func (a *Account) recomputeAS() error {
	if a.Data == nil {
		// Level 1-3: AS = ALS
		a.AS = a.Auth.State
		return nil
	}

	// Level 4+: AS = Hash(ALS || DLS)
	// Get the primary derivation from each
	var alsDigest, dlsDigest coz.B64
	for _, d := range a.Auth.State {
		alsDigest = d.Dig
		break
	}
	for _, d := range a.Data.State {
		dlsDigest = d.Dig
		break
	}

	combined := append(alsDigest, dlsDigest...)
	digest, err := coz.Hash(coz.SHA256, combined)
	if err != nil {
		return err
	}

	a.AS = Derivations{
		coz.B64s(digest.String()): Dig{
			Alg: coz.SHA256,
			Dig: digest,
		},
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Transactions (Auth Layer Mutations)
////////////////////////////////////////////////////////////////////////////////

// VerifyTransaction checks that a Coz transaction is valid for this account:
//   - The signing key (tmb) was active at the transaction time (iat/now)
//   - The signature is cryptographically valid
//
// Returns the key that signed it, or error if invalid.
func (a *Account) VerifyTransaction(tx *coz.Coz) (*Key, error) {
	if tx == nil {
		return nil, ErrInvalidTransaction
	}

	// Extract tmb from pay
	if err := tx.Meta(); err != nil {
		return nil, err
	}

	// Check key was active at transaction time
	if !a.IsKeyActiveAt(tx.Parsed.Tmb, tx.Parsed.Now) {
		return nil, ErrKeyNotActive
	}

	// Get the key for verification
	key := a.GetKey(tx.Parsed.Tmb)
	if key == nil {
		return nil, ErrKeyNotActive
	}

	// Verify signature
	valid, err := key.Key.VerifyCoz(tx)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("cyphrpass: invalid signature")
	}

	return key, nil
}

// AddKey adds a new key via a signed transaction.
// The signer must be an active key in the account.
func (a *Account) AddKey(tx *coz.Coz, newKey *coz.Key) error {
	// Verify the transaction
	signer, err := a.VerifyTransaction(tx)
	if err != nil {
		return err
	}

	// Validate new key
	if newKey == nil || len(newKey.Tmb) == 0 {
		return errors.New("cyphrpass: invalid new key")
	}

	// Check not already present
	tmbStr := coz.B64s(newKey.Tmb.String())
	if _, exists := a.Auth.Keys[tmbStr]; exists {
		return errors.New("cyphrpass: key already active")
	}
	if _, exists := a.Auth.RevokedKeys[tmbStr]; exists {
		return errors.New("cyphrpass: key was previously revoked")
	}

	// Add key
	now := time.Now().Unix()
	a.Auth.Keys[tmbStr] = &Key{
		Key:       newKey,
		FirstSeen: now,
	}

	// Update signer's last used
	signer.LastUsed = now

	// Record transaction
	a.Auth.Transactions = append(a.Auth.Transactions, tx)

	// Recompute state
	if err := a.recomputeALS(); err != nil {
		return err
	}
	return a.recomputeAS()
}

// RevokeKey revokes a key via a signed transaction.
// Self-revoke: signer revokes their own key.
// Other-revoke: signer revokes another key.
func (a *Account) RevokeKey(tx *coz.Coz, targetTmb coz.B64) error {
	// Verify the transaction
	signer, err := a.VerifyTransaction(tx)
	if err != nil {
		return err
	}

	// Find target key
	tmbStr := coz.B64s(targetTmb.String())
	target, ok := a.Auth.Keys[tmbStr]
	if !ok {
		return errors.New("cyphrpass: target key not active")
	}

	// Get revocation time from transaction (Meta already called by VerifyTransaction)
	// Revoke the key
	target.RevokedAt = tx.Parsed.Now
	if !bytes.Equal(signer.Key.Tmb, targetTmb) {
		target.RevokedBy = signer.Key.Tmb
	}

	// Move from active to revoked
	delete(a.Auth.Keys, tmbStr)
	a.Auth.RevokedKeys[tmbStr] = target

	// Check we still have active keys
	if len(a.Auth.Keys) == 0 {
		return ErrNoActiveKeys
	}

	// Update signer's last used
	signer.LastUsed = tx.Parsed.Now

	// Record transaction
	a.Auth.Transactions = append(a.Auth.Transactions, tx)

	// Recompute state
	if err := a.recomputeALS(); err != nil {
		return err
	}
	return a.recomputeAS()
}

////////////////////////////////////////////////////////////////////////////////
// Actions (Data Layer - Level 4)
////////////////////////////////////////////////////////////////////////////////

// EnableDataLedger initializes the Data Ledger for Level 4 functionality.
// Must be called before recording actions.
func (a *Account) EnableDataLedger() error {
	if a.Data != nil {
		return nil // Already enabled
	}

	a.Data = &DataLedger{
		State:   Derivations{},
		Actions: make([]*coz.Coz, 0),
	}

	// Now AS = Hash(ALS || DLS), but DLS is empty so we need initial state
	// Empty DLS state is just the hash of empty
	emptyDigest, err := coz.Hash(coz.SHA256, nil)
	if err != nil {
		return err
	}

	a.Data.State = Derivations{
		coz.B64s(emptyDigest.String()): Dig{
			Alg: coz.SHA256,
			Dig: emptyDigest,
		},
	}

	return a.recomputeAS()
}

// RecordAction records a user action (comment, post, reaction, etc).
// The action must be signed by an active key.
func (a *Account) RecordAction(action *coz.Coz) error {
	if a.Data == nil {
		return errors.New("cyphrpass: data ledger not enabled (Level 4 required)")
	}

	// Verify the action is signed by an active key
	signer, err := a.VerifyTransaction(action) // Same verification logic
	if err != nil {
		return err
	}

	// Meta already called by VerifyTransaction, use action.Parsed
	// Update signer's last used
	signer.LastUsed = action.Parsed.Now

	// Record action
	a.Data.Actions = append(a.Data.Actions, action)

	// Recompute DLS (simplified: hash of all action czds concatenated)
	if err := a.recomputeDLS(); err != nil {
		return err
	}

	return a.recomputeAS()
}

// recomputeDLS recalculates Data Ledger State from actions.
func (a *Account) recomputeDLS() error {
	if a.Data == nil {
		return nil
	}

	// If no actions, use empty hash
	if len(a.Data.Actions) == 0 {
		emptyDigest, err := coz.Hash(coz.SHA256, nil)
		if err != nil {
			return err
		}
		a.Data.State = Derivations{
			coz.B64s(emptyDigest.String()): Dig{
				Alg: coz.SHA256,
				Dig: emptyDigest,
			},
		}
		return nil
	}

	// Hash all action czds together
	var buf bytes.Buffer
	for _, action := range a.Data.Actions {
		// Ensure Meta is called to populate Czd
		if err := action.Meta(); err != nil {
			return err
		}
		buf.Write(action.Czd)
	}

	digest, err := coz.Hash(coz.SHA256, buf.Bytes())
	if err != nil {
		return err
	}

	a.Data.State = Derivations{
		coz.B64s(digest.String()): Dig{
			Alg: coz.SHA256,
			Dig: digest,
		},
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Typ Parsing (from Cyphr.me everything.go)
////////////////////////////////////////////////////////////////////////////////

// TypPath represents a parsed typ URI.
// Example: "cyphr.me/ac/image/create" parses to:
//   - Authority: "cyphr.me"
//   - Root: "ac"
//   - Noun: "ac/image"
//   - Verb: "create"
type TypPath struct {
	Authority string `json:"authority"`
	Root      string `json:"root"`
	Noun      string `json:"noun"`
	Verb      string `json:"verb"`
	Child     string `json:"child"`
}

// ParseTyp parses a typ string into its components.
func ParseTyp(typ string) *TypPath {
	// Implementation matches Cyphr.me's EveryPathParse
	// Omitted for brevity - see everything.go
	return nil // TODO: Implement
}
