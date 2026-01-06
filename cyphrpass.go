// account.go
package cyphrpass

import (
	"bytes"
	"errors"
	"sort"

	"github.com/cyphrme/coz"
)

// TODO:
//  - Proof of possession.
//  - Consider including POP in Coz.
//  - Maybe Coz export type `now` for timestamps.

// Tran is a Transaction includes all signatures required to result in a auth
// new block. A single signature is required for the most frequent use case.
// Multiple signatures may be required to perform a Level 5+ transaction. Lookup
// key for each coz is `czd`
//
// Basic Transactions (before weights):
// Account creation,
// add key,
// self-revoke key,
// other-revoke key,
// remove key
//
// Transaction Verbs:
// Create
// Delete
// Update (For key tags and user information like email)
// Revoke (Self-revoke and other revoke)
//
// Action General Verbs:
// Create
// Read
// Upsert
// Update
// Delete
//
// /cyphrpass/account/create
// /cyphrpass/account/delete
// /cyphrpass/account/update
// /cyphrpass/account/key/create
// /cyphrpass/account/key/delete
// /cyphrpass/account/key/update
// /cyphrpass/account/key/revoke
// /cyphrpass/account/key/other-revoke
type Tran map[coz.B64s][]coz.Coz

// Dig is labeled digest: the algorithm label and digest value.
type Dig struct {
	alg coz.HshAlg
	dig coz.B64
}

// A derivation is the identifier for auth using a particular hashing algorithm.
// The abstract ID may have multiple derivations, one for each algorithm hashing
// algorithm.
type Derivation struct {
	Dig
	Bid coz.B64 // A particular Block ID using the hash alg of the derivation.
}

// Derivations is a map of derivations for a particular block.
type Derivations map[coz.B64s]Derivation

// Account represents a Cyphrpass user account (Levels 1–3).
//
//   - AR (Account Root) the permanent account identifier.
//
//   - AS is the current account state.  (Includes ALS and DLS. "Latest block".)
//
//   - ALS, Auth Ledger State, is the current Merkle Root of auth for current block: all active key
//     thumbprints, all transactions, rules, (and potentially a nonce).
//     An AS changes as auth changes, and is below the master MR for a block, ID.
//
//   - DLS, Data Ledger State, is the current Merkle Root of auth for current block: all active key
//     thumbprints, all transactions, rules, (and potentially a nonce).
//     An AS changes as auth changes, and is below the master MR for a block, ID.
//
//   - Keys maps thumbprint (as base64ut string) to the full key.
//     Using string is required because []byte / coz.B64 cannot be a map key.
//     This gives good type safety while remaining JSON-friendly.
//
//   - RevokedKeys maps revoked thumbprints to revocation timestamp.
//
//   - Trans holds all signed state-changing operations.
type Account struct {
	AR  Derivations `json:"ar"`
	AS  Derivations `json:"as"`
	ALS Derivations `json:"als"`
	DLS Derivations `json:"dls"`

	Keys        map[coz.B64s]*coz.Key `json:"keys,omitempty"`
	RevokedKeys map[coz.B64s]*coz.Key `json:"revoked_keys,omitempty"`
	Tran        []*coz.Coz            `json:"transactions,omitempty"` // Transactions
}

// Global that holds all keys loaded in memory.  This avoids reloading keys into
// memory that are already referenced in other blocks/checkpoints.
type Keys map[coz.B64s]coz.Key

// Block is a particular ALS, the auth state of the account at a particular moment.
//
// A Checkpoint is the full account at a particular point.  This is useful for
// rebuilds, so user state doesn't have to recalculate from all previous
// transactions, only to the last checkpoint.  May want to do checkpoints every
// nth transaction, based on size, or timestamp.
type Block struct {
	ID Derivations `json:"id"`
	AS Derivations `json:"as"` // Auth State

	Prev coz.B64 // Previous Block.  Nil on genesis.
	Next coz.B64 // Next Block. (Might be nil. Dunno yet)
	now  int64   // Local timestamp for when the block was created.
	Tran         // Last transaction to create the current state at this block.

	Checkpoint Account // Full account.  Checkpoints are useful for rebuilding state.
}

var ActiveKeys map[coz.B64s]coz.Key  // Flat with all active keys
var RevokedKeys map[coz.B64s]coz.Key // Flat with all revoked keys

type Chain map[coz.B64s]*Block

// NewAccount creates a new Cyphrpass account with exactly one initial key.
// It is a convenience wrapper around NewMultiAccount.
func NewAccount(initialKey *coz.Key) (*Account, error) {

	return NewMultiAccount(initialKey)
}

// NewMultiAccount creates a new Cyphrpass account with one or more initial keys.
//
// The first key provided determines the permanent Account Root (AR = SHA-256(firstKey.Tmb)).
// All supplied keys are added as active keys, and the current Merkle Root (MR) is computed
// from the full set of initial keys.
//
// Requires at least one key. All keys must have valid thumbprints.
func NewMultiAccount(initialKeys ...*coz.Key) (*Account, error) {
	if len(initialKeys) == 0 {
		return nil, errors.New("at least one initial key is required")
	}

	acc := &Account{
		Keys: make(map[coz.B64s]*coz.Key),
		//RevokedKeys: make(map[B64s]int64),
		Tran: make([]*coz.Coz, 0),
	}

	// Add all initial keys
	for _, key := range initialKeys {
		if key == nil {
			return nil, errors.New("nil key provided")
		}
		if len(key.Tmb) == 0 {
			return nil, errors.New("key with empty thumbprint provided")
		}
		acc.Keys[coz.B64s(key.Tmb.String())] = key
	}

	// Compute initial Merkle Root from all keys
	if err := acc.updateMerkleRoot(); err != nil {
		return nil, err
	}

	// Initial MR will differ from AR if more than one key
	return acc, nil
}

// updateMerkleRoot recomputes the current Merkle Root.
// It sorts all active thumbprints lexicographically (as base64ut strings),
// decodes them, concatenates the raw bytes, then hashes with SHA-256.
func (a *Account) updateMerkleRoot() error {
	if len(a.Keys) == 0 {
		return errors.New("cannot compute Merkle root: no active keys")
	}

	// Collect and sort thumbprint strings
	var tmbStrs []string
	for t := range a.Keys {
		tmbStrs = append(tmbStrs, t)
	}
	sort.Strings(tmbStrs)

	// Concatenate decoded bytes
	var buf bytes.Buffer
	for _, s := range tmbStrs {
		b, err := coz.Decode(s)
		if err != nil {
			return err
		}
		buf.Write(b)
	}

	// Hash the concatenation
	digest, err := coz.Hash(coz.SHA256, buf.Bytes())
	if err != nil {
		return err
	}

	a.MR = digest
	return nil
}

// // UpsertKey adds or replaces a key via a signed "cyphr.me/key/upsert" transaction.
// // The signer must be an active key in the account.
// // The new key may contain a private component (d) if this is a local wallet.
// func (a *Account) UpsertKey(signer *coz.Key, newKey *coz.Key) error {
// 	if signer == nil || newKey == nil {
// 		return errors.New("signer and new key cannot be nil")
// 	}
// 	if len(newKey.Tmb) == 0 {
// 		return errors.New("new key must have a valid thumbprint")
// 	}

// 	// Verify signer is currently active
// 	if _, active := a.Keys[signer.Tmb.String()]; !active {
// 		return errors.New("signer key is not active")
// 	}

// 	// Payload for the upsert transaction
// 	type UpsertPay struct {
// 		Alg coz.SEAlg `json:"alg"`
// 		Iat int64      `json:"iat"`
// 		Tmb coz.B64   `json:"tmb"`
// 		Typ string     `json:"typ"`
// 		Key *coz.Key  `json:"key"`
// 	}

// 	pay := UpsertPay{
// 		Alg: signer.Alg,
// 		Iat: time.Now().Unix(),
// 		Tmb: signer.Tmb,
// 		Typ: "cyphr.me/key/upsert",
// 		Key: newKey,
// 	}

// 	payJSON, err := coz.Marshal(pay)
// 	if err != nil {
// 		return err
// 	}

// 	var genericPay coz.Pay
// 	if err := json.Unmarshal(payJSON, &genericPay); err != nil {
// 		return err
// 	}

// 	// Sign the transaction
// 	tx, err := signer.SignPay(&genericPay)
// 	if err != nil {
// 		return err
// 	}

// 	// Defensive verification
// 	valid, err := signer.VerifyCoz(tx)
// 	if err != nil {
// 		return err
// 	}
// 	if !valid {
// 		return errors.New("upsert transaction has invalid signature")
// 	}

// 	// Insert / replace the key
// 	a.Keys[newKey.Tmb.String()] = newKey

// 	// Recompute Merkle root
// 	if err := a.updateMerkleRoot(); err != nil {
// 		return err
// 	}

// 	// Record the signed transaction
// 	a.Transactions = append(a.Transactions, tx)

// 	return nil
// }
