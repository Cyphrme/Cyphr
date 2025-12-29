// account.go
package cyphrpass

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/cyphrme/coze"
)

// TODO:
// Proof of possession
// Maybe Coze export type `now` for timestamps.
// Consider B64s in Coze, not type map[string], and would prefer type coze.B64.  Go maps cannot use []byte

// String B64 because maps can't take coze.B64
// "URI safe Base 64 canonical truncated", b64t.
type B64s string

// A Transaction includes all signatures required to result in a new block.
// A single signature is required for the most frequent use case. Multiple signatures may be
// required to perform a transaction (Level 5) so multiple cozies may be
// require.
type Tran map[B64s][]coze.Coze

// Account represents a Cyphrpass user account (Levels 1–3).
//
//   - AR is the permanent Account Root: SHA-256 of the first key's tmb.
//   - MR is the current Merkle Root of all active key thumbprints.
//   - Keys maps thumbprint (as base64ut string) to the full key.
//     Using string is required because []byte / coze.B64 cannot be a map key.
//     This gives good type safety while remaining JSON-friendly.
//   - RevokedKeys maps revoked thumbprints to revocation timestamp.
//   - Transactions holds all signed state-changing operations.
type Account struct {
	AR          coze.B64           `json:"ar"`
	MR          coze.B64           `json:"mr"`
	Keys        map[B64s]*coze.Key `json:"keys,omitempty"`         // tmb.String() → key
	RevokedKeys map[B64s]int64     `json:"revoked_keys,omitempty"` // tmb.String() → rvk unix timestamp
	Tran        `json:"transactions,omitempty"`
}

type Ident struct {
	Alg coze.HshAlg
	Dig coze.B64 // Merkle root for the particular instance and particular alg
	BID coze.B64 // Pointer to Block ID
}

// Block is the state of the account at a particular moment.
//
// A Checkpoint is the full account at a particular point.  This is useful for
// rebuilds, so user state doesn't have to recalculate from all previous
// transactions, only to the last checkpoint.  May want to do checkpoints every
// nth transaction, based on size, or timestamp.
type Block struct {
	// BID is hardcoded to SHA256.  Block ID's are internal only and are not
	// "cryptographically secure", we just needed an identifier.  We're using BID
	// as an internal ID.  However, Blocks do have cryptographically secure ID's
	// which are the `Idents`
	BID        coze.B64       // Block ID: Block ID is the hash of the block.
	Prev       coze.B64       // Previous Block.  Nil on genesis.
	Next       coze.B64       // Next Block. Might be nil.
	now        int64          // Local Timestamp for when the block was created.
	Idents     map[B64s]Ident // Digests in various algorithms.  Cryptographically secure to the alg.
	State      Tran           // Last transaction to create the current state at this block.
	Checkpoint Account        // Full account.  Checkpoints are useful for rebuilding state.
}

type Chain map[B64s]*Block

// NewAccount creates a new Cyphrpass account with exactly one initial key.
// It is a convenience wrapper around NewMultiAccount.
func NewAccount(initialKey *coze.Key) (*Account, error) {
	return NewMultiAccount(initialKey)
}

// NewMultiAccount creates a new Cyphrpass account with one or more initial keys.
//
// The first key provided determines the permanent Account Root (AR = SHA-256(firstKey.Tmb)).
// All supplied keys are added as active keys, and the current Merkle Root (MR) is computed
// from the full set of initial keys.
//
// Requires at least one key. All keys must have valid thumbprints.
func NewMultiAccount(initialKeys ...*coze.Key) (*Account, error) {
	if len(initialKeys) == 0 {
		return nil, errors.New("at least one initial key is required")
	}

	firstKey := initialKeys[0]
	if len(firstKey.Tmb) == 0 { // Sanity check
		return nil, errors.New("first key must have a valid thumbprint")
	}

	// Compute permanent Account Root from the first key's thumbprint
	// TODO incorrect
	ar, err := coze.Hash(firstKey.Alg.SigAlg().Hash(), firstKey.Tmb)
	if err != nil {
		return nil, err
	}

	acc := &Account{
		AR:           ar,
		Keys:         make(map[string]*coze.Key),
		RevokedKeys:  make(map[string]int64),
		Transactions: make([]*coze.Coze, 0),
	}

	// Add all initial keys
	for _, key := range initialKeys {
		if key == nil {
			return nil, errors.New("nil key provided in initial keys")
		}
		if len(key.Tmb) == 0 {
			return nil, errors.New("key with empty thumbprint provided")
		}
		acc.Keys[key.Tmb.String()] = key
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
		b, err := coze.Decode(s)
		if err != nil {
			return err
		}
		buf.Write(b)
	}

	// Hash the concatenation
	digest, err := coze.Hash(coze.SHA256, buf.Bytes())
	if err != nil {
		return err
	}

	a.MR = digest
	return nil
}

// UpsertKey adds or replaces a key via a signed "cyphr.me/key/upsert" transaction.
// The signer must be an active key in the account.
// The new key may contain a private component (d) if this is a local wallet.
func (a *Account) UpsertKey(signer *coze.Key, newKey *coze.Key) error {
	if signer == nil || newKey == nil {
		return errors.New("signer and new key cannot be nil")
	}
	if len(newKey.Tmb) == 0 {
		return errors.New("new key must have a valid thumbprint")
	}

	// Verify signer is currently active
	if _, active := a.Keys[signer.Tmb.String()]; !active {
		return errors.New("signer key is not active")
	}

	// Payload for the upsert transaction
	type UpsertPay struct {
		Alg coze.SEAlg `json:"alg"`
		Iat int64      `json:"iat"`
		Tmb coze.B64   `json:"tmb"`
		Typ string     `json:"typ"`
		Key *coze.Key  `json:"key"`
	}

	pay := UpsertPay{
		Alg: signer.Alg,
		Iat: time.Now().Unix(),
		Tmb: signer.Tmb,
		Typ: "cyphr.me/key/upsert",
		Key: newKey,
	}

	payJSON, err := coze.Marshal(pay)
	if err != nil {
		return err
	}

	var genericPay coze.Pay
	if err := json.Unmarshal(payJSON, &genericPay); err != nil {
		return err
	}

	// Sign the transaction
	tx, err := signer.SignPay(&genericPay)
	if err != nil {
		return err
	}

	// Defensive verification
	valid, err := signer.VerifyCoze(tx)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("upsert transaction has invalid signature")
	}

	// Insert / replace the key
	a.Keys[newKey.Tmb.String()] = newKey

	// Recompute Merkle root
	if err := a.updateMerkleRoot(); err != nil {
		return err
	}

	// Record the signed transaction
	a.Transactions = append(a.Transactions, tx)

	return nil
}
