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

// Account represents a Cyphrpass user account (Levels 1–3).
//
//   - AR is the permanent Account Root: SHA-256 of the first key's tmb.
//   - MR is the current Merkle Root of all active key thumbprints.
//   - Keys maps thumbprint (as base64ut string) to the full key.
//     Using string is required because []byte / coze.B64 cannot be a map key.
//     This gives good type safety while remaining JSON-friendly.
//   - RevokedKeys maps revoked thumbprints to revocation timestamp.
//   - Transactions holds all signed state-changing operations.
//
// TODO: would prefer to not use type map[string], and would prefer type coze.B64.  Go maps cannot use []byte
type Account struct {
	AR           coze.B64             `json:"ar"`
	MR           coze.B64             `json:"mr"`
	Keys         map[string]*coze.Key `json:"keys,omitempty"`         // tmb.String() → key
	RevokedKeys  map[string]int64     `json:"revoked_keys,omitempty"` // tmb.String() → rvk unix timestamp
	Transactions []*coze.Coze         `json:"transactions,omitempty"`
}

// NewAccount creates a new Cyphrpass account with one initial key.
// The Account Root (AR) is SHA-256(initialKey.Tmb).
func NewAccount(initialKey *coze.Key) (*Account, error) {
	if initialKey == nil {
		return nil, errors.New("initial key cannot be nil")
	}
	if len(initialKey.Tmb) == 0 {
		return nil, errors.New("initial key must have a valid thumbprint")
	}

	// Compute Account Root = hash(tmb)
	ar, err := coze.Hash(coze.SHA256, initialKey.Tmb)
	if err != nil {
		return nil, err
	}

	acc := &Account{
		AR:           ar,
		MR:           ar, // initially same as AR
		Keys:         map[string]*coze.Key{initialKey.Tmb.String(): initialKey},
		RevokedKeys:  make(map[string]int64),
		Transactions: make([]*coze.Coze, 0),
	}

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
