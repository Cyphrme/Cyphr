package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// VerifiedTx is a transaction that has been cryptographically verified.
// It can only be created through Principal.VerifyTransaction.
// This type ensures that ApplyTransaction can never receive an unverified transaction.
type VerifiedTx struct {
	tx     *Transaction // unexported: can only be constructed via VerifyTransaction
	signer *Key         // the key that verified this transaction
	newKey *coz.Key     // optional: new key for add/replace operations
}

// Transaction returns a copy of the verified transaction data.
// The returned Transaction is read-only for inspection purposes.
func (vt *VerifiedTx) Transaction() Transaction {
	return *vt.tx
}

// Signer returns the key that signed and verified this transaction.
func (vt *VerifiedTx) Signer() *Key {
	return vt.signer
}

// VerifyTransaction verifies a Coz message and returns a VerifiedTx if valid.
//
// The coz message must contain:
//   - pay: JSON payload with transaction fields
//   - sig: signature over the payload
//
// For key/add and key/replace, newKey must be provided.
//
// # Errors
//
//   - ErrInvalidSignature: Signature doesn't verify
//   - ErrUnknownKey: Signer not in current KS
//   - ErrKeyRevoked: Signer key is revoked
//   - ErrMalformedPayload: Invalid payload structure
func (p *Principal) VerifyTransaction(cz *coz.Coz, newKey *coz.Key) (*VerifiedTx, error) {
	// Parse the payload to extract signer thumbprint
	var pay TransactionPay
	if err := json.Unmarshal(cz.Pay, &pay); err != nil {
		return nil, ErrMalformedPayload
	}

	// Look up the signing key
	signerKey := p.Key(pay.Tmb)
	if signerKey == nil {
		return nil, ErrUnknownKey
	}

	// Check if key is revoked (for most transaction types)
	// Self-revoke handled specially in apply
	if !signerKey.IsActive() {
		return nil, ErrKeyRevoked
	}

	// Verify the signature using the coz library
	valid, err := signerKey.Key.VerifyCoz(cz)
	if err != nil || !valid {
		return nil, ErrInvalidSignature
	}

	// Compute metadata including czd
	if err := cz.Meta(); err != nil {
		return nil, ErrMalformedPayload
	}

	// Parse the transaction
	tx, err := ParseTransaction(&pay, cz.Czd)
	if err != nil {
		return nil, err
	}

	// Store raw bytes for bit-perfect export
	// Build the complete entry: {pay, sig, key?}
	rawEntry, err := buildRawEntry(cz, newKey)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	tx.Raw = rawEntry

	return &VerifiedTx{
		tx:     tx,
		signer: signerKey,
		newKey: newKey,
	}, nil
}

// buildRawEntry constructs the raw JSON entry from a verified Coz message.
// This includes pay, sig, and optionally key for key/add and key/replace.
func buildRawEntry(cz *coz.Coz, newKey *coz.Key) (json.RawMessage, error) {
	// Build entry map with preserved pay bytes
	entry := map[string]any{
		"pay": json.RawMessage(cz.Pay),
		"sig": cz.Sig.String(), // base64url encoded
	}

	// Include key material for key/add and key/replace
	if newKey != nil {
		entry["key"] = map[string]any{
			"alg": string(newKey.Alg),
			"pub": newKey.Pub.String(),
			"tmb": newKey.Tmb.String(),
		}
	}

	return json.Marshal(entry)
}
