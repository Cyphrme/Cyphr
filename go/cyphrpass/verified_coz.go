package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// VerifiedCoz is a coz that has been cryptographically verified.
// It can only be created through Principal.VerifyCoz.
// This type ensures that ApplyCoz can never receive an unverified coz.
type VerifiedCoz struct {
	cz     *ParsedCoz // unexported: can only be constructed via VerifyCoz
	signer *Key       // the key that verified this coz
	newKey *coz.Key   // optional: new key for add/replace operations
}

// ParsedCoz returns a copy of the verified coz data.
// The returned ParsedCoz is read-only for inspection purposes.
func (vt *VerifiedCoz) ParsedCoz() ParsedCoz {
	return *vt.cz
}

// Signer returns the key that signed and verified this coz.
func (vt *VerifiedCoz) Signer() *Key {
	return vt.signer
}

// VerifyCoz verifies a Coz message and returns a VerifiedCoz if valid.
//
// The coz message must contain:
//   - pay: JSON payload with coz fields
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
func (p *Principal) VerifyCoz(cz *coz.Coz, newKey *coz.Key) (*VerifiedCoz, error) {
	// Parse the payload to extract signer thumbprint
	var pay CozPay
	if err := json.Unmarshal(cz.Pay, &pay); err != nil {
		return nil, ErrMalformedPayload
	}

	// Look up the signing key
	signerKey := p.Key(pay.Tmb)
	if signerKey == nil {
		return nil, ErrUnknownKey
	}

	// Check if key is revoked (for most coz types)
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

	// Parse the coz
	parsed, err := ParseCoz(&pay, cz.Czd)
	if err != nil {
		return nil, err
	}

	// Store raw bytes for bit-perfect export
	// Build the complete entry: {pay, sig, key?}
	rawEntry, err := buildRawEntry(cz, newKey)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	parsed.raw = rawEntry

	return &VerifiedCoz{
		cz:     parsed,
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
