package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// Action represents a signed user action (Level 4 AAA).
//
// Actions are arbitrary signed Coz messages recorded in Data State.
// They are stateless (no chaining via pre field).
type Action struct {
	// Typ is the action type URI (e.g., "cyphr.me/comment/create").
	Typ string

	// Signer is the thumbprint of the signing key.
	Signer coz.B64

	// Now is the action timestamp.
	Now int64

	// Czd is the Coz digest of this action.
	Czd coz.B64

	// raw is the original CozJson bytes for this action.
	// This field enables bit-perfect export for storage round-trips.
	raw json.RawMessage
}

// Raw returns the original CozJson bytes for this action.
func (a *Action) Raw() json.RawMessage {
	return a.raw
}

// SetRaw sets the raw JSON bytes for storage round-trips.
// This is used during import to preserve bit-perfect fidelity.
func (a *Action) SetRaw(raw json.RawMessage) {
	a.raw = raw
}

// ParseAction creates an Action from a CozPay object.
// The czd must be pre-computed from the full Coz message.
func ParseAction(pay *CozPay, czd coz.B64) (*Action, error) {
	if pay == nil {
		return nil, ErrMalformedPayload
	}
	if pay.Typ == "" {
		return nil, ErrMalformedPayload
	}
	// [data-action-no-pre]: Data action cozies MUST NOT contain pre.
	if pay.Pre != "" {
		return nil, ErrMalformedPayload
	}

	return &Action{
		Typ:    pay.Typ,
		Signer: pay.Tmb,
		Now:    pay.Now,
		Czd:    czd,
	}, nil
}
