package cyphrpass

import "github.com/cyphrme/coz"

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
}

// ParseAction creates an Action from a Coz pay object.
// The czd must be pre-computed from the full Coz message.
func ParseAction(pay *coz.Pay, czd coz.B64) (*Action, error) {
	if pay == nil {
		return nil, ErrMalformedPayload
	}
	if pay.Typ == "" {
		return nil, ErrMalformedPayload
	}

	return &Action{
		Typ:    pay.Typ,
		Signer: pay.Tmb,
		Now:    pay.Now,
		Czd:    czd,
	}, nil
}
