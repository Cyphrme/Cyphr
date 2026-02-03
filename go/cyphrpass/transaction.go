package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// Transaction type constants per SPEC §4.2.
// These are typ suffixes; full typ is "<authority>/<suffix>".
const (
	TypKeyCreate  = "key/create" // SPEC §4.2
	TypKeyDelete  = "key/delete"
	TypKeyReplace = "key/replace"
	TypKeyRevoke  = "key/revoke"

	TypPrincipalCreate = "principal/create" // SPEC §5.1 genesis finalization
)

// TransactionKind represents the type of auth mutation.
type TransactionKind int

const (
	TxKeyCreate TransactionKind = iota
	TxKeyDelete
	TxKeyReplace
	TxSelfRevoke
	TxOtherRevoke
	TxPrincipalCreate // SPEC §5.1 genesis finalization
)

// String returns the string representation of a TransactionKind.
func (k TransactionKind) String() string {
	switch k {
	case TxKeyCreate:
		return "key/create"
	case TxKeyDelete:
		return "key/delete"
	case TxKeyReplace:
		return "key/replace"
	case TxSelfRevoke:
		return "key/revoke (self)"
	case TxOtherRevoke:
		return "key/revoke (other)"
	case TxPrincipalCreate:
		return "principal/create"
	default:
		return "unknown"
	}
}

// Transaction is a parsed auth mutation.
//
// Transactions mutate Auth State and form a chain via the Pre field.
type Transaction struct {
	// Kind is the type of transaction.
	Kind TransactionKind

	// Signer is the thumbprint of the signing key.
	Signer coz.B64

	// Now is the transaction timestamp.
	Now int64

	// Czd is the Coz digest of this transaction.
	Czd coz.B64

	// Pre is the prior Auth State (required except for self-revoke).
	Pre AuthState

	// ID is the target key thumbprint (for add/delete/replace/other-revoke).
	ID coz.B64

	// Rvk is the revocation timestamp (for revoke transactions).
	Rvk int64

	// IsCommit indicates this transaction finalizes a commit (SPEC §4.2.1).
	IsCommit bool

	// Raw is the original CozJson bytes for this transaction.
	// This field enables bit-perfect export for storage round-trips.
	// It includes the complete {pay, sig, key?} structure.
	Raw json.RawMessage
}

// TransactionPay represents the payload fields for a Cyphrpass transaction.
// This struct is used for JSON unmarshaling of transaction payloads.
type TransactionPay struct {
	Alg    coz.SEAlg `json:"alg"`
	Tmb    coz.B64   `json:"tmb"`
	Now    int64     `json:"now"`
	Typ    string    `json:"typ"`
	Pre    string    `json:"pre,omitempty"`    // Base64url previous auth state
	ID     string    `json:"id,omitempty"`     // Base64url target key thumbprint
	Rvk    int64     `json:"rvk,omitempty"`    // Revocation timestamp
	Commit bool      `json:"commit,omitempty"` // True if this finalizes a commit (SPEC §4.2.1)
}

// ParseTransaction parses a transaction from a TransactionPay and czd.
// The czd must be pre-computed from the full Coz message.
func ParseTransaction(pay *TransactionPay, czd coz.B64) (*Transaction, error) {
	if pay == nil || pay.Typ == "" {
		return nil, ErrMalformedPayload
	}

	tx := &Transaction{
		Signer:   pay.Tmb,
		Now:      pay.Now,
		Czd:      czd,
		Rvk:      pay.Rvk,
		IsCommit: pay.Commit,
	}

	// Parse typ suffix to determine kind
	suffix := typSuffix(pay.Typ)

	switch suffix {
	case TypKeyCreate:
		tx.Kind = TxKeyCreate
		if err := tx.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := tx.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyDelete:
		tx.Kind = TxKeyDelete
		if err := tx.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := tx.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyReplace:
		tx.Kind = TxKeyReplace
		if err := tx.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := tx.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyRevoke:
		// Determine if self-revoke or other-revoke based on id presence
		if pay.ID != "" {
			tx.Kind = TxOtherRevoke
			if err := tx.parseID(pay.ID); err != nil {
				return nil, err
			}
			if err := tx.parsePre(pay.Pre); err != nil {
				return nil, err
			}
		} else {
			tx.Kind = TxSelfRevoke
		}
		if pay.Rvk == 0 {
			return nil, ErrMalformedPayload
		}

	case TypPrincipalCreate:
		// SPEC §5.1: Genesis finalization transaction
		// For principal/create, id is an AuthState (tagged digest format)
		tx.Kind = TxPrincipalCreate
		if err := tx.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := tx.parseIDAsAuthState(pay.ID); err != nil {
			return nil, err
		}

	default:
		return nil, ErrMalformedPayload
	}

	return tx, nil
}

// parsePre decodes the pre field in alg:digest format.
func (tx *Transaction) parsePre(pre string) error {
	if pre == "" {
		return ErrMalformedPayload
	}
	tagged, err := ParseTaggedDigest(pre)
	if err != nil {
		return ErrMalformedPayload
	}
	// Create single-variant AuthState from tagged digest
	tx.Pre = AuthState{FromSingleDigest(tagged.Alg, tagged.Digest)}
	return nil
}

// parseID decodes the id field (raw base64 thumbprint).
func (tx *Transaction) parseID(id string) error {
	if id == "" {
		return ErrMalformedPayload
	}
	idBytes, err := coz.Decode(id)
	if err != nil {
		return ErrMalformedPayload
	}
	tx.ID = idBytes
	return nil
}

// parseIDAsAuthState decodes the id field as an AuthState (alg:digest format).
// Used for principal/create where id is the current AuthState per SPEC §5.1.
func (tx *Transaction) parseIDAsAuthState(id string) error {
	if id == "" {
		return ErrMalformedPayload
	}
	tagged, err := ParseTaggedDigest(id)
	if err != nil {
		return ErrMalformedPayload
	}
	// Store the raw digest bytes in ID field
	tx.ID = tagged.Digest
	return nil
}

// typSuffix returns the suffix of a typ string after the authority.
// E.g., "cyphr.me/key/add" returns "key/add".
func typSuffix(typ string) string {
	for i := 0; i < len(typ); i++ {
		if typ[i] == '/' {
			return typ[i+1:]
		}
	}
	return typ
}
