package cyphrpass

import (
	"encoding/json"
	"strings"

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
type TransactionKind string

const (
	TxKeyCreate       TransactionKind = "key/create"
	TxKeyDelete       TransactionKind = "key/delete"
	TxKeyReplace      TransactionKind = "key/replace"
	TxRevoke          TransactionKind = "key/revoke"
	TxPrincipalCreate TransactionKind = "principal/create" // SPEC §5.1 genesis finalization
)

// String returns the string representation of a TransactionKind.
func (k TransactionKind) String() string {
	return string(k)
}

// Transaction is a parsed auth mutation.
//
// Transactions mutate Auth State and form a chain via the Pre field.
// Pre references the prior Principal State (PS) per SPEC §4.3.
type Transaction struct {
	// Kind is the type of transaction.
	Kind TransactionKind

	// Signer is the thumbprint of the signing key.
	Signer coz.B64

	// Now is the transaction timestamp.
	Now int64

	// Czd is the Coz digest of this transaction.
	Czd coz.B64

	// Pre is the prior Principal State (required for all transaction types).
	Pre PrincipalState

	// ID is the target key thumbprint (for add/delete/replace/other-revoke).
	ID coz.B64

	// Rvk is the revocation timestamp (for revoke transactions).
	Rvk int64

	// CommitCS is the commit state from the `commit` field (terminal coz only).
	// Per SPEC §4.4, the last coz in a commit contains `"commit":<CS>`
	// where CS = MR(AS, DS?). Nil for non-terminal transactions.
	CommitCS *CommitState

	// raw is the original CozJson bytes for this transaction.
	// This field enables bit-perfect export for storage round-trips.
	// It includes the complete {pay, sig, key?} structure.
	raw json.RawMessage
}

// Raw returns the original CozJson bytes for this transaction.
func (t *Transaction) Raw() json.RawMessage {
	return t.raw
}

// TransactionPay represents the payload fields for a Cyphrpass transaction.
// This struct is used for JSON unmarshaling of transaction payloads.
type TransactionPay struct {
	Alg    coz.SEAlg `json:"alg"`
	Tmb    coz.B64   `json:"tmb"`
	Now    int64     `json:"now"`
	Typ    string    `json:"typ"`
	Pre    string    `json:"pre,omitempty"`    // Base64url previous commit state
	ID     string    `json:"id,omitempty"`     // Base64url target key thumbprint
	Rvk    int64     `json:"rvk,omitempty"`    // Revocation timestamp
	Commit string    `json:"commit,omitempty"` // Commit State (alg:digest, terminal coz only)
}

// ParseTransaction parses a transaction from a TransactionPay and czd.
// The czd must be pre-computed from the full Coz message.
func ParseTransaction(pay *TransactionPay, czd coz.B64) (*Transaction, error) {
	if pay == nil || pay.Typ == "" {
		return nil, ErrMalformedPayload
	}

	tx := &Transaction{
		Signer: pay.Tmb,
		Now:    pay.Now,
		Czd:    czd,
		Rvk:    pay.Rvk,
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
		tx.Kind = TxRevoke
		if pay.ID != "" {
			if err := tx.parseID(pay.ID); err != nil {
				return nil, err
			}
		}
		// All revoke types require pre (unified pre semantics)
		if err := tx.parsePre(pay.Pre); err != nil {
			return nil, err
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

	// Parse optional commit field (terminal coz finality marker)
	if pay.Commit != "" {
		if err := tx.parseCommit(pay.Commit); err != nil {
			return nil, err
		}
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
	// Create single-variant PrincipalState from tagged digest
	tx.Pre = PrincipalState{FromSingleDigest(tagged.Alg, tagged.Digest)}
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

// parseCommit decodes the commit field as a CommitState in alg:digest format.
// Per SPEC §4.4, the commit field contains CS = MR(AS, DS?).
func (tx *Transaction) parseCommit(commit string) error {
	tagged, err := ParseTaggedDigest(commit)
	if err != nil {
		return ErrMalformedPayload
	}
	cs := CommitState{FromSingleDigest(tagged.Alg, tagged.Digest)}
	tx.CommitCS = &cs
	return nil
}

// typSuffix extracts the transaction type suffix from a full typ string.
// E.g., "cyphr.me/key/create" or "cyphr.me/cyphrpass/key/create" both return "key/create".
// Uses suffix matching against known types for robustness against varying authority paths.
func typSuffix(typ string) string {
	known := []string{
		TypKeyCreate,
		TypKeyDelete,
		TypKeyReplace,
		TypKeyRevoke,
		TypPrincipalCreate,
	}
	for _, suffix := range known {
		if strings.HasSuffix(typ, suffix) {
			return suffix
		}
	}
	return ""
}
