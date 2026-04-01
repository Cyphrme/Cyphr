package cyphrpass

import (
	"encoding/json"
	"strings"

	"github.com/cyphrme/coz"
)

// ParsedCoz type constants per SPEC §4.2.
// These are typ suffixes; full typ is "<authority>/<suffix>".
const (
	TypKeyCreate  = "key/create" // SPEC §4.2
	TypKeyDelete  = "key/delete"
	TypKeyReplace = "key/replace"
	TypKeyRevoke  = "key/revoke"

	TypPrincipalCreate = "principal/create" // SPEC §5.1 genesis finalization
)

// CozKind represents the type of auth mutation.
type CozKind string

const (
	TxKeyCreate       CozKind = "key/create"
	TxKeyDelete       CozKind = "key/delete"
	TxKeyReplace      CozKind = "key/replace"
	TxRevoke          CozKind = "key/revoke"
	TxPrincipalCreate CozKind = "principal/create" // SPEC §5.1 genesis finalization
)

// String returns the string representation of a CozKind.
func (k CozKind) String() string {
	return string(k)
}

// ParsedCoz is a parsed auth mutation.
//
// Cozies mutate Auth State and form a chain via the Pre field.
// Pre references the prior Principal State (PS) per SPEC §4.3.
type ParsedCoz struct {
	// Kind is the type of coz.
	Kind CozKind

	// Signer is the thumbprint of the signing key.
	Signer coz.B64

	// Now is the coz timestamp.
	Now int64

	// Czd is the Coz digest of this coz.
	Czd coz.B64

	// Pre is the prior Principal State (required for all coz types).
	Pre PrincipalRoot

	// ID is the target key thumbprint (for add/delete/replace/other-revoke).
	ID coz.B64

	// Rvk is the revocation timestamp (for revoke cozies).
	Rvk int64

	// CommitSR is the state root from the `commit` field (terminal coz only).
	// Per SPEC §4.4, the last coz in a commit contains `"commit":<SR>`
	// where SR = MR(AR, DR?). Nil for non-terminal cozies.
	CommitSR *StateRoot

	// raw is the original CozJson bytes for this coz.
	// This field enables bit-perfect export for storage round-trips.
	// It includes the complete {pay, sig, key?} structure.
	raw json.RawMessage
}

// Raw returns the original CozJson bytes for this coz.
func (t *ParsedCoz) Raw() json.RawMessage {
	return t.raw
}

// CozPay represents the payload fields for a Cyphrpass coz.
// This struct is used for JSON unmarshaling of coz payloads.
type CozPay struct {
	Alg    coz.SEAlg `json:"alg"`
	Tmb    coz.B64   `json:"tmb"`
	Now    int64     `json:"now"`
	Typ    string    `json:"typ"`
	Pre    string    `json:"pre,omitempty"`    // Base64url previous state root
	ID     string    `json:"id,omitempty"`     // Base64url target key thumbprint
	Rvk    int64     `json:"rvk,omitempty"`    // Revocation timestamp
	Commit string    `json:"commit,omitempty"` // State Root (alg:digest, terminal coz only)
}

// ParseCoz parses a coz from a CozPay and czd.
// The czd must be pre-computed from the full Coz message.
func ParseCoz(pay *CozPay, czd coz.B64) (*ParsedCoz, error) {
	if pay == nil || pay.Typ == "" {
		return nil, ErrMalformedPayload
	}

	cz := &ParsedCoz{
		Signer: pay.Tmb,
		Now:    pay.Now,
		Czd:    czd,
		Rvk:    pay.Rvk,
	}

	// Parse typ suffix to determine kind
	suffix := typSuffix(pay.Typ)

	switch suffix {
	case TypKeyCreate:
		cz.Kind = TxKeyCreate
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyDelete:
		cz.Kind = TxKeyDelete
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyReplace:
		cz.Kind = TxKeyReplace
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TypKeyRevoke:
		cz.Kind = TxRevoke
		if pay.ID != "" {
			if err := cz.parseID(pay.ID); err != nil {
				return nil, err
			}
		}
		// All revoke types require pre (unified pre semantics)
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if pay.Rvk == 0 {
			return nil, ErrMalformedPayload
		}

	case TypPrincipalCreate:
		// SPEC §5.1: Genesis finalization coz
		// For principal/create, id is an AuthRoot (tagged digest format)
		cz.Kind = TxPrincipalCreate
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseIDAsAuthRoot(pay.ID); err != nil {
			return nil, err
		}

	default:
		return nil, ErrMalformedPayload
	}

	// Parse optional commit field (terminal coz finality marker)
	if pay.Commit != "" {
		if err := cz.parseCommit(pay.Commit); err != nil {
			return nil, err
		}
	}

	return cz, nil
}

// parsePre decodes the pre field in alg:digest format.
func (cz *ParsedCoz) parsePre(pre string) error {
	if pre == "" {
		return ErrMalformedPayload
	}
	tagged, err := ParseTaggedDigest(pre)
	if err != nil {
		return ErrMalformedPayload
	}
	// Create single-variant PrincipalRoot from tagged digest
	cz.Pre = PrincipalRoot{FromSingleDigest(tagged.Alg, tagged.Digest)}
	return nil
}

// parseID decodes the id field (raw base64 thumbprint).
func (cz *ParsedCoz) parseID(id string) error {
	if id == "" {
		return ErrMalformedPayload
	}
	idBytes, err := coz.Decode(id)
	if err != nil {
		return ErrMalformedPayload
	}
	cz.ID = idBytes
	return nil
}

// parseIDAsAuthRoot decodes the id field as an AuthRoot (alg:digest format).
// Used for principal/create where id is the current AuthRoot per SPEC §5.1.
func (cz *ParsedCoz) parseIDAsAuthRoot(id string) error {
	if id == "" {
		return ErrMalformedPayload
	}
	tagged, err := ParseTaggedDigest(id)
	if err != nil {
		return ErrMalformedPayload
	}
	// Store the raw digest bytes in ID field
	cz.ID = tagged.Digest
	return nil
}

// parseCommit decodes the commit field as a StateRoot in alg:digest format.
// Per SPEC §4.4, the commit field contains SR = MR(AR, DR?).
func (cz *ParsedCoz) parseCommit(commit string) error {
	tagged, err := ParseTaggedDigest(commit)
	if err != nil {
		return ErrMalformedPayload
	}
	sr := StateRoot{FromSingleDigest(tagged.Alg, tagged.Digest)}
	cz.CommitSR = &sr
	return nil
}

// typSuffix extracts the coz type suffix from a full typ string.
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
