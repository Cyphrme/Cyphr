package cyphr

import (
	"encoding/json"
	"strings"

	"github.com/cyphrme/coz"
)

// CozKind values are the canonical typ suffixes (SPEC §7.2).
// Each is a protocol-qualified suffix: `cyphr/<noun>/<verb>`.
// Full typ is `<authority>/cyphr/<noun>/<verb>` — authority injected at call-site.
// typSuffix() performs authority-agnostic matching via HasSuffix.

// CozKind represents the type of auth mutation.
type CozKind string

const (
	TxKeyCreate       CozKind = "cyphr/key/create"
	TxKeyDelete       CozKind = "cyphr/key/delete"
	TxKeyReplace      CozKind = "cyphr/key/replace"
	TxSelfRevoke      CozKind = "cyphr/key/revoke"       // Level 1+: signer revokes itself, no ID field
	TxPrincipalCreate CozKind = "cyphr/principal/create" // SPEC §5.1 genesis finalization
	TxCommitCreate    CozKind = "cyphr/commit/create"    // Arrow finality (SPEC §4.4)
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

	// Arrow is the computation MR(pre, fwd, TMR) (terminal coz only).
	Arrow *MultihashDigest

	// HashAlg is the hash algorithm used to sign this coz.
	HashAlg HashAlg
	// This field enables bit-perfect export for storage round-trips.
	// It includes the complete {pay, sig, key?} structure.
	raw json.RawMessage
}

// Raw returns the original CozJson bytes for this coz.
func (t *ParsedCoz) Raw() json.RawMessage {
	return t.raw
}

// CozPay represents the payload fields for a Cyphr coz.
// This struct is used for JSON unmarshaling of coz payloads.
type CozPay struct {
	Alg   coz.SEAlg `json:"alg"`
	Tmb   coz.B64   `json:"tmb"`
	Now   int64     `json:"now"`
	Typ   string    `json:"typ"`
	Pre   string    `json:"pre,omitempty"`   // Base64url previous state root
	ID    string    `json:"id,omitempty"`    // Base64url target key thumbprint
	Rvk   int64     `json:"rvk,omitempty"`   // Revocation timestamp
	Arrow string    `json:"arrow,omitempty"` // Arrow Digest (terminal coz only)
}

// ParseCoz parses a coz from a CozPay and czd.
// The czd must be pre-computed from the full Coz message.
func ParseCoz(pay *CozPay, czd coz.B64) (*ParsedCoz, error) {
	if pay == nil || pay.Typ == "" {
		return nil, ErrMalformedPayload
	}

	cz := &ParsedCoz{
		Signer:  pay.Tmb,
		Now:     pay.Now,
		Czd:     czd,
		Rvk:     pay.Rvk,
		HashAlg: HashAlgFromSEAlg(pay.Alg),
	}

	// Determine kind from typ via authority-agnostic suffix matching.
	kind := typSuffix(pay.Typ)

	switch kind {
	case TxKeyCreate:
		cz.Kind = TxKeyCreate
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TxKeyDelete:
		cz.Kind = TxKeyDelete
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TxKeyReplace:
		cz.Kind = TxKeyReplace
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseID(pay.ID); err != nil {
			return nil, err
		}

	case TxSelfRevoke:
		// [no-revoke-non-self]: signer IS the revoked key. ID, if present,
		// must match the signer (enforced in applyCozInternal).
		// Phase 3 will update intent files to omit ID and tighten this further.
		cz.Kind = TxSelfRevoke
		if pay.ID != "" {
			if err := cz.parseID(pay.ID); err != nil {
				return nil, err
			}
		}
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if pay.Rvk == 0 {
			return nil, ErrMalformedPayload
		}

	case TxPrincipalCreate:
		// SPEC §5.1: Genesis finalization. ID is the current AuthRoot.
		cz.Kind = TxPrincipalCreate
		if err := cz.parsePre(pay.Pre); err != nil {
			return nil, err
		}
		if err := cz.parseIDAsAuthRoot(pay.ID); err != nil {
			return nil, err
		}

	case TxCommitCreate:
		// Arrow finality (SPEC §4.4): arrow field parsed below.
		cz.Kind = TxCommitCreate

	default:
		return nil, ErrMalformedPayload
	}

	// Parse optional arrow field (terminal coz finality marker)
	if pay.Arrow != "" {
		if err := cz.parseArrow(pay.Arrow); err != nil {
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

// parseArrow decodes the arrow field in alg:digest format.
// Per SPEC transactions, Arrow = MR(pre, fwd, TMR).
func (cz *ParsedCoz) parseArrow(arrow string) error {
	tagged, err := ParseTaggedDigest(arrow)
	if err != nil {
		return ErrMalformedPayload
	}
	md, err := NewMultihashDigest(map[HashAlg]coz.B64{tagged.Alg: tagged.Digest})
	if err != nil {
		return ErrMalformedPayload
	}
	cz.Arrow = &md
	return nil
}

// typSuffix returns the CozKind matching typ via authority-agnostic suffix matching.
// E.g., "cyphr.me/cyphr/key/create", "example.com/cyphr/key/create" all resolve to TxKeyCreate.
func typSuffix(typ string) CozKind {
	for _, kind := range []CozKind{
		TxKeyCreate,
		TxKeyDelete,
		TxKeyReplace,
		TxSelfRevoke,
		TxPrincipalCreate,
		TxCommitCreate,
	} {
		if strings.HasSuffix(typ, string(kind)) {
			return kind
		}
	}
	return ""
}
