package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Entry is a stored entry preserving bit-perfect JSON bytes.
//
// CRITICAL INVARIANT: The original JSON bytes are preserved exactly as received.
// This ensures correct czd computation, which hashes the exact bytes of `pay`.
//
// Re-serialization can alter:
//   - Field ordering
//   - Whitespace
//   - Number representation (e.g., 1.0 → 1)
//
// By storing the raw bytes, we preserve the original and extract `pay`
// from the same source, ensuring bit-perfect fidelity.
type Entry struct {
	// raw is the complete JSON entry as received.
	// This is the immutable source of truth for this entry.
	raw json.RawMessage

	// Now is the pay.now timestamp, extracted for ordering and filtering.
	Now int64
}

// NewEntry creates an Entry from raw JSON bytes.
//
// This is the primary constructor for entries loaded from storage.
// The original bytes are preserved exactly.
func NewEntry(data []byte) (*Entry, error) {
	// Validate JSON and extract pay.now for ordering
	now, err := extractNow(data)
	if err != nil {
		return nil, err
	}

	// Make a copy to ensure immutability
	raw := make(json.RawMessage, len(data))
	copy(raw, data)

	return &Entry{
		raw: raw,
		Now: now,
	}, nil
}

// NewEntryFromValue creates an Entry by serializing a value.
//
// WARNING: This serializes the value, which may not preserve original
// byte ordering. Use only when creating new entries (e.g., during export),
// not when loading from storage.
func NewEntryFromValue(v any) (*Entry, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry: %w", err)
	}
	return NewEntry(data)
}

// Bytes returns the raw JSON bytes.
//
// This returns the exact bytes stored, suitable for I/O operations.
func (e *Entry) Bytes() []byte {
	return e.raw
}

// PayBytes extracts the `pay` field as raw bytes, preserving exact byte sequence.
//
// This is the critical method for czd computation. It extracts the `pay`
// field from the original JSON, preserving exact bytes including whitespace
// and field ordering.
func (e *Entry) PayBytes() ([]byte, error) {
	// Parse with pay as RawMessage to preserve its exact bytes
	var extractor struct {
		Pay json.RawMessage `json:"pay"`
	}

	if err := json.Unmarshal(e.raw, &extractor); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if extractor.Pay == nil {
		return nil, ErrMissingPay
	}

	return extractor.Pay, nil
}

// SigBytes extracts the `sig` field as decoded bytes.
func (e *Entry) SigBytes() ([]byte, error) {
	var extractor struct {
		Sig string `json:"sig"`
	}

	if err := json.Unmarshal(e.raw, &extractor); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if extractor.Sig == "" {
		return nil, ErrMissingSig
	}

	// Decode base64url (no padding)
	return base64.RawURLEncoding.DecodeString(extractor.Sig)
}

// KeyJSON extracts the optional `key` field as raw JSON bytes.
// Returns nil if no key field is present (e.g., for actions or non-key-add cozies).
func (e *Entry) KeyJSON() (json.RawMessage, error) {
	var extractor struct {
		Key json.RawMessage `json:"key"`
	}

	if err := json.Unmarshal(e.raw, &extractor); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return extractor.Key, nil // nil is valid (no key)
}

// Typ extracts the pay.typ field.
func (e *Entry) Typ() (string, error) {
	var extractor struct {
		Pay struct {
			Typ string `json:"typ"`
		} `json:"pay"`
	}

	if err := json.Unmarshal(e.raw, &extractor); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	return extractor.Pay.Typ, nil
}

// HasCommit returns true if the entry's pay has a "commit" field (indicating terminal coz).
func (e *Entry) HasCommit() (bool, error) {
	var extractor struct {
		Pay struct {
			Commit string `json:"commit"`
		} `json:"pay"`
	}

	if err := json.Unmarshal(e.raw, &extractor); err != nil {
		return false, fmt.Errorf("invalid JSON: %w", err)
	}

	return extractor.Pay.Commit != "", nil
}

// IsTransaction returns true if this entry is a coz (key mutation).
// Per SPEC: cozies have typ containing "/key/".
func (e *Entry) IsTransaction() bool {
	typ, err := e.Typ()
	if err != nil {
		return false
	}
	return containsKeyPrefix(typ)
}

// containsKeyPrefix checks if typ indicates a coz.
// Per SPEC: cozies have typ containing "/key/" or "/principal/".
func containsKeyPrefix(typ string) bool {
	// Look for "/key/" or "/principal/" in the typ string
	for i := 0; i+5 <= len(typ); i++ {
		if typ[i:i+5] == "/key/" {
			return true
		}
	}
	for i := 0; i+11 <= len(typ); i++ {
		if typ[i:i+11] == "/principal/" {
			return true
		}
	}
	return false
}

// extractNow extracts the pay.now timestamp from JSON.
func extractNow(data []byte) (int64, error) {
	var extractor struct {
		Pay struct {
			Now int64 `json:"now"`
		} `json:"pay"`
	}

	if err := json.Unmarshal(data, &extractor); err != nil {
		return 0, ErrInvalidJSON
	}

	if extractor.Pay.Now == 0 {
		return 0, ErrMissingNow
	}

	return extractor.Pay.Now, nil
}
