package storage

import (
	"encoding/json"
	"fmt"
)

// Entry is a stored entry preserving bit-perfect JSON bytes.
//
// CRITICAL INVARIANT: The original JSON string is preserved exactly as received.
// This ensures correct czd computation, which hashes the exact bytes of `pay`.
//
// Re-serialization can alter:
//   - Field ordering
//   - Whitespace
//   - Number representation (e.g., 1.0 → 1)
//
// By storing json.RawMessage, we preserve the original bytes and extract `pay`
// from the same source, ensuring bit-perfect fidelity.
type Entry struct {
	// Raw is the complete JSON entry as received.
	Raw json.RawMessage

	// Now is the pay.now timestamp, extracted for ordering.
	Now int64
}

// EntryFromJSON creates an Entry from a raw JSON string.
//
// This is the primary constructor for entries loaded from storage.
// The original bytes are preserved exactly.
func EntryFromJSON(data []byte) (*Entry, error) {
	// Extract pay.now for ordering
	now, err := extractNow(data)
	if err != nil {
		return nil, err
	}

	return &Entry{
		Raw: json.RawMessage(data),
		Now: now,
	}, nil
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

	if err := json.Unmarshal(e.Raw, &extractor); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if extractor.Pay == nil {
		return nil, fmt.Errorf("entry missing pay field")
	}

	return extractor.Pay, nil
}

// extractNow extracts the pay.now timestamp from JSON.
func extractNow(data []byte) (int64, error) {
	var extractor struct {
		Pay struct {
			Now int64 `json:"now"`
		} `json:"pay"`
	}

	if err := json.Unmarshal(data, &extractor); err != nil {
		return 0, fmt.Errorf("invalid JSON: %w", err)
	}

	if extractor.Pay.Now == 0 {
		return 0, fmt.Errorf("entry missing pay.now field")
	}

	return extractor.Pay.Now, nil
}
