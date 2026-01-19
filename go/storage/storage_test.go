package storage_test

import (
	"encoding/json"
	"testing"

	"github.com/cyphrme/cyphrpass/storage"
)

// TestNewEntry verifies Entry creation from raw bytes.
func TestNewEntry(t *testing.T) {
	raw := []byte(`{"pay":{"now":12345,"typ":"test"},"sig":"AAAA"}`)

	entry, err := storage.NewEntry(raw)
	if err != nil {
		t.Fatalf("NewEntry failed: %v", err)
	}

	if entry.Now != 12345 {
		t.Errorf("Now = %d, want 12345", entry.Now)
	}
}

// TestNewEntry_MissingNow verifies error on missing pay.now.
func TestNewEntry_MissingNow(t *testing.T) {
	raw := []byte(`{"pay":{"typ":"test"},"sig":"AAAA"}`)

	_, err := storage.NewEntry(raw)
	if err == nil {
		t.Fatal("expected error for missing pay.now")
	}
}

// TestNewEntry_InvalidJSON verifies error on invalid JSON.
func TestNewEntry_InvalidJSON(t *testing.T) {
	raw := []byte(`not valid json`)

	_, err := storage.NewEntry(raw)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestEntry_PayBytes verifies bit-perfect pay extraction.
func TestEntry_PayBytes(t *testing.T) {
	// Carefully crafted JSON with specific field order
	raw := []byte(`{"pay":{"now":1000,"typ":"test","extra":"value"},"sig":"AAAA"}`)

	entry, err := storage.NewEntry(raw)
	if err != nil {
		t.Fatalf("NewEntry failed: %v", err)
	}

	payBytes, err := entry.PayBytes()
	if err != nil {
		t.Fatalf("PayBytes failed: %v", err)
	}

	// Verify the exact bytes are preserved
	expected := `{"now":1000,"typ":"test","extra":"value"}`
	if string(payBytes) != expected {
		t.Errorf("PayBytes = %q, want %q", string(payBytes), expected)
	}
}

// TestEntry_SigBytes verifies signature extraction.
func TestEntry_SigBytes(t *testing.T) {
	// Base64url: "AAAA" = 0x00, 0x00, 0x00
	raw := []byte(`{"pay":{"now":1000},"sig":"AAAA"}`)

	entry, err := storage.NewEntry(raw)
	if err != nil {
		t.Fatalf("NewEntry failed: %v", err)
	}

	sigBytes, err := entry.SigBytes()
	if err != nil {
		t.Fatalf("SigBytes failed: %v", err)
	}

	if len(sigBytes) != 3 {
		t.Errorf("SigBytes length = %d, want 3", len(sigBytes))
	}
}

// TestEntry_IsTransaction verifies transaction detection.
func TestEntry_IsTransaction(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "key/add transaction",
			raw:  `{"pay":{"now":1000,"typ":"cyphr.me/key/add"},"sig":"AA"}`,
			want: true,
		},
		{
			name: "key/revoke transaction",
			raw:  `{"pay":{"now":1000,"typ":"cyphr.me/key/revoke"},"sig":"AA"}`,
			want: true,
		},
		{
			name: "action (comment)",
			raw:  `{"pay":{"now":1000,"typ":"cyphr.me/comment/create"},"sig":"AA"}`,
			want: false,
		},
		{
			name: "action (file)",
			raw:  `{"pay":{"now":1000,"typ":"example.com/file/upload"},"sig":"AA"}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := storage.NewEntry([]byte(tt.raw))
			if err != nil {
				t.Fatalf("NewEntry failed: %v", err)
			}

			if got := entry.IsTransaction(); got != tt.want {
				t.Errorf("IsTransaction() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEntry_KeyJSON verifies optional key extraction.
func TestEntry_KeyJSON(t *testing.T) {
	// Entry with key
	withKey := []byte(`{"pay":{"now":1000},"sig":"AA","key":{"alg":"ES256","pub":"abc","tmb":"xyz"}}`)
	entry1, _ := storage.NewEntry(withKey)
	keyJSON, err := entry1.KeyJSON()
	if err != nil {
		t.Fatalf("KeyJSON failed: %v", err)
	}
	if keyJSON == nil {
		t.Error("expected key JSON, got nil")
	}

	// Entry without key
	withoutKey := []byte(`{"pay":{"now":1000},"sig":"AA"}`)
	entry2, _ := storage.NewEntry(withoutKey)
	keyJSON2, err := entry2.KeyJSON()
	if err != nil {
		t.Fatalf("KeyJSON failed: %v", err)
	}
	if keyJSON2 != nil {
		t.Error("expected nil key JSON")
	}
}

// TestNewEntryFromValue verifies value serialization.
func TestNewEntryFromValue(t *testing.T) {
	value := map[string]any{
		"pay": map[string]any{
			"now": int64(5000),
			"typ": "test",
		},
		"sig": "BBBB",
	}

	entry, err := storage.NewEntryFromValue(value)
	if err != nil {
		t.Fatalf("NewEntryFromValue failed: %v", err)
	}

	if entry.Now != 5000 {
		t.Errorf("Now = %d, want 5000", entry.Now)
	}
}

// TestGenesis_Types verifies Genesis type safety.
func TestGenesis_Types(t *testing.T) {
	// Implicit genesis
	implicit := storage.ImplicitGenesis{}
	_ = storage.Genesis(implicit) // compile-time check

	// Explicit genesis
	explicit := storage.ExplicitGenesis{}
	_ = storage.Genesis(explicit) // compile-time check
}

// TestEntry_Bytes verifies raw bytes access.
func TestEntry_Bytes(t *testing.T) {
	raw := []byte(`{"pay":{"now":1000},"sig":"AA"}`)
	entry, _ := storage.NewEntry(raw)

	if string(entry.Bytes()) != string(raw) {
		t.Error("Bytes() should return original raw bytes")
	}
}

// TestEntry_BytesCopy verifies immutability.
func TestEntry_BytesCopy(t *testing.T) {
	raw := []byte(`{"pay":{"now":1000},"sig":"AA"}`)
	entry, _ := storage.NewEntry(raw)

	// Modify original
	raw[0] = 'X'

	// Entry should be unchanged (it made a copy)
	if entry.Bytes()[0] == 'X' {
		t.Error("Entry should copy bytes, not reference original")
	}
}

// Benchmark bit-perfect pay extraction
func BenchmarkEntry_PayBytes(b *testing.B) {
	raw := []byte(`{"pay":{"now":1000,"typ":"cyphr.me/comment/create","data":"some payload"},"sig":"AAAA"}`)
	entry, _ := storage.NewEntry(raw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = entry.PayBytes()
	}
}

// Helper to verify JSON structure (not exported, just for tests)
func mustUnmarshal(data []byte) map[string]any {
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		panic(err)
	}
	return result
}
