package cyphrpass

import (
	"bytes"
	"testing"

	"github.com/cyphrme/coz"
)

// Golden thumbprint from SPEC §15.1
var goldenTmb = mustDecode("U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg")

func mustDecode(s string) coz.B64 {
	b, err := coz.Decode(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHashAlgFromSEAlg(t *testing.T) {
	tests := []struct {
		alg  coz.SEAlg
		want HashAlg
	}{
		{coz.SEAlg(coz.ES256), HashAlg(coz.SHA256)},
		{coz.SEAlg(coz.ES384), HashAlg(coz.SHA384)},
		{coz.SEAlg(coz.ES512), HashAlg(coz.SHA512)},
		{coz.SEAlg(coz.Ed25519), HashAlg(coz.SHA512)},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got := HashAlgFromSEAlg(tt.alg)
			if got != tt.want {
				t.Errorf("HashAlgFromSEAlg(%q) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestHashSortedConcat_SingleComponent(t *testing.T) {
	// Single component should be returned unchanged (implicit promotion)
	input := []byte{1, 2, 3, 4}
	result, err := HashSortedConcat(HashAlg(coz.SHA256), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, input) {
		t.Errorf("single component should promote without hashing: got %v, want %v", result, input)
	}
}

func TestHashSortedConcat_Empty(t *testing.T) {
	result, err := HashSortedConcat(HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("empty components should return nil: got %v", result)
	}
}

func TestHashSortedConcat_MultipleComponents(t *testing.T) {
	// Multiple components should be sorted, concatenated, and hashed
	a := []byte{0x01, 0x02}
	b := []byte{0x00, 0x03} // b < a lexicographically

	result, err := HashSortedConcat(HashAlg(coz.SHA256), a, b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Result should be a hash (32 bytes for SHA-256)
	if len(result) != 32 {
		t.Errorf("expected 32-byte SHA-256 hash, got %d bytes", len(result))
	}

	// Verify order independence: H(a, b) == H(b, a)
	result2, err := HashSortedConcat(HashAlg(coz.SHA256), b, a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, result2) {
		t.Errorf("hash should be order-independent: got %x vs %x", result, result2)
	}
}

func TestComputeKS_ImplicitPromotion(t *testing.T) {
	// SPEC §7.2: Single key, no nonce → KS = tmb
	ks, err := ComputeKS([]coz.B64{goldenTmb}, nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ks, goldenTmb) {
		t.Errorf("single key should promote to KS: got %x, want %x", ks, goldenTmb)
	}
}

func TestComputeKS_EmptyKeys(t *testing.T) {
	_, err := ComputeKS(nil, nil, HashAlg(coz.SHA256))
	if err != ErrNoActiveKeys {
		t.Errorf("expected ErrNoActiveKeys, got %v", err)
	}
}

func TestComputeAS_ImplicitPromotion(t *testing.T) {
	// SPEC §7.5: Only KS, no TS, no nonce → AS = KS
	ks := KeyState(goldenTmb)
	as, err := ComputeAS(ks, TransactionState(nil), nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(as, ks) {
		t.Errorf("AS should promote from KS: got %x, want %x", as, ks)
	}
}

func TestComputePS_ImplicitPromotion(t *testing.T) {
	// SPEC §7.6: Only AS, no DS, no nonce → PS = AS
	as := AuthState(goldenTmb)
	ps, err := ComputePS(as, DataState(nil), nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ps, as) {
		t.Errorf("PS should promote from AS: got %x, want %x", ps, as)
	}
}

func TestImplicitGenesisSingleKey(t *testing.T) {
	// SPEC §15.3: Level 1 single-key → PR = PS = AS = KS = tmb
	ks, err := ComputeKS([]coz.B64{goldenTmb}, nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("ComputeKS: %v", err)
	}
	as, err := ComputeAS(ks, TransactionState(nil), nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("ComputeAS: %v", err)
	}
	ps, err := ComputePS(as, DataState(nil), nil, HashAlg(coz.SHA256))
	if err != nil {
		t.Fatalf("ComputePS: %v", err)
	}

	// All states should equal the thumbprint
	if !bytes.Equal(ks, goldenTmb) {
		t.Errorf("KS != tmb")
	}
	if !bytes.Equal(as, goldenTmb) {
		t.Errorf("AS != tmb")
	}
	if !bytes.Equal(ps, goldenTmb) {
		t.Errorf("PS != tmb")
	}
}
