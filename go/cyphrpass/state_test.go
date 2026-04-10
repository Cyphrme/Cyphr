package cyphrpass

import (
	"bytes"
	"errors"
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

func TestComputeKR_ImplicitPromotion(t *testing.T) {
	// SPEC §7.2: Single key, no nonce → KS = tmb
	algs := []HashAlg{HashAlg(coz.SHA256)}
	kr, err := ComputeKR([]coz.B64{goldenTmb}, nil, algs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// First variant should equal the thumbprint (implicit promotion)
	if !bytes.Equal(kr.First(), goldenTmb) {
		t.Errorf("single key should promote to KS: got %x, want %x", kr.First(), goldenTmb)
	}
}

func TestComputeKR_EmptyKeys(t *testing.T) {
	algs := []HashAlg{HashAlg(coz.SHA256)}
	_, err := ComputeKR(nil, nil, algs)
	if err != ErrNoActiveKeys {
		t.Errorf("expected ErrNoActiveKeys, got %v", err)
	}
}

func TestComputeAR_ImplicitPromotion(t *testing.T) {
	// SPEC §8.4: Only KS, no RS, no nonce → AS = KS
	algs := []HashAlg{HashAlg(coz.SHA256)}
	kr := KeyRoot{FromSingleDigest(HashSha256, goldenTmb)}
	ar, err := ComputeAR(kr, nil, nil, algs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ar.First(), kr.First()) {
		t.Errorf("AS should promote from KS: got %x, want %x", ar.First(), kr.First())
	}
}

func TestComputePR_ImplicitPromotion(t *testing.T) {
	// SPEC §3.7.1: Only SR, no CR → PR = SR (implicit promotion)
	algs := []HashAlg{HashAlg(coz.SHA256)}
	ar := AuthRoot{FromSingleDigest(HashSha256, goldenTmb)}
	sr, err := ComputeSR(ar, nil, nil, algs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pr, err := ComputePR(sr, nil, nil, algs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(pr.First(), ar.First()) {
		t.Errorf("PR should promote from SR (from AR): got %x, want %x", pr.First(), ar.First())
	}
}

func TestImplicitGenesisSingleKey(t *testing.T) {
	// SPEC §15.3: Level 1 single-key → PR = PS = CS = AS = KS = tmb
	algs := []HashAlg{HashAlg(coz.SHA256)}
	kr, err := ComputeKR([]coz.B64{goldenTmb}, nil, algs)
	if err != nil {
		t.Fatalf("ComputeKR: %v", err)
	}
	ar, err := ComputeAR(kr, nil, nil, algs)
	if err != nil {
		t.Fatalf("ComputeAR: %v", err)
	}
	sr, err := ComputeSR(ar, nil, nil, algs)
	if err != nil {
		t.Fatalf("ComputeSR: %v", err)
	}
	pr, err := ComputePR(sr, nil, nil, algs)
	if err != nil {
		t.Fatalf("ComputePR: %v", err)
	}

	// All states should equal the thumbprint
	if !bytes.Equal(kr.First(), goldenTmb) {
		t.Errorf("KR != tmb")
	}
	if !bytes.Equal(ar.First(), goldenTmb) {
		t.Errorf("AR != tmb")
	}
	if !bytes.Equal(sr.First(), goldenTmb) {
		t.Errorf("SR != tmb")
	}
	if !bytes.Equal(pr.First(), goldenTmb) {
		t.Errorf("PR != tmb")
	}
}

func TestDeriveHashAlgs(t *testing.T) {
	// Create test keys with different algorithms
	key256 := &Key{
		Key: &coz.Key{
			Alg: coz.SEAlg(coz.ES256),
			Tmb: bytes.Repeat([]byte{0x11}, 32),
		},
	}
	key384 := &Key{
		Key: &coz.Key{
			Alg: coz.SEAlg(coz.ES384),
			Tmb: bytes.Repeat([]byte{0x22}, 48),
		},
	}

	// Single algorithm
	algs := DeriveHashAlgs([]*Key{key256})
	if len(algs) != 1 {
		t.Errorf("expected 1 algorithm, got %d", len(algs))
	}
	if algs[0] != HashSha256 {
		t.Errorf("expected SHA-256, got %v", algs[0])
	}

	// Multiple algorithms (should be sorted)
	algs = DeriveHashAlgs([]*Key{key384, key256})
	if len(algs) != 2 {
		t.Errorf("expected 2 algorithms, got %d", len(algs))
	}
	// SHA-256 should come before SHA-384 lexicographically
	if algs[0] != HashSha256 {
		t.Errorf("expected SHA-256 first, got %v", algs[0])
	}
	if algs[1] != HashSha384 {
		t.Errorf("expected SHA-384 second, got %v", algs[1])
	}
}

func TestMultihashDigest_Variants(t *testing.T) {
	// Test multihash with multiple variants
	variants := map[HashAlg]coz.B64{
		HashSha256: bytes.Repeat([]byte{0xAA}, 32),
		HashSha384: bytes.Repeat([]byte{0xBB}, 48),
	}
	mh, err := NewMultihashDigest(variants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check variant access
	if !bytes.Equal(mh.Get(HashSha256), variants[HashSha256]) {
		t.Error("Get(SHA-256) failed")
	}
	if !bytes.Equal(mh.Get(HashSha384), variants[HashSha384]) {
		t.Error("Get(SHA-384) failed")
	}
	if mh.Get(HashSha512) != nil {
		t.Error("Get(SHA-512) should return nil")
	}

	// Check Contains
	if !mh.Contains(HashSha256) {
		t.Error("Contains(SHA-256) should be true")
	}
	if mh.Contains(HashSha512) {
		t.Error("Contains(SHA-512) should be false")
	}

	// Check Algorithms (should be sorted)
	algs := mh.Algorithms()
	if len(algs) != 2 {
		t.Errorf("expected 2 algorithms, got %d", len(algs))
	}

	// Check First (should be lexicographically first)
	first := mh.First()
	if !bytes.Equal(first, variants[HashSha256]) {
		t.Error("First() should return SHA-256 variant")
	}
}

func TestParseTaggedDigest_Valid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		alg    HashAlg
		digest string
	}{
		{
			name:   "SHA-256 golden",
			input:  "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			alg:    HashSha256,
			digest: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
		},
		{
			name:   "SHA-384",
			input:  "SHA-384:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			alg:    HashSha384,
			digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:   "SHA-512",
			input:  "SHA-512:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			alg:    HashSha512,
			digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td, err := ParseTaggedDigest(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if td.Alg != tt.alg {
				t.Errorf("Alg = %v, want %v", td.Alg, tt.alg)
			}
			expectedDigest, _ := coz.Decode(tt.digest)
			if !bytes.Equal(td.Digest, expectedDigest) {
				t.Errorf("Digest mismatch")
			}
		})
	}
}

func TestParseTaggedDigest_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "missing separator",
			input:   "SHA-256U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			wantErr: ErrMalformedDigest,
		},
		{
			name:    "unsupported algorithm",
			input:   "MD5:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			wantErr: ErrUnsupportedAlgorithm,
		},
		{
			name:    "wrong length for SHA-256",
			input:   "SHA-256:AAAA",
			wantErr: ErrMalformedDigest,
		},
		{
			name:    "wrong length for SHA-384",
			input:   "SHA-384:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
			wantErr: ErrMalformedDigest,
		},
		{
			name:    "invalid base64",
			input:   "SHA-256:!!!invalid!!!",
			wantErr: nil, // wrapping error — just check err != nil
		},
		{
			name:    "empty digest",
			input:   "SHA-256:",
			wantErr: ErrMalformedDigest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTaggedDigest(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %q, want errors.Is(%v)", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestTaggedDigest_RoundTrip(t *testing.T) {
	original := "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
	td, err := ParseTaggedDigest(original)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// String round-trip
	if td.String() != original {
		t.Errorf("String() = %q, want %q", td.String(), original)
	}
}

func TestTaggedDigest_JSON(t *testing.T) {
	original := "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
	td, err := ParseTaggedDigest(original)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Marshal
	data, err := td.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	expected := `"SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"`
	if string(data) != expected {
		t.Errorf("MarshalJSON = %s, want %s", data, expected)
	}

	// Unmarshal
	var td2 TaggedDigest
	if err := td2.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}
	if td2.Alg != td.Alg || !bytes.Equal(td2.Digest, td.Digest) {
		t.Error("JSON round-trip produced different result")
	}
}
