package cyphrpass

import (
	"bytes"
	"testing"

	"github.com/cyphrme/coz"
)

// Coz Golden key:
//
//	{
//		"alg":"ES256",
//		"now":1623132000,
//		"prv":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
//		"pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
//		"tag":"Zami's Majuscule Key.",
//		"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
//	}
var GoldenKey = coz.Key{
	Alg: coz.SEAlg(coz.ES256),
	Tag: "Zami's Majuscule Key.",
	Now: 1623132000,
	Pub: coz.MustDecode("2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"),
	Prv: coz.MustDecode("bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"),
	Tmb: coz.MustDecode("U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"),
}

func TestNewAccount(t *testing.T) {
	// Create account with single key
	k := GoldenKey // Copy
	acc, err := NewAccount(&k)
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}

	// Should have exactly one active key
	if len(acc.Auth.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(acc.Auth.Keys))
	}

	// Key should be active
	if !acc.IsKeyActive(k.Tmb) {
		t.Error("key should be active")
	}

	// AR should be set (initial state)
	if len(acc.AR) == 0 {
		t.Error("AR should be set")
	}

	// AS should equal AR initially (no DLS)
	if len(acc.AS) != len(acc.AR) {
		t.Error("AS should equal AR initially")
	}

	// ALS should be set
	if len(acc.Auth.State) == 0 {
		t.Error("ALS should be set")
	}

	t.Logf("Account Root (first derivation): ")
	for dig, deriv := range acc.AR {
		t.Logf("  %s: alg=%s", dig, deriv.Alg)
	}
}

func TestNewMultiKeyAccount(t *testing.T) {
	// Generate a second key
	key2, err := coz.NewKey(coz.SEAlg(coz.ES256))
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}

	k1 := GoldenKey
	acc, err := NewAccount(&k1, key2)
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}

	// Should have two active keys
	if len(acc.Auth.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(acc.Auth.Keys))
	}

	// Both keys should be active
	if !acc.IsKeyActive(k1.Tmb) {
		t.Error("key1 should be active")
	}
	if !acc.IsKeyActive(key2.Tmb) {
		t.Error("key2 should be active")
	}

	// AR should still be set
	if len(acc.AR) == 0 {
		t.Error("AR should be set")
	}
}

func TestEnableDataLedger(t *testing.T) {
	k := GoldenKey
	acc, err := NewAccount(&k)
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}

	// Initially no data ledger (Level 3)
	if acc.Data != nil {
		t.Error("Data ledger should be nil before enabling")
	}

	// Enable Level 4
	if err := acc.EnableDataLedger(); err != nil {
		t.Fatalf("EnableDataLedger failed: %v", err)
	}

	// Now data ledger should exist
	if acc.Data == nil {
		t.Error("Data ledger should exist after enabling")
	}

	// DLS should be set (empty hash)
	if len(acc.Data.State) == 0 {
		t.Error("DLS should be set")
	}

	// AS should now be different from ALS (it's Hash(ALS || DLS))
	var alsDigest, asDigest coz.B64
	for _, d := range acc.Auth.State {
		alsDigest = d.Dig
		break
	}
	for _, d := range acc.AS {
		asDigest = d.Dig
		break
	}

	// After enabling DLS, AS = Hash(ALS || DLS), not just ALS
	// So AS should differ from ALS
	if bytes.Equal(alsDigest, asDigest) {
		t.Error("AS should differ from ALS after DLS is enabled")
	}
}

func TestKeyActiveAt(t *testing.T) {
	k := GoldenKey
	acc, err := NewAccount(&k)
	if err != nil {
		t.Fatalf("NewAccount failed: %v", err)
	}

	// Get the wrapped key
	key := acc.GetKey(k.Tmb)
	if key == nil {
		t.Fatal("key not found")
	}

	// Key should be active at any time (not revoked)
	if !key.IsActiveAt(1000000000) {
		t.Error("unrevokedkey should be active at any time")
	}

	// Simulate revocation
	key.RevokedAt = 1700000000

	// Key should be active before revocation
	if !key.IsActiveAt(1600000000) {
		t.Error("key should be active before revocation time")
	}

	// Key should NOT be active at or after revocation
	if key.IsActiveAt(1700000000) {
		t.Error("key should not be active at revocation time")
	}
	if key.IsActiveAt(1800000000) {
		t.Error("key should not be active after revocation time")
	}
}

func TestErrors(t *testing.T) {
	// Test no keys
	_, err := NewAccount()
	if err == nil {
		t.Error("expected error for no keys")
	}

	// Test nil key
	_, err = NewAccount(nil)
	if err == nil {
		t.Error("expected error for nil key")
	}

	// Test key without thumbprint
	badKey := coz.Key{Alg: coz.SEAlg(coz.ES256)}
	_, err = NewAccount(&badKey)
	if err == nil {
		t.Error("expected error for key without thumbprint")
	}
}
