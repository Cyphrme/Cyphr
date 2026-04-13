package cyphr

import (
	"bytes"
	"testing"

	"github.com/cyphrme/coz"
)

func makeTestCozKey(id byte) *coz.Key {
	return &coz.Key{
		Alg: coz.SEAlg(coz.ES256),
		Tmb: bytes.Repeat([]byte{id}, 32),
		Pub: bytes.Repeat([]byte{id}, 64),
	}
}

func TestImplicit_SingleKey(t *testing.T) {
	key := makeTestCozKey(0xAA)
	p, err := Implicit(key)
	if err != nil {
		t.Fatalf("Implicit failed: %v", err)
	}

	// Level 1: PR is nil (no principal/create at L1)
	if p.PG() != nil {
		t.Errorf("PR should be nil at Level 1")
	}
	if !bytes.Equal(p.PR().First(), key.Tmb) {
		t.Errorf("PS != tmb")
	}
	if !bytes.Equal(p.AR().First(), key.Tmb) {
		t.Errorf("AS != tmb")
	}
	if !bytes.Equal(p.KR().First(), key.Tmb) {
		t.Errorf("KS != tmb")
	}
}

func TestImplicit_HasOneActiveKey(t *testing.T) {
	key := makeTestCozKey(0xBB)
	p, err := Implicit(key)
	if err != nil {
		t.Fatalf("Implicit failed: %v", err)
	}

	if p.ActiveKeyCount() != 1 {
		t.Errorf("expected 1 active key, got %d", p.ActiveKeyCount())
	}
	if !p.IsKeyActive(key.Tmb) {
		t.Error("key should be active")
	}
	if p.Level() != Level1 {
		t.Errorf("expected Level1, got %v", p.Level())
	}
}

func TestExplicit_MultiKey(t *testing.T) {
	key1 := makeTestCozKey(0x11)
	key2 := makeTestCozKey(0x22)
	p, err := Explicit([]*coz.Key{key1, key2})
	if err != nil {
		t.Fatalf("Explicit failed: %v", err)
	}

	// PR should be nil (not yet established — needs principal/create)
	if p.PG() != nil {
		t.Error("PR should be nil before principal/create")
	}

	// Should have 2 active keys
	if p.ActiveKeyCount() != 2 {
		t.Errorf("expected 2 active keys, got %d", p.ActiveKeyCount())
	}
	if !p.IsKeyActive(key1.Tmb) || !p.IsKeyActive(key2.Tmb) {
		t.Error("both keys should be active")
	}

	// Level 3 due to multiple keys
	if p.Level() != Level3 {
		t.Errorf("expected Level3, got %v", p.Level())
	}
}

func TestExplicit_EmptyKeys(t *testing.T) {
	_, err := Explicit([]*coz.Key{})
	if err != ErrNoActiveKeys {
		t.Errorf("expected ErrNoActiveKeys, got %v", err)
	}
}

func TestPR_IsNilAtLevel1(t *testing.T) {
	key := makeTestCozKey(0xCC)
	p, _ := Implicit(key)

	// PR is nil at Level 1 (no principal/create)
	if p.PG() != nil {
		t.Error("PR should be nil at Level 1")
	}

	// PS still exists and is stable
	psBefore := append([]byte{}, p.PR().First()...)
	pr := p.PR()
	_ = pr
	if !bytes.Equal(p.PR().First(), psBefore) {
		t.Error("PS should be stable")
	}
}

// Test golden value from SPEC §15.1
func TestImplicit_GoldenKey(t *testing.T) {
	// Golden key thumbprint from test vectors
	goldenTmbB64 := "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
	goldenTmb, err := coz.Decode(goldenTmbB64)
	if err != nil {
		t.Fatalf("failed to decode golden tmb: %v", err)
	}

	key := &coz.Key{
		Alg: coz.SEAlg(coz.ES256),
		Tmb: goldenTmb,
		Pub: mustDecode("2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"),
	}

	p, err := Implicit(key)
	if err != nil {
		t.Fatalf("Implicit failed: %v", err)
	}

	// At Level 1, PR is nil, PS = AS = KS = tmb
	if p.PG() != nil {
		t.Error("PR should be nil at Level 1")
	}
	if p.PR().String() != goldenTmbB64 {
		t.Errorf("PS = %s, want %s", p.PR().String(), goldenTmbB64)
	}
	if p.AR().String() != goldenTmbB64 {
		t.Errorf("AS = %s, want %s", p.AR().String(), goldenTmbB64)
	}
	if p.KR().String() != goldenTmbB64 {
		t.Errorf("KS = %s, want %s", p.KR().String(), goldenTmbB64)
	}
}

// ParsedCoz tests

func TestApplyTransaction_KeyAdd(t *testing.T) {
	key1 := makeTestCozKey(0x11)
	p, _ := Implicit(key1)

	key2 := makeTestCozKey(0x22)
	cz := &ParsedCoz{
		Kind:    TxKeyCreate,
		Signer:  key1.Tmb,
		HashAlg: HashSha256,
		Now:     2000,
		Czd:     bytes.Repeat([]byte{0xAB}, 32),
		Pre:     p.PR(),
		ID:      key2.Tmb,
	}

	oldAS := append([]byte{}, p.AR().First()...)

	_, err := p.ApplyTransactionUnsafe(cz, key2)
	if err != nil {
		t.Fatalf("ApplyCoz failed: %v", err)
	}

	// Should now have 2 keys
	if p.ActiveKeyCount() != 2 {
		t.Errorf("expected 2 active keys, got %d", p.ActiveKeyCount())
	}
	if !p.IsKeyActive(key2.Tmb) {
		t.Error("key2 should be active")
	}

	// Level should be L3 now
	if p.Level() != Level3 {
		t.Errorf("expected Level3, got %v", p.Level())
	}

	// AS should have changed
	if bytes.Equal(p.AR().First(), oldAS) {
		t.Error("AS should change after key add")
	}
}

func TestApplyTransaction_InvalidPre(t *testing.T) {
	key1 := makeTestCozKey(0x11)
	p, _ := Implicit(key1)

	key2 := makeTestCozKey(0x22)
	wrongPre := PrincipalRoot{FromSingleDigest(HashSha256, bytes.Repeat([]byte{0xFF}, 32))}
	cz := &ParsedCoz{
		Kind:    TxKeyCreate,
		Signer:  key1.Tmb,
		HashAlg: HashSha256,
		Now:     2000,
		Czd:     bytes.Repeat([]byte{0xAB}, 32),
		Pre:     wrongPre, // Wrong!
		ID:      key2.Tmb,
	}

	_, err := p.ApplyTransactionUnsafe(cz, key2)
	if err != ErrInvalidPrior {
		t.Errorf("expected ErrInvalidPrior, got %v", err)
	}
}

func TestApplyTransaction_SelfRevokeLastKey(t *testing.T) {
	key := makeTestCozKey(0xDD)
	p, _ := Implicit(key)

	// Level 1: single key, self-revoke should fail
	cz := &ParsedCoz{
		Kind:    TxRevoke,
		Signer:  key.Tmb,
		HashAlg: HashSha256,
		Now:     2000,
		Czd:     bytes.Repeat([]byte{0xEE}, 32),
		Rvk:     2000,
		Pre:     p.PR(), // Unified pre semantics: all cozies require pre
	}

	_, err := p.ApplyTransactionUnsafe(cz, nil)
	if err != ErrNoActiveKeys {
		t.Errorf("expected ErrNoActiveKeys, got %v", err)
	}

	// Key should still be active (no mutation occurred)
	if p.ActiveKeyCount() != 1 {
		t.Errorf("key count should be 1, got %d", p.ActiveKeyCount())
	}
	if !p.IsKeyActive(key.Tmb) {
		t.Error("key should still be active")
	}
}

func TestPR_StillNilAfterTransaction(t *testing.T) {
	key1 := makeTestCozKey(0x11)
	p, _ := Implicit(key1)

	// PR is nil at L1
	if p.PG() != nil {
		t.Fatal("PR should be nil before principal/create")
	}

	key2 := makeTestCozKey(0x22)
	cz := &ParsedCoz{
		Kind:    TxKeyCreate,
		Signer:  key1.Tmb,
		HashAlg: HashSha256,
		Now:     2000,
		Czd:     bytes.Repeat([]byte{0xAB}, 32),
		Pre:     p.PR(),
		ID:      key2.Tmb,
	}
	p.ApplyTransactionUnsafe(cz, key2) //nolint:errcheck

	// PR should still be nil (no principal/create was issued)
	if p.PG() != nil {
		t.Error("PR should still be nil without principal/create")
	}
}

// Action tests (Level 4)

func TestRecordAction_UpgradesToLevel4(t *testing.T) {
	key := makeTestCozKey(0xAA)
	p, _ := Implicit(key)

	if p.Level() != Level1 {
		t.Errorf("expected Level1, got %v", p.Level())
	}
	if p.DR() != nil {
		t.Error("DS should be nil before actions")
	}

	action := &Action{
		Typ:    "cyphr.me/comment/create",
		Signer: key.Tmb,
		Now:    3000,
		Czd:    bytes.Repeat([]byte{0xCC}, 32),
	}

	err := p.RecordAction(action)
	if err != nil {
		t.Fatalf("RecordAction failed: %v", err)
	}

	if p.Level() != Level4 {
		t.Errorf("expected Level4, got %v", p.Level())
	}
	if p.DR() == nil {
		t.Error("DS should not be nil after action")
	}
	if p.ActionCount() != 1 {
		t.Errorf("expected 1 action, got %d", p.ActionCount())
	}
}

func TestRecordAction_ChangesPS(t *testing.T) {
	key := makeTestCozKey(0xBB)
	p, _ := Implicit(key)

	psBefore := append([]byte{}, p.PR().First()...)

	action := &Action{
		Typ:    "cyphr.me/action/test",
		Signer: key.Tmb,
		Now:    3000,
		Czd:    bytes.Repeat([]byte{0xDD}, 32),
	}
	p.RecordAction(action)

	if bytes.Equal(p.PR().First(), psBefore) {
		t.Error("PS should change after adding DS")
	}
}

func TestRecordAction_UnknownSigner(t *testing.T) {
	key := makeTestCozKey(0xCC)
	p, _ := Implicit(key)

	unknownTmb := bytes.Repeat([]byte{0xFF}, 32)
	action := &Action{
		Typ:    "cyphr.me/action/test",
		Signer: unknownTmb,
		Now:    3000,
		Czd:    bytes.Repeat([]byte{0xEE}, 32),
	}

	err := p.RecordAction(action)
	if err != ErrUnknownKey {
		t.Errorf("expected ErrUnknownKey, got %v", err)
	}
}
