package cyphrpass

import (
	"testing"

	"github.com/cyphrme/coz"
)

func makeTestKey(revocation *Revocation) *Key {
	return &Key{
		Key: &coz.Key{
			Alg: coz.SEAlg(coz.ES256),
			Tmb: make(coz.B64, 32),
			Pub: make(coz.B64, 64),
		},
		FirstSeen:  1000,
		LastUsed:   0,
		Revocation: revocation,
	}
}

func TestKey_IsActive(t *testing.T) {
	t.Run("no revocation", func(t *testing.T) {
		k := makeTestKey(nil)
		if !k.IsActive() {
			t.Error("expected active key")
		}
	})

	t.Run("with revocation", func(t *testing.T) {
		k := makeTestKey(&Revocation{Rvk: 2000})
		if k.IsActive() {
			t.Error("expected revoked key")
		}
	})
}

func TestKey_IsActiveAt(t *testing.T) {
	tests := []struct {
		name       string
		revocation *Revocation
		timestamp  int64
		want       bool
	}{
		{"no revocation - any time", nil, 1000, true},
		{"no revocation - max time", nil, 1 << 62, true},
		{"before revocation", &Revocation{Rvk: 2000}, 1999, true},
		{"at revocation", &Revocation{Rvk: 2000}, 2000, false}, // SPEC: now >= rvk invalid
		{"after revocation", &Revocation{Rvk: 2000}, 2001, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := makeTestKey(tt.revocation)
			if got := k.IsActiveAt(tt.timestamp); got != tt.want {
				t.Errorf("IsActiveAt(%d) = %v, want %v", tt.timestamp, got, tt.want)
			}
		})
	}
}
