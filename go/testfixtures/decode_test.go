package testfixtures

import (
	"encoding/hex"
	"testing"

	"github.com/cyphrme/coz"
)

func TestDecodeDebug(t *testing.T) {
	b64str := "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
	decoded, err := coz.Decode(b64str)
	if err != nil {
		t.Fatalf("coz.Decode failed: %v", err)
	}
	t.Logf("Input string len: %d", len(b64str))
	t.Logf("Decoded len: %d", len(decoded))
	t.Logf("First 10 decoded bytes hex: %s", hex.EncodeToString(decoded[:min(10, len(decoded))]))
	t.Logf("Expected first bytes (from Python): da74ce685566d902f199")

	expectedPrefix := "da74ce685566d902f199"
	actualPrefix := hex.EncodeToString(decoded[:10])
	if actualPrefix != expectedPrefix {
		t.Errorf("coz.Decode returned wrong bytes!\n  Expected prefix: %s\n  Actual prefix:   %s", expectedPrefix, actualPrefix)
		t.Logf("This confirms the bug: coz.Decode is returning ASCII bytes of the base64 string instead of decoded binary")
	}
}
