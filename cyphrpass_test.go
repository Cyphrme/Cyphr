package cyphrpass

import (
	"github.com/cyphrme/coz"
)

var GoldenKey = coz.Key{
	Alg: coz.SEAlg(coz.ES256),
	Tag: "Zami's Majuscule Key.",
	Now: 1623132000,
	Pub: coz.MustDecode("2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"),
	Prv: coz.MustDecode("bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"),
	Tmb: coz.MustDecode("cLj8vsYtMBwYkzoFVZHBZo6SNL8wSdCIjCKAwXNuhOk"),
}

// func TestAccountCreationAndUpsert(t *testing.T) {
// 	// Use the GoldenKey provided by the coz library
// 	initialKey := GoldenKey

// 	// Create a new account
// 	acc, err := NewAccount(&initialKey)
// 	if err != nil {
// 		t.Fatalf("NewAccount failed: %v", err)
// 	}

// 	// Verify Account Root matches the documented value
// 	expectedAR := "RpMM4_lU6jCj3asZEtIFyYqPjC2L6mlucl7VGMvAuno"
// 	if acc.AR.String() != expectedAR {
// 		t.Errorf("AR mismatch: got %s, want %s", acc.AR.String(), expectedAR)
// 	}

// 	// Initially MR == AR
// 	if !bytes.Equal(acc.MR, acc.AR) {
// 		t.Error("initial MR should equal AR")
// 	}

// 	// One active key
// 	if len(acc.Keys) != 1 {
// 		t.Errorf("expected 1 key, got %d", len(acc.Keys))
// 	}

// 	// Generate a second key for testing
// 	secondKey, err := coz.NewKey(coz.SEAlg(coz.ES256))
// 	if err != nil {
// 		t.Fatalf("failed to generate second key: %v", err)
// 	}

// 	// Perform upsert using the initial key as signer
// 	err = acc.UpsertKey(&initialKey, secondKey)
// 	if err != nil {
// 		t.Fatalf("UpsertKey failed: %v", err)
// 	}

// 	// Now two active keys
// 	if len(acc.Keys) != 2 {
// 		t.Errorf("expected 2 keys after upsert, got %d", len(acc.Keys))
// 	}

// 	// One transaction in history
// 	if len(acc.Transactions) != 1 {
// 		t.Errorf("expected 1 transaction, got %d", len(acc.Transactions))
// 	}

// 	// MR must have changed
// 	if bytes.Equal(acc.MR, acc.AR) {
// 		t.Error("MR did not change after adding second key")
// 	}

// 	t.Logf("New Merkle Root after upsert: %s", acc.MR.String())
// }

// func TestUpsertWithInactiveSigner(t *testing.T) {
// 	initialKey := GoldenKey

// 	acc, err := NewAccount(&initialKey)
// 	if err != nil {
// 		t.Fatalf("NewAccount failed: %v", err)
// 	}

// 	// Create unrelated keys (not part of the account)
// 	badSigner, _ := coz.NewKey(coz.SEAlg(coz.ES256))
// 	newKey, _ := coz.NewKey(coz.SEAlg(coz.ES256))

// 	// Attempt to upsert using a key that is not active
// 	err = acc.UpsertKey(badSigner, newKey)
// 	if err == nil {
// 		t.Error("UpsertKey with inactive signer should have failed")
// 	} else if err.Error() != "signer key is not active" {
// 		t.Errorf("unexpected error: %v", err)
// 	}
// }
