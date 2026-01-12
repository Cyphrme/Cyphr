package coz_login

import (
	"fmt"

	"github.com/cyphrme/coz"
)

// ExampleNewKey demonstrates creating a new ES256 key without any cast.
func ExampleNewKey() {
	key, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(key)
	fmt.Printf("Alg: %s\n", key.Alg)
	fmt.Printf("Tmb length: %d\n", len(key.Tmb))
	// Output:
	// Alg: ES256
	// Tmb length: 43
}

// // ExampleGenerateLoginRequest shows a full round-trip without challenge.
// func ExampleGenerateLoginRequest() {
// 	clientKey, _ := coz.NewSigningKey(coz.ES256)

// 	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) {
// 		return clientKey, nil
// 	})

// 	reqCoz, _ := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", true)

// 	userID, err := VerifyLoginRequest(reqCoz, cfg, "")
// 	if err != nil {
// 		fmt.Println("Verification failed:", err)
// 		return
// 	}
// 	fmt.Println("UserID (tmb):", userID)
// 	fmt.Println("Matches client key tmb:", userID == string(clientKey.Tmb))
// 	// Output:
// 	// UserID (tmb): [some 43-char base64 tmb]
// 	// Matches client key tmb: true
// }

// // TestLoginFlow is the original table-style test, updated with direct constant.
// func TestLoginFlow(t *testing.T) {
// 	clientKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

// 	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", true)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	userID, err := VerifyLoginRequest(reqCoz, cfg, "")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if userID != string(clientKey.Tmb) {
// 		t.Errorf("expected userID %q, got %q", string(clientKey.Tmb), userID)
// 	}

// 	serverKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	bearerCoz, err := IssueBearerToken(serverKey, userID, map[string]any{"role": "admin"})
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	verifiedID, claims, err := VerifyBearerToken(bearerCoz, serverKey, 300)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if verifiedID != userID {
// 		t.Errorf("ID mismatch: %q != %q", verifiedID, userID)
// 	}
// 	if claims["role"] != "admin" {
// 		t.Errorf("claims role mismatch: got %v", claims["role"])
// 	}
// }

// // TestWithChallenge updated with proper error handling.
// func TestWithChallenge(t *testing.T) {
// 	serverKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	challCoz, err := GenerateChallenge(serverKey, "cyphr.me/user/login/challenge/create")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	var chall ChallengePay
// 	if err := json.Unmarshal(challCoz.Pay, &chall); err != nil {
// 		t.Fatal(err)
// 	}

// 	clientKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", chall.Nonce, false)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

// 	_, err = VerifyLoginRequest(reqCoz, cfg, chall.Nonce)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// Mismatch should fail
// 	_, err = VerifyLoginRequest(reqCoz, cfg, "wrong-nonce")
// 	if err == nil || err != ErrInvalidChallenge {
// 		t.Errorf("expected ErrInvalidChallenge, got %v", err)
// 	}
// }

// // ... (TestInvalidTimestamp and TestRevokedKey remain the same, just update NewKey calls)

// func TestInvalidTimestamp(t *testing.T) {
// 	clientKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", false)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	reqCoz.Parsed.Now = coz.Timestamp(time.Now().Unix() - 600) // Old

// 	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

// 	_, err = VerifyLoginRequest(reqCoz, cfg, "")
// 	if err == nil || err != ErrInvalidTimestamp {
// 		t.Errorf("expected ErrInvalidTimestamp, got %v", err)
// 	}
// }

// func TestRevokedKey(t *testing.T) {
// 	clientKey, err := coz.NewSigningKey(coz.ES256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// Revoke the key
// 	_, err = clientKey.Revoke()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", false)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

// 	_, err = VerifyLoginRequest(reqCoz, cfg, "")
// 	if err == nil || err != ErrRevokedKey {
// 		t.Errorf("expected ErrRevokedKey, got %v", err)
// 	}
// }
