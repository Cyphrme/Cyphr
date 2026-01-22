package coz_login

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cyphrme/coz"
)

// GoldenUserKey0 is the first user key.
//
//	{
//	  "alg": "ES256",
//	  "now":1623132000,
//	  "tag": "User Key 0",
//	  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
//	  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
//	  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
//	}
var GoldenUserKey0 = coz.Key{
	Tag: "User Key 0",
	Alg: coz.SEAlg(coz.ES256),
	Now: 1623132000,
	Pub: coz.MustDecode("2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"),
	Prv: coz.MustDecode("bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"),
	Tmb: coz.MustDecode("U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"),
}

// GoldenUserKey1 is the second user key.
//
//	{
//	  "alg": "ES256",
//	  "now":1623132000,
//	  "tag": "User Key 1",
//	  "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
//	  "prv": "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
//	  "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
//	}
var GoldenUserKey1 = coz.Key{
	Tag: "User Key 1",
	Alg: coz.SEAlg(coz.ES256),
	Now: 1623132000,
	Pub: coz.MustDecode("iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ"),
	Prv: coz.MustDecode("dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls"),
	Tmb: coz.MustDecode("CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"),
}

// GoldenServerKey is the server key.
//
//	{
//	  "alg":"ES256",
//	  "now":1623132000,
//		"tag": "Cyphrpass Server Key A",
//	  "tmb":"T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA",
//	  "pub":"yfZ-PY4QdhWKJ0o41yc8-X9qnahpfKoTN6sr0zd68lMFNbAzOwj9LSVdRngno4Bs_CNyDJCQJ6uqq9Q65cjn-A",
//	  "prv":"WG-hEn8De4fJJ3FxWAsOAADDp89XigiRajUCI9MFWSo"
//	}
var GoldenServerKey = coz.Key{
	Tag: "Cyphrpass Server Key A",
	Alg: coz.SEAlg(coz.ES256),
	Now: 1623132000,
	Pub: coz.MustDecode(""),
	Prv: coz.MustDecode(""),
	Tmb: coz.MustDecode(""),
}

// ExampleGenerateLoginRequest shows a full round-trip without challenge.
func ExampleGenerateLoginRequest() {
	//clientKey, _ := coz.NewSigningKey(coz.ES256)

	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) {
		return &GoldenUserKey0, nil
	})

	reqCoz, _ := GenerateLoginRequest(&GoldenUserKey0, "cyphr.me/user/login/request/create", "", true)

	userID, err := VerifyLoginRequest(reqCoz, cfg, "")
	if err != nil {
		fmt.Println("Verification failed:", err)
		return
	}
	fmt.Println("UserID (tmb):", userID)
	fmt.Println("Matches client key tmb:", userID == string(GoldenUserKey0.Tmb))
	// Output:
	// UserID (tmb): [some 43-char base64 tmb]
	// Matches client key tmb: true
}

// TestLoginFlow is the original table-style test, updated with direct constant.
func TestLoginFlow(t *testing.T) {
	clientKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", true)
	if err != nil {
		t.Fatal(err)
	}

	userID, err := VerifyLoginRequest(reqCoz, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if userID != string(clientKey.Tmb) {
		t.Errorf("expected userID %q, got %q", string(clientKey.Tmb), userID)
	}

	serverKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	bearerCoz, err := IssueBearerToken(serverKey, userID, map[string]any{"role": "admin"})
	if err != nil {
		t.Fatal(err)
	}

	verifiedID, claims, err := VerifyBearerToken(bearerCoz, serverKey, 300)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID != userID {
		t.Errorf("ID mismatch: %q != %q", verifiedID, userID)
	}
	if claims["role"] != "admin" {
		t.Errorf("claims role mismatch: got %v", claims["role"])
	}
}

// TestWithChallenge updated with proper error handling.
func TestWithChallenge(t *testing.T) {
	serverKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	challCoz, err := GenerateChallenge(serverKey, "cyphr.me/user/login/challenge/create")
	if err != nil {
		t.Fatal(err)
	}

	var chall ChallengePay
	if err := json.Unmarshal(challCoz.Pay, &chall); err != nil {
		t.Fatal(err)
	}

	clientKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", chall.Nonce, false)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

	_, err = VerifyLoginRequest(reqCoz, cfg, chall.Nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Mismatch should fail
	_, err = VerifyLoginRequest(reqCoz, cfg, "wrong-nonce")
	if err == nil || err != ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge, got %v", err)
	}
}

// ... (TestInvalidTimestamp and TestRevokedKey remain the same, just update NewKey calls)

func TestInvalidTimestamp(t *testing.T) {
	clientKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", false)
	if err != nil {
		t.Fatal(err)
	}
	reqCoz.Parsed.Now = coz.Timestamp(time.Now().Unix() - 600) // Old

	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

	_, err = VerifyLoginRequest(reqCoz, cfg, "")
	if err == nil || err != ErrInvalidTimestamp {
		t.Errorf("expected ErrInvalidTimestamp, got %v", err)
	}
}

func TestRevokedKey(t *testing.T) {
	clientKey, err := coz.NewSigningKey(coz.ES256)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke the key
	_, err = clientKey.Revoke()
	if err != nil {
		t.Fatal(err)
	}

	reqCoz, err := GenerateLoginRequest(clientKey, "cyphr.me/user/login/request/create", "", false)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig(func(tmb coz.B64) (*coz.Key, error) { return clientKey, nil })

	_, err = VerifyLoginRequest(reqCoz, cfg, "")
	if err == nil || err != ErrRevokedKey {
		t.Errorf("expected ErrRevokedKey, got %v", err)
	}
}
