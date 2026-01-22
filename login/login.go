package coz_login

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cyphrme/coz"
)

// Errors
var (
	ErrInvalidTimestamp = errors.New("invalid timestamp: outside acceptance window")
	ErrInvalidChallenge = errors.New("invalid or mismatched challenge")
	ErrRevokedKey       = errors.New("key is revoked")
	ErrInvalidTyp       = errors.New("invalid typ")
)

// Config for server-side validation.
type Config struct {
	TimeWindow int64                               // Seconds for now validation (e.g., 300 for 5 min).
	KeyLookup  func(tmb coz.B64) (*coz.Key, error) // App-provided key fetch (e.g., from DB).
	IsRevoked  func(key *coz.Key) bool             // Optional revocation check (defaults to key.IsRevoked()).
}

// ChallengePay for server challenges.
type ChallengePay struct {
	coz.Pay
	Nonce string `json:"nonce"`
}

// DefaultConfig with 5-min window.
func DefaultConfig(keyLookup func(tmb coz.B64) (*coz.Key, error)) *Config {
	return &Config{TimeWindow: 300, KeyLookup: keyLookup, IsRevoked: func(k *coz.Key) bool { return k.IsRevoked() }}
}

// LoginRequestPay embeds coz.Pay for login requests.
type LoginRequestPay struct {
	coz.Pay
	Challenge string `json:"challenge,omitempty"` // Optional nonce.
}

// BearerTokenPay embeds coz.Pay for bearers.
type BearerTokenPay struct {
	coz.Pay
	UserID string         `json:"user_id"`          // Authenticated identity.
	Claims map[string]any `json:"claims,omitempty"` // Session claims.
}

// GenerateLoginRequest creates and signs a login request Coz.
// If firstTime, embeds the public key.
// If challenge != "", includes it.
func GenerateLoginRequest(clientKey *coz.Key, typ string, challenge string, firstTime bool) (*coz.Coz, error) {
	pay := &LoginRequestPay{
		Pay: coz.Pay{
			Alg: clientKey.Alg,
			Now: coz.Now(),
			Tmb: clientKey.Tmb, // Assumes thumbprint set.
			Typ: typ,           // e.g., "cyphr.me/user/login/request/create"
		},
		Challenge: challenge,
	}
	cozObj, err := clientKey.SignPay(&pay.Pay)
	if err != nil {
		return nil, err
	}
	if firstTime {
		cozObj.Key = &coz.Key{ // Public only.
			Alg: clientKey.Alg,
			Now: clientKey.Now,
			Pub: clientKey.Pub,
			Tag: clientKey.Tag,
			Tmb: clientKey.Tmb,
		}
	}
	return cozObj, nil
}

// VerifyLoginRequest verifies a request Coz and returns userID (e.g., tmb or app-specific).
// If challengeExpected != "", verifies it matches.
// If firstTime, uses embedded key (trusts if signed correctly).
func VerifyLoginRequest(cz *coz.Coz, cfg *Config, challengeExpected string) (userID string, err error) {
	if err = cz.Meta(); err != nil {
		return "", err
	}
	if cz.Parsed.Typ != "cyphr.me/user/login/request/create" { // Enforce typ; customize.
		return "", ErrInvalidTyp
	}
	var key *coz.Key
	if cz.Key != nil { // First-time: Use embedded.
		key = cz.Key
	} else {
		key, err = cfg.KeyLookup(cz.Parsed.Tmb)
		if err != nil {
			return "", err
		}
	}
	if cfg.IsRevoked(key) {
		return "", ErrRevokedKey
	}
	valid, err := key.VerifyCoz(cz)
	if err != nil || !valid {
		return "", err
	}
	// Timestamp check.
	if !validateTimestamp(int64(cz.Parsed.Now), cfg.TimeWindow) {
		return "", ErrInvalidTimestamp
	}
	// Challenge check.
	var reqPay LoginRequestPay
	if err = json.Unmarshal(cz.Pay, &reqPay); err != nil {
		return "", err
	}
	if challengeExpected != "" && reqPay.Challenge != challengeExpected {
		return "", ErrInvalidChallenge
	}
	return string(cz.Parsed.Tmb), nil // Use tmb as userID; customize.
}

// IssueBearerToken signs a bearer Coz.
func IssueBearerToken(serverKey *coz.Key, userID string, claims map[string]any) (*coz.Coz, error) {
	pay := &BearerTokenPay{
		Pay: coz.Pay{
			Alg: serverKey.Alg,
			Now: coz.Now(),
			Tmb: serverKey.Tmb,
			Typ: "cyphr.me/user/login/bearer/create",
		},
		UserID: userID,
		Claims: claims,
	}
	return serverKey.SignPay(&pay.Pay)
}

// VerifyBearerToken verifies a bearer Coz and extracts userID/claims.
// Uses serverKey for verification.
func VerifyBearerToken(cz *coz.Coz, serverKey *coz.Key, timeWindow int64) (userID string, claims map[string]any, err error) {
	if err = cz.Meta(); err != nil {
		return "", nil, err
	}
	if cz.Parsed.Typ != "cyphr.me/user/login/bearer/create" {
		return "", nil, ErrInvalidTyp
	}
	valid, err := serverKey.VerifyCoz(cz)
	if err != nil || !valid {
		return "", nil, err
	}
	if !validateTimestamp(int64(cz.Parsed.Now), timeWindow) {
		return "", nil, ErrInvalidTimestamp
	}
	var bearerPay BearerTokenPay
	if err = json.Unmarshal(cz.Pay, &bearerPay); err != nil {
		return "", nil, err
	}
	return bearerPay.UserID, bearerPay.Claims, nil
}

func validateTimestamp(now, window int64) bool {
	current := time.Now().Unix()
	return now >= current-window && now <= current+window
}

// GenerateChallenge creates a signed challenge Coz with random nonce.
func GenerateChallenge(serverKey *coz.Key, typ string) (*coz.Coz, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes) // b64ut.

	pay := &ChallengePay{
		Pay: coz.Pay{
			Alg: serverKey.Alg,
			Now: coz.Now(),
			Tmb: serverKey.Tmb,
			Typ: typ, // e.g., "cyphr.me/user/login/challenge/create"
		},
		Nonce: nonce,
	}
	return serverKey.SignPay(&pay.Pay)
}

// BearerMiddleware verifies bearer from Authorization header or cookie.
// On success, sets r.Header["User-ID"] = userID.
func BearerMiddleware(serverKey *coz.Key, timeWindow int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if strings.HasPrefix(token, "Bearer ") {
				token = strings.TrimPrefix(token, "Bearer ")
			} else if cookie, err := r.Cookie("bearer_token"); err == nil {
				token = cookie.Value
			}
			if token == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			var cz coz.Coz
			if err := json.Unmarshal([]byte(token), &cz); err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
			userID, claims, err := VerifyBearerToken(&cz, serverKey, timeWindow)
			if err != nil {
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}
			r.Header.Set("User-ID", userID) // Or use context.
			_ = claims                      // Use as needed.
			next.ServeHTTP(w, r)
		})
	}
}
