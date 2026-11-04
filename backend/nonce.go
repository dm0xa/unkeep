package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

const nonceTTL = 2 * time.Minute

type noncePayload struct {
	SecretID  string `json:"s"`
	SessionID string `json:"d"`
	ExpiresAt int64  `json:"e"`
	Random    string `json:"n"`
}

// NonceService issues short-lived, session-bound challenges. Verification is
// stateless: the challenge is HMAC-signed and expires. Replay cannot retrieve
// a second ciphertext because Store.Consume removes the record atomically on
// the first valid open. Avoiding a used-nonce map keeps memory flat under
// sustained open throughput.
type NonceService struct {
	secret []byte
	now    func() time.Time
}

func NewNonceService(secret []byte, now func() time.Time) *NonceService {
	return &NonceService{
		secret: secret,
		now:    now,
	}
}

func (n *NonceService) Issue(secretID, sessionID string) (string, int64) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable")
	}
	expiresAt := n.now().Add(nonceTTL)
	payload, _ := json.Marshal(noncePayload{
		SecretID:  secretID,
		SessionID: sessionID,
		ExpiresAt: expiresAt.UnixMilli(),
		Random:    base64.RawURLEncoding.EncodeToString(buf),
	})
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, n.secret)
	mac.Write([]byte("nonce:"))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig, expiresAt.UnixMilli()
}

func (n *NonceService) Verify(token, secretID, sessionID string) bool {
	parts := splitTwo(token, '.')
	if parts == nil {
		return false
	}
	mac := hmac.New(sha256.New, n.secret)
	mac.Write([]byte("nonce:"))
	mac.Write([]byte(parts[0]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var payload noncePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}
	now := n.now()
	return payload.ExpiresAt >= now.UnixMilli() &&
		payload.SecretID == secretID &&
		payload.SessionID == sessionID
}

func splitTwo(s string, sep byte) []string {
	i := -1
	for j := range len(s) {
		if s[j] == sep {
			if i >= 0 {
				return nil
			}
			i = j
		}
	}
	if i <= 0 || i == len(s)-1 {
		return nil
	}
	return []string{s[:i], s[i+1:]}
}
