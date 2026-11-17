package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

type envelopeInput struct {
	V          int    `json:"v"`
	Alg        string `json:"alg"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	MaxViews   int    `json:"maxViews"`
}

type validatedEnvelope struct {
	IV         []byte
	Ciphertext []byte
	Tag        []byte
	MaxViews   int
}

type createRequest struct {
	Envelope   envelopeInput `json:"envelope"`
	TTLSeconds int           `json:"ttlSeconds"`
	// Proof is SHA-256("not-saved:open-proof:v1" || key); the label is frozen so
	// links created before the unkeep rename keep working. It lets the server
	// reject a burn attempt from someone who holds only a passphrase-wrapped
	// link and therefore cannot derive the key.
	Proof string `json:"proof"`
}

type openRequest struct {
	Challenge    string `json:"challenge"`
	Confirmation string `json:"confirmation"`
}

type decryptedRequest struct {
	ViewToken string `json:"viewToken"`
}

type requestError struct {
	status  int
	code    string
	message string
}

func (e *requestError) Error() string { return e.message }

func badRequest(message string) *requestError {
	return &requestError{status: http.StatusBadRequest, code: "invalid_request", message: message}
}

func forbidden(message string) *requestError {
	return &requestError{status: http.StatusForbidden, code: "invalid_confirmation", message: message}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &requestError{status: http.StatusUnsupportedMediaType, code: "unsupported_media_type", message: "Send application/json."}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &requestError{status: http.StatusRequestEntityTooLarge, code: "too_large", message: "Request body is too large."}
		}
		return badRequest("Invalid JSON body.")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return badRequest("Invalid JSON body.")
	}
	return nil
}

func validateSecretID(id string) bool {
	if len(id) != 22 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil || len(raw) != 16 {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == id
}

func validateToken(token string, rawLen int) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(rawLen) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != rawLen {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(raw) == token
}

func decodeB64URL(value string, maxLen int) ([]byte, bool) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maxLen) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) > maxLen {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, false
	}
	return raw, true
}

func validateEnvelope(in envelopeInput, maxCiphertext int) (validatedEnvelope, *requestError) {
	if in.V != 1 || in.Alg != "A256GCM" || in.MaxViews != 1 {
		return validatedEnvelope{}, badRequest("Unsupported envelope.")
	}
	iv, ok := decodeB64URL(in.IV, 12)
	if !ok || len(iv) != 12 {
		return validatedEnvelope{}, badRequest("Invalid envelope IV.")
	}
	tag, ok := decodeB64URL(in.Tag, 16)
	if !ok || len(tag) != 16 {
		return validatedEnvelope{}, badRequest("Invalid envelope tag.")
	}
	ciphertext, ok := decodeB64URL(in.Ciphertext, maxCiphertext)
	if !ok {
		return validatedEnvelope{}, badRequest("Invalid envelope ciphertext.")
	}
	return validatedEnvelope{
		IV:         iv,
		Ciphertext: ciphertext,
		Tag:        tag,
		MaxViews:   1,
	}, nil
}

func validateTTL(seconds int, cfg Config) (time.Duration, *requestError) {
	if seconds == 0 {
		return cfg.DefaultTTL, nil
	}
	if seconds < 0 {
		return 0, badRequest("Invalid expiry.")
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < cfg.MinTTL || ttl > cfg.MaxTTL {
		return 0, badRequest("Expiry is outside the allowed range.")
	}
	return ttl, nil
}
