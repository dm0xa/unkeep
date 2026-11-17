package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type apiCreateResponse struct {
	SecretID         string `json:"secretId"`
	ExpiresAt        int64  `json:"expiresAt"`
	ReceiptToken     string `json:"receiptToken"`
	ReceiptExpiresAt int64  `json:"receiptExpiresAt"`
	MaxViews         int    `json:"maxViews"`
}

type apiChallengeResponse struct {
	SecretID           string `json:"secretId"`
	ExpiresAt          int64  `json:"expiresAt"`
	MaxViews           int    `json:"maxViews"`
	Challenge          string `json:"challenge"`
	ChallengeExpiresAt int64  `json:"challengeExpiresAt"`
}

type apiOpenResponse struct {
	Envelope  Envelope `json:"envelope"`
	ViewToken string   `json:"viewToken"`
	BurnedAt  int64    `json:"burnedAt"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type clientSecret struct {
	key      []byte
	envelope envelopeInput
	plain    string
	proof    string
}

func openProof(key []byte) string {
	h := sha256.New()
	h.Write([]byte("not-saved:open-proof:v1"))
	h.Write(key)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func newAPIServer(t *testing.T, mutate func(*Config)) (string, *http.Client, *MemoryLogger, *Server) {
	t.Helper()
	cfg := defaultConfig()
	cfg.MinTTL = time.Second
	cfg.MaxTTL = time.Hour
	cfg.DefaultTTL = time.Minute
	cfg.ReceiptGrace = time.Hour
	cfg.RateCreatePerMin = 1000
	cfg.RateChallengePerMin = 1000
	cfg.RateOpenPerMin = 1000
	cfg.RateReceiptPerMin = 1000
	cfg.Logger = &MemoryLogger{}
	cfg.Now = time.Now
	cfg.Rand = rand.Reader
	if mutate != nil {
		mutate(&cfg)
	}
	app, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(app.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(app.Close)
	jar, _ := cookiejar.New(nil)
	return ts.URL, &http.Client{Jar: jar}, cfg.Logger.(*MemoryLogger), app
}

func makeClientSecret(t *testing.T, secret string) clientSecret {
	t.Helper()
	key := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UnixMilli()
	expiresAt := createdAt + 3_600_000
	payload, _ := json.Marshal(map[string]any{
		"v":         1,
		"secret":    secret,
		"createdAt": createdAt,
		"expiresAt": expiresAt,
		"maxViews":  1,
	})
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, iv, payload, []byte("not-saved:v1"))
	ciphertext := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]
	return clientSecret{
		key:   key,
		plain: secret,
		proof: openProof(key),
		envelope: envelopeInput{
			V:          1,
			Alg:        "A256GCM",
			IV:         base64.RawURLEncoding.EncodeToString(iv),
			Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
			Tag:        base64.RawURLEncoding.EncodeToString(tag),
			CreatedAt:  createdAt,
			ExpiresAt:  expiresAt,
			MaxViews:   1,
		},
	}
}

func decryptClientSecret(t *testing.T, envelope Envelope, key []byte) string {
	t.Helper()
	iv, err := base64.RawURLEncoding.DecodeString(envelope.IV)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(envelope.Tag)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]byte(nil), ciphertext...), tag...)
	plain, err := gcm.Open(nil, iv, combined, []byte("not-saved:v1"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	var payload struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Secret
}

func doJSON(t *testing.T, client *http.Client, method, url string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res, data
}

func mustStatus(t *testing.T, res *http.Response, data []byte, want int) {
	t.Helper()
	if res.StatusCode != want {
		t.Fatalf("status = %d, want %d; body=%s", res.StatusCode, want, data)
	}
}

func mustJSON[T any](t *testing.T, data []byte, dst *T) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

func createThroughAPI(t *testing.T, client *http.Client, base, secret string, ttl int) (apiCreateResponse, clientSecret, []byte) {
	t.Helper()
	cs := makeClientSecret(t, secret)
	body, _ := json.Marshal(map[string]any{
		"envelope":   cs.envelope,
		"ttlSeconds": ttl,
		"proof":      cs.proof,
	})
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusCreated)
	var created apiCreateResponse
	mustJSON(t, data, &created)
	return created, cs, data
}

func challengeThroughAPI(t *testing.T, client *http.Client, base, id string) apiChallengeResponse {
	t.Helper()
	res, data := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+id, nil, nil)
	mustStatus(t, res, data, http.StatusOK)
	var challenge apiChallengeResponse
	mustJSON(t, data, &challenge)
	return challenge
}

func openThroughAPI(t *testing.T, client *http.Client, base, id, challenge, proof string) (*http.Response, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"challenge":    challenge,
		"confirmation": "reveal",
	})
	return doJSON(t, client, http.MethodPost, base+"/api/secrets/"+id+"/open", body, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
		"X-Secret-Proof":      proof,
	})
}

func receiptThroughAPI(t *testing.T, client *http.Client, base, id, token string) ReceiptView {
	t.Helper()
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets/"+id+"/receipt", nil, map[string]string{
		"X-Receipt-Token": token,
	})
	mustStatus(t, res, data, http.StatusOK)
	var view ReceiptView
	mustJSON(t, data, &view)
	return view
}

func TestAPIFullOneViewFlow(t *testing.T) {
	base, client, logger, _ := newAPIServer(t, nil)
	created, cs, createBody := createThroughAPI(t, client, base, "correct horse battery staple", 3600)
	keyB64 := base64.RawURLEncoding.EncodeToString(cs.key)
	if strings.Contains(string(createBody), keyB64) {
		t.Fatal("create response contained the key")
	}
	if strings.Contains(string(createBody), cs.envelope.Ciphertext) {
		t.Fatal("create response contained ciphertext")
	}

	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if len(view.Events) != 1 || view.Events[0].Type != eventCreated || view.State != stateAvailable {
		t.Fatalf("initial receipt: %+v", view)
	}

	challenge := challengeThroughAPI(t, client, base, created.SecretID)
	if challenge.Challenge == "" || challenge.MaxViews != 1 {
		t.Fatalf("bad challenge: %+v", challenge)
	}

	res, openBody := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, openBody, http.StatusOK)
	var opened apiOpenResponse
	mustJSON(t, openBody, &opened)
	if opened.ViewToken == "" {
		t.Fatal("missing view token")
	}
	if strings.Contains(string(openBody), cs.plain) {
		t.Fatal("open response contained plaintext")
	}
	if got := decryptClientSecret(t, opened.Envelope, cs.key); got != cs.plain {
		t.Fatalf("decrypted %q", got)
	}

	res, gone := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, res, gone, http.StatusGone)
	if strings.Contains(string(gone), created.SecretID) {
		t.Fatal("unavailable response echoed the secret id")
	}

	res, replay := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusGone {
		t.Fatalf("replay status = %d; body=%s", res.StatusCode, replay)
	}

	confirmBody, _ := json.Marshal(map[string]string{"viewToken": opened.ViewToken})
	res, confirm := doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/decrypted", confirmBody, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, res, confirm, http.StatusOK)

	view = receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.State != stateBurned || !view.Decrypted || view.BurnedAt == 0 {
		t.Fatalf("final receipt: %+v", view)
	}
	types := make([]string, len(view.Events))
	for i, event := range view.Events {
		types[i] = event.Type
	}
	want := []string{eventCreated, eventLinkOpened, eventDecryptAttempted, eventBurned, eventDecrypted}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", types, want)
	}

	res, _ = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/receipt", nil, map[string]string{
		"X-Receipt-Token": "wrong-token",
	})
	mustStatus(t, res, nil, http.StatusNotFound)

	assertLogSafe(t, logger, cs.plain, keyB64, cs.envelope.Ciphertext, cs.envelope.IV, cs.envelope.Tag, opened.ViewToken, created.ReceiptToken, created.SecretID)
}

func TestCrawlerCannotBurnOrSeeCiphertext(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, cs, _ := createThroughAPI(t, client, base, "do not preview me", 3600)

	req, _ := http.NewRequest(http.MethodGet, base+"/s/"+created.SecretID, nil)
	req.Header.Set("User-Agent", "Twitterbot/1.0")
	req.Header.Set("Accept", "text/html")
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	mustStatus(t, res, page, http.StatusOK)
	if !strings.Contains(string(page), "A secure secret is waiting") {
		t.Fatalf("interstitial metadata missing: %s", page)
	}
	for _, forbidden := range []string{cs.envelope.Ciphertext, cs.envelope.IV, cs.envelope.Tag, cs.plain, base64.RawURLEncoding.EncodeToString(cs.key)} {
		if strings.Contains(string(page), forbidden) {
			t.Fatal("crawler page contained secret material")
		}
	}

	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if len(view.Events) != 1 || view.Events[0].Type != eventCreated {
		t.Fatalf("crawler generated receipt events: %+v", view.Events)
	}

	res, data := doJSON(t, (&http.Client{}), http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", []byte(`{"challenge":"","confirmation":"reveal"}`), map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, res, data, http.StatusForbidden)

	challenge := challengeThroughAPI(t, client, base, created.SecretID)
	res, data = openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
}

func TestSessionNonceOriginAndHumanConfirmation(t *testing.T) {
	base, clientA, _, _ := newAPIServer(t, nil)
	created, cs, _ := createThroughAPI(t, clientA, base, "session-bound", 3600)
	challenge := challengeThroughAPI(t, clientA, base, created.SecretID)

	clientB := &http.Client{}
	res, data := openThroughAPI(t, clientB, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusForbidden)

	clientC := &http.Client{}
	_ = challengeThroughAPI(t, clientC, base, created.SecretID)
	res, data = openThroughAPI(t, clientC, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusForbidden)

	body, _ := json.Marshal(map[string]string{"challenge": challenge.Challenge, "confirmation": "reveal"})
	res, data = doJSON(t, clientA, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", body, nil)
	mustStatus(t, res, data, http.StatusForbidden)

	res, data = doJSON(t, clientA, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", body, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
		"Origin":              "https://evil.example",
	})
	mustStatus(t, res, data, http.StatusForbidden)

	res, data = doJSON(t, clientA, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", body, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
		"Sec-Fetch-Site":      "cross-site",
	})
	mustStatus(t, res, data, http.StatusForbidden)

	res, data = openThroughAPI(t, clientA, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
}

func TestExpiryIsServerAuthoritative(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, _, _ := createThroughAPI(t, client, base, "short lived", 1)
	time.Sleep(1200 * time.Millisecond)
	res, data := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, res, data, http.StatusGone)
	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.State != stateExpired {
		t.Fatalf("state = %q, want expired", view.State)
	}
	found := false
	for _, event := range view.Events {
		if event.Type == eventExpired {
			found = true
		}
	}
	if !found {
		t.Fatalf("expired event missing: %+v", view.Events)
	}
}

func TestSecurityHeadersAndStaticSurface(t *testing.T) {
	base, _, _, _ := newAPIServer(t, nil)
	res, page := doJSON(t, &http.Client{}, http.MethodGet, base+"/", nil, nil)
	mustStatus(t, res, page, http.StatusOK)
	headers := map[string]string{
		"Strict-Transport-Security":  "max-age=63072000",
		"Content-Security-Policy":    "default-src 'none'",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Permissions-Policy":         "camera=()",
		"Cache-Control":              "no-store",
		"X-Robots-Tag":               "noindex",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for name, want := range headers {
		if got := res.Header.Get(name); !strings.Contains(got, want) {
			t.Fatalf("%s = %q, want substring %q", name, got, want)
		}
	}
	// Inline scripts are allowed only when the CSP pins their exact hash.
	csp := res.Header.Get("Content-Security-Policy")
	for _, hash := range inlineScriptHashes(page) {
		if !strings.Contains(csp, "'sha256-"+hash+"'") {
			t.Fatalf("inline script not allowlisted by CSP: %q", csp)
		}
	}

	res, assetBody := doJSON(t, &http.Client{}, http.MethodGet, base+"/app.js", nil, nil)
	mustStatus(t, res, assetBody, http.StatusOK)
	if !strings.Contains(res.Header.Get("Cache-Control"), "public") {
		t.Fatalf("asset Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	etag := res.Header.Get("ETag")
	if etag == "" {
		t.Fatal("asset ETag missing")
	}
	res, data := doJSON(t, &http.Client{}, http.MethodGet, base+"/app.js", nil, map[string]string{
		"If-None-Match": etag,
	})
	mustStatus(t, res, data, http.StatusNotModified)

	res, font := doJSON(t, &http.Client{}, http.MethodGet, base+"/assets/archivo-latin-wght.woff2", nil, nil)
	mustStatus(t, res, font, http.StatusOK)
	if !strings.Contains(res.Header.Get("Content-Type"), "font/woff2") {
		t.Fatalf("font Content-Type = %q", res.Header.Get("Content-Type"))
	}

	res, data = doJSON(t, &http.Client{}, http.MethodGet, base+"/api/secrets", nil, nil)
	mustStatus(t, res, data, http.StatusMethodNotAllowed)
	if res.Header.Get("Allow") != "POST" {
		t.Fatalf("Allow = %q", res.Header.Get("Allow"))
	}
	res, data = doJSON(t, &http.Client{}, http.MethodGet, base+"/healthz", nil, nil)
	mustStatus(t, res, data, http.StatusOK)
	res, data = doJSON(t, &http.Client{}, http.MethodGet, base+"/robots.txt", nil, nil)
	mustStatus(t, res, data, http.StatusOK)
	if !strings.Contains(string(data), "Disallow: /") {
		t.Fatal("robots.txt does not disallow indexing")
	}
}

func TestRateLimitCreation(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.RateCreatePerMin = 1
	})
	for i := 0; i < 3; i++ {
		createThroughAPI(t, client, base, fmt.Sprintf("rate-%d", i), 60)
	}
	cs := makeClientSecret(t, "rate-4")
	body, _ := json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 60})
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusTooManyRequests)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	var apiErr apiError
	mustJSON(t, data, &apiErr)
	if apiErr.Error.Code != "rate_limited" {
		t.Fatalf("code = %q", apiErr.Error.Code)
	}
}

func TestInputValidationAndOversizedBodies(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.MaxSecretBytes = 1024
	})
	cs := makeClientSecret(t, "validation")

	invalid := cs.envelope
	invalid.MaxViews = 2
	body, _ := json.Marshal(map[string]any{"envelope": invalid, "ttlSeconds": 60})
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)

	invalid = cs.envelope
	invalid.IV = "AAAA"
	body, _ = json.Marshal(map[string]any{"envelope": invalid, "ttlSeconds": 60})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)

	body, _ = json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 60, "extra": 1})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)

	body, _ = json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 60})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status = %d", res.StatusCode)
	}

	large := []byte(`{"padding":"` + strings.Repeat("x", 70<<10) + `"}`)
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", large, nil)
	mustStatus(t, res, data, http.StatusRequestEntityTooLarge)

	body, _ = json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 999999})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)

	bigCiphertext := make([]byte, 2048)
	if _, err := rand.Read(bigCiphertext); err != nil {
		t.Fatal(err)
	}
	invalid = cs.envelope
	invalid.Ciphertext = base64.RawURLEncoding.EncodeToString(bigCiphertext)
	body, _ = json.Marshal(map[string]any{"envelope": invalid, "ttlSeconds": 60})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)

	res, data = doJSON(t, client, http.MethodGet, base+"/api/secrets/not-an-id", nil, nil)
	mustStatus(t, res, data, http.StatusGone)

	body, _ = json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 60})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", body, map[string]string{"Origin": "https://evil.example"})
	mustStatus(t, res, data, http.StatusForbidden)
}

func TestLogsAndFilesystemDoNotRetainSecrets(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatal(err)
		}
	}()

	base, client, logger, _ := newAPIServer(t, nil)
	created, cs, _ := createThroughAPI(t, client, base, "filesystem-canary", 60)
	challenge := challengeThroughAPI(t, client, base, created.SecretID)
	res, data := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
	var opened apiOpenResponse
	mustJSON(t, data, &opened)
	confirmBody, _ := json.Marshal(map[string]string{"viewToken": opened.ViewToken})
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/decrypted", confirmBody, map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, res, data, http.StatusOK)

	assertLogSafe(t, logger, "filesystem-canary", base64.RawURLEncoding.EncodeToString(cs.key), cs.envelope.Ciphertext, created.ReceiptToken, opened.ViewToken, created.SecretID)
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("runtime wrote files: %v", entries)
	}
}

func TestErrorsAndLogsDoNotEchoBodies(t *testing.T) {
	base, client, logger, _ := newAPIServer(t, func(cfg *Config) {
		cfg.Rand = failingReader{}
	})
	cs := makeClientSecret(t, "error-canary")
	body, _ := json.Marshal(map[string]any{"envelope": cs.envelope, "ttlSeconds": 60, "proof": cs.proof})
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets?canary=query-canary", body, nil)
	mustStatus(t, res, data, http.StatusInternalServerError)
	for _, forbidden := range []string{"error-canary", cs.envelope.Ciphertext, base64.RawURLEncoding.EncodeToString(cs.key), "query-canary", "goroutine", "stack"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("error response leaked %q: %s", forbidden, data)
		}
	}

	malformed := []byte(`{"envelope":{"ciphertext":"body-canary"},"broken":`)
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets", malformed, nil)
	mustStatus(t, res, data, http.StatusBadRequest)
	if strings.Contains(string(data), "body-canary") {
		t.Fatal("malformed body echoed")
	}
	assertLogSafe(t, logger, "error-canary", "body-canary", "query-canary", cs.envelope.Ciphertext, base64.RawURLEncoding.EncodeToString(cs.key))
}

func TestGenericUnavailableResponses(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	unknownID := randomID(t)
	resUnknown, unknownBody := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+unknownID, nil, nil)
	mustStatus(t, resUnknown, unknownBody, http.StatusGone)

	created, cs, _ := createThroughAPI(t, client, base, "burn me", 60)
	challenge := challengeThroughAPI(t, client, base, created.SecretID)
	res, data := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
	resBurned, burnedBody := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, resBurned, burnedBody, http.StatusGone)

	if string(unknownBody) != string(burnedBody) {
		t.Fatalf("unavailable responses differ: %s vs %s", unknownBody, burnedBody)
	}
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/receipt", nil, map[string]string{
		"X-Receipt-Token": "invalid",
	})
	mustStatus(t, res, data, http.StatusNotFound)
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/decrypted", []byte(`{"viewToken":"invalid"}`), map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, res, data, http.StatusNotFound)
}

func TestReceiptTokenIsRequiredForPolling(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, _, _ := createThroughAPI(t, client, base, "receipt", 60)
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/receipt", nil, nil)
	mustStatus(t, res, data, http.StatusNotFound)
	res, data = doJSON(t, client, http.MethodPost, base+"/api/secrets/"+"AAAAAAAAAAAAAAAAAAAAAA"+"/receipt", nil, map[string]string{
		"X-Receipt-Token": created.ReceiptToken,
	})
	mustStatus(t, res, data, http.StatusNotFound)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func randomID(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func assertLogSafe(t *testing.T, logger *MemoryLogger, forbidden ...string) {
	t.Helper()
	data, err := json.Marshal(logger.Entries())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range forbidden {
		if value == "" {
			continue
		}
		if strings.Contains(string(data), value) {
			t.Fatalf("log leaked %q: %s", value, data)
		}
	}
}

func TestCompressedAssetsNegotiateAndRevalidate(t *testing.T) {
	base, _, _, _ := newAPIServer(t, nil)
	// Go's default transport adds Accept-Encoding: gzip and decompresses for us,
	// which would hide the negotiation under test.
	plainTransport := &http.Transport{DisableCompression: true}

	get := func(path, acceptEncoding, ifNoneMatch string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		res, err := plainTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	plain := get("/app.js", "", "")
	plainBody := readAll(t, plain)
	if plain.Header.Get("Content-Encoding") != "" {
		t.Fatalf("identity request got encoding %q", plain.Header.Get("Content-Encoding"))
	}
	if v := plain.Header.Get("Vary"); v != "Accept-Encoding" {
		t.Fatalf("Vary = %q", v)
	}

	zipped := get("/app.js", "gzip", "")
	if zipped.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip request got encoding %q", zipped.Header.Get("Content-Encoding"))
	}
	zlibReader, err := gzip.NewReader(zipped.Body)
	if err != nil {
		t.Fatal(err)
	}
	unzipped, err := io.ReadAll(zlibReader)
	if err != nil {
		t.Fatal(err)
	}
	_ = zipped.Body.Close()
	if !bytes.Equal(unzipped, plainBody) {
		t.Fatal("gzip body does not match the identity body")
	}
	if len(unzipped) <= len(plainBody)/2 {
		t.Fatalf("compression had no effect: %d vs %d", len(unzipped), len(plainBody))
	}

	gzipETag := zipped.Header.Get("ETag")
	if gzipETag == plain.Header.Get("ETag") || gzipETag == "" {
		t.Fatalf("gzip ETag %q must differ from identity ETag %q", gzipETag, plain.Header.Get("ETag"))
	}
	notModified := get("/app.js", "gzip", gzipETag)
	_ = notModified.Body.Close()
	if notModified.StatusCode != http.StatusNotModified {
		t.Fatalf("gzip revalidation = %d, want 304", notModified.StatusCode)
	}

	// q=0 means the client refuses gzip.
	refused := get("/app.js", "gzip;q=0", "")
	_ = refused.Body.Close()
	if refused.Header.Get("Content-Encoding") != "" {
		t.Fatal("q=0 client was served gzip")
	}

	pageCompressed := get("/", "gzip", "")
	pageBody, err := io.ReadAll(pageCompressed.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = pageCompressed.Body.Close()
	if pageCompressed.Header.Get("Content-Encoding") != "gzip" || len(pageBody) == 0 {
		t.Fatal("index was not served compressed")
	}
}

func readAll(t *testing.T, res *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return body
}

func TestWriteOpenMatchesStructEncoding(t *testing.T) {
	server := &Server{}

	cases := []struct {
		name string
		env  Envelope
	}{
		{
			name: "base64url",
			env: Envelope{
				V: 1, Alg: "A256GCM",
				IV: "AAAAAAAAAAAAAAAA", Ciphertext: "BBBB", Tag: "CCCC",
				CreatedAt: 1, ExpiresAt: 2, MaxViews: 1,
			},
		},
		{
			name: "hostile characters fall back to the encoder",
			env: Envelope{
				V: 1, Alg: "A256GCM",
				IV: `a"b\c`, Ciphertext: "<x>", Tag: "t",
				CreatedAt: 3, ExpiresAt: 4, MaxViews: 1,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.writeOpen(rec, c.env, "view-token-value", 99)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			var got struct {
				Envelope  Envelope `json:"envelope"`
				ViewToken string   `json:"viewToken"`
				BurnedAt  int64    `json:"burnedAt"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not valid JSON: %v (%s)", err, rec.Body.String())
			}
			if got.Envelope != c.env {
				t.Fatalf("envelope = %+v, want %+v", got.Envelope, c.env)
			}
			if got.ViewToken != "view-token-value" || got.BurnedAt != 99 {
				t.Fatalf("tail fields = %+v", got)
			}
		})
	}
}
