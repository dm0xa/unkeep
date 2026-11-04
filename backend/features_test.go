package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func revokeThroughAPI(t *testing.T, client *http.Client, base, id, token string) (*http.Response, []byte) {
	t.Helper()
	return doJSON(t, client, http.MethodPost, base+"/api/secrets/"+id+"/revoke", nil, map[string]string{
		"X-Receipt-Token":     token,
		"X-Not-Saved-Confirm": "revoke",
	})
}

func TestSenderCanRevokeAnUnreadSecret(t *testing.T) {
	base, client, _, app := newAPIServer(t, nil)
	created, cs, _ := createThroughAPI(t, client, base, "revoke me", 3600)
	challenge := challengeThroughAPI(t, client, base, created.SecretID)

	res, data := revokeThroughAPI(t, client, base, created.SecretID, "wrong-token")
	mustStatus(t, res, data, http.StatusNotFound)

	res, data = revokeThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	mustStatus(t, res, data, http.StatusOK)
	var revoked struct {
		State     string `json:"state"`
		RevokedAt int64  `json:"revokedAt"`
	}
	mustJSON(t, data, &revoked)
	if revoked.State != stateRevoked || revoked.RevokedAt == 0 {
		t.Fatalf("revoke response = %+v", revoked)
	}

	res, data = doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, res, data, http.StatusGone)

	res, data = openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusGone)

	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.State != stateRevoked || view.RevokedAt == 0 || view.BurnedAt != 0 {
		t.Fatalf("receipt after revoke = %+v", view)
	}
	types := make([]string, len(view.Events))
	for i, event := range view.Events {
		types[i] = event.Type
	}
	want := []string{eventCreated, eventLinkOpened, eventRevoked}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", types, want)
	}

	res, data = revokeThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	mustStatus(t, res, data, http.StatusOK)
	mustJSON(t, data, &revoked)
	if revoked.State != stateRevoked {
		t.Fatalf("idempotent revoke state = %q", revoked.State)
	}
	view = receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if len(view.Events) != 3 {
		t.Fatalf("idempotent revoke appended an event: %+v", view.Events)
	}
	if stats := app.store.Stats(); stats.Secrets != 0 || stats.Revokes != 1 {
		t.Fatalf("store stats after revoke = %+v", stats)
	}
}

func TestOpenRequiresKeyProofAndDoesNotBurnOnMismatch(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, cs, _ := createThroughAPI(t, client, base, "proof gated", 3600)
	challenge := challengeThroughAPI(t, client, base, created.SecretID)

	missing, body := doJSON(t, client, http.MethodPost, base+"/api/secrets/"+created.SecretID+"/open", []byte(`{"challenge":"`+challenge.Challenge+`","confirmation":"reveal"}`), map[string]string{
		"X-Not-Saved-Confirm": "reveal",
	})
	mustStatus(t, missing, body, http.StatusForbidden)

	wrong := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	res, data := openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, wrong)
	mustStatus(t, res, data, http.StatusForbidden)

	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.State != stateAvailable || view.BurnedAt != 0 || view.Decrypted {
		t.Fatalf("a mismatched proof changed the receipt: %+v", view)
	}
	for _, event := range view.Events {
		if event.Type == eventBurned || event.Type == eventDecryptAttempted {
			t.Fatalf("a mismatched proof burned the secret: %+v", view.Events)
		}
	}

	res, data = openThroughAPI(t, client, base, created.SecretID, challenge.Challenge, cs.proof)
	mustStatus(t, res, data, http.StatusOK)
}

func TestCreateRequiresAKeyProof(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	cs := makeClientSecret(t, "no proof")
	body, _ := json.Marshal(map[string]any{
		"envelope":   cs.envelope,
		"ttlSeconds": 60,
	})
	res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets", body, nil)
	mustStatus(t, res, data, http.StatusBadRequest)
}

func TestChallengeIsSameOriginAndCountsOpensWithoutSpam(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, _, _ := createThroughAPI(t, client, base, "count me", 3600)

	res, data := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, map[string]string{
		"Origin": "https://evil.example",
	})
	mustStatus(t, res, data, http.StatusForbidden)
	view := receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.Opens != 0 || len(view.Events) != 1 {
		t.Fatalf("cross-origin challenge changed the receipt: %+v", view)
	}

	challengeThroughAPI(t, client, base, created.SecretID)
	challengeThroughAPI(t, client, base, created.SecretID)
	view = receiptThroughAPI(t, client, base, created.SecretID, created.ReceiptToken)
	if view.Opens != 2 || view.LastOpenedAt == 0 {
		t.Fatalf("open count = %d lastOpenedAt = %d", view.Opens, view.LastOpenedAt)
	}
	openedEvents := 0
	for _, event := range view.Events {
		if event.Type == eventLinkOpened {
			openedEvents++
		}
	}
	if openedEvents != 1 {
		t.Fatalf("link_opened events = %d, want 1; %+v", openedEvents, view.Events)
	}
}

func TestMetricsAreTokenGatedAndCarryNoSecretMaterial(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.MetricsToken = "metrics-secret"
		cfg.BuildVersion = "test-build"
	})
	created, cs, _ := createThroughAPI(t, client, base, "metrics canary", 3600)

	for _, headers := range []map[string]string{nil, {"Authorization": "Bearer wrong"}} {
		res, data := doJSON(t, &http.Client{}, http.MethodGet, base+"/metrics", nil, headers)
		mustStatus(t, res, data, http.StatusNotFound)
	}

	res, data := doJSON(t, &http.Client{}, http.MethodGet, base+"/metrics", nil, map[string]string{
		"Authorization": "Bearer metrics-secret",
	})
	mustStatus(t, res, data, http.StatusOK)
	body := string(data)
	for _, want := range []string{
		"unkeep_live_secrets 1",
		"unkeep_creates_total 1",
		`unkeep_build_info{version="test-build"} 1`,
		"unkeep_http_requests_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{created.SecretID, created.ReceiptToken, cs.proof, "metrics-secret", "metrics canary"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics leaked %q:\n%s", forbidden, body)
		}
	}

	res, data = doJSON(t, &http.Client{}, http.MethodGet, base+"/readyz", nil, nil)
	mustStatus(t, res, data, http.StatusOK)
}

func TestReadyzFailsAtCapacity(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.MaxSecrets = 1
		cfg.MaxReceipts = 1
	})
	createThroughAPI(t, client, base, "one", 3600)
	res, data := doJSON(t, &http.Client{}, http.MethodGet, base+"/readyz", nil, nil)
	mustStatus(t, res, data, http.StatusServiceUnavailable)
}

func TestMetricsAreDisabledWithoutAToken(t *testing.T) {
	base, _, _, _ := newAPIServer(t, nil)
	res, data := doJSON(t, &http.Client{}, http.MethodGet, base+"/metrics", nil, nil)
	mustStatus(t, res, data, http.StatusNotFound)
}
