package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestHostAllowlistRejectsDNSRebinding(t *testing.T) {
	base, client, _, _ := newAPIServer(t, nil)
	created, _, _ := createThroughAPI(t, client, base, "rebinding", 3600)

	req, err := http.NewRequest(http.MethodGet, base+"/api/secrets/"+created.SecretID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "rebind.example"
	req.Header.Set("Origin", "http://rebind.example")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding host status = %d, want 403", res.StatusCode)
	}

	// The same request on an allowed loopback Host still works.
	if view := challengeThroughAPI(t, client, base, created.SecretID); view.SecretID != created.SecretID {
		t.Fatalf("loopback challenge failed: %+v", view)
	}
}

func TestAllowedHostsConfigPermitsListedHostOnly(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.AllowedHosts = []string{"app.example.com"}
	})
	cs := makeClientSecret(t, "listed host")
	body, _ := json.Marshal(map[string]any{
		"envelope":   cs.envelope,
		"ttlSeconds": 60,
		"proof":      cs.proof,
	})
	req, err := http.NewRequest(http.MethodPost, base+"/api/secrets", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://app.example.com")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 0, 512)
	buf := bytes.NewBuffer(data)
	_, _ = buf.ReadFrom(res.Body)
	_ = res.Body.Close()
	mustStatus(t, res, buf.Bytes(), http.StatusCreated)
	var created apiCreateResponse
	mustJSON(t, buf.Bytes(), &created)

	// The default loopback Host is no longer in the allowlist.
	res, data2 := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, nil)
	mustStatus(t, res, data2, http.StatusForbidden)
}

func TestCrossOriginRequestsDoNotConsumeRateLimit(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.RateCreatePerMin = 10 // burst 3
	})
	cs := makeClientSecret(t, "csrf create")
	body, _ := json.Marshal(map[string]any{
		"envelope":   cs.envelope,
		"ttlSeconds": 60,
		"proof":      cs.proof,
	})
	for i := 0; i < 4; i++ {
		res, data := doJSON(t, client, http.MethodPost, base+"/api/secrets", body, map[string]string{
			"Origin": "https://evil.example",
		})
		mustStatus(t, res, data, http.StatusForbidden)
	}
	createThroughAPI(t, client, base, "after csrf", 60)
}

func TestCrossOriginChallengesDoNotConsumeRateLimit(t *testing.T) {
	base, client, _, _ := newAPIServer(t, func(cfg *Config) {
		cfg.RateChallengePerMin = 6 // burst 3
	})
	created, _, _ := createThroughAPI(t, client, base, "csrf challenge", 60)
	for i := 0; i < 4; i++ {
		res, data := doJSON(t, client, http.MethodGet, base+"/api/secrets/"+created.SecretID, nil, map[string]string{
			"Origin": "https://evil.example",
		})
		mustStatus(t, res, data, http.StatusForbidden)
	}
	challengeThroughAPI(t, client, base, created.SecretID)
}
