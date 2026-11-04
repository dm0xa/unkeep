package main

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestLoadConfigAcceptsSharedSessionSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i*7 + 3)
	}
	t.Setenv("SESSION_SECRET", base64.RawURLEncoding.EncodeToString(secret))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !bytes.Equal(cfg.SessionSecret, secret) {
		t.Fatal("session secret was not loaded")
	}
}

func TestLoadConfigRejectsWeakSessionSecret(t *testing.T) {
	for _, value := range []string{
		"short",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)),
		"not base64!",
		base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)),
	} {
		t.Setenv("SESSION_SECRET", value)
		if _, err := loadConfig(); err == nil {
			t.Fatalf("accepted weak SESSION_SECRET %q", value)
		}
	}
}
