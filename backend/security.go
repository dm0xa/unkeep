package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// sessionCookieName is a frozen cookie label kept for compatibility with
// sessions issued before the unkeep rename.
const sessionCookieName = "ns_sid"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; manifest-src 'self'; require-trusted-types-for 'script'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		h.Set("Cache-Control", "no-store, max-age=0")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func sameOriginRequest(r *http.Request, allowedHosts []string) bool {
	if !hostAllowed(r.Host, allowedHosts) {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		if !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	return true
}

// hostAllowed rejects Host headers outside the configured allowlist. Without
// this check, a DNS-rebinding page can make Host and Origin agree on an
// attacker-controlled name and defeat sameOriginRequest.
func hostAllowed(rawHost string, allowed []string) bool {
	host, port := splitHost(rawHost)
	if host == "" {
		return false
	}
	for _, entry := range allowed {
		entryHost, entryPort := splitHost(entry)
		if entryHost == "" || host != entryHost {
			continue
		}
		if entryPort == "" || entryPort == port {
			return true
		}
	}
	return false
}

func splitHost(value string) (host, port string) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return host, port
	}
	// No port, or a bare IPv6 literal without brackets.
	return strings.Trim(value, "[]"), ""
}

func requestIsHTTPS(r *http.Request, trustProxy bool) bool {
	if r.TLS != nil {
		return true
	}
	return trustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hmacKey(secret []byte, parts ...string) []byte {
	m := hmac.New(sha256.New, secret)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return m.Sum(nil)
}

type sessionCodec struct {
	secret []byte
}

func newSessionCodec(secret []byte) *sessionCodec {
	return &sessionCodec{secret: secret}
}

func (c *sessionCodec) newSession() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (c *sessionCodec) sign(sid string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte("session:"))
	mac.Write([]byte(sid))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c *sessionCodec) encode(sid string) string {
	return sid + "." + c.sign(sid)
}

func (c *sessionCodec) parse(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || len(parts[0]) != 22 || len(parts[1]) != 43 {
		return "", false
	}
	want := c.sign(parts[0])
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return "", false
	}
	return parts[0], true
}

func (c *sessionCodec) fromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	return c.parse(cookie.Value)
}

func (c *sessionCodec) setCookie(w http.ResponseWriter, r *http.Request, trustProxy bool, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    c.encode(sid),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r, trustProxy),
		SameSite: http.SameSiteStrictMode,
	})
}

func tokenHash(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func hashesEqual(a, b [32]byte) bool {
	return hmac.Equal(a[:], b[:])
}
