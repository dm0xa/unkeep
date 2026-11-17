package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// sessionCookieName is a frozen cookie label kept for compatibility with
// sessions issued before the unkeep rename.
const sessionCookieName = "ns_sid"

// contentSecurityPolicy builds the header once per server. The inline theme
// boot script in index.html is allowed by the hash of its exact bytes, which is
// derived from the embedded page at startup: no hardcoded hash can drift.
func contentSecurityPolicy(scriptHashes, styleHashes []string) string {
	scriptSrc := "'self'"
	for _, hash := range scriptHashes {
		scriptSrc += " 'sha256-" + hash + "'"
	}
	styleSrc := "'self'"
	for _, hash := range styleHashes {
		styleSrc += " 'sha256-" + hash + "'"
	}
	return "default-src 'none'; script-src " + scriptSrc + "; style-src " + styleSrc + "; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; manifest-src 'self'; require-trusted-types-for 'script'"
}

// documentHeaders and apiHeaders are written verbatim. Precomputing them keeps
// the per-request cost to a map copy instead of 14 formatting calls, and the
// API set deliberately omits document-only policies: JSON is never rendered as
// a document, nosniff plus the application/json content type already stop
// sniffing, and the CSP alone was 278 bytes on every reply.
func securityHeaders(next http.Handler, scriptHashes, styleHashes []string) http.Handler {
	document := http.Header{
		"Strict-Transport-Security":    {"max-age=63072000; includeSubDomains"},
		"Content-Security-Policy":      {contentSecurityPolicy(scriptHashes, styleHashes)},
		"X-Content-Type-Options":       {"nosniff"},
		"X-Frame-Options":              {"DENY"},
		"Referrer-Policy":              {"no-referrer"},
		"Permissions-Policy":           {"accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"},
		"Cross-Origin-Opener-Policy":   {"same-origin"},
		"Cross-Origin-Resource-Policy": {"same-origin"},
		"Cross-Origin-Embedder-Policy": {"require-corp"},
		"X-Robots-Tag":                 {"noindex, nofollow, noarchive, nosnippet"},
		"Cache-Control":                {"no-store, max-age=0"},
		"Pragma":                       {"no-cache"},
		"Expires":                      {"0"},
	}
	api := http.Header{
		"Strict-Transport-Security": {"max-age=63072000; includeSubDomains"},
		"X-Content-Type-Options":    {"nosniff"},
		"Referrer-Policy":           {"no-referrer"},
		"X-Robots-Tag":              {"noindex, nofollow, noarchive, nosnippet"},
		"Cache-Control":             {"no-store, max-age=0"},
		"Pragma":                    {"no-cache"},
		"Expires":                   {"0"},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := document
		if strings.HasPrefix(r.URL.Path, "/api/") {
			set = api
		}
		h := w.Header()
		for name, values := range set {
			h[name] = values
		}
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

// clientIP returns the address a rate-limit bucket is keyed on. With
// TRUST_PROXY the client is hops entries from the right of X-Forwarded-For:
// proxies append the peer they saw, so the right-most entry is written by our
// own edge. Taking the left-most entry would let any client choose its bucket.
func clientIP(r *http.Request, trustProxy bool, hops int) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			entries := strings.Split(xff, ",")
			if hops < 1 {
				hops = 1
			}
			if hops > len(entries) {
				hops = len(entries)
			}
			candidate := strings.TrimSpace(entries[len(entries)-hops])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitIdentity collapses addresses that one host controls: a single IPv6
// subscriber owns a whole /64, so per-address limits would be free to bypass.
func rateLimitIdentity(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if prefix, err := addr.Prefix(64); err == nil {
			return prefix.String()
		}
	}
	return addr.String()
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

// fromRequest reads the session cookie straight from the header: the stdlib
// accessor parses and unescapes every cookie on the request for 2 allocations
// and ~230 ns, and this runs on three of the five API paths. The value still
// has to pass the exact-length signature check in parse.
func (c *sessionCodec) fromRequest(r *http.Request) (string, bool) {
	raw := r.Header.Get("Cookie")
	if raw == "" {
		return "", false
	}
	prefix := sessionCookieName + "="
	for len(raw) > 0 {
		var part string
		part, raw, _ = strings.Cut(raw, ";")
		if value, ok := strings.CutPrefix(strings.TrimSpace(part), prefix); ok {
			return c.parse(value)
		}
	}
	return "", false
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
