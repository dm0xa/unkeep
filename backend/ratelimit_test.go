package main

import (
	"net/http"
	"testing"
	"time"
)

func TestClientIPUsesProxyAppendedHop(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "10.0.0.9:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"203.0.113.7, 10.0.0.9"}},
	}
	if got := clientIP(req, true, 1); got != "10.0.0.9" {
		t.Fatalf("one hop = %q, want the proxy-appended peer", got)
	}
	if got := clientIP(req, true, 2); got != "203.0.113.7" {
		t.Fatalf("two hops = %q, want the client hop", got)
	}
	if got := clientIP(req, false, 1); got != "10.0.0.9" {
		t.Fatalf("trust_proxy off = %q, want the socket peer", got)
	}

	// A client-supplied value cannot move the selected hop: it only prepends.
	spoofed := &http.Request{
		RemoteAddr: "10.0.0.9:5555",
		Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.4, 203.0.113.7, 10.0.0.9"}},
	}
	if got := clientIP(spoofed, true, 2); got != "203.0.113.7" {
		t.Fatalf("spoofed chain = %q, want the peer our proxy saw", got)
	}
}

func TestRateLimitIdentityGroupsIPv6ByPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb::2", "2001:db8:1:2::/64"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := rateLimitIdentity(c.in); got != c.want {
			t.Fatalf("rateLimitIdentity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRateLimiterEvictsInsteadOfScanningWhenFull(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	limiter := NewRateLimiter(func() time.Time { return now }, 4)
	for i := range 4 {
		if ok, _ := limiter.Allow(string(rune('a'+i)), 60, 3); !ok {
			t.Fatalf("seed key %d denied", i)
		}
	}
	// At capacity a fresh key must still be admitted: the limiter sheds stale
	// entries instead of denying every new client or scanning the whole map.
	if ok, _ := limiter.Allow("fresh", 60, 3); !ok {
		t.Fatal("new key denied while the bucket table is full")
	}
	if len(limiter.buckets) > 4 {
		t.Fatalf("bucket table grew past its cap: %d", len(limiter.buckets))
	}

	// A bucket that is still in use keeps its token budget.
	limiter.buckets["fresh"].tokens = 0
	if ok, _ := limiter.Allow("fresh", 60, 3); ok {
		t.Fatal("exhausted bucket admitted a request")
	}
}
