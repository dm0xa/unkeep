package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
)

// Metrics is a fixed-cardinality, privacy-preserving operational registry.
// It never records a secret ID, IP address, route parameter, or token.
type Metrics struct {
	requests    atomic.Int64
	responses   [6]atomic.Int64
	rateLimited atomic.Int64
	panics      atomic.Int64
	storeFull   atomic.Int64
}

func (m *Metrics) Record(status int, errorClass string) {
	m.requests.Add(1)
	class := status / 100
	if class < 1 || class > 5 {
		class = 0
	}
	m.responses[class].Add(1)
	if status == 429 {
		m.rateLimited.Add(1)
	}
	if errorClass == "panic" {
		m.panics.Add(1)
	}
}

func (m *Metrics) noteStoreFull() {
	m.storeFull.Add(1)
}

func (m *Metrics) render(stats StoreStats, version string) []byte {
	var b bytes.Buffer
	gauge := func(name, help string, value any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
	}
	counter := func(name, help string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}

	gauge("unkeep_live_secrets", "Unread secrets currently held in the store.", stats.Secrets)
	gauge("unkeep_receipts", "Receipt records currently retained by the store.", stats.Receipts)
	gauge("unkeep_ciphertext_bytes", "Bytes currently held by the store (Valkey mode: instance used_memory).", stats.TotalBytes)

	counter("unkeep_creates_total", "Secrets created.", stats.Creates)
	counter("unkeep_opens_total", "Confirmation screens served for an unread secret.", stats.Opens)
	counter("unkeep_burns_total", "Secrets consumed and removed from memory.", stats.Burns)
	counter("unkeep_revokes_total", "Unread secrets revoked by their sender.", stats.Revokes)
	counter("unkeep_expiries_total", "Unread secrets removed by expiry.", stats.Expiries)
	counter("unkeep_receipt_evictions_total", "Terminal receipts evicted by the receipt cap.", stats.Evictions)
	counter("unkeep_store_full_total", "Create requests rejected because a store cap was reached.", m.storeFull.Load())

	counter("unkeep_http_requests_total", "HTTP requests handled.", m.requests.Load())
	fmt.Fprint(&b,
		"# HELP unkeep_http_responses_total HTTP responses by status class.\n"+
			"# TYPE unkeep_http_responses_total counter\n")
	for class := 1; class <= 5; class++ {
		fmt.Fprintf(&b,
			"unkeep_http_responses_total{class=\"%dxx\"} %d\n",
			class, m.responses[class].Load())
	}
	counter("unkeep_rate_limited_total", "Requests rejected by a rate limit.", m.rateLimited.Load())
	counter("unkeep_panics_total", "Recovered handler panics.", m.panics.Load())

	fmt.Fprintf(&b,
		"# HELP unkeep_build_info Build identity.\n"+
			"# TYPE unkeep_build_info gauge\n"+
			"unkeep_build_info{version=\"%s\"} 1\n",
		metricLabel(version))
	return b.Bytes()
}

// metricLabel keeps the label valid Prometheus text without allowing a
// deployment-controlled version string to break the exposition format.
func metricLabel(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	if b.Len() > 64 {
		return b.String()[:64]
	}
	return b.String()
}
