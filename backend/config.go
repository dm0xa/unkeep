package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// buildVersion is replaced at build time with -X main.buildVersion=...
// and reported by /metrics. BUILD_VERSION overrides it at runtime.
var buildVersion = "dev"

// Config is the complete runtime configuration. The service has no database,
// no filesystem persistence, and no outbound network calls.
type Config struct {
	Addr       string
	TrustProxy bool
	// TrustProxyHops is how many X-Forwarded-For entries the deployment's own
	// proxies appended. 1 means a single edge proxy in front of the service.
	TrustProxyHops int
	TLSCertFile    string
	TLSKeyFile     string

	// AllowedHosts is the Host-header allowlist enforced on API routes.
	// Entries may include a port; an entry without one matches any port.
	AllowedHosts []string

	ValkeyURL    string
	ValkeyPrefix string

	MinTTL     time.Duration
	MaxTTL     time.Duration
	DefaultTTL time.Duration

	ReceiptGrace time.Duration

	MaxSecrets     int
	MaxReceipts    int
	MaxTotalBytes  int64
	MaxBodyBytes   int64
	MaxSecretBytes int

	RateCreatePerMin    int
	RateChallengePerMin int
	RateOpenPerMin      int
	RateReceiptPerMin   int

	StaticFS fs.FS

	MetricsToken string
	BuildVersion string

	Now           func() time.Time
	Logger        Logger
	Rand          io.Reader
	SessionSecret []byte
}

func defaultConfig() Config {
	return Config{
		Addr: "127.0.0.1:8080",
		// Frozen default: changing it hides secrets written before the rename.
		ValkeyPrefix:        "ns:",
		MinTTL:              time.Minute,
		MaxTTL:              7 * 24 * time.Hour,
		DefaultTTL:          24 * time.Hour,
		ReceiptGrace:        24 * time.Hour,
		MaxSecrets:          10_000,
		MaxReceipts:         50_000,
		MaxTotalBytes:       64 << 20,
		MaxBodyBytes:        64 << 10,
		MaxSecretBytes:      32 << 10,
		RateCreatePerMin:    10,
		RateChallengePerMin: 60,
		RateOpenPerMin:      30,
		RateReceiptPerMin:   120,
		BuildVersion:        buildVersion,
		Now:                 time.Now,
	}
}

func loadConfig() (Config, error) {
	cfg := defaultConfig()
	cfg.Logger = NewJSONLogger(os.Stdout)
	cfg.Rand = rand.Reader

	host := envOr("HOST", "127.0.0.1")
	port := envOr("PORT", "8080")
	cfg.Addr = net.JoinHostPort(host, port)

	if v := os.Getenv("ADDR"); v != "" {
		cfg.Addr = v
	}
	cfg.ValkeyURL = os.Getenv("VALKEY_URL")
	cfg.ValkeyPrefix = envOr("VALKEY_PREFIX", cfg.ValkeyPrefix)

	trustProxy, err := envBool("TRUST_PROXY", false)
	if err != nil {
		return Config{}, err
	}
	cfg.TrustProxy = trustProxy
	cfg.TrustProxyHops, err = envInt("TRUST_PROXY_HOPS", 1)
	if err != nil {
		return Config{}, err
	}
	if cfg.TrustProxyHops < 1 {
		return Config{}, fmt.Errorf("TRUST_PROXY_HOPS must be at least 1")
	}
	cfg.TLSCertFile = os.Getenv("TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("TLS_KEY_FILE")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	cfg.AllowedHosts = parseHostList(os.Getenv("ALLOWED_HOSTS"))
	cfg.MetricsToken = os.Getenv("METRICS_TOKEN")
	cfg.BuildVersion = envOr("BUILD_VERSION", cfg.BuildVersion)
	if v := os.Getenv("SESSION_SECRET"); v != "" {
		secret, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || len(secret) < 32 {
			return Config{}, fmt.Errorf("SESSION_SECRET must be base64url of at least 32 random bytes")
		}
		if err := validateSessionSecret(secret); err != nil {
			return Config{}, err
		}
		cfg.SessionSecret = secret
	}

	if cfg.MinTTL, err = envDurationSeconds("MIN_TTL_SECONDS", cfg.MinTTL); err != nil {
		return Config{}, err
	}
	if cfg.MaxTTL, err = envDurationSeconds("MAX_TTL_SECONDS", cfg.MaxTTL); err != nil {
		return Config{}, err
	}
	if cfg.DefaultTTL, err = envDurationSeconds("DEFAULT_TTL_SECONDS", cfg.DefaultTTL); err != nil {
		return Config{}, err
	}
	if cfg.ReceiptGrace, err = envDurationHours("RECEIPT_GRACE_HOURS", cfg.ReceiptGrace); err != nil {
		return Config{}, err
	}
	if cfg.MaxSecrets, err = envInt("MAX_SECRETS", cfg.MaxSecrets); err != nil {
		return Config{}, err
	}
	if cfg.MaxReceipts, err = envInt("MAX_RECEIPTS", cfg.MaxReceipts); err != nil {
		return Config{}, err
	}
	if cfg.MaxTotalBytes, err = envInt64MB("MAX_TOTAL_MB", cfg.MaxTotalBytes); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBytes, err = envInt64KB("MAX_BODY_KB", cfg.MaxBodyBytes); err != nil {
		return Config{}, err
	}
	if cfg.MaxSecretBytes, err = envInt("MAX_SECRET_BYTES", cfg.MaxSecretBytes); err != nil {
		return Config{}, err
	}

	if cfg.RateCreatePerMin, err = envInt("RATE_CREATE_PER_MIN", cfg.RateCreatePerMin); err != nil {
		return Config{}, err
	}
	if cfg.RateChallengePerMin, err = envInt("RATE_CHALLENGE_PER_MIN", cfg.RateChallengePerMin); err != nil {
		return Config{}, err
	}
	if cfg.RateOpenPerMin, err = envInt("RATE_OPEN_PER_MIN", cfg.RateOpenPerMin); err != nil {
		return Config{}, err
	}
	if cfg.RateReceiptPerMin, err = envInt("RATE_RECEIPT_PER_MIN", cfg.RateReceiptPerMin); err != nil {
		return Config{}, err
	}

	if cfg.MinTTL < time.Second || cfg.MaxTTL < cfg.MinTTL {
		return Config{}, fmt.Errorf("invalid TTL bounds")
	}
	if cfg.DefaultTTL < cfg.MinTTL || cfg.DefaultTTL > cfg.MaxTTL {
		return Config{}, fmt.Errorf("DEFAULT_TTL_SECONDS outside TTL bounds")
	}
	if cfg.MaxSecrets < 1 || cfg.MaxReceipts < 1 || cfg.MaxTotalBytes < 1024 || cfg.MaxBodyBytes < 1024 || cfg.MaxSecretBytes < 1024 {
		return Config{}, fmt.Errorf("invalid capacity limits")
	}
	if cfg.RateCreatePerMin < 1 || cfg.RateChallengePerMin < 1 || cfg.RateOpenPerMin < 1 || cfg.RateReceiptPerMin < 1 {
		return Config{}, fmt.Errorf("rate limits must be positive")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return b, nil
}

func envInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return n, nil
}

func envDurationSeconds(key string, fallback time.Duration) (time.Duration, error) {
	n, err := envInt(key, int(fallback/time.Second))
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

func envDurationHours(key string, fallback time.Duration) (time.Duration, error) {
	n, err := envInt(key, int(fallback/time.Hour))
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Hour, nil
}

func envInt64MB(key string, fallback int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer in MiB", key)
	}
	return n << 20, nil
}

func envInt64KB(key string, fallback int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer in KiB", key)
	}
	return n << 10, nil
}

// parseHostList reads a comma-separated ALLOWED_HOSTS value. Entries are kept
// verbatim (case is folded at comparison time) and may include a port.
func parseHostList(value string) []string {
	var hosts []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		hosts = append(hosts, part)
	}
	return hosts
}

// defaultAllowedHosts keeps loopback deployments working without configuration
// while refusing arbitrary hostnames, which is what DNS rebinding needs.
func defaultAllowedHosts(addr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return hosts
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		return hosts
	}
	hosts = append(hosts, host)
	return hosts
}

// weakSessionSecrets rejects values that have appeared in documentation, test
// fixtures, or generated deployment examples. A leaked session secret lets an
// attacker mint session cookies and challenge nonces.
var weakSessionSecrets = map[string]struct{}{
	"0123456789abcdef0123456789abcdef": {},
}

func validateSessionSecret(secret []byte) error {
	if len(secret) < 32 {
		return fmt.Errorf("SESSION_SECRET must be base64url of at least 32 random bytes")
	}
	if _, weak := weakSessionSecrets[string(secret)]; weak {
		return fmt.Errorf("SESSION_SECRET is a known placeholder; generate one with openssl rand -base64 32 | tr '+/' '-_' | tr -d '='")
	}
	if isAllSameBytes(secret) {
		return fmt.Errorf("SESSION_SECRET has no entropy; generate one with openssl rand -base64 32 | tr '+/' '-_' | tr -d '='")
	}
	return nil
}

func isAllSameBytes(data []byte) bool {
	for i := 1; i < len(data); i++ {
		if data[i] != data[0] {
			return false
		}
	}
	return len(data) > 0
}
