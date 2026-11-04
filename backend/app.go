package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"unkeep/frontend"
)

type asset struct {
	data        []byte
	contentType string
	etag        string
}

type Server struct {
	cfg     Config
	session *sessionCodec
	nonces  *NonceService
	limiter *RateLimiter
	store   SecretStore
	metrics *Metrics
	logger  Logger

	index  []byte
	assets map[string]asset
	mux    http.Handler

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewServer(cfg Config) (*Server, error) {
	cfg = normalizeConfig(cfg)

	staticFS := cfg.StaticFS
	if staticFS == nil {
		sub, err := fs.Sub(frontend.Dist, "dist")
		if err != nil {
			return nil, fmt.Errorf("frontend assets: %w", err)
		}
		staticFS = sub
	}
	index, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		return nil, fmt.Errorf("frontend index: %w", err)
	}
	appJS, err := fs.ReadFile(staticFS, "app.js")
	if err != nil {
		return nil, fmt.Errorf("frontend app.js: %w", err)
	}
	styles, err := fs.ReadFile(staticFS, "styles.css")
	if err != nil {
		return nil, fmt.Errorf("frontend styles.css: %w", err)
	}
	assets := map[string]asset{
		"/app.js":     {data: appJS, contentType: "text/javascript; charset=utf-8", etag: assetETag(appJS)},
		"/styles.css": {data: styles, contentType: "text/css; charset=utf-8", etag: assetETag(styles)},
	}
	if favicon, err := fs.ReadFile(staticFS, "favicon.svg"); err == nil {
		assets["/favicon.svg"] = asset{data: favicon, contentType: "image/svg+xml", etag: assetETag(favicon)}
	}
	// Fonts and licences live under assets/. Walk them at startup so adding a
	// file to the bundle does not require a new route.
	if err := fs.WalkDir(staticFS, "assets", func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, readErr := fs.ReadFile(staticFS, filePath)
		if readErr != nil {
			return readErr
		}
		contentType := mime.TypeByExtension(path.Ext(filePath))
		switch path.Ext(filePath) {
		case ".woff2":
			contentType = "font/woff2"
		case ".txt":
			contentType = "text/plain; charset=utf-8"
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		assets["/"+filePath] = asset{data: data, contentType: contentType, etag: assetETag(data)}
		return nil
	}); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("frontend assets: %w", err)
	}

	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = defaultAllowedHosts(cfg.Addr)
	}
	if cfg.SessionSecret == nil {
		cfg.SessionSecret = make([]byte, 32)
		if _, err := rand.Read(cfg.SessionSecret); err != nil {
			return nil, fmt.Errorf("session secret: %w", err)
		}
	} else {
		cfg.SessionSecret = append([]byte(nil), cfg.SessionSecret...)
	}
	if err := validateSessionSecret(cfg.SessionSecret); err != nil {
		return nil, fmt.Errorf("session secret: %w", err)
	}

	s := &Server{
		cfg:     cfg,
		session: newSessionCodec(cfg.SessionSecret),
		limiter: NewRateLimiter(cfg.Now, 100_000),
		metrics: &Metrics{},
		logger:  cfg.Logger,
		index:   index,
		assets:  assets,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	s.nonces = NewNonceService(deriveKey(cfg.SessionSecret, "nonce"), cfg.Now)
	storeCfg := StoreConfig{
		MaxSecrets:    cfg.MaxSecrets,
		MaxReceipts:   cfg.MaxReceipts,
		MaxTotalBytes: cfg.MaxTotalBytes,
		ReceiptGrace:  cfg.ReceiptGrace,
		Now:           cfg.Now,
		Rand:          cfg.Rand,
	}
	if cfg.ValkeyURL != "" {
		valkeyStore, err := NewValkeyStore(cfg.ValkeyURL, cfg.ValkeyPrefix, storeCfg)
		if err != nil {
			return nil, fmt.Errorf("valkey store: %w", err)
		}
		s.store = valkeyStore
	} else {
		s.store = NewStore(storeCfg)
	}
	s.mux = s.buildMux()
	s.startSweeper()
	return s, nil
}

func normalizeConfig(cfg Config) Config {
	def := defaultConfig()
	if cfg.MinTTL == 0 {
		cfg.MinTTL = def.MinTTL
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = def.MaxTTL
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = def.DefaultTTL
	}
	if cfg.ReceiptGrace == 0 {
		cfg.ReceiptGrace = def.ReceiptGrace
	}
	if cfg.ValkeyPrefix == "" {
		cfg.ValkeyPrefix = def.ValkeyPrefix
	}
	if cfg.MaxSecrets == 0 {
		cfg.MaxSecrets = def.MaxSecrets
	}
	if cfg.MaxReceipts == 0 {
		cfg.MaxReceipts = def.MaxReceipts
	}
	if cfg.MaxTotalBytes == 0 {
		cfg.MaxTotalBytes = def.MaxTotalBytes
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = def.MaxBodyBytes
	}
	if cfg.MaxSecretBytes == 0 {
		cfg.MaxSecretBytes = def.MaxSecretBytes
	}
	if cfg.RateCreatePerMin == 0 {
		cfg.RateCreatePerMin = def.RateCreatePerMin
	}
	if cfg.RateChallengePerMin == 0 {
		cfg.RateChallengePerMin = def.RateChallengePerMin
	}
	if cfg.RateOpenPerMin == 0 {
		cfg.RateOpenPerMin = def.RateOpenPerMin
	}
	if cfg.RateReceiptPerMin == 0 {
		cfg.RateReceiptPerMin = def.RateReceiptPerMin
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = NewJSONLogger(io.Discard)
	}
	if cfg.BuildVersion == "" {
		cfg.BuildVersion = "dev"
	}
	return cfg
}

func deriveKey(secret []byte, label string) []byte {
	return hmacKey(secret, "derive", label)
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.observe(s.mux))
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
		s.store.Close()
	})
}

func (s *Server) startSweeper() {
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.store.Sweep()
			case <-s.stop:
				return
			}
		}
	}()
}

func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /s/{id}", s.handleIndex)
	mux.HandleFunc("GET /receipt/{id}", s.handleIndex)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /robots.txt", s.handleRobots)
	for assetPath := range s.assets {
		mux.HandleFunc("GET "+assetPath, s.handleAsset(assetPath))
	}

	mux.HandleFunc("POST /api/secrets", s.handleCreate)
	mux.HandleFunc("GET /api/secrets/{id}", s.handleChallenge)
	mux.HandleFunc("POST /api/secrets/{id}/open", s.handleOpen)
	mux.HandleFunc("POST /api/secrets/{id}/decrypted", s.handleDecrypted)
	mux.HandleFunc("POST /api/secrets/{id}/receipt", s.handleReceipt)
	mux.HandleFunc("POST /api/secrets/{id}/revoke", s.handleRevoke)

	mux.HandleFunc("/api/secrets", s.methodNotAllowed("POST"))
	mux.HandleFunc("/api/secrets/{id}", s.methodNotAllowed("GET"))
	mux.HandleFunc("/api/secrets/{id}/open", s.methodNotAllowed("POST"))
	mux.HandleFunc("/api/secrets/{id}/decrypted", s.methodNotAllowed("POST"))
	mux.HandleFunc("/api/secrets/{id}/receipt", s.methodNotAllowed("POST"))
	mux.HandleFunc("/api/secrets/{id}/revoke", s.methodNotAllowed("POST"))
	mux.HandleFunc("/api/", s.handleAPINotFound)
	mux.HandleFunc("/", s.handleNotFound)

	return mux
}

// confirmHeader is a frozen wire label. The product is unkeep, but existing
// pages and clients still send the original header; renaming it would break
// them mid-flight.
const confirmHeader = "X-Not-Saved-Confirm"

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) {
		s.writeError(w, http.StatusForbidden, "forbidden", "Request origin is not allowed.")
		return
	}
	if !s.allow(w, r, "create", s.cfg.RateCreatePerMin) {
		return
	}
	var req createRequest
	if err := decodeJSON(w, r, &req, s.cfg.MaxBodyBytes); err != nil {
		s.writeRequestError(w, err)
		return
	}
	ttl, reqErr := validateTTL(req.TTLSeconds, s.cfg)
	if reqErr != nil {
		s.writeRequestError(w, reqErr)
		return
	}
	envelope, reqErr := validateEnvelope(req.Envelope, s.cfg.MaxSecretBytes)
	if reqErr != nil {
		s.writeRequestError(w, reqErr)
		return
	}
	if !validateToken(req.Proof, 32) {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "A key proof is required.")
		return
	}

	result, err := s.store.Create(envelope, ttl, tokenHash(req.Proof))
	if err != nil {
		if errors.Is(err, ErrStoreFull) {
			s.metrics.noteStoreFull()
			s.writeError(w, http.StatusServiceUnavailable, "busy", "The service is at capacity. Try again shortly.")
			return
		}
		if errors.Is(err, ErrStoreUnavailable) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The secret could not be stored.")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"secretId":         result.SecretID,
		"expiresAt":        result.ExpiresAt,
		"receiptToken":     result.ReceiptToken,
		"receiptExpiresAt": result.ReceiptExpiresAt,
		"maxViews":         result.MaxViews,
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) {
		s.writeError(w, http.StatusForbidden, "forbidden", "Request origin is not allowed.")
		return
	}
	if !s.allow(w, r, "challenge", s.cfg.RateChallengePerMin) {
		return
	}
	id := r.PathValue("id")
	if !validateSecretID(id) {
		s.writeUnavailable(w)
		return
	}
	info, err := s.store.Challenge(id)
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The secret could not be loaded.")
		return
	}
	if info.SecretID == "" {
		s.writeUnavailable(w)
		return
	}

	sessionID, ok := s.session.fromRequest(r)
	if !ok {
		sessionID = s.session.newSession()
	}
	s.session.setCookie(w, r, s.cfg.TrustProxy, sessionID)
	challenge, challengeExpiresAt := s.nonces.Issue(id, sessionID)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"secretId":           info.SecretID,
		"expiresAt":          info.ExpiresAt,
		"maxViews":           info.MaxViews,
		"challenge":          challenge,
		"challengeExpiresAt": challengeExpiresAt,
	})
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) || r.Header.Get(confirmHeader) != "reveal" {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation is required.")
		return
	}
	if !s.allow(w, r, "open", s.cfg.RateOpenPerMin) {
		return
	}
	var req openRequest
	if err := decodeJSON(w, r, &req, s.cfg.MaxBodyBytes); err != nil {
		s.writeRequestError(w, err)
		return
	}
	id := r.PathValue("id")
	if !validateSecretID(id) || req.Confirmation != "reveal" || req.Challenge == "" {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation expired. Reload and try again.")
		return
	}
	sessionID, ok := s.session.fromRequest(r)
	if !ok {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation expired. Reload and try again.")
		return
	}
	if !s.nonces.Verify(req.Challenge, id, sessionID) {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation expired. Reload and try again.")
		return
	}
	proof := r.Header.Get("X-Secret-Proof")
	if !validateToken(proof, 32) {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "This link cannot open the secret.")
		return
	}

	result, err := s.store.Consume(id, tokenHash(proof))
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			s.writeUnavailable(w)
			return
		}
		if errors.Is(err, ErrProofMismatch) {
			s.writeError(w, http.StatusForbidden, "invalid_confirmation", "This link cannot open the secret.")
			return
		}
		if errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrStoreFull) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The secret could not be opened.")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"envelope":  result.Envelope,
		"viewToken": result.ViewToken,
		"burnedAt":  result.BurnedAt,
	})
}

func (s *Server) handleDecrypted(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) || r.Header.Get(confirmHeader) != "reveal" {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation is required.")
		return
	}
	if !s.allow(w, r, "decrypted", s.cfg.RateOpenPerMin) {
		return
	}
	var req decryptedRequest
	if err := decodeJSON(w, r, &req, s.cfg.MaxBodyBytes); err != nil {
		s.writeRequestError(w, err)
		return
	}
	id := r.PathValue("id")
	if !validateSecretID(id) || !validateToken(req.ViewToken, 32) {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	ok, err := s.store.ConfirmDecrypted(id, req.ViewToken)
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The receipt could not be updated.")
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleReceipt(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) {
		s.writeError(w, http.StatusForbidden, "forbidden", "Request origin is not allowed.")
		return
	}
	if !s.allow(w, r, "receipt", s.cfg.RateReceiptPerMin) {
		return
	}
	id := r.PathValue("id")
	token := r.Header.Get("X-Receipt-Token")
	if !validateSecretID(id) || !validateToken(token, 32) {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	view, err := s.store.Receipt(id, token)
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The receipt could not be loaded.")
		return
	}
	if view.SecretID == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	s.writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r, s.cfg.AllowedHosts) || r.Header.Get(confirmHeader) != "revoke" {
		s.writeError(w, http.StatusForbidden, "invalid_confirmation", "Confirmation is required.")
		return
	}
	if !s.allow(w, r, "revoke", s.cfg.RateReceiptPerMin) {
		return
	}
	id := r.PathValue("id")
	token := r.Header.Get("X-Receipt-Token")
	if !validateSecretID(id) || !validateToken(token, 32) {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	result, err := s.store.Revoke(id, token)
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) {
			s.writeError(w, http.StatusServiceUnavailable, "store_unavailable", "The service is temporarily unavailable.")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "internal", "The secret could not be revoked.")
		return
	}
	if result.State == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "Receipt not found.")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"state":     result.State,
		"revokedAt": result.RevokedAt,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.store.Ready() {
		s.writeError(w, http.StatusServiceUnavailable, "busy", "The service is at capacity.")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMetrics is disabled unless METRICS_TOKEN is set. A missing or wrong
// token gets the same 404 as an unknown route so the endpoint cannot be
// discovered by probing.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	failed := s.cfg.MetricsToken == "" || !strings.HasPrefix(r.Header.Get("Authorization"), prefix)
	if !failed {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), prefix)
		failed = !hashesEqual(tokenHash(provided), tokenHash(s.cfg.MetricsToken))
	}
	if failed {
		s.writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return
	}
	s.writeBytes(w, s.metrics.render(s.store.Stats(), s.cfg.BuildVersion), "text/plain; version=0.0.4; charset=utf-8")
}

func (s *Server) handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.writeBytes(w, s.index, "text/html; charset=utf-8")
}

func (s *Server) handleAsset(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.assets[path]
		if !ok {
			s.handleNotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("ETag", a.etag)
		if r.Header.Get("If-None-Match") == a.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.writeBytes(w, a.data, a.contentType)
	}
}

func assetETag(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (s *Server) handleAPINotFound(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotFound, "not_found", "Not found.")
}

func (s *Server) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<!doctype html><title>Not found</title><p>Not found. <a href=\"/\">Start over</a>.</p>")
}

func (s *Server) methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	}
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, scope string, perMinute int) bool {
	ip := clientIP(r, s.cfg.TrustProxy)
	bucket := scope + ":" + hex.EncodeToString(hmacKey(s.cfg.SessionSecret, "rate", ip))
	burst := perMinute / 6
	if burst < 3 {
		burst = 3
	}
	ok, wait := s.limiter.Allow(bucket, perMinute, burst)
	if ok {
		return true
	}
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	s.writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again shortly.")
	return false
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func (s *Server) writeRequestError(w http.ResponseWriter, err error) {
	var reqErr *requestError
	if errors.As(err, &reqErr) {
		s.writeError(w, reqErr.status, reqErr.code, reqErr.message)
		return
	}
	s.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request.")
}

func (s *Server) writeUnavailable(w http.ResponseWriter) {
	s.writeError(w, http.StatusGone, "unavailable", "This secret is no longer available.")
}

func (s *Server) writeBytes(w http.ResponseWriter, data []byte, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		errorClass := ""
		defer func() {
			if recovered := recover(); recovered != nil {
				errorClass = "panic"
				if !sw.wroteHeader {
					s.writeError(sw, http.StatusInternalServerError, "internal", "Internal server error.")
				}
			}
			if sw.status >= 500 && errorClass == "" {
				errorClass = "internal"
			}
			if sw.status == http.StatusTooManyRequests && errorClass == "" {
				errorClass = "rate_limited"
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			s.metrics.Record(sw.status, errorClass)
			s.logger.Log(LogEntry{
				Method:     r.Method,
				Route:      route,
				Status:     sw.status,
				DurationMS: float64(s.cfg.Now().Sub(start).Microseconds()) / 1000.0,
				ErrorClass: errorClass,
			})
		}()
		next.ServeHTTP(sw, r)
	})
}
