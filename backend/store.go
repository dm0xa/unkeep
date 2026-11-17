package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"runtime"
	"sync"
	"time"
)

var (
	ErrStoreFull        = errors.New("store full")
	ErrUnavailable      = errors.New("secret unavailable")
	ErrProofMismatch    = errors.New("key proof mismatch")
	ErrStoreUnavailable = errors.New("store unavailable")
	ErrInternal         = errors.New("internal store error")
)

const (
	eventCreated          = "created"
	eventLinkOpened       = "link_opened"
	eventDecryptAttempted = "decrypt_attempted"
	eventDecrypted        = "decrypted"
	eventBurned           = "burned"
	eventExpired          = "expired"
	eventRevoked          = "revoked"

	stateAvailable = "available"
	stateBurned    = "burned"
	stateExpired   = "expired"
	stateRevoked   = "revoked"

	maxReceiptEvents = 64

	// Fixed per-secret overhead: base64url of a 16-byte ID plus the proof hash.
	secretIDBytes  = 22
	proofHashBytes = 32
)

type Envelope struct {
	V          int    `json:"v"`
	Alg        string `json:"alg"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	MaxViews   int    `json:"maxViews"`
}

type storedSecret struct {
	id         string
	iv         []byte
	ciphertext []byte
	tag        []byte
	proofHash  [32]byte
	createdAt  time.Time
	expiresAt  time.Time
	maxViews   int
}

func (s *storedSecret) byteSize() int64 {
	return int64(len(s.id) + len(s.iv) + len(s.ciphertext) + len(s.tag) + len(s.proofHash))
}

type ReceiptEvent struct {
	Type string `json:"type"`
	At   int64  `json:"at"`
}

type receiptRecord struct {
	secretID         string
	tokenHash        [32]byte
	viewTokenHash    [32]byte
	viewTokenSet     bool
	decrypted        bool
	state            string
	createdAt        time.Time
	expiresAt        time.Time
	receiptExpiresAt time.Time
	burnedAt         time.Time
	revokedAt        time.Time
	opens            int
	lastOpenedAt     time.Time
	events           []ReceiptEvent
}

type StoreConfig struct {
	MaxSecrets    int
	MaxReceipts   int
	MaxTotalBytes int64
	ReceiptGrace  time.Duration
	Now           func() time.Time
	Rand          io.Reader
}

type Store struct {
	mu            sync.Mutex
	cfg           StoreConfig
	records       map[string]*storedSecret
	receipts      map[string]*receiptRecord
	terminalQueue []string
	totalBytes    int64
	lastSweep     time.Time
	counters      storeCounters
}

type storeCounters struct {
	creates   int64
	opens     int64
	burns     int64
	revokes   int64
	expiries  int64
	evictions int64
}

// StoreStats is a consistent snapshot used by readiness checks and /metrics.
type StoreStats struct {
	Secrets    int
	Receipts   int
	TotalBytes int64
	Creates    int64
	Opens      int64
	Burns      int64
	Revokes    int64
	Expiries   int64
	Evictions  int64
}

type CreateResult struct {
	SecretID         string
	ReceiptToken     string
	ExpiresAt        int64
	ReceiptExpiresAt int64
	MaxViews         int
}

type ChallengeInfo struct {
	SecretID  string
	ExpiresAt int64
	MaxViews  int
}

type ConsumeResult struct {
	Envelope  Envelope
	ViewToken string
	BurnedAt  int64
}

type ReceiptView struct {
	SecretID         string         `json:"secretId"`
	State            string         `json:"state"`
	CreatedAt        int64          `json:"createdAt"`
	ExpiresAt        int64          `json:"expiresAt"`
	ReceiptExpiresAt int64          `json:"receiptExpiresAt"`
	BurnedAt         int64          `json:"burnedAt,omitempty"`
	RevokedAt        int64          `json:"revokedAt,omitempty"`
	Opens            int            `json:"opens"`
	LastOpenedAt     int64          `json:"lastOpenedAt,omitempty"`
	Decrypted        bool           `json:"decrypted"`
	Events           []ReceiptEvent `json:"events"`
}

type RevokeResult struct {
	State     string
	RevokedAt int64
}

func NewStore(cfg StoreConfig) *Store {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.MaxSecrets < 1 {
		cfg.MaxSecrets = 10_000
	}
	if cfg.MaxReceipts < 1 {
		cfg.MaxReceipts = 50_000
	}
	if cfg.MaxTotalBytes < 1 {
		cfg.MaxTotalBytes = 64 << 20
	}
	if cfg.ReceiptGrace <= 0 {
		cfg.ReceiptGrace = 24 * time.Hour
	}
	return &Store{
		cfg:      cfg,
		records:  make(map[string]*storedSecret),
		receipts: make(map[string]*receiptRecord),
	}
}

// Create takes ownership of env's byte slices: they are wiped when the record
// is burned, so the caller must not share them with another record.
func (s *Store) Create(env validatedEnvelope, ttl time.Duration, proofHash [32]byte) (CreateResult, error) {
	// Identifier material is generated before the lock: crypto/rand reads must
	// not stall every other store operation behind the mutex.
	id, err := s.newToken(16)
	if err != nil {
		return CreateResult{}, ErrInternal
	}
	receiptToken, err := s.newToken(32)
	if err != nil {
		return CreateResult{}, ErrInternal
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	// A full map scan on every create would serialise the store behind
	// O(MaxSecrets) work. The background sweeper already expires records; only
	// refresh the count when the previous scan is older than a second.
	if now.Sub(s.lastSweep) >= time.Second {
		s.sweepRecordsLocked(now)
	}

	if len(s.records) >= s.cfg.MaxSecrets {
		return CreateResult{}, ErrStoreFull
	}
	if len(s.receipts) >= s.cfg.MaxReceipts {
		s.evictTerminalReceiptsLocked()
	}
	if len(s.receipts) >= s.cfg.MaxReceipts {
		return CreateResult{}, ErrStoreFull
	}
	size := int64(len(env.IV) + len(env.Ciphertext) + len(env.Tag) + proofHashBytes + secretIDBytes)
	if s.totalBytes+size > s.cfg.MaxTotalBytes {
		return CreateResult{}, ErrStoreFull
	}

	// A pre-generated ID collides only on a broken RNG; retry a few times before
	// giving up rather than paying for a crypto/rand read on the common path.
	for s.records[id] != nil {
		next, genErr := s.newToken(16)
		if genErr != nil {
			return CreateResult{}, ErrInternal
		}
		id = next
	}

	expiresAt := now.Add(ttl)
	record := &storedSecret{
		id:         id,
		iv:         env.IV,
		ciphertext: env.Ciphertext,
		tag:        env.Tag,
		proofHash:  proofHash,
		createdAt:  now,
		expiresAt:  expiresAt,
		maxViews:   1,
	}
	receipt := &receiptRecord{
		secretID:         id,
		tokenHash:        sha256.Sum256([]byte(receiptToken)),
		state:            stateAvailable,
		createdAt:        now,
		expiresAt:        expiresAt,
		receiptExpiresAt: expiresAt.Add(s.cfg.ReceiptGrace),
	}
	s.appendEventLocked(receipt, eventCreated, now)
	s.records[id] = record
	s.receipts[id] = receipt
	s.totalBytes += size
	s.counters.creates++

	return CreateResult{
		SecretID:         id,
		ReceiptToken:     receiptToken,
		ExpiresAt:        expiresAt.UnixMilli(),
		ReceiptExpiresAt: receipt.receiptExpiresAt.UnixMilli(),
		MaxViews:         1,
	}, nil
}

func (s *Store) Challenge(id string) (ChallengeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	s.expireIfNeededLocked(id, now)
	record, ok := s.records[id]
	if !ok {
		return ChallengeInfo{}, nil
	}
	if receipt := s.receipts[id]; receipt != nil && receipt.state == stateAvailable {
		receipt.opens++
		receipt.lastOpenedAt = now
		s.counters.opens++
		// The receipt is a proof log, not a refresh counter. Record the first
		// open as an event and keep later opens as a count.
		if receipt.opens == 1 {
			s.appendEventLocked(receipt, eventLinkOpened, now)
		}
	}
	return ChallengeInfo{
		SecretID:  id,
		ExpiresAt: record.expiresAt.UnixMilli(),
		MaxViews:  record.maxViews,
	}, nil
}

func (s *Store) Consume(id string, proofHash [32]byte) (ConsumeResult, error) {
	// Generated before the lock so every other store operation is not queued
	// behind a crypto/rand read.
	viewToken, err := s.newToken(32)
	if err != nil {
		return ConsumeResult{}, ErrInternal
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	s.expireIfNeededLocked(id, now)
	record, ok := s.records[id]
	if !ok {
		return ConsumeResult{}, ErrUnavailable
	}
	if !hashesEqual(record.proofHash, proofHash) {
		return ConsumeResult{}, ErrProofMismatch
	}

	envelope := Envelope{
		V:          1,
		Alg:        "A256GCM",
		IV:         base64.RawURLEncoding.EncodeToString(record.iv),
		Ciphertext: base64.RawURLEncoding.EncodeToString(record.ciphertext),
		Tag:        base64.RawURLEncoding.EncodeToString(record.tag),
		CreatedAt:  record.createdAt.UnixMilli(),
		ExpiresAt:  record.expiresAt.UnixMilli(),
		MaxViews:   record.maxViews,
	}
	burnedAt := now.UnixMilli()

	s.removeSecretLocked(record)
	s.counters.burns++
	receipt := s.receipts[id]
	if receipt != nil {
		s.appendEventLocked(receipt, eventDecryptAttempted, now)
		s.appendEventLocked(receipt, eventBurned, now)
		receipt.state = stateBurned
		receipt.burnedAt = now
		receipt.viewTokenHash = sha256.Sum256([]byte(viewToken))
		receipt.viewTokenSet = true
		s.queueTerminalLocked(receipt.secretID)
		if receipt.receiptExpiresAt.Before(now.Add(s.cfg.ReceiptGrace)) {
			receipt.receiptExpiresAt = now.Add(s.cfg.ReceiptGrace)
		}
	}

	return ConsumeResult{
		Envelope:  envelope,
		ViewToken: viewToken,
		BurnedAt:  burnedAt,
	}, nil
}

// Revoke removes an unread secret after the sender proves receipt ownership.
// It is idempotent: a burned, expired, or already revoked receipt reports its
// terminal state without emitting a second event.
func (s *Store) Revoke(id, receiptToken string) (RevokeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	s.expireIfNeededLocked(id, now)
	receipt, ok := s.receipts[id]
	if !ok || now.After(receipt.receiptExpiresAt) {
		return RevokeResult{}, nil
	}
	if !hashesEqual(receipt.tokenHash, tokenHash(receiptToken)) {
		return RevokeResult{}, nil
	}

	if record, exists := s.records[id]; exists && receipt.state == stateAvailable {
		s.removeSecretLocked(record)
		receipt.state = stateRevoked
		receipt.revokedAt = now
		s.appendEventLocked(receipt, eventRevoked, now)
		s.counters.revokes++
		s.queueTerminalLocked(id)
		if receipt.receiptExpiresAt.Before(now.Add(s.cfg.ReceiptGrace)) {
			receipt.receiptExpiresAt = now.Add(s.cfg.ReceiptGrace)
		}
	}

	result := RevokeResult{State: receipt.state}
	if !receipt.revokedAt.IsZero() {
		result.RevokedAt = receipt.revokedAt.UnixMilli()
	}
	return result, nil
}

func (s *Store) ConfirmDecrypted(id, viewToken string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	receipt, ok := s.receipts[id]
	if !ok || now.After(receipt.receiptExpiresAt) {
		return false, nil
	}
	if !receipt.viewTokenSet || !hashesEqual(receipt.viewTokenHash, sha256.Sum256([]byte(viewToken))) {
		return false, nil
	}
	if !receipt.decrypted {
		receipt.decrypted = true
		s.appendEventLocked(receipt, eventDecrypted, now)
	}
	return true, nil
}

func (s *Store) Receipt(id, receiptToken string) (ReceiptView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	s.expireIfNeededLocked(id, now)
	receipt, ok := s.receipts[id]
	if !ok {
		return ReceiptView{}, nil
	}
	if now.After(receipt.receiptExpiresAt) {
		s.removeReceiptLocked(receipt)
		return ReceiptView{}, nil
	}
	if !hashesEqual(receipt.tokenHash, sha256.Sum256([]byte(receiptToken))) {
		return ReceiptView{}, nil
	}

	events := make([]ReceiptEvent, len(receipt.events))
	copy(events, receipt.events)
	var burnedAt, revokedAt, lastOpenedAt int64
	if !receipt.burnedAt.IsZero() {
		burnedAt = receipt.burnedAt.UnixMilli()
	}
	if !receipt.revokedAt.IsZero() {
		revokedAt = receipt.revokedAt.UnixMilli()
	}
	if !receipt.lastOpenedAt.IsZero() {
		lastOpenedAt = receipt.lastOpenedAt.UnixMilli()
	}
	return ReceiptView{
		SecretID:         receipt.secretID,
		State:            receipt.state,
		CreatedAt:        receipt.createdAt.UnixMilli(),
		ExpiresAt:        receipt.expiresAt.UnixMilli(),
		ReceiptExpiresAt: receipt.receiptExpiresAt.UnixMilli(),
		BurnedAt:         burnedAt,
		RevokedAt:        revokedAt,
		Opens:            receipt.opens,
		LastOpenedAt:     lastOpenedAt,
		Decrypted:        receipt.decrypted,
		Events:           events,
	}, nil
}

func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.cfg.Now()
	s.sweepRecordsLocked(now)
	for _, receipt := range s.receipts {
		if !now.Before(receipt.receiptExpiresAt) {
			s.removeReceiptLocked(receipt)
		}
	}
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range s.records {
		s.removeSecretLocked(record)
	}
	for _, receipt := range s.receipts {
		s.removeReceiptLocked(receipt)
	}
}

func (s *Store) Stats() StoreStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return StoreStats{
		Secrets:    len(s.records),
		Receipts:   len(s.receipts),
		TotalBytes: s.totalBytes,
		Creates:    s.counters.creates,
		Opens:      s.counters.opens,
		Burns:      s.counters.burns,
		Revokes:    s.counters.revokes,
		Expiries:   s.counters.expiries,
		Evictions:  s.counters.evictions,
	}
}

// Ready reports whether a create can be accepted without evicting a live
// secret or receipt. It is deliberately conservative: a full receipt map may
// still admit a create after terminal eviction, but readiness should not
// advertise capacity the next request might not get.
func (s *Store) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records) < s.cfg.MaxSecrets &&
		len(s.receipts) < s.cfg.MaxReceipts &&
		s.totalBytes < s.cfg.MaxTotalBytes
}

func (s *Store) sweepRecordsLocked(now time.Time) {
	s.lastSweep = now
	for id := range s.records {
		s.expireIfNeededLocked(id, now)
	}
}

func (s *Store) expireIfNeededLocked(id string, now time.Time) {
	record, ok := s.records[id]
	if !ok || now.Before(record.expiresAt) {
		return
	}
	s.removeSecretLocked(record)
	if receipt := s.receipts[id]; receipt != nil {
		if receipt.state == stateAvailable {
			receipt.state = stateExpired
			s.appendEventLocked(receipt, eventExpired, now)
			s.counters.expiries++
			s.queueTerminalLocked(receipt.secretID)
		}
		if receipt.receiptExpiresAt.Before(now.Add(s.cfg.ReceiptGrace)) {
			receipt.receiptExpiresAt = now.Add(s.cfg.ReceiptGrace)
		}
	}
}

func (s *Store) removeSecretLocked(record *storedSecret) {
	delete(s.records, record.id)
	s.totalBytes -= record.byteSize()
	if s.totalBytes < 0 {
		s.totalBytes = 0
	}
	wipe(record.iv)
	wipe(record.ciphertext)
	wipe(record.tag)
	wipe(record.proofHash[:])
}

func (s *Store) removeReceiptLocked(receipt *receiptRecord) {
	delete(s.receipts, receipt.secretID)
	wipe(receipt.tokenHash[:])
	wipe(receipt.viewTokenHash[:])
	for i := range receipt.events {
		receipt.events[i] = ReceiptEvent{}
	}
	receipt.events = nil
}

func (s *Store) queueTerminalLocked(secretID string) {
	s.terminalQueue = append(s.terminalQueue, secretID)
	if len(s.terminalQueue) > s.cfg.MaxReceipts*2 {
		live := s.terminalQueue[:0]
		for _, id := range s.terminalQueue {
			if receipt, ok := s.receipts[id]; ok && receipt.state != stateAvailable {
				live = append(live, id)
			}
		}
		s.terminalQueue = live
	}
}

// evictTerminalReceiptsLocked keeps the receipt map bounded under sustained
// load. Live receipts are never evicted; terminal receipts are dropped in
// creation order from a FIFO queue, so reaching the cap costs O(1) amortized
// per eviction rather than sorting the whole map under the store lock.
func (s *Store) evictTerminalReceiptsLocked() {
	target := s.cfg.MaxReceipts * 9 / 10
	if target < 1 {
		target = 1
	}
	if len(s.receipts) <= target {
		return
	}
	need := len(s.receipts) - target
	for need > 0 && len(s.terminalQueue) > 0 {
		id := s.terminalQueue[0]
		s.terminalQueue = s.terminalQueue[1:]
		receipt, ok := s.receipts[id]
		if !ok || receipt.state == stateAvailable {
			continue
		}
		s.removeReceiptLocked(receipt)
		s.counters.evictions++
		need--
	}
	if need > 0 {
		for _, receipt := range s.receipts {
			if need <= 0 {
				break
			}
			if receipt.state != stateAvailable {
				s.removeReceiptLocked(receipt)
				s.counters.evictions++
				need--
			}
		}
	}
}

func (s *Store) appendEventLocked(receipt *receiptRecord, eventType string, at time.Time) {
	if len(receipt.events) >= maxReceiptEvents {
		receipt.events = append(receipt.events[:1], receipt.events[2:]...)
	}
	receipt.events = append(receipt.events, ReceiptEvent{Type: eventType, At: at.UnixMilli()})
}

// newToken is lock-free: it only touches cfg.Rand, so callers may use it before
// taking s.mu.
func (s *Store) newToken(rawLen int) (string, error) {
	buf := make([]byte, rawLen)
	if _, err := io.ReadFull(s.cfg.Rand, buf); err != nil {
		wipe(buf)
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	wipe(buf)
	return token, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
