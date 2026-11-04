package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ValkeyStore keeps the same contract as the in-memory store but shares state
// across API replicas. The client speaks RESP; the server is Valkey.
//
// Capacity is enforced with two sorted-set indexes scored by expiry, plus the
// instance's used_memory for the byte ceiling. The indexes are pruned by the
// create script, so expired secrets and receipts never count against a limit.
// A single Valkey instance is assumed: the index keys are not hash-tagged for
// Cluster.
type ValkeyStore struct {
	client *redis.Client
	prefix string
	grace  time.Duration

	maxSecrets    int
	maxReceipts   int
	maxTotalBytes int64
	now           func() time.Time
	usedMemory    func(context.Context) (int64, error)

	readyMu    sync.Mutex
	readyAt    time.Time
	readyValue bool
}

func NewValkeyStore(url, prefix string, cfg StoreConfig) (*ValkeyStore, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse VALKEY_URL: %w", err)
	}
	opts.PoolSize = 64
	opts.MinIdleConns = 8
	opts.DialTimeout = 3 * time.Second
	opts.ReadTimeout = 2 * time.Second
	opts.WriteTimeout = 2 * time.Second
	opts.MaxRetries = 0

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("valkey ping: %w", err)
	}

	if prefix == "" {
		prefix = "ns:"
	}
	if !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
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
	s := &ValkeyStore{
		client:        client,
		prefix:        prefix,
		grace:         cfg.ReceiptGrace,
		maxSecrets:    cfg.MaxSecrets,
		maxReceipts:   cfg.MaxReceipts,
		maxTotalBytes: cfg.MaxTotalBytes,
		now:           cfg.Now,
	}
	s.usedMemory = s.infoUsedMemory
	return s, nil
}

func (s *ValkeyStore) Create(env validatedEnvelope, ttl time.Duration, proofHash [32]byte) (CreateResult, error) {
	now := s.now()
	expiresAt := now.Add(ttl)
	receiptExpiresAt := expiresAt.Add(s.grace)
	receiptToken, err := randomToken(32)
	if err != nil {
		return CreateResult{}, ErrInternal
	}

	ctx, cancel := s.opCtx()
	used, err := s.usedMemory(ctx)
	cancel()
	if err != nil {
		return CreateResult{}, mapValkeyError(err)
	}
	size := int64(len(env.IV) + len(env.Ciphertext) + len(env.Tag) + proofHashBytes + secretIDBytes)
	if used+size > s.maxTotalBytes {
		return CreateResult{}, ErrStoreFull
	}

	iv := base64.RawURLEncoding.EncodeToString(env.IV)
	ciphertext := base64.RawURLEncoding.EncodeToString(env.Ciphertext)
	tag := base64.RawURLEncoding.EncodeToString(env.Tag)
	proofHex := hex.EncodeToString(proofHash[:])
	tokenHash := tokenHashHex(receiptToken)
	createdEvent := eventJSON(eventCreated, now)
	secretTTL := ttlSeconds(ttl)
	receiptTTL := ttlSeconds(ttl + s.grace)

	for range 8 {
		id, err := randomToken(16)
		if err != nil {
			return CreateResult{}, ErrInternal
		}
		secretKey, receiptKey, eventsKey := s.keys(id)
		ctx, cancel := s.opCtx()
		created, err := createScript.Run(ctx, s.client,
			[]string{secretKey, receiptKey, eventsKey, s.secretIndex(), s.receiptIndex()},
			iv, ciphertext, tag, proofHex,
			now.UnixMilli(), expiresAt.UnixMilli(),
			secretTTL, tokenHash, receiptExpiresAt.UnixMilli(), receiptTTL, createdEvent,
			strconv.Itoa(s.maxSecrets), strconv.Itoa(s.maxReceipts), id,
		).Int()
		cancel()
		if err != nil {
			return CreateResult{}, mapValkeyError(err)
		}
		switch created {
		case 1:
			s.incrStats("creates")
			s.invalidateReady()
			return CreateResult{
				SecretID:         id,
				ReceiptToken:     receiptToken,
				ExpiresAt:        expiresAt.UnixMilli(),
				ReceiptExpiresAt: receiptExpiresAt.UnixMilli(),
				MaxViews:         1,
			}, nil
		case 0:
			continue // ID collision, try another
		case -2, -3:
			return CreateResult{}, ErrStoreFull
		default:
			return CreateResult{}, ErrInternal
		}
	}
	return CreateResult{}, ErrInternal
}

func (s *ValkeyStore) Challenge(id string) (ChallengeInfo, error) {
	now := s.now()
	secretKey, receiptKey, eventsKey := s.keys(id)
	ctx, cancel := s.opCtx()
	defer cancel()
	result, err := challengeScript.Run(ctx, s.client,
		[]string{secretKey, receiptKey, eventsKey, s.secretIndex(), s.receiptIndex()},
		now.UnixMilli(), eventJSON(eventExpired, now), eventJSON(eventLinkOpened, now),
		s.grace.Milliseconds(), id,
	).Slice()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ChallengeInfo{}, nil
		}
		return ChallengeInfo{}, mapValkeyError(err)
	}
	if int64At(result, 0) != 1 {
		if int64At(result, 3) == 1 {
			s.incrStats("expiries")
			s.invalidateReady()
		}
		return ChallengeInfo{}, nil
	}
	s.incrStats("opens")
	return ChallengeInfo{
		SecretID:  id,
		ExpiresAt: int64At(result, 1),
		MaxViews:  int(int64At(result, 2)),
	}, nil
}

func (s *ValkeyStore) Consume(id string, proofHash [32]byte) (ConsumeResult, error) {
	viewToken, err := randomToken(32)
	if err != nil {
		return ConsumeResult{}, ErrInternal
	}
	now := s.now()
	secretKey, receiptKey, eventsKey := s.keys(id)
	ctx, cancel := s.opCtx()
	defer cancel()
	result, err := consumeScript.Run(ctx, s.client,
		[]string{secretKey, receiptKey, eventsKey, s.secretIndex(), s.receiptIndex()},
		hex.EncodeToString(proofHash[:]),
		now.UnixMilli(),
		tokenHashHex(viewToken),
		eventJSON(eventDecryptAttempted, now),
		eventJSON(eventBurned, now),
		eventJSON(eventExpired, now),
		now.Add(s.grace).UnixMilli(),
		ttlSeconds(s.grace),
		id,
	).Slice()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ConsumeResult{}, ErrUnavailable
		}
		return ConsumeResult{}, mapValkeyError(err)
	}
	switch int64At(result, 0) {
	case -1:
		return ConsumeResult{}, ErrProofMismatch
	case 0:
		if int64At(result, 1) == 1 {
			s.incrStats("expiries")
			s.invalidateReady()
		}
		return ConsumeResult{}, ErrUnavailable
	case 1:
		s.invalidateReady()
		envelope := Envelope{
			V:          1,
			Alg:        "A256GCM",
			IV:         stringAt(result, 1),
			Ciphertext: stringAt(result, 2),
			Tag:        stringAt(result, 3),
			CreatedAt:  int64At(result, 4),
			ExpiresAt:  int64At(result, 5),
			MaxViews:   int(int64At(result, 6)),
		}
		s.incrStats("burns")
		return ConsumeResult{
			Envelope:  envelope,
			ViewToken: viewToken,
			BurnedAt:  now.UnixMilli(),
		}, nil
	default:
		return ConsumeResult{}, ErrInternal
	}
}

func (s *ValkeyStore) Revoke(id, receiptToken string) (RevokeResult, error) {
	now := s.now()
	secretKey, receiptKey, eventsKey := s.keys(id)
	ctx, cancel := s.opCtx()
	defer cancel()
	result, err := revokeScript.Run(ctx, s.client,
		[]string{secretKey, receiptKey, eventsKey, s.secretIndex(), s.receiptIndex()},
		tokenHashHex(receiptToken),
		now.UnixMilli(),
		eventJSON(eventRevoked, now),
		now.Add(s.grace).UnixMilli(),
		ttlSeconds(s.grace),
		eventJSON(eventExpired, now),
		id,
	).Slice()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return RevokeResult{}, nil
		}
		return RevokeResult{}, mapValkeyError(err)
	}
	if int64At(result, 0) != 1 {
		return RevokeResult{}, nil
	}
	state := stringAt(result, 1)
	changed := int64At(result, 3) == 1
	if changed {
		s.invalidateReady()
		if state == stateRevoked {
			s.incrStats("revokes")
		} else if state == stateExpired {
			s.incrStats("expiries")
		}
	}
	return RevokeResult{State: state, RevokedAt: int64At(result, 2)}, nil
}

func (s *ValkeyStore) ConfirmDecrypted(id, viewToken string) (bool, error) {
	now := s.now()
	_, receiptKey, eventsKey := s.keys(id)
	ctx, cancel := s.opCtx()
	defer cancel()
	ok, err := confirmDecryptedScript.Run(ctx, s.client, []string{receiptKey, eventsKey},
		tokenHashHex(viewToken), eventJSON(eventDecrypted, now),
	).Int()
	if err != nil {
		return false, mapValkeyError(err)
	}
	return ok == 1, nil
}

func (s *ValkeyStore) Receipt(id, receiptToken string) (ReceiptView, error) {
	now := s.now()
	secretKey, receiptKey, eventsKey := s.keys(id)
	ctx, cancel := s.opCtx()
	defer cancel()
	raw, err := receiptScript.Run(ctx, s.client,
		[]string{receiptKey, eventsKey, secretKey, s.secretIndex(), s.receiptIndex()},
		now.UnixMilli(), eventJSON(eventExpired, now),
		now.Add(s.grace).UnixMilli(), id,
	).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ReceiptView{}, nil
		}
		return ReceiptView{}, mapValkeyError(err)
	}
	outer, ok := raw.([]interface{})
	if !ok || len(outer) < 3 {
		return ReceiptView{}, ErrInternal
	}
	values, ok := outer[0].([]interface{})
	if !ok || len(values) < 11 {
		return ReceiptView{}, ErrInternal
	}
	if subtle.ConstantTimeCompare([]byte(stringAt(values, 9)), []byte(tokenHashHex(receiptToken))) != 1 {
		return ReceiptView{}, nil
	}
	eventsRaw, ok := outer[1].([]interface{})
	if !ok {
		return ReceiptView{}, ErrInternal
	}
	events := make([]ReceiptEvent, 0, len(eventsRaw))
	for _, value := range eventsRaw {
		var event ReceiptEvent
		if err := json.Unmarshal([]byte(stringValue(value)), &event); err == nil {
			events = append(events, event)
		}
	}
	if int64At(outer, 2) == 1 {
		s.incrStats("expiries")
		s.invalidateReady()
	}
	return ReceiptView{
		SecretID:         id,
		State:            stringAt(values, 0),
		CreatedAt:        int64At(values, 1),
		ExpiresAt:        int64At(values, 2),
		ReceiptExpiresAt: int64At(values, 3),
		BurnedAt:         int64At(values, 4),
		RevokedAt:        int64At(values, 5),
		Opens:            int(int64At(values, 6)),
		LastOpenedAt:     int64At(values, 7),
		Decrypted:        stringAt(values, 8) == "1",
		Events:           events,
	}, nil
}

// Sweep prunes expired members from the capacity indexes. The records
// themselves expire through their own Valkey TTLs; the indexes need this so a
// burst of short-lived secrets cannot leave stale members behind.
func (s *ValkeyStore) Sweep() {
	ctx, cancel := s.opCtx()
	defer cancel()
	now := strconv.FormatInt(s.now().UnixMilli(), 10)
	_ = s.client.ZRemRangeByScore(ctx, s.secretIndex(), "-inf", now).Err()
	_ = s.client.ZRemRangeByScore(ctx, s.receiptIndex(), "-inf", now).Err()
}

func (s *ValkeyStore) Close() {
	_ = s.client.Close()
}

func (s *ValkeyStore) Stats() StoreStats {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats := StoreStats{}
	values, err := s.client.HGetAll(ctx, s.statsKey()).Result()
	if err == nil {
		stats.Creates = parseInt64(values["creates"])
		stats.Opens = parseInt64(values["opens"])
		stats.Burns = parseInt64(values["burns"])
		stats.Revokes = parseInt64(values["revokes"])
		stats.Expiries = parseInt64(values["expiries"])
		stats.Evictions = 0
	}
	now := s.now().UnixMilli()
	stats.Secrets = s.liveCount(ctx, s.secretIndex(), now)
	stats.Receipts = s.liveCount(ctx, s.receiptIndex(), now)
	if used, err := s.usedMemory(ctx); err == nil {
		stats.TotalBytes = used
	}
	return stats
}

// Ready mirrors the in-memory contract: it reports capacity, not just
// reachability. Results are cached briefly so an untrusted /readyz flood
// cannot turn into a Valkey round trip per request.
func (s *ValkeyStore) Ready() bool {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	now := s.now()
	if !s.readyAt.IsZero() && now.Sub(s.readyAt) < time.Second {
		return s.readyValue
	}
	s.readyValue = s.checkReady(now)
	s.readyAt = now
	return s.readyValue
}

func (s *ValkeyStore) checkReady(now time.Time) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.client.Ping(ctx).Err(); err != nil {
		return false
	}
	used, err := s.usedMemory(ctx)
	if err != nil {
		return false
	}
	if used >= s.maxTotalBytes {
		return false
	}
	if s.liveCount(ctx, s.secretIndex(), now.UnixMilli()) >= s.maxSecrets {
		return false
	}
	if s.liveCount(ctx, s.receiptIndex(), now.UnixMilli()) >= s.maxReceipts {
		return false
	}
	return true
}

func (s *ValkeyStore) invalidateReady() {
	s.readyMu.Lock()
	s.readyAt = time.Time{}
	s.readyMu.Unlock()
}

func (s *ValkeyStore) keys(id string) (secret, receipt, events string) {
	tag := "{" + id + "}"
	return s.prefix + "secret:" + tag, s.prefix + "receipt:" + tag, s.prefix + "events:" + tag
}

func (s *ValkeyStore) secretIndex() string {
	return s.prefix + "live:secrets"
}

func (s *ValkeyStore) receiptIndex() string {
	return s.prefix + "live:receipts"
}

func (s *ValkeyStore) statsKey() string {
	return s.prefix + "stats"
}

func (s *ValkeyStore) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func (s *ValkeyStore) incrStats(field string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.client.HIncrBy(ctx, s.statsKey(), field, 1).Err()
}

// liveCount counts index members whose expiry is still in the future. Expired
// members are pruned by the create/sweep paths; the exclusive lower bound
// keeps the count correct before that happens.
func (s *ValkeyStore) liveCount(ctx context.Context, key string, now int64) int {
	n, err := s.client.ZCount(ctx, key, "("+strconv.FormatInt(now, 10), "+inf").Result()
	if err != nil {
		return 0
	}
	return int(n)
}

// infoUsedMemory reads used_memory for the whole instance. The Valkey
// deployment is expected to be dedicated to this service; if prefixes are
// shared, the byte cap is conservative.
func (s *ValkeyStore) infoUsedMemory(ctx context.Context) (int64, error) {
	info, err := s.client.Info(ctx, "memory").Result()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "used_memory:"); ok {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, err
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("used_memory missing from INFO memory")
}

func mapValkeyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, redis.Nil) {
		return ErrUnavailable
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "oom") || strings.Contains(msg, "maxmemory") || strings.Contains(msg, "noeviction") {
		return ErrStoreFull
	}
	return ErrStoreUnavailable
}

func randomToken(rawLen int) (string, error) {
	buf := make([]byte, rawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenHashHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func eventJSON(eventType string, at time.Time) string {
	raw, _ := json.Marshal(ReceiptEvent{Type: eventType, At: at.UnixMilli()})
	return string(raw)
}

func ttlSeconds(d time.Duration) int64 {
	seconds := int64(d / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func stringAt(values []interface{}, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return stringValue(values[index])
}

func stringValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

func int64At(values []interface{}, index int) int64 {
	if index < 0 || index >= len(values) {
		return 0
	}
	switch v := values[index].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		return parseInt64(v)
	case []byte:
		return parseInt64(string(v))
	default:
		return parseInt64(fmt.Sprint(v))
	}
}

func parseInt64(value string) int64 {
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}

var createScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', ARGV[5])
if redis.call('ZCARD', KEYS[4]) >= tonumber(ARGV[12]) then return -2 end
if redis.call('ZCARD', KEYS[5]) >= tonumber(ARGV[13]) then return -3 end
redis.call('HSET', KEYS[1],
  'iv', ARGV[1],
  'ct', ARGV[2],
  'tag', ARGV[3],
  'proof_hash', ARGV[4],
  'created_at', ARGV[5],
  'expires_at', ARGV[6],
  'max_views', '1')
redis.call('EXPIRE', KEYS[1], ARGV[7])
redis.call('HSET', KEYS[2],
  'token_hash', ARGV[8],
  'state', 'available',
  'created_at', ARGV[5],
  'expires_at', ARGV[6],
  'receipt_expires_at', ARGV[9],
  'opens', '0',
  'decrypted', '0')
redis.call('EXPIRE', KEYS[2], ARGV[10])
redis.call('RPUSH', KEYS[3], ARGV[11])
redis.call('EXPIRE', KEYS[3], ARGV[10])
redis.call('ZADD', KEYS[4], ARGV[6], ARGV[14])
redis.call('ZADD', KEYS[5], ARGV[9], ARGV[14])
return 1
`)

var challengeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 0 then return {0,0,0,0} end
local state = redis.call('HGET', KEYS[2], 'state')
if not state or state ~= 'available' then return {0,0,0,0} end
local now = tonumber(ARGV[1])
local expires = tonumber(redis.call('HGET', KEYS[2], 'expires_at') or '0')
if redis.call('EXISTS', KEYS[1]) == 0 or expires <= now then
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[2], 'state', 'expired')
  local existing = tonumber(redis.call('HGET', KEYS[2], 'receipt_expires_at') or '0')
  local retention = math.max(existing, now + tonumber(ARGV[4]))
  redis.call('HSET', KEYS[2], 'receipt_expires_at', retention)
  local ttl = math.ceil((retention - now) / 1000)
  if ttl < 1 then ttl = 1 end
  redis.call('EXPIRE', KEYS[2], ttl)
  redis.call('EXPIRE', KEYS[3], ttl)
  redis.call('RPUSH', KEYS[3], ARGV[2])
  redis.call('LTRIM', KEYS[3], -64, -1)
  redis.call('ZREM', KEYS[4], ARGV[5])
  redis.call('ZADD', KEYS[5], retention, ARGV[5])
  return {0,0,0,1}
end
local opens = redis.call('HINCRBY', KEYS[2], 'opens', 1)
redis.call('HSET', KEYS[2], 'last_opened_at', ARGV[1])
if opens == 1 then
  redis.call('RPUSH', KEYS[3], ARGV[3])
  redis.call('LTRIM', KEYS[3], -64, -1)
end
return {1, expires, 1, 0}
`)

var consumeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 0 then return {0,0} end
local state = redis.call('HGET', KEYS[2], 'state')
if not state or state ~= 'available' then return {0,0} end
local now = tonumber(ARGV[2])
local expires = tonumber(redis.call('HGET', KEYS[2], 'expires_at') or '0')
local existing = tonumber(redis.call('HGET', KEYS[2], 'receipt_expires_at') or '0')
local retention = math.max(existing, tonumber(ARGV[7]))
local ttl = math.ceil((retention - now) / 1000)
if ttl < 1 then ttl = 1 end
if redis.call('EXISTS', KEYS[1]) == 0 or expires <= now then
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[2], 'state', 'expired', 'receipt_expires_at', retention)
  redis.call('EXPIRE', KEYS[2], ttl)
  redis.call('EXPIRE', KEYS[3], ttl)
  redis.call('RPUSH', KEYS[3], ARGV[6])
  redis.call('LTRIM', KEYS[3], -64, -1)
  redis.call('ZREM', KEYS[4], ARGV[9])
  redis.call('ZADD', KEYS[5], retention, ARGV[9])
  return {0,1}
end
local proof = redis.call('HGET', KEYS[1], 'proof_hash')
if not proof or proof ~= ARGV[1] then return {-1,0} end
local iv = redis.call('HGET', KEYS[1], 'iv')
local ct = redis.call('HGET', KEYS[1], 'ct')
local tag = redis.call('HGET', KEYS[1], 'tag')
local created = redis.call('HGET', KEYS[1], 'created_at')
local exp = redis.call('HGET', KEYS[1], 'expires_at')
local maxViews = redis.call('HGET', KEYS[1], 'max_views')
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[2],
  'state','burned',
  'burned_at',ARGV[2],
  'view_hash',ARGV[3],
  'view_set','1',
  'decrypted','0',
  'receipt_expires_at',retention)
redis.call('RPUSH', KEYS[3], ARGV[4], ARGV[5])
redis.call('LTRIM', KEYS[3], -64, -1)
redis.call('EXPIRE', KEYS[2], ttl)
redis.call('EXPIRE', KEYS[3], ttl)
redis.call('ZREM', KEYS[4], ARGV[9])
redis.call('ZADD', KEYS[5], retention, ARGV[9])
return {1, iv, ct, tag, created, exp, maxViews}
`)

var revokeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 0 then return {0} end
local stored = redis.call('HGET', KEYS[2], 'token_hash')
if not stored or stored ~= ARGV[1] then return {0} end
local state = redis.call('HGET', KEYS[2], 'state')
if state == 'available' then
  local now = tonumber(ARGV[2])
  local existing = tonumber(redis.call('HGET', KEYS[2], 'receipt_expires_at') or '0')
  local retention = math.max(existing, tonumber(ARGV[4]))
  local ttl = math.ceil((retention - now) / 1000)
  if ttl < 1 then ttl = 1 end
  if redis.call('EXISTS', KEYS[1]) == 0 then
    redis.call('HSET', KEYS[2], 'state', 'expired', 'receipt_expires_at', retention)
    redis.call('EXPIRE', KEYS[2], ttl)
    redis.call('EXPIRE', KEYS[3], ttl)
    redis.call('RPUSH', KEYS[3], ARGV[6])
    redis.call('LTRIM', KEYS[3], -64, -1)
    redis.call('ZREM', KEYS[4], ARGV[7])
    redis.call('ZADD', KEYS[5], retention, ARGV[7])
    return {1, 'expired', '', 1}
  end
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[2], 'state','revoked','revoked_at',ARGV[2], 'receipt_expires_at', retention)
  redis.call('EXPIRE', KEYS[2], ttl)
  redis.call('EXPIRE', KEYS[3], ttl)
  redis.call('RPUSH', KEYS[3], ARGV[3])
  redis.call('LTRIM', KEYS[3], -64, -1)
  redis.call('ZREM', KEYS[4], ARGV[7])
  redis.call('ZADD', KEYS[5], retention, ARGV[7])
  return {1, 'revoked', ARGV[2], 1}
end
local revokedAt = redis.call('HGET', KEYS[2], 'revoked_at') or ''
return {1, state, revokedAt, 0}
`)

var confirmDecryptedScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HGET', KEYS[1], 'state') ~= 'burned' then return 0 end
if redis.call('HGET', KEYS[1], 'view_set') ~= '1' then return 0 end
if redis.call('HGET', KEYS[1], 'view_hash') ~= ARGV[1] then return 0 end
if redis.call('HGET', KEYS[1], 'decrypted') == '1' then return 1 end
redis.call('HSET', KEYS[1], 'decrypted', '1')
redis.call('RPUSH', KEYS[2], ARGV[2])
redis.call('LTRIM', KEYS[2], -64, -1)
return 1
`)

var receiptScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return nil end
local state = redis.call('HGET', KEYS[1], 'state')
local expires = tonumber(redis.call('HGET', KEYS[1], 'expires_at') or '0')
local changed = 0
if state == 'available' and expires <= tonumber(ARGV[1]) and redis.call('EXISTS', KEYS[3]) == 0 then
  local now = tonumber(ARGV[1])
  local existing = tonumber(redis.call('HGET', KEYS[1], 'receipt_expires_at') or '0')
  local retention = math.max(existing, tonumber(ARGV[3]))
  redis.call('HSET', KEYS[1], 'state', 'expired', 'receipt_expires_at', retention)
  local ttl = math.ceil((retention - now) / 1000)
  if ttl < 1 then ttl = 1 end
  redis.call('EXPIRE', KEYS[1], ttl)
  redis.call('EXPIRE', KEYS[2], ttl)
  redis.call('RPUSH', KEYS[2], ARGV[2])
  redis.call('LTRIM', KEYS[2], -64, -1)
  redis.call('ZREM', KEYS[4], ARGV[4])
  redis.call('ZADD', KEYS[5], retention, ARGV[4])
  changed = 1
end
local vals = redis.call('HMGET', KEYS[1],
  'state','created_at','expires_at','receipt_expires_at','burned_at','revoked_at','opens','last_opened_at','decrypted','token_hash','view_hash')
local events = redis.call('LRANGE', KEYS[2], 0, -1)
return {vals, events, changed}
`)
