package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"sync"
	"time"
)

type rateBucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

// maxPruneScan bounds how many buckets one request may inspect when the table
// is at capacity. The table holds 100k entries, so an unbounded scan would put
// O(100k) work behind the limiter mutex on every request from a new client.
const maxPruneScan = 256

type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*rateBucket
	now        func() time.Time
	maxBuckets int
}

func NewRateLimiter(now func() time.Time, maxBuckets int) *RateLimiter {
	if maxBuckets < 1 {
		maxBuckets = 1
	}
	return &RateLimiter{
		buckets:    make(map[string]*rateBucket),
		now:        now,
		maxBuckets: maxBuckets,
	}
}

// Allow consumes one token. perMinute sets the refill rate; burst sets the
// bucket capacity. It returns a conservative Retry-After when denied.
func (l *RateLimiter) Allow(key string, perMinute, burst int) (bool, time.Duration) {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = 1
	}
	ratePerSecond := float64(perMinute) / 60.0
	capacity := float64(burst)

	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// Map iteration starts at a random offset, so sampling a fixed number of
		// entries keeps the per-request cost bounded even when the table is full:
		// a full scan here would stall every request behind the limiter mutex.
		if len(l.buckets) >= l.maxBuckets {
			scanned, oldestKey := 0, ""
			var oldestSeen time.Time
			for k, candidate := range l.buckets {
				if now.Sub(candidate.seen) > 15*time.Minute {
					delete(l.buckets, k)
				} else if oldestKey == "" || candidate.seen.Before(oldestSeen) {
					oldestKey, oldestSeen = k, candidate.seen
				}
				scanned++
				if scanned >= maxPruneScan {
					break
				}
			}
			if len(l.buckets) >= l.maxBuckets {
				if oldestKey == "" {
					return false, time.Minute
				}
				// Shed the stalest sampled bucket rather than deny every new
				// client until something happens to expire.
				delete(l.buckets, oldestKey)
			}
		}
		b = &rateBucket{tokens: capacity, last: now, seen: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * ratePerSecond
		if b.tokens > capacity {
			b.tokens = capacity
		}
		b.last = now
	}
	b.seen = now

	if b.tokens < 1 {
		wait := time.Duration((1-b.tokens)/ratePerSecond*float64(time.Second)) + time.Second
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}
	b.tokens--
	return true, 0
}

// rateKeyer derives the per-client bucket key without the per-request
// allocations of a fresh HMAC: hmac.New + hex + concatenation cost 13
// allocations and ~490 ns on every rate-limited request. The key is still a
// keyed digest of the address, so the limiter table never holds raw IPs.
type rateKeyer struct {
	secret []byte
	pool   sync.Pool
}

func newRateKeyer(secret []byte) *rateKeyer {
	return &rateKeyer{
		secret: secret,
		pool: sync.Pool{
			New: func() any { return hmac.New(sha256.New, secret) },
		},
	}
}

func (k *rateKeyer) key(scope, ip string) string {
	mac := k.pool.Get().(hash.Hash)
	var scratch [256]byte
	sum := scratch[:0]
	// Byte layout matches hmacKey(secret, "rate", ip): parts separated by 0x00.
	for _, part := range [2]string{"rate", ip} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	sum = mac.Sum(sum)
	mac.Reset()
	k.pool.Put(mac)
	buf := make([]byte, 0, len(scope)+1+len(sum))
	buf = append(buf, scope...)
	buf = append(buf, ':')
	buf = append(buf, sum...)
	return string(buf)
}
