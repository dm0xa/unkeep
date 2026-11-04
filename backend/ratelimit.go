package main

import (
	"sync"
	"time"
)

type rateBucket struct {
	tokens float64
	last   time.Time
	seen   time.Time
}

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
		if len(l.buckets) >= l.maxBuckets {
			for k, candidate := range l.buckets {
				if now.Sub(candidate.seen) > 15*time.Minute {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= l.maxBuckets {
				return false, time.Minute
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
