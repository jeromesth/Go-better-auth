// Package ratelimit provides in-memory rate limiting for the auth API.
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/jeromesth/go-better-auth/internal"
)

// Config holds the configuration for a RateLimiter.
type Config struct {
	Limit    int           // max requests per window
	Window   time.Duration // length of each fixed window
	IPHeader string        // trusted proxy header for real client IP (e.g. "X-Forwarded-For"); empty means auto-detect
}

// RateLimiter is a fixed-window rate limiter keyed by an arbitrary string.
// Each key gets a counter that resets after Window duration from the first hit.
type RateLimiter struct {
	mu        sync.Mutex
	entries   map[string]*entry
	window    time.Duration
	limit     int
	ipHeader  string
	lastEvict time.Time
}

type entry struct {
	count   int
	resetAt time.Time
}

// New creates a RateLimiter with the given Config.
func New(cfg Config) *RateLimiter {
	return &RateLimiter{
		entries:  make(map[string]*entry),
		window:   cfg.Window,
		limit:    cfg.Limit,
		ipHeader: cfg.IPHeader,
	}
}

// Allow returns true if the key is within the rate limit, false if exceeded.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Periodic full sweep: once per window, evict all expired entries to bound
	// memory over time without paying O(n) on every call.
	if now.After(rl.lastEvict.Add(rl.window)) {
		for k, e := range rl.entries {
			if now.After(e.resetAt) {
				delete(rl.entries, k)
			}
		}
		rl.lastEvict = now
	}

	e, ok := rl.entries[key]
	if !ok {
		rl.entries[key] = &entry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	// Lazy eviction on touch: if the entry is expired, reset it in place.
	if now.After(e.resetAt) {
		e.count = 1
		e.resetAt = now.Add(rl.window)
		return true
	}

	e.count++
	return e.count <= rl.limit
}

// Middleware returns an HTTP middleware that rate-limits by real client IP.
// It consults the configured IPHeader first, then falls back to common proxy
// headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP), and finally
// RemoteAddr — so it works correctly behind load balancers and reverse proxies.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := internal.GetClientIP(r, rl.ipHeader)
		if !rl.Allow(ip) {
			http.Error(w, `{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
