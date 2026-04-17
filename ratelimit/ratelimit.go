// Package ratelimit provides in-memory rate limiting for the auth API.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Config holds the configuration for a RateLimiter.
type Config struct {
	Limit  int           // max requests per window
	Window time.Duration // length of the sliding window
}

// RateLimiter is a sliding-window rate limiter keyed by an arbitrary string.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	window  time.Duration
	limit   int
}

type entry struct {
	count   int
	resetAt time.Time
}

// New creates a RateLimiter with the given Config.
func New(cfg Config) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*entry),
		window:  cfg.Window,
		limit:   cfg.Limit,
	}
}

// Allow returns true if the key is within the rate limit, false if exceeded.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Evict expired entries if map is getting large.
	if len(rl.entries) > 10000 {
		for k, e := range rl.entries {
			if now.After(e.resetAt) {
				delete(rl.entries, k)
			}
		}
	}

	e, ok := rl.entries[key]
	if !ok || now.After(e.resetAt) {
		rl.entries[key] = &entry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	e.count++
	return e.count <= rl.limit
}

// Middleware returns an HTTP middleware that rate-limits by remote IP (host only, no port).
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !rl.Allow(host) {
			http.Error(w, `{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
