// Package ratelimit provides in-memory rate limiting for the auth API.
package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

// Limiter is a sliding-window rate limiter keyed by an arbitrary string.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	window  time.Duration
	max     int
}

type entry struct {
	count       int
	windowStart time.Time
}

// New creates a Limiter with the given window (seconds) and max request count.
func New(windowSeconds, max int) *Limiter {
	return &Limiter{
		entries: make(map[string]*entry),
		window:  time.Duration(windowSeconds) * time.Second,
		max:     max,
	}
}

// Allow returns true if the key is within the rate limit, false if exceeded.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.Sub(e.windowStart) > l.window {
		l.entries[key] = &entry{count: 1, windowStart: now}
		return true
	}

	if e.count >= l.max {
		return false
	}
	e.count++
	return true
}

// Middleware returns an HTTP middleware that rate-limits by remote IP.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if !l.Allow(key) {
			http.Error(w, `{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
