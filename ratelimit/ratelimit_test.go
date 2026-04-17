package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeromesth/go-better-auth/ratelimit"
)

func TestAllow_LimitsRequests(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{Limit: 3, Window: time.Second})
	allowed := 0
	for i := 0; i < 5; i++ {
		if rl.Allow("test-key") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("got %d allowed, want 3", allowed)
	}
}

func TestAllow_ResetsAfterWindow(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{Limit: 2, Window: 50 * time.Millisecond})
	rl.Allow("k")
	rl.Allow("k")
	if rl.Allow("k") {
		t.Error("third request in window should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("k") {
		t.Error("first request after window reset should be allowed")
	}
}

func TestAllow_EvictsExpiredEntries(t *testing.T) {
	window := 50 * time.Millisecond
	rl := ratelimit.New(ratelimit.Config{Limit: 10, Window: window})

	// Populate entries for several keys.
	keys := []string{"a", "b", "c", "d", "e"}
	for _, k := range keys {
		rl.Allow(k)
	}

	// Wait for the window to expire, then touch one key to trigger the
	// periodic sweep (lastEvict is zero, so the sweep fires on the first
	// Allow call after the window).
	time.Sleep(window + 10*time.Millisecond)

	// This call should trigger the full sweep and evict the stale entries.
	rl.Allow("trigger")

	// After eviction the swept keys should behave as new entries (count resets).
	// We verify by exhausting the limit starting fresh — if the entry wasn't
	// evicted the count might carry over and Allow would return false immediately.
	for i := 0; i < 10; i++ {
		if !rl.Allow("a") {
			t.Errorf("request %d for key 'a' after eviction should be allowed", i+1)
		}
	}
}

func TestMiddleware_UsesHostNotPort(t *testing.T) {
	rl := ratelimit.New(ratelimit.Config{Limit: 1, Window: time.Second})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests from the same IP but different ports should share the limit
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "1.2.3.4:10001"
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "1.2.3.4:10002"

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: got %d, want 200", w1.Code)
	}

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request from same IP different port: got %d, want 429", w2.Code)
	}
}
