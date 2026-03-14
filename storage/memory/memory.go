// Package memory provides an in-memory implementation of storage.Store.
// It is suitable for testing and single-server deployments.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/jeromesth/go-better-auth/storage"
)

// Compile-time check that Store implements storage.Store.
var _ storage.Store = (*Store)(nil)

type entry struct {
	value     string
	expiresAt time.Time // zero value means no expiry
}

func (e entry) isExpired() bool {
	if e.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.expiresAt)
}

// Store is an in-memory key-value store with TTL support.
// Expiration is checked lazily on Get and Exists.
type Store struct {
	mu      sync.RWMutex
	entries map[string]entry
}

// New creates a new in-memory Store.
func New() *Store {
	return &Store{
		entries: make(map[string]entry),
	}
}

// Get retrieves a value by key. Returns empty string and nil error if not found or expired.
func (s *Store) Get(_ context.Context, key string) (string, error) {
	s.mu.RLock()
	e, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return "", nil
	}
	if e.isExpired() {
		// Lazy cleanup: remove expired entry.
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		return "", nil
	}
	return e.value, nil
}

// Set stores a value with a TTL. If ttl is 0, the value does not expire.
func (s *Store) Set(_ context.Context, key string, value string, ttl time.Duration) error {
	e := entry{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	s.mu.Lock()
	s.entries[key] = e
	s.mu.Unlock()
	return nil
}

// Delete removes a key.
func (s *Store) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	delete(s.entries, key)
	s.mu.Unlock()
	return nil
}

// Exists checks if a key exists and has not expired.
func (s *Store) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	e, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok {
		return false, nil
	}
	if e.isExpired() {
		s.mu.Lock()
		delete(s.entries, key)
		s.mu.Unlock()
		return false, nil
	}
	return true, nil
}
