// Package oauth implements the OAuth 2.0 authorization code flow.
package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// StateEntry holds the data associated with an OAuth state parameter.
type StateEntry struct {
	CallbackURL  string
	CodeVerifier string
	CreatedAt    time.Time
}

// StateStore is a thread-safe in-memory store for OAuth state parameters.
type StateStore struct {
	mu      sync.Mutex
	entries map[string]StateEntry
}

// NewStateStore creates an empty StateStore.
func NewStateStore() *StateStore {
	return &StateStore{entries: make(map[string]StateEntry)}
}

// Generate creates and stores a new random state value.
func (s *StateStore) Generate(callbackURL, codeVerifier string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[state] = StateEntry{
		CallbackURL:  callbackURL,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now(),
	}
	return state, nil
}

// Consume retrieves and removes the state entry, returning nil if not found or expired.
func (s *StateStore) Consume(state string) *StateEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[state]
	if !ok {
		return nil
	}
	delete(s.entries, state)

	// State expires after 10 minutes.
	if time.Since(e.CreatedAt) > 10*time.Minute {
		return nil
	}
	return &e
}
