// Package storage defines the SecondaryStorage interface for caching and ephemeral data.
package storage

import (
	"context"
	"time"
)

// Store provides key-value storage with TTL support.
// Used for session caching, rate limiting, and ephemeral challenge storage.
type Store interface {
	// Get retrieves a value by key. Returns empty string and nil error if not found.
	Get(ctx context.Context, key string) (string, error)
	// Set stores a value with a TTL. If ttl is 0, the value does not expire.
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	// Delete removes a key.
	Delete(ctx context.Context, key string) error
	// Exists checks if a key exists.
	Exists(ctx context.Context, key string) (bool, error)
}
