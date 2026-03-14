// Package redis provides a Redis-backed implementation of storage.Store.
package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/jeromesth/go-better-auth/storage"
)

// Compile-time check that Store implements storage.Store.
var _ storage.Store = (*Store)(nil)

// Store is a Redis-backed key-value store with TTL support.
type Store struct {
	client *redis.Client
}

// New creates a Redis storage from an existing redis.Client.
func New(client *redis.Client) *Store {
	return &Store{client: client}
}

// NewFromURL creates a Redis storage from a connection URL (e.g. "redis://localhost:6379/0").
func NewFromURL(url string) (*Store, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Store{client: redis.NewClient(opts)}, nil
}

// Get retrieves a value by key. Returns empty string and nil error if not found.
func (s *Store) Get(ctx context.Context, key string) (string, error) {
	val, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

// Set stores a value with a TTL. If ttl is 0, the value does not expire.
func (s *Store) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

// Delete removes a key.
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// Exists checks if a key exists.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Client returns the underlying redis.Client for advanced usage.
func (s *Store) Client() *redis.Client {
	return s.client
}
