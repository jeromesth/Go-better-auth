package memory

import (
	"context"
	"testing"
	"time"
)

func TestSetAndGet(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.Set(ctx, "key1", "value1", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "value1" {
		t.Errorf("Get = %q, want %q", got, "value1")
	}
}

func TestGetNotFound(t *testing.T) {
	s := New()
	ctx := context.Background()

	got, err := s.Get(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "" {
		t.Errorf("Get = %q, want empty string", got)
	}
}

func TestSetOverwrite(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.Set(ctx, "key1", "v1", 0)
	_ = s.Set(ctx, "key1", "v2", 0)

	got, _ := s.Get(ctx, "key1")
	if got != "v2" {
		t.Errorf("Get after overwrite = %q, want %q", got, "v2")
	}
}

func TestDelete(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.Set(ctx, "key1", "value1", 0)
	if err := s.Delete(ctx, "key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, _ := s.Get(ctx, "key1")
	if got != "" {
		t.Errorf("Get after Delete = %q, want empty", got)
	}
}

func TestDeleteNonexistent(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Should not error when deleting a key that doesn't exist.
	if err := s.Delete(ctx, "nonexistent"); err != nil {
		t.Fatalf("Delete nonexistent: %v", err)
	}
}

func TestExists(t *testing.T) {
	s := New()
	ctx := context.Background()

	exists, err := s.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("Exists = true for nonexistent key")
	}

	_ = s.Set(ctx, "key1", "value1", 0)
	exists, err = s.Exists(ctx, "key1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Error("Exists = false for existing key")
	}
}

func TestTTLExpiration(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Set with a very short TTL.
	_ = s.Set(ctx, "key1", "value1", 50*time.Millisecond)

	// Should exist immediately.
	got, _ := s.Get(ctx, "key1")
	if got != "value1" {
		t.Errorf("Get before expiry = %q, want %q", got, "value1")
	}

	// Wait for expiration.
	time.Sleep(100 * time.Millisecond)

	got, _ = s.Get(ctx, "key1")
	if got != "" {
		t.Errorf("Get after expiry = %q, want empty", got)
	}

	exists, _ := s.Exists(ctx, "key1")
	if exists {
		t.Error("Exists = true after expiry")
	}
}

func TestNoTTL(t *testing.T) {
	s := New()
	ctx := context.Background()

	// TTL of 0 means no expiry.
	_ = s.Set(ctx, "key1", "value1", 0)

	// Should still exist after a short delay.
	time.Sleep(10 * time.Millisecond)

	got, _ := s.Get(ctx, "key1")
	if got != "value1" {
		t.Errorf("Get = %q, want %q", got, "value1")
	}
}
