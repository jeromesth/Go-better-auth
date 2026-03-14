package redis

import (
	"testing"

	"github.com/jeromesth/go-better-auth/storage"
)

// Compile-time check that Store implements storage.Store.
// This verifies interface compliance without requiring a running Redis server.
var _ storage.Store = (*Store)(nil)

func TestNewFromURL_InvalidURL(t *testing.T) {
	_, err := NewFromURL("not-a-valid-url")
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestNewFromURL_ValidURL(t *testing.T) {
	s, err := NewFromURL("redis://localhost:6379/0")
	if err != nil {
		t.Fatalf("unexpected error for valid URL: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Store")
	}
	if s.Client() == nil {
		t.Fatal("expected non-nil Client")
	}
}

func TestNew(t *testing.T) {
	// New should accept a nil client without panicking during construction.
	// Operations would fail, but construction should succeed.
	s := New(nil)
	if s == nil {
		t.Fatal("expected non-nil Store")
	}
}
