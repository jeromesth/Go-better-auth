package memory_test

import (
	"context"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth/adapter"

	"github.com/jeromesth/go-better-auth/adapter/memory"
)

func TestFindMany_OffsetBeyondResults_ReturnsEmptySlice(t *testing.T) {
	a := memory.New()
	ctx := context.Background()

	// Insert one record
	a.Create(ctx, "users", map[string]any{"id": "1", "email": "a@b.com"})

	// Query with offset past the end
	results, err := a.FindMany(ctx, "users", betterauth.Query{Offset: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results == nil {
		t.Error("FindMany with exhausted offset returned nil, want empty slice")
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}
