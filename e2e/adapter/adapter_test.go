// Package adapter contains end-to-end tests for database adapters.
// These tests validate that adapters correctly implement the full Adapter interface.
package adapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter"
	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter/memory"
)

// adapterTestSuite runs the full adapter test suite against any Adapter implementation.
func adapterTestSuite(t *testing.T, adp adapter.Adapter) {
	ctx := context.Background()

	t.Run("CreateAndFindOne", func(t *testing.T) {
		now := time.Now().UTC()
		_, err := adp.Create(ctx, "user", map[string]any{
			"id": "u1", "email": "test@test.com", "name": "Test", "created_at": now,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		found, err := adp.FindOne(ctx, "user", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", "u1")},
		})
		if err != nil {
			t.Fatalf("FindOne: %v", err)
		}
		if found == nil {
			t.Fatal("expected record to be found")
		}
		if found["email"] != "test@test.com" {
			t.Fatalf("expected email 'test@test.com', got %v", found["email"])
		}
	})

	t.Run("Update", func(t *testing.T) {
		updated, err := adp.Update(ctx, "user",
			adapter.Query{Where: []adapter.Where{adapter.EQ("id", "u1")}},
			map[string]any{"name": "Updated"},
		)
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if updated["name"] != "Updated" {
			t.Fatalf("expected name 'Updated', got %v", updated["name"])
		}
	})

	t.Run("FindMany", func(t *testing.T) {
		_, _ = adp.Create(ctx, "user", map[string]any{
			"id": "u2", "email": "two@test.com", "name": "Two",
		})
		results, err := adp.FindMany(ctx, "user", adapter.Query{})
		if err != nil {
			t.Fatalf("FindMany: %v", err)
		}
		if len(results) < 2 {
			t.Fatalf("expected at least 2 results, got %d", len(results))
		}
	})

	t.Run("Count", func(t *testing.T) {
		count, err := adp.Count(ctx, "user", adapter.Query{})
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if count < 2 {
			t.Fatalf("expected count >= 2, got %d", count)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		err := adp.Delete(ctx, "user", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", "u2")},
		})
		if err != nil {
			t.Fatalf("Delete: %v", err)
		}
		found, _ := adp.FindOne(ctx, "user", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", "u2")},
		})
		if found != nil {
			t.Fatal("expected record to be deleted")
		}
	})

	t.Run("CreateMany", func(t *testing.T) {
		err := adp.CreateMany(ctx, "session", []map[string]any{
			{"id": "s1", "user_id": "u1"},
			{"id": "s2", "user_id": "u1"},
		})
		if err != nil {
			t.Fatalf("CreateMany: %v", err)
		}
		count, _ := adp.Count(ctx, "session", adapter.Query{})
		if count != 2 {
			t.Fatalf("expected 2 sessions, got %d", count)
		}
	})

	t.Run("UpdateMany", func(t *testing.T) {
		err := adp.UpdateMany(ctx, "session",
			adapter.Query{Where: []adapter.Where{adapter.EQ("user_id", "u1")}},
			map[string]any{"user_id": "u1-updated"},
		)
		if err != nil {
			t.Fatalf("UpdateMany: %v", err)
		}
	})

	t.Run("DeleteMany", func(t *testing.T) {
		err := adp.DeleteMany(ctx, "session",
			adapter.Query{Where: []adapter.Where{adapter.EQ("user_id", "u1-updated")}},
		)
		if err != nil {
			t.Fatalf("DeleteMany: %v", err)
		}
		count, _ := adp.Count(ctx, "session", adapter.Query{})
		if count != 0 {
			t.Fatalf("expected 0 sessions after delete, got %d", count)
		}
	})
}

func TestMemoryAdapter(t *testing.T) {
	adapterTestSuite(t, memory.New())
}
