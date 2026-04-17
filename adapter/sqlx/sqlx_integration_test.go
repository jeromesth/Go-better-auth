//go:build integration

package sqlxadapter_test

import (
	"context"
	"os"
	"testing"

	"github.com/jeromesth/go-better-auth/adapter"
	sqlxadapter "github.com/jeromesth/go-better-auth/adapter/sqlx"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// getTestDSN returns the Postgres DSN for integration tests or skips the test.
func getTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set — skipping integration test")
	}
	return dsn
}

// newPGTestDB opens a Postgres connection, creates the users table, and registers cleanup.
func newPGTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	dsn := getTestDSN(t)

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sqlx.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("db.Ping: %v", err)
	}

	// Each test gets an isolated table via a unique name derived from the test name.
	t.Cleanup(func() { db.Close() })
	return db
}

// createUsersTable creates a fresh users table with the given name and registers a drop on cleanup.
func createUsersTable(t *testing.T, db *sqlx.DB, tableName string) {
	t.Helper()
	db.MustExec(`CREATE TABLE IF NOT EXISTS ` + tableName + ` (
		id      TEXT PRIMARY KEY,
		email   TEXT,
		name    TEXT,
		role    TEXT
	)`)
	t.Cleanup(func() {
		db.MustExec(`DROP TABLE IF EXISTS ` + tableName)
	})
}

// TestPGAdapter_CreateAndFindOne verifies basic insert and point-lookup behavior.
func TestPGAdapter_CreateAndFindOne(t *testing.T) {
	db := newPGTestDB(t)
	createUsersTable(t, db, "pg_users_create")

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	rec, err := adp.Create(ctx, "pg_users_create", map[string]any{
		"id":    "u1",
		"email": "alice@example.com",
		"name":  "Alice",
		"role":  "admin",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec["id"] != "u1" {
		t.Errorf("Create: expected id=u1, got %v", rec["id"])
	}

	found, err := adp.FindOne(ctx, "pg_users_create", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	})
	if err != nil {
		t.Fatalf("FindOne: %v", err)
	}
	if found == nil {
		t.Fatal("FindOne: expected record, got nil")
	}
	if found["email"] != "alice@example.com" {
		t.Errorf("FindOne: expected email alice@example.com, got %v", found["email"])
	}
}

// TestPGAdapter_FindMany_WithFilter verifies equality filtering returns only matching rows.
func TestPGAdapter_FindMany_WithFilter(t *testing.T) {
	db := newPGTestDB(t)
	createUsersTable(t, db, "pg_users_filter")

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	seed := []map[string]any{
		{"id": "u1", "email": "a@a.com", "name": "Alice", "role": "admin"},
		{"id": "u2", "email": "b@b.com", "name": "Bob", "role": "user"},
		{"id": "u3", "email": "c@c.com", "name": "Carol", "role": "admin"},
	}
	if err := adp.CreateMany(ctx, "pg_users_filter", seed); err != nil {
		t.Fatalf("CreateMany: %v", err)
	}

	rows, err := adp.FindMany(ctx, "pg_users_filter", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "admin")},
	})
	if err != nil {
		t.Fatalf("FindMany: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("FindMany: expected 2 admin rows, got %d", len(rows))
	}
}

// TestPGAdapter_Update_And_Delete verifies that Update modifies a record and Delete removes it.
func TestPGAdapter_Update_And_Delete(t *testing.T) {
	db := newPGTestDB(t)
	createUsersTable(t, db, "pg_users_update")

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	if _, err := adp.Create(ctx, "pg_users_update", map[string]any{
		"id":    "u1",
		"email": "old@example.com",
		"name":  "Old Name",
		"role":  "user",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := adp.Update(ctx, "pg_users_update", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	}, map[string]any{"name": "New Name"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated == nil {
		t.Fatal("Update: expected updated record, got nil")
	}
	if updated["name"] != "New Name" {
		t.Errorf("Update: expected name=New Name, got %v", updated["name"])
	}

	// Delete and verify the record is gone.
	if err := adp.Delete(ctx, "pg_users_update", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	gone, err := adp.FindOne(ctx, "pg_users_update", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	})
	if err != nil {
		t.Fatalf("FindOne after delete: %v", err)
	}
	if gone != nil {
		t.Error("Delete: expected nil record after delete, got a record")
	}
}

// TestPGAdapter_FindMany_Pagination verifies that Limit and Offset work correctly.
func TestPGAdapter_FindMany_Pagination(t *testing.T) {
	db := newPGTestDB(t)
	createUsersTable(t, db, "pg_users_pagination")

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	seed := []map[string]any{
		{"id": "u1", "email": "a@a.com", "name": "Alice", "role": "user"},
		{"id": "u2", "email": "b@b.com", "name": "Bob", "role": "user"},
		{"id": "u3", "email": "c@c.com", "name": "Carol", "role": "user"},
		{"id": "u4", "email": "d@d.com", "name": "Dave", "role": "user"},
		{"id": "u5", "email": "e@e.com", "name": "Eve", "role": "user"},
	}
	if err := adp.CreateMany(ctx, "pg_users_pagination", seed); err != nil {
		t.Fatalf("CreateMany: %v", err)
	}

	// Page 1: rows 1–2.
	page1, err := adp.FindMany(ctx, "pg_users_pagination", adapter.Query{
		Limit:   2,
		Offset:  0,
		SortBy:  "id",
		SortDir: "asc",
	})
	if err != nil {
		t.Fatalf("FindMany page1: %v", err)
	}
	if len(page1) != 2 {
		t.Errorf("page1: expected 2 rows, got %d", len(page1))
	}

	// Page 2: rows 3–4.
	page2, err := adp.FindMany(ctx, "pg_users_pagination", adapter.Query{
		Limit:   2,
		Offset:  2,
		SortBy:  "id",
		SortDir: "asc",
	})
	if err != nil {
		t.Fatalf("FindMany page2: %v", err)
	}
	if len(page2) != 2 {
		t.Errorf("page2: expected 2 rows, got %d", len(page2))
	}

	// Offset past the end should return empty slice, not nil.
	beyond, err := adp.FindMany(ctx, "pg_users_pagination", adapter.Query{
		Limit:  2,
		Offset: 100,
	})
	if err != nil {
		t.Fatalf("FindMany beyond offset: %v", err)
	}
	if len(beyond) != 0 {
		t.Errorf("beyond offset: expected 0 rows, got %d", len(beyond))
	}

	// Count should reflect all rows regardless of pagination.
	count, err := adp.Count(ctx, "pg_users_pagination", adapter.Query{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 5 {
		t.Errorf("Count: expected 5, got %d", count)
	}
}

// TestPGAdapter_UpdateMany verifies that UpdateMany updates all matching rows.
func TestPGAdapter_UpdateMany(t *testing.T) {
	db := newPGTestDB(t)
	createUsersTable(t, db, "pg_users_updatemany")

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	seed := []map[string]any{
		{"id": "u1", "email": "a@a.com", "name": "A", "role": "user"},
		{"id": "u2", "email": "b@b.com", "name": "B", "role": "user"},
		{"id": "u3", "email": "c@c.com", "name": "C", "role": "admin"},
	}
	if err := adp.CreateMany(ctx, "pg_users_updatemany", seed); err != nil {
		t.Fatalf("CreateMany: %v", err)
	}

	if err := adp.UpdateMany(ctx, "pg_users_updatemany", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "user")},
	}, map[string]any{"role": "moderator"}); err != nil {
		t.Fatalf("UpdateMany: %v", err)
	}

	count, err := adp.Count(ctx, "pg_users_updatemany", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "moderator")},
	})
	if err != nil {
		t.Fatalf("Count moderators: %v", err)
	}
	if count != 2 {
		t.Errorf("UpdateMany: expected 2 moderators, got %d", count)
	}
}
