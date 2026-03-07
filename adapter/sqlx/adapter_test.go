package sqlxadapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	sqlxadapter "github.com/jeromesth/go-better-auth/adapter/sqlx"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func newTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSqlxAdapter_CreateAndFindOne(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, name TEXT, created_at DATETIME)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	now := time.Now().UTC()
	rec, err := adp.Create(ctx, "user", map[string]any{
		"id":         "u1",
		"email":      "test@example.com",
		"name":       "Test User",
		"created_at": now,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec["id"] != "u1" {
		t.Errorf("expected id=u1, got %v", rec["id"])
	}

	found, err := adp.FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	})
	if err != nil {
		t.Fatalf("FindOne: %v", err)
	}
	if found == nil {
		t.Fatal("expected record, got nil")
	}
	if found["email"] != "test@example.com" {
		t.Errorf("expected email test@example.com, got %v", found["email"])
	}
}

func TestSqlxAdapter_FindMany(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, role TEXT)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	for i, r := range []string{"admin", "user", "admin"} {
		id := []string{"u1", "u2", "u3"}[i]
		email := []string{"a@a.com", "b@b.com", "c@c.com"}[i]
		_, err := adp.Create(ctx, "user", map[string]any{"id": id, "email": email, "role": r})
		if err != nil {
			t.Fatal(err)
		}
	}

	rows, err := adp.FindMany(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "admin")},
	})
	if err != nil {
		t.Fatalf("FindMany: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(rows))
	}
}

func TestSqlxAdapter_Update(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, name TEXT)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	_, err := adp.Create(ctx, "user", map[string]any{"id": "u1", "email": "old@example.com", "name": "Old"})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := adp.Update(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	}, map[string]any{"name": "New"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated == nil {
		t.Fatal("expected updated record, got nil")
	}

	found, _ := adp.FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	})
	if found["name"] != "New" {
		t.Errorf("expected name=New, got %v", found["name"])
	}
}

func TestSqlxAdapter_Delete(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	_, err := adp.Create(ctx, "user", map[string]any{"id": "u1", "email": "x@x.com"})
	if err != nil {
		t.Fatal(err)
	}

	if err := adp.Delete(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	found, _ := adp.FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", "u1")},
	})
	if found != nil {
		t.Error("expected nil after delete")
	}
}

func TestSqlxAdapter_Count(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, role TEXT)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	for _, r := range []struct{ id, role string }{{"u1", "admin"}, {"u2", "user"}, {"u3", "admin"}} {
		_, _ = adp.Create(ctx, "user", map[string]any{"id": r.id, "email": r.id + "@x.com", "role": r.role})
	}

	count, err := adp.Count(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "admin")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected count=2, got %d", count)
	}
}

func TestSqlxAdapter_CreateManyAndDeleteMany(t *testing.T) {
	db := newTestDB(t)
	db.MustExec(`CREATE TABLE user (id TEXT PRIMARY KEY, email TEXT, role TEXT)`)

	adp := sqlxadapter.New(db)
	ctx := context.Background()

	records := []map[string]any{
		{"id": "u1", "email": "a@a.com", "role": "user"},
		{"id": "u2", "email": "b@b.com", "role": "user"},
		{"id": "u3", "email": "c@c.com", "role": "admin"},
	}
	if err := adp.CreateMany(ctx, "user", records); err != nil {
		t.Fatal(err)
	}

	count, _ := adp.Count(ctx, "user", adapter.Query{})
	if count != 3 {
		t.Errorf("expected 3 records, got %d", count)
	}

	if err := adp.DeleteMany(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("role", "user")},
	}); err != nil {
		t.Fatal(err)
	}

	count, _ = adp.Count(ctx, "user", adapter.Query{})
	if count != 1 {
		t.Errorf("expected 1 record after delete, got %d", count)
	}
}
