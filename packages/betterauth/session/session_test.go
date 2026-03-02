package session_test

import (
	"context"
	"testing"

	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter/memory"
	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

func TestCreateAndFindSession(t *testing.T) {
	mem := memory.New()
	mgr := session.NewManager(mem, 604800, 86400)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, "user1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("expected non-empty token")
	}

	found, err := mgr.FindByToken(ctx, sess.Token)
	if err != nil {
		t.Fatalf("FindByToken error: %v", err)
	}
	if found == nil {
		t.Fatal("expected session to be found")
	}
	if found.UserID != "user1" {
		t.Fatalf("expected UserID %q, got %q", "user1", found.UserID)
	}
}

func TestRevokeSession(t *testing.T) {
	mem := memory.New()
	mgr := session.NewManager(mem, 604800, 86400)
	ctx := context.Background()

	sess, _ := mgr.Create(ctx, "user2", "", "")
	if err := mgr.Revoke(ctx, sess.Token); err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	found, err := mgr.FindByToken(ctx, sess.Token)
	if err != nil {
		t.Fatalf("FindByToken error: %v", err)
	}
	if found != nil {
		t.Fatal("expected session to be deleted")
	}
}
