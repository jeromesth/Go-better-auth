package fiberauth

import (
	"io"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
)

func newTestAuth() *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Fiber Test",
		BasePath: "/auth",
		Secret:   "test-secret",
		Database: &betterauth.DatabaseConfig{Adapter: memory.New()},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled:           true,
			MinPasswordLength: 8,
			MaxPasswordLength: 128,
		},
		RateLimit: &betterauth.RateLimitConfig{Enabled: false},
	})
}

func TestFiberMount_GetSession(t *testing.T) {
	app := fiber.New()
	Mount(app, "/auth", newTestAuth())

	req, _ := http.NewRequest(http.MethodGet, "/auth/get-session", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// No cookie -> null session, but not 404
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("expected non-404 for /auth/get-session, got 404")
	}
}

func TestFiberMount_SignUpRoute(t *testing.T) {
	app := fiber.New()
	Mount(app, "/auth", newTestAuth())

	req, _ := http.NewRequest(http.MethodPost, "/auth/sign-up/email", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Should get 400 (missing body), not 404
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("sign-up route not mounted, got 404")
	}
}

func TestFiberMount_UnknownRoute(t *testing.T) {
	app := fiber.New()
	Mount(app, "/auth", newTestAuth())

	req, _ := http.NewRequest(http.MethodGet, "/auth/does-not-exist", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Logf("unknown route returned %d (acceptable)", resp.StatusCode)
	}
}
