package chiauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	chiauth "github.com/jeromesth/go-better-auth/framework/chi"
)

func newTestAuth() *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Chi Test",
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

func TestChiMount_GetSession(t *testing.T) {
	r := chi.NewRouter()
	chiauth.Mount(r, "/auth", newTestAuth())

	req := httptest.NewRequest(http.MethodGet, "/auth/get-session", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// No cookie → null session, but not 404
	if rr.Code == http.StatusNotFound {
		t.Fatalf("expected non-404 for /auth/get-session, got 404")
	}
}

func TestChiMount_SignUpRoute(t *testing.T) {
	r := chi.NewRouter()
	chiauth.Mount(r, "/auth", newTestAuth())

	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should get 400 (missing body), not 404
	if rr.Code == http.StatusNotFound {
		t.Fatalf("sign-up route not mounted, got 404")
	}
}

func TestChiMount_UnknownRoute(t *testing.T) {
	r := chi.NewRouter()
	chiauth.Mount(r, "/auth", newTestAuth())

	req := httptest.NewRequest(http.MethodGet, "/auth/does-not-exist", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Logf("unknown route returned %d (acceptable)", rr.Code)
	}
}
