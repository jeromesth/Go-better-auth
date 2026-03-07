package ginauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	ginauth "github.com/jeromesth/go-better-auth/framework/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestAuth() *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Gin Test",
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

func TestGinMount_GetSession(t *testing.T) {
	r := gin.New()
	ginauth.Mount(r, "/auth", newTestAuth())

	req := httptest.NewRequest(http.MethodGet, "/auth/get-session", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code == http.StatusNotFound {
		t.Fatalf("expected non-404 for /auth/get-session, got 404")
	}
}

func TestGinMount_SignUpRoute(t *testing.T) {
	r := gin.New()
	ginauth.Mount(r, "/auth", newTestAuth())

	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code == http.StatusNotFound {
		t.Fatalf("sign-up route not mounted, got 404")
	}
}
