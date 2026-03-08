package echoauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	betterauth "github.com/jeromesth/go-better-auth"
)

func TestMount(t *testing.T) {
	auth := betterauth.New(betterauth.BetterAuthOptions{
		BaseURL: "http://localhost:3000",
	})

	e := echo.New()
	Mount(e, "/api/auth", auth)

	// GET /api/auth/get-session is a valid endpoint registered by the auth handler.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/get-session", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// The handler should match the route and return a non-404 status.
	if rec.Code == http.StatusNotFound {
		t.Errorf("expected route to be registered, got 404")
	}
}
