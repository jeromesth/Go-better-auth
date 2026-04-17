package magiclink_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/magiclink"
	testutil "github.com/jeromesth/go-better-auth/testutil"
)

const basePath = "/api/auth"

func newTestAuth(t *testing.T, p *magiclink.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "MagicLink Test",
		BasePath: basePath,
		Secret:   "test-secret",
		Database: &betterauth.DatabaseConfig{
			Adapter: memory.New(),
		},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled:           true,
			MinPasswordLength: 8,
			MaxPasswordLength: 128,
			AutoSignIn:        true,
		},
		RateLimit: &betterauth.RateLimitConfig{Enabled: false},
		Plugins:   []plugin.Plugin{p},
	})
	return a, a.Handler()
}

func registerUser(t *testing.T, h http.Handler, email string) {
	t.Helper()
	rr := testutil.PostJSON(t, h, basePath+"/sign-up/email", map[string]string{
		"email": email, "password": "password123", "name": "Test",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}
}

func TestMagicLinkPlugin_ID(t *testing.T) {
	t.Parallel()
	p := magiclink.New(magiclink.Options{
		SendMagicLink: func(_ context.Context, _, _ string) error { return nil },
		BaseURL:       "http://localhost",
	})
	if p.ID() != "magiclink" {
		t.Errorf("expected ID=magiclink, got %s", p.ID())
	}
}

func TestMagicLink_SendAndVerify(t *testing.T) {
	t.Parallel()
	var capturedLink string
	p := magiclink.New(magiclink.Options{
		SendMagicLink: func(_ context.Context, _, link string) error {
			capturedLink = link
			return nil
		},
		BaseURL: "http://localhost/api/auth",
	})
	_, h := newTestAuth(t, p)

	// Register a user first
	registerUser(t, h, "magic@example.com")

	// Request magic link
	rr := testutil.PostJSON(t, h, basePath+"/magic-link/send", map[string]string{
		"email": "magic@example.com",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("send: %d %s", rr.Code, rr.Body.String())
	}
	if capturedLink == "" {
		t.Fatal("SendMagicLink was not called or capturedLink is empty")
	}

	// Extract token from link
	tokenIdx := strings.Index(capturedLink, "token=")
	if tokenIdx < 0 {
		t.Fatalf("no token= in link: %q", capturedLink)
	}
	token := capturedLink[tokenIdx+6:]
	// Strip any trailing query params
	if ampIdx := strings.Index(token, "&"); ampIdx >= 0 {
		token = token[:ampIdx]
	}

	// Verify the magic link
	req := httptest.NewRequest(http.MethodGet, basePath+"/magic-link/verify?token="+token, nil)
	rrv := httptest.NewRecorder()
	h.ServeHTTP(rrv, req)

	if rrv.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rrv.Code, rrv.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rrv.Body).Decode(&resp)
	if resp["user"] == nil {
		t.Error("expected user in verify response")
	}
	if resp["session"] == nil {
		t.Error("expected session in verify response")
	}
}

func TestMagicLink_UnknownEmail(t *testing.T) {
	t.Parallel()
	called := false
	p := magiclink.New(magiclink.Options{
		SendMagicLink: func(_ context.Context, _, _ string) error {
			called = true
			return nil
		},
		BaseURL: "http://localhost",
	})
	_, h := newTestAuth(t, p)

	rr := testutil.PostJSON(t, h, basePath+"/magic-link/send", map[string]string{
		"email": "nobody@example.com",
	}, nil)
	// Should return 200 (don't leak user existence) and not call sender
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email, got %d", rr.Code)
	}
	if called {
		t.Error("SendMagicLink should not be called for unknown email")
	}
}

func TestMagicLink_InvalidToken(t *testing.T) {
	t.Parallel()
	p := magiclink.New(magiclink.Options{
		SendMagicLink: func(_ context.Context, _, _ string) error { return nil },
		BaseURL:       "http://localhost",
	})
	_, h := newTestAuth(t, p)

	req := httptest.NewRequest(http.MethodGet, basePath+"/magic-link/verify?token=invalidtoken", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMagicLink_MissingEmail(t *testing.T) {
	t.Parallel()
	p := magiclink.New(magiclink.Options{
		SendMagicLink: func(_ context.Context, _, _ string) error { return nil },
		BaseURL:       "http://localhost",
	})
	_, h := newTestAuth(t, p)

	rr := testutil.PostJSON(t, h, basePath+"/magic-link/send", map[string]string{}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d", rr.Code)
	}
}
