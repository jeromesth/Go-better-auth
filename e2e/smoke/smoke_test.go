// Package smoke contains quick smoke tests that validate core auth functionality
// works end-to-end with minimal setup.
package smoke_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
)

func newAuth() *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Smoke Test",
		BasePath: "/api/auth",
		Secret:   "smoke-test-secret",
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
	})
}

func post(handler http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func get(handler http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestSmokeSignUpSignInSignOut validates the full authentication lifecycle.
func TestSmokeSignUpSignInSignOut(t *testing.T) {
	auth := newAuth()
	h := auth.Handler()

	// 1. Sign up
	rr := post(h, "/api/auth/sign-up/email", map[string]string{
		"email": "smoke@example.com", "password": "smoketest123", "name": "Smoke User",
	}, nil)
	if rr.Code != 200 {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie after sign-up")
	}

	// 2. Get session (should be authenticated)
	rr = get(h, "/api/auth/get-session", cookies)
	if rr.Code != 200 {
		t.Fatalf("get-session failed: %d", rr.Code)
	}
	var sess map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&sess)
	if sess["user"] == nil || sess["session"] == nil {
		t.Fatal("expected user and session in response")
	}

	// 3. Sign out
	rr = post(h, "/api/auth/sign-out", nil, cookies)
	if rr.Code != 200 {
		t.Fatalf("sign-out failed: %d", rr.Code)
	}

	// 4. Session should be gone
	rr = get(h, "/api/auth/get-session", cookies)
	var after any
	_ = json.NewDecoder(rr.Body).Decode(&after)
	if after != nil {
		t.Fatal("expected null session after sign-out")
	}

	// 5. Sign back in
	rr = post(h, "/api/auth/sign-in/email", map[string]string{
		"email": "smoke@example.com", "password": "smoketest123",
	}, nil)
	if rr.Code != 200 {
		t.Fatalf("sign-in failed: %d %s", rr.Code, rr.Body.String())
	}
}

// TestSmokeAuthServerStarts validates the auth server can be created and serves the handler.
func TestSmokeAuthServerStarts(t *testing.T) {
	auth := newAuth()
	if auth.Handler() == nil {
		t.Fatal("expected non-nil handler")
	}
	if auth.Options().AppName != "Smoke Test" {
		t.Fatalf("unexpected app name: %s", auth.Options().AppName)
	}
}
