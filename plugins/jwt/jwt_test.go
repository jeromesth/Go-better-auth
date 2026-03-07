package jwt_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	jwtplugin "github.com/jeromesth/go-better-auth/plugins/jwt"
)

func newTestAuth(t *testing.T, p *jwtplugin.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "JWT Test",
		BasePath: "/api/auth",
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

func postJSON(t *testing.T, h http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func signUp(t *testing.T, h http.Handler) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    "user@example.com",
		"password": "password123",
		"name":     "Test User",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func TestJWTPlugin_SignInAttachesJWT(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{
		Secret: []byte("super-secret-key"),
		Expiry: time.Hour,
	})
	_, h := newTestAuth(t, p)

	// Sign up first
	postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email": "user@example.com", "password": "password123", "name": "Test",
	}, nil)

	// Sign in
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email": "user@example.com", "password": "password123",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", rr.Code, rr.Body.String())
	}

	// JWT should be in Authorization header
	auth := rr.Header().Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("expected Authorization: Bearer <token>, got %q", auth)
	}
}

func TestJWTPlugin_SignUpAttachesJWT(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{
		Secret: []byte("super-secret-key"),
		Expiry: time.Hour,
	})
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email": "user@example.com", "password": "password123", "name": "Test",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}

	auth := rr.Header().Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Errorf("expected Authorization: Bearer <token> on sign-up, got %q", auth)
	}
}

func TestJWTPlugin_VerifyValidToken(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{
		Secret: []byte("super-secret-key"),
		Expiry: time.Hour,
		Issuer: "test-app",
	})
	_, h := newTestAuth(t, p)
	_ = signUp(t, h)

	// Sign in to get JWT
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email": "user@example.com", "password": "password123",
	}, nil)
	token := strings.TrimPrefix(rr.Header().Get("Authorization"), "Bearer ")
	if token == "" {
		t.Fatal("no JWT in sign-in response")
	}

	// Verify the JWT
	req := httptest.NewRequest(http.MethodGet, "/api/auth/jwt/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rrv := httptest.NewRecorder()
	h.ServeHTTP(rrv, req)

	if rrv.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rrv.Code, rrv.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rrv.Body).Decode(&resp)
	if resp["sub"] == nil && resp["user_id"] == nil {
		t.Errorf("expected sub or user_id in verify response, got %v", resp)
	}
}

func TestJWTPlugin_VerifyInvalidToken(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{
		Secret: []byte("super-secret-key"),
		Expiry: time.Hour,
	})
	_, h := newTestAuth(t, p)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/jwt/verify", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestJWTPlugin_VerifyNoToken(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{
		Secret: []byte("super-secret-key"),
		Expiry: time.Hour,
	})
	_, h := newTestAuth(t, p)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/jwt/verify", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
}

func TestJWTPlugin_ID(t *testing.T) {
	p := jwtplugin.New(jwtplugin.Options{Secret: []byte("key")})
	if p.ID() != "jwt" {
		t.Errorf("expected ID=jwt, got %s", p.ID())
	}
}
