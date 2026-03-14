package username_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/username"
)

// --- Test helpers ---

func newTestAuth(p *username.Plugin) http.Handler {
	auth := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Username Test",
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
	return auth.Handler()
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

func decodeResp(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

// --- Tests ---

func TestSignUpHappyPath(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice@test.com",
		"password": "password123",
		"name":     "Alice",
	}, nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)

	// Verify user in response.
	user, ok := resp["user"].(map[string]any)
	if !ok {
		t.Fatal("expected user in response")
	}
	if user["email"] != "alice@test.com" {
		t.Errorf("expected email alice@test.com, got %v", user["email"])
	}
	if user["name"] != "Alice" {
		t.Errorf("expected name Alice, got %v", user["name"])
	}

	// Verify session in response.
	sess, ok := resp["session"].(map[string]any)
	if !ok {
		t.Fatal("expected session in response")
	}
	if sess["token"] == nil || sess["token"] == "" {
		t.Error("expected session token to be non-empty")
	}

	// Verify session cookie is set.
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if strings.Contains(c.Name, "session") || strings.Contains(c.Name, "token") {
			found = true
			break
		}
	}
	if !found && len(cookies) == 0 {
		t.Error("expected at least one cookie to be set")
	}
}

func TestSignUpDefaultName(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "bob",
		"email":    "bob@test.com",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	user, _ := resp["user"].(map[string]any)
	// When no name is provided, the username is used as the name.
	if user["name"] != "bob" {
		t.Errorf("expected name to default to username 'bob', got %v", user["name"])
	}
}

func TestSignInHappyPath(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	// First, sign up.
	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice@test.com",
		"password": "password123",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}

	// Now sign in with username.
	rr = postJSON(t, h, "/api/auth/sign-in/username", map[string]string{
		"username": "alice",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["user"] == nil {
		t.Error("expected user in sign-in response")
	}
	if resp["session"] == nil {
		t.Error("expected session in sign-in response")
	}
}

func TestUsernameTooShort(t *testing.T) {
	p := username.New(username.Options{MinLength: 3})
	h := newTestAuth(p)

	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "ab",
		"email":    "short@test.com",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_USERNAME" {
		t.Errorf("expected code INVALID_USERNAME, got %v", resp["code"])
	}
}

func TestUsernameTooLong(t *testing.T) {
	p := username.New(username.Options{MaxLength: 10})
	h := newTestAuth(p)

	longName := strings.Repeat("a", 11)
	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": longName,
		"email":    "long@test.com",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_USERNAME" {
		t.Errorf("expected code INVALID_USERNAME, got %v", resp["code"])
	}
}

func TestDuplicateUsername(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	// Sign up first user.
	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice@test.com",
		"password": "password123",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("first sign-up failed: %d %s", rr.Code, rr.Body.String())
	}

	// Attempt duplicate username with different email.
	rr = postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice2@test.com",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "USERNAME_TAKEN" {
		t.Errorf("expected code USERNAME_TAKEN, got %v", resp["code"])
	}
}

func TestDuplicateEmail(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	// Sign up first user.
	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice@test.com",
		"password": "password123",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("first sign-up failed: %d %s", rr.Code, rr.Body.String())
	}

	// Attempt different username but same email.
	rr = postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "bob",
		"email":    "alice@test.com",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "EMAIL_ALREADY_USED" {
		t.Errorf("expected code EMAIL_ALREADY_USED, got %v", resp["code"])
	}
}

func TestMissingFields(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	t.Run("missing username", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
			"email":    "nouser@test.com",
			"password": "password123",
		}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing email", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
			"username": "nomail",
			"password": "password123",
		}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "MISSING_EMAIL" {
			t.Errorf("expected code MISSING_EMAIL, got %v", resp["code"])
		}
	})

	t.Run("missing password", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
			"username": "nopass",
			"email":    "nopass@test.com",
		}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "MISSING_PASSWORD" {
			t.Errorf("expected code MISSING_PASSWORD, got %v", resp["code"])
		}
	})
}

func TestSignInWrongPassword(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	// Sign up.
	rr := postJSON(t, h, "/api/auth/sign-up/username", map[string]string{
		"username": "alice",
		"email":    "alice@test.com",
		"password": "password123",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}

	// Sign in with wrong password.
	rr = postJSON(t, h, "/api/auth/sign-in/username", map[string]string{
		"username": "alice",
		"password": "wrongpassword",
	}, nil)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_CREDENTIALS" {
		t.Errorf("expected code INVALID_CREDENTIALS, got %v", resp["code"])
	}
}

func TestSignInUnknownUsername(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	rr := postJSON(t, h, "/api/auth/sign-in/username", map[string]string{
		"username": "nonexistent",
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_CREDENTIALS" {
		t.Errorf("expected code INVALID_CREDENTIALS, got %v", resp["code"])
	}
}

func TestSignInMissingUsername(t *testing.T) {
	p := username.New(username.Options{})
	h := newTestAuth(p)

	rr := postJSON(t, h, "/api/auth/sign-in/username", map[string]string{
		"password": "password123",
	}, nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "MISSING_USERNAME" {
		t.Errorf("expected code MISSING_USERNAME, got %v", resp["code"])
	}
}
