package anonymous_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/anonymous"
)

func newTestAuth(plugins ...plugin.Plugin) *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Anon Test",
		BasePath: "/auth",
		Secret:   "test-secret",
		Database: &betterauth.DatabaseConfig{Adapter: memory.New()},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled:           true,
			MinPasswordLength: 8,
			MaxPasswordLength: 128,
		},
		RateLimit: &betterauth.RateLimitConfig{Enabled: false},
		Plugins:   plugins,
	})
}

// signInAnonymous performs an anonymous sign-in and returns the response body and cookies.
func signInAnonymous(t *testing.T, handler http.Handler) (map[string]any, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-in/anonymous", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in/anonymous: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return body, rr.Result().Cookies()
}

func TestSignInAnonymous(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	body, cookies := signInAnonymous(t, handler)

	// Check user fields.
	user, ok := body["user"].(map[string]any)
	if !ok {
		t.Fatal("expected user in response")
	}

	if user["isAnonymous"] != true {
		t.Errorf("expected isAnonymous=true, got %v", user["isAnonymous"])
	}

	if user["id"] == nil || user["id"] == "" {
		t.Error("expected non-empty user ID")
	}

	// Check session exists.
	sess, ok := body["session"].(map[string]any)
	if !ok {
		t.Fatal("expected session in response")
	}
	if sess["token"] == nil || sess["token"] == "" {
		t.Error("expected non-empty session token")
	}

	// Check that a session cookie was set.
	var found bool
	for _, c := range cookies {
		if c.Name == "better-auth.session_token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}
}

func TestGetSessionAfterAnonymousSignIn(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	_, cookies := signInAnonymous(t, handler)

	// Use the session cookie to get the session.
	req := httptest.NewRequest(http.MethodGet, "/auth/get-session", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("get-session: expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["user"] == nil {
		t.Error("expected user in get-session response")
	}
	if body["session"] == nil {
		t.Error("expected session in get-session response")
	}
}

func TestLinkCredentials(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	_, cookies := signInAnonymous(t, handler)

	// Link with email and password.
	linkBody := map[string]string{
		"email":    "real@example.com",
		"password": "securepassword123",
		"name":     "Real User",
	}
	bodyBytes, _ := json.Marshal(linkBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/anonymous/link", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("anonymous/link: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	user, ok := body["user"].(map[string]any)
	if !ok {
		t.Fatal("expected user in response")
	}

	if user["isAnonymous"] != false {
		t.Errorf("expected isAnonymous=false after linking, got %v", user["isAnonymous"])
	}
	if user["email"] != "real@example.com" {
		t.Errorf("expected email=real@example.com, got %v", user["email"])
	}
	if user["name"] != "Real User" {
		t.Errorf("expected name=Real User, got %v", user["name"])
	}
}

func TestLinkDuplicateEmail(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	// Sign up a real user first.
	signUpBody := map[string]string{
		"email":    "taken@example.com",
		"password": "securepassword123",
		"name":     "Existing User",
	}
	bodyBytes, _ := json.Marshal(signUpBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Sign in as anonymous.
	_, cookies := signInAnonymous(t, handler)

	// Try to link with the same email.
	linkBody := map[string]string{
		"email":    "taken@example.com",
		"password": "anotherpassword123",
		"name":     "Another User",
	}
	bodyBytes, _ = json.Marshal(linkBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/anonymous/link", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate email, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

func TestLinkWhenNotAnonymous(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	// Sign up a real user.
	signUpBody := map[string]string{
		"email":    "realuser@example.com",
		"password": "securepassword123",
		"name":     "Real User",
	}
	bodyBytes, _ := json.Marshal(signUpBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	// Sign in to get a session cookie.
	signInBody := map[string]string{
		"email":    "realuser@example.com",
		"password": "securepassword123",
	}
	bodyBytes, _ = json.Marshal(signInBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/sign-in/email", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in: expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	cookies := rr.Result().Cookies()

	// Try to link (not anonymous).
	linkBody := map[string]string{
		"email":    "another@example.com",
		"password": "anotherpassword123",
		"name":     "Another",
	}
	bodyBytes, _ = json.Marshal(linkBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/anonymous/link", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-anonymous user, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["code"] != "NOT_ANONYMOUS" {
		t.Errorf("expected code=NOT_ANONYMOUS, got %v", body["code"])
	}
}

func TestLinkWithoutAuth(t *testing.T) {
	anonPlugin := anonymous.New(anonymous.Options{})
	auth := newTestAuth(anonPlugin)
	handler := auth.Handler()

	linkBody := map[string]string{
		"email":    "test@example.com",
		"password": "securepassword123",
	}
	bodyBytes, _ := json.Marshal(linkBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/anonymous/link", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d; body: %s", rr.Code, rr.Body.String())
	}
}
