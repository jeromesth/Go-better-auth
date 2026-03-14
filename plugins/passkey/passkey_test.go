package passkey_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/passkey"
)

func newTestAuth(t *testing.T, p *passkey.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Passkey Test",
		BasePath: "/api/auth",
		BaseURL:  "http://localhost:3000",
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

func getWith(t *testing.T, h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func deleteWith(t *testing.T, h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
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
		"email": "user@example.com", "password": "password123", "name": "Test User",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func newPasskeyPlugin() *passkey.Plugin {
	return passkey.New(&passkey.Options{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000"},
	})
}

// --- Tests ---

func TestPlugin_ID(t *testing.T) {
	p := newPasskeyPlugin()
	if p.ID() != "passkey" {
		t.Errorf("expected ID=passkey, got %s", p.ID())
	}
}

func TestPlugin_Schema(t *testing.T) {
	p := newPasskeyPlugin()
	// Need to trigger SetAuth to initialize, but Schema() is available before.
	schema := p.Schema()
	if _, ok := schema["passkey"]; !ok {
		t.Fatal("expected 'passkey' table in schema")
	}

	fields := schema["passkey"].Fields
	fieldNames := make(map[string]bool)
	for _, f := range fields {
		fieldNames[f.Name] = true
	}

	required := []string{"id", "user_id", "credential_id", "public_key", "counter", "created_at"}
	for _, name := range required {
		if !fieldNames[name] {
			t.Errorf("missing required field %q in schema", name)
		}
	}

	optional := []string{"device_type", "backed_up", "transports", "name"}
	for _, name := range optional {
		if !fieldNames[name] {
			t.Errorf("missing optional field %q in schema", name)
		}
	}
}

func TestPlugin_Endpoints(t *testing.T) {
	p := newPasskeyPlugin()
	// Use a dummy auth to initialize endpoints.
	_, _ = newTestAuth(t, p)

	endpoints := p.Endpoints()
	if len(endpoints) != 6 {
		t.Fatalf("expected 6 endpoints, got %d", len(endpoints))
	}

	expectedPaths := map[string]string{
		"/passkey/register/begin":  http.MethodPost,
		"/passkey/register/finish": http.MethodPost,
		"/passkey/login/begin":     http.MethodPost,
		"/passkey/login/finish":    http.MethodPost,
		"/passkey/list":            http.MethodGet,
		"/passkey/":                http.MethodDelete,
	}

	for _, ep := range endpoints {
		expectedMethod, ok := expectedPaths[ep.Path]
		if !ok {
			t.Errorf("unexpected endpoint path: %s", ep.Path)
			continue
		}
		if ep.Method != expectedMethod {
			t.Errorf("endpoint %s: expected method %s, got %s", ep.Path, expectedMethod, ep.Method)
		}
	}
}

func TestRegisterBegin_RequiresAuth(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/passkey/register/begin", nil, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestRegisterBegin_ReturnsOptions(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	rr := postJSON(t, h, "/api/auth/passkey/register/begin", nil, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("register begin: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Should contain publicKey with rp, user, challenge, etc.
	publicKey, ok := resp["publicKey"].(map[string]any)
	if !ok {
		t.Fatal("expected publicKey in response")
	}
	if publicKey["challenge"] == nil {
		t.Error("expected challenge in publicKey")
	}
	rp, _ := publicKey["rp"].(map[string]any)
	if rp == nil {
		t.Fatal("expected rp in publicKey")
	}
	if rp["name"] != "Test App" {
		t.Errorf("expected rp.name='Test App', got %v", rp["name"])
	}
	if rp["id"] != "localhost" {
		t.Errorf("expected rp.id='localhost', got %v", rp["id"])
	}
}

func TestRegisterFinish_RequiresAuth(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/passkey/register/finish", nil, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestRegisterFinish_NoPendingChallenge(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Try to finish without beginning.
	rr := postJSON(t, h, "/api/auth/passkey/register/finish", map[string]string{}, cookies)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without pending challenge, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestLoginBegin_ReturnsOptions(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	// Discoverable login (no email) should work.
	rr := postJSON(t, h, "/api/auth/passkey/login/begin", nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("login begin: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	publicKey, ok := resp["publicKey"].(map[string]any)
	if !ok {
		t.Fatal("expected publicKey in response")
	}
	if publicKey["challenge"] == nil {
		t.Error("expected challenge in publicKey")
	}
	if publicKey["rpId"] != "localhost" {
		t.Errorf("expected rpId='localhost', got %v", publicKey["rpId"])
	}
}

func TestLoginBegin_WithEmail_NoPasskeys(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)
	signUp(t, h) // create user but no passkeys

	rr := postJSON(t, h, "/api/auth/passkey/login/begin", map[string]string{
		"email": "user@example.com",
	}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for user with no passkeys, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["code"] != "NO_PASSKEYS" {
		t.Errorf("expected code=NO_PASSKEYS, got %v", resp["code"])
	}
}

func TestLoginBegin_WithEmail_UserNotFound(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/passkey/login/begin", map[string]string{
		"email": "nobody@example.com",
	}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for nonexistent user, got %d", rr.Code)
	}
}

func TestLoginFinish_NoPendingChallenge(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	// Try to finish without beginning -- body won't parse as valid assertion.
	rr := postJSON(t, h, "/api/auth/passkey/login/finish", map[string]string{"foo": "bar"}, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid assertion, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestList_RequiresAuth(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	rr := getWith(t, h, "/api/auth/passkey/list", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestList_EmptyList(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	rr := getWith(t, h, "/api/auth/passkey/list", cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	passkeys, _ := resp["passkeys"].([]any)
	if len(passkeys) != 0 {
		t.Errorf("expected empty passkey list, got %d", len(passkeys))
	}
}

func TestDelete_RequiresAuth(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	rr := deleteWith(t, h, "/api/auth/passkey/some-id", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rr.Code)
	}
}

func TestDelete_NonexistentPasskey(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Deleting a nonexistent passkey should still return success (idempotent).
	rr := deleteWith(t, h, "/api/auth/passkey/nonexistent-id", cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent delete, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRegisterBegin_MethodNotAllowed(t *testing.T) {
	p := newPasskeyPlugin()
	_, h := newTestAuth(t, p)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/passkey/register/begin", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET on POST endpoint, got %d", rr.Code)
	}
}

func TestWebAuthnUser_Interface(t *testing.T) {
	// Verify that WebAuthnUser satisfies the interface contract.
	u := &passkey.WebAuthnUser{}
	_ = u.WebAuthnID()
	_ = u.WebAuthnName()
	_ = u.WebAuthnDisplayName()
	_ = u.WebAuthnCredentials()
}
