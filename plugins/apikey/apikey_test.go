package apikey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/apikey"
)

func newTestAuth(t *testing.T, p *apikey.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "APIKey Test",
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

func getWith(t *testing.T, h http.Handler, path string, cookies []*http.Cookie, apiKeyHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if apiKeyHeader != "" {
		req.Header.Set("Authorization", apiKeyHeader)
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
		"email": "user@example.com", "password": "password123", "name": "Test",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func TestAPIKeyPlugin_ID(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	if p.ID() != "apikey" {
		t.Errorf("expected ID=apikey, got %s", p.ID())
	}
}

func TestAPIKey_CreateAndList(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Create a key
	rr := postJSON(t, h, "/api/auth/api-key/create", map[string]string{"name": "my key"}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var createResp map[string]any
	json.NewDecoder(rr.Body).Decode(&createResp)

	// Full key should be present at creation
	fullKey, _ := createResp["key"].(string)
	if !strings.HasPrefix(fullKey, "ak_") {
		t.Errorf("expected key to start with ak_, got %q", fullKey)
	}

	// List keys — should appear without plaintext
	rr2 := getWith(t, h, "/api/auth/api-key/list", cookies, "")
	if rr2.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr2.Code, rr2.Body.String())
	}
	var listResp map[string]any
	json.NewDecoder(rr2.Body).Decode(&listResp)
	keys, _ := listResp["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in list, got %d", len(keys))
	}
	keyEntry := keys[0].(map[string]any)
	// Plaintext key must NOT appear in list
	if keyEntry["key"] != nil {
		t.Error("plaintext key must not appear in list response")
	}
	if keyEntry["name"] != "my key" {
		t.Errorf("expected name='my key', got %v", keyEntry["name"])
	}
}

func TestAPIKey_Verify(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Create key
	rr := postJSON(t, h, "/api/auth/api-key/create", map[string]string{"name": "svc"}, cookies)
	var createResp map[string]any
	json.NewDecoder(rr.Body).Decode(&createResp)
	fullKey := createResp["key"].(string)

	// Verify with the key
	rr2 := postJSON(t, h, "/api/auth/api-key/verify", nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/api-key/verify", nil)
	req.Header.Set("Authorization", "Bearer "+fullKey)
	rrv := httptest.NewRecorder()
	h.ServeHTTP(rrv, req)

	if rrv.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rrv.Code, rrv.Body.String())
	}
	var verifyResp map[string]any
	json.NewDecoder(rrv.Body).Decode(&verifyResp)
	if verifyResp["valid"] != true {
		t.Errorf("expected valid=true, got %v", verifyResp["valid"])
	}
	_ = rr2
}

func TestAPIKey_VerifyInvalidKey(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	_, h := newTestAuth(t, p)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/api-key/verify", nil)
	req.Header.Set("Authorization", "Bearer ak_invalid")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid key, got %d", rr.Code)
	}
}

func TestAPIKey_Revoke(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	_, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Create key
	rr := postJSON(t, h, "/api/auth/api-key/create", map[string]string{"name": "to-revoke"}, cookies)
	var cr map[string]any
	json.NewDecoder(rr.Body).Decode(&cr)
	keyID := cr["id"].(string)
	fullKey := cr["key"].(string)

	// Revoke it
	rrd := deleteWith(t, h, "/api/auth/api-key/"+keyID, cookies)
	if rrd.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rrd.Code, rrd.Body.String())
	}

	// Verify should fail
	req := httptest.NewRequest(http.MethodPost, "/api/auth/api-key/verify", nil)
	req.Header.Set("Authorization", "Bearer "+fullKey)
	rrv := httptest.NewRecorder()
	h.ServeHTTP(rrv, req)
	if rrv.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d", rrv.Code)
	}
}

func TestAPIKey_RequiresAuth(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/api-key/create", map[string]string{"name": "x"}, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rr.Code)
	}
}

// TestWithoutCancel_SurvivesParentCancellation documents the assumption that
// context.WithoutCancel relies on: a detached context must not inherit the
// parent's cancellation. This is the property the goroutine in handleVerify
// depends on — if it ever broke, the last-used update would silently drop.
func TestWithoutCancel_SurvivesParentCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ctx.Err(); err == nil {
		t.Fatal("parent ctx should be cancelled")
	}
	detached := context.WithoutCancel(ctx)
	if err := detached.Err(); err != nil {
		t.Fatalf("detached ctx should not be cancelled, got %v", err)
	}
}

func TestVerifyAPIKey_UpdatesLastUsed(t *testing.T) {
	t.Parallel()
	p := apikey.New(apikey.Options{Prefix: "ak_"})
	auth, h := newTestAuth(t, p)
	cookies := signUp(t, h)

	// Create a key
	rr := postJSON(t, h, "/api/auth/api-key/create", map[string]string{"name": "test"}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var createResp map[string]any
	json.NewDecoder(rr.Body).Decode(&createResp)
	keyID := createResp["id"].(string)
	fullKey := createResp["key"].(string)

	// Verify the key (this triggers the goroutine)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/api-key/verify", nil)
	req.Header.Set("Authorization", "Bearer "+fullKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}

	// Give goroutine time to complete
	time.Sleep(50 * time.Millisecond)

	// Check last_used_at was updated via the raw adapter
	adp := auth.InternalAdapter().Adapter()
	records, err := adp.FindMany(t.Context(), "apiKey", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", keyID)},
	})
	if err != nil {
		t.Fatalf("FindMany: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0]["last_used_at"] == nil {
		t.Error("last_used_at should be set after verify, but was nil")
	}
}
