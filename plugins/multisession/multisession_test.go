package multisession_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/multisession"
)

// --- Test helpers ---

func newTestAuth(msPlugin *multisession.Plugin) *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "MultiSession Test",
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
		Plugins:   []plugin.Plugin{msPlugin},
	})
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

func getJSON(t *testing.T, h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getJSONWithUA(t *testing.T, h http.Handler, path string, cookies []*http.Cookie, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("User-Agent", userAgent)
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

func signUpUser(t *testing.T, h http.Handler, email, password, name string) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func signInUser(t *testing.T, h http.Handler, email, password string) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func signUpUserWithUA(t *testing.T, h http.Handler, email, password, name, userAgent string) []*http.Cookie {
	t.Helper()
	b, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-up/email", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func signInUserWithUA(t *testing.T, h http.Handler, email, password, userAgent string) []*http.Cookie {
	t.Helper()
	b, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

// --- Tests ---

func TestListSessions(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	// Sign up creates session 1.
	cookies1 := signUpUser(t, h, "user@example.com", "password123", "Test User")

	// Sign in creates session 2.
	cookies2 := signInUser(t, h, "user@example.com", "password123")

	// List sessions from session 1.
	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions failed: %d %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	sessions, ok := resp["sessions"].([]any)
	if !ok {
		t.Fatal("expected sessions array in response")
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	// Verify one is marked as current.
	currentCount := 0
	for _, s := range sessions {
		sess := s.(map[string]any)
		if isCurrent, ok := sess["isCurrent"].(bool); ok && isCurrent {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Errorf("expected exactly 1 current session, got %d", currentCount)
	}

	// List from session 2 should also show 2 sessions, but with different current.
	rr2 := getJSON(t, h, "/api/auth/multi-session/list", cookies2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("list sessions from session 2 failed: %d %s", rr2.Code, rr2.Body.String())
	}
}

func TestListSessionsUnauthorized(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	rr := getJSON(t, h, "/api/auth/multi-session/list", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestListSessionsWithUserAgent(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	_ = signUpUserWithUA(t, h, "user@example.com", "password123", "Test User", chromeUA)

	firefoxUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
	cookies2 := signInUserWithUA(t, h, "user@example.com", "password123", firefoxUA)

	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies2)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions failed: %d %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	sessions := resp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	// Check that at least one session has parsed device info.
	foundBrowser := false
	for _, s := range sessions {
		sess := s.(map[string]any)
		if browser, ok := sess["browser"].(string); ok && browser != "" && browser != "Unknown" {
			foundBrowser = true
		}
	}
	if !foundBrowser {
		t.Error("expected at least one session with a parsed browser name")
	}
}

func TestRevokeSession(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies1 := signUpUser(t, h, "user@example.com", "password123", "Test User")
	cookies2 := signInUser(t, h, "user@example.com", "password123")

	// Get session list to find the session IDs.
	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	resp := decodeResp(t, rr)
	sessions := resp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	// Find the non-current session ID (the one to revoke).
	var otherSessionID string
	for _, s := range sessions {
		sess := s.(map[string]any)
		if isCurrent, ok := sess["isCurrent"].(bool); !ok || !isCurrent {
			otherSessionID = sess["id"].(string)
		}
	}
	if otherSessionID == "" {
		t.Fatal("could not find non-current session to revoke")
	}

	// Revoke the other session.
	rr = postJSON(t, h, "/api/auth/multi-session/revoke", map[string]string{
		"sessionId": otherSessionID,
	}, cookies1)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke session failed: %d %s", rr.Code, rr.Body.String())
	}

	// List sessions - should now only have 1.
	rr = getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	resp = decodeResp(t, rr)
	sessions = resp["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after revoke, got %d", len(sessions))
	}

	// Session 2 should now be invalid.
	rr = getJSON(t, h, "/api/auth/multi-session/list", cookies2)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected session 2 to be unauthorized, got %d", rr.Code)
	}
}

func TestRevokeCurrentSessionFails(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@example.com", "password123", "Test User")

	// Get the current session ID.
	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies)
	resp := decodeResp(t, rr)
	sessions := resp["sessions"].([]any)
	currentSessionID := sessions[0].(map[string]any)["id"].(string)

	// Try to revoke the current session - should fail.
	rr = postJSON(t, h, "/api/auth/multi-session/revoke", map[string]string{
		"sessionId": currentSessionID,
	}, cookies)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for revoking current session, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestRevokeAllOthers(t *testing.T) {
	p := multisession.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies1 := signUpUser(t, h, "user@example.com", "password123", "Test User")
	_ = signInUser(t, h, "user@example.com", "password123")
	_ = signInUser(t, h, "user@example.com", "password123")

	// Verify 3 sessions exist.
	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	resp := decodeResp(t, rr)
	sessions := resp["sessions"].([]any)
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(sessions))
	}

	// Revoke all others from session 1.
	rr = postJSON(t, h, "/api/auth/multi-session/revoke-all-others", nil, cookies1)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke all others failed: %d %s", rr.Code, rr.Body.String())
	}

	resp = decodeResp(t, rr)
	revoked, ok := resp["revoked"].(float64)
	if !ok {
		t.Fatal("expected revoked count in response")
	}
	if int(revoked) != 2 {
		t.Errorf("expected 2 sessions revoked, got %d", int(revoked))
	}

	// Verify only 1 session remains.
	rr = getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	resp = decodeResp(t, rr)
	sessions = resp["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after revoke-all-others, got %d", len(sessions))
	}
}

func TestMaxSessionsRevokeOldest(t *testing.T) {
	p := multisession.New(&multisession.Options{
		MaxSessions:  2,
		OnMaxReached: "revoke-oldest",
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	// Session 1.
	cookies1 := signUpUser(t, h, "user@example.com", "password123", "Test User")
	// Session 2.
	_ = signInUser(t, h, "user@example.com", "password123")
	// Session 3 should trigger revocation of session 1.
	cookies3 := signInUser(t, h, "user@example.com", "password123")

	// List sessions from session 3.
	rr := getJSON(t, h, "/api/auth/multi-session/list", cookies3)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions failed: %d %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	sessions := resp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions (max), got %d", len(sessions))
	}

	// Session 1 should have been revoked (oldest).
	rr = getJSON(t, h, "/api/auth/multi-session/list", cookies1)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected session 1 (oldest) to be revoked, got status %d", rr.Code)
	}
}

func TestMaxSessionsDenyNew(t *testing.T) {
	p := multisession.New(&multisession.Options{
		MaxSessions:  2,
		OnMaxReached: "deny-new",
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	// Session 1.
	_ = signUpUser(t, h, "user@example.com", "password123", "Test User")
	// Session 2.
	_ = signInUser(t, h, "user@example.com", "password123")
	// Session 3 should be denied.
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email":    "user@example.com",
		"password": "password123",
	}, nil)
	// The session create hook returns an error, which should result in a non-200 response.
	if rr.Code == http.StatusOK {
		t.Fatalf("expected sign-in to fail when max sessions reached with deny-new, got 200")
	}
}

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name       string
		ua         string
		browser    string
		os         string
		deviceType string
	}{
		{
			name:       "Chrome on Windows",
			ua:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			browser:    "Chrome",
			os:         "Windows",
			deviceType: "desktop",
		},
		{
			name:       "Firefox on macOS",
			ua:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
			browser:    "Firefox",
			os:         "macOS",
			deviceType: "desktop",
		},
		{
			name:       "Safari on iPhone",
			ua:         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			browser:    "Safari",
			os:         "iOS",
			deviceType: "mobile",
		},
		{
			name:       "Chrome on Android Mobile",
			ua:         "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			browser:    "Chrome",
			os:         "Android",
			deviceType: "mobile",
		},
		{
			name:       "Edge on Windows",
			ua:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			browser:    "Edge",
			os:         "Windows",
			deviceType: "desktop",
		},
		{
			name:       "Safari on iPad",
			ua:         "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			browser:    "Safari",
			os:         "iOS",
			deviceType: "tablet",
		},
		{
			name:       "Chrome on Linux",
			ua:         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			browser:    "Chrome",
			os:         "Linux",
			deviceType: "desktop",
		},
		{
			name:       "Empty UA",
			ua:         "",
			browser:    "Unknown",
			os:         "Unknown",
			deviceType: "desktop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			browser, os, deviceType := multisession.ParseUserAgent(tt.ua)
			if browser != tt.browser {
				t.Errorf("browser = %q, want %q", browser, tt.browser)
			}
			if os != tt.os {
				t.Errorf("os = %q, want %q", os, tt.os)
			}
			if deviceType != tt.deviceType {
				t.Errorf("deviceType = %q, want %q", deviceType, tt.deviceType)
			}
		})
	}
}

func TestPluginID(t *testing.T) {
	p := multisession.New(nil)
	if p.ID() != "multi-session" {
		t.Errorf("ID() = %q, want %q", p.ID(), "multi-session")
	}
}

func TestPluginSchema(t *testing.T) {
	p := multisession.New(nil)
	schema := p.Schema()

	sessionSchema, ok := schema["session"]
	if !ok {
		t.Fatal("expected session table in schema")
	}

	expectedFields := map[string]bool{
		"device_name": false,
		"device_type": false,
		"os":          false,
		"browser":     false,
	}

	for _, f := range sessionSchema.Fields {
		if _, ok := expectedFields[f.Name]; ok {
			expectedFields[f.Name] = true
			if f.Type != "text" {
				t.Errorf("field %q type = %q, want %q", f.Name, f.Type, "text")
			}
			if f.Required {
				t.Errorf("field %q should not be required", f.Name)
			}
		}
	}

	for name, found := range expectedFields {
		if !found {
			t.Errorf("expected field %q in schema", name)
		}
	}
}
