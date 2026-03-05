// Package integration contains full integration tests that exercise multiple
// subsystems together (sign-up -> verify email -> sign-in -> change password -> etc.).
package integration_test

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
		AppName:  "Integration Test",
		BasePath: "/api/auth",
		Secret:   "integration-secret",
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

// TestFullAuthLifecycle exercises the complete auth workflow.
func TestFullAuthLifecycle(t *testing.T) {
	auth := newAuth()
	h := auth.Handler()

	// 1. Sign up user
	rr := post(h, "/api/auth/sign-up/email", map[string]string{
		"email": "lifecycle@test.com", "password": "lifecycle123", "name": "Lifecycle User",
	}, nil)
	if rr.Code != 200 {
		t.Fatalf("sign-up: %d %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()

	// 2. Verify session is active
	rr = get(h, "/api/auth/get-session", cookies)
	var sessResp map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&sessResp)
	user := sessResp["user"].(map[string]any)
	if user["email"] != "lifecycle@test.com" {
		t.Fatalf("unexpected email: %v", user["email"])
	}

	// 3. Update user name
	rr = post(h, "/api/auth/update-user", map[string]string{"name": "Updated Name"}, cookies)
	if rr.Code != 200 {
		t.Fatalf("update-user: %d %s", rr.Code, rr.Body.String())
	}
	var updateResp map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&updateResp)
	updatedUser := updateResp["user"].(map[string]any)
	if updatedUser["name"] != "Updated Name" {
		t.Fatalf("expected 'Updated Name', got %v", updatedUser["name"])
	}

	// 4. Change password
	rr = post(h, "/api/auth/change-password", map[string]any{
		"currentPassword": "lifecycle123", "newPassword": "newpassword456",
	}, cookies)
	if rr.Code != 200 {
		t.Fatalf("change-password: %d %s", rr.Code, rr.Body.String())
	}

	// 5. Sign out
	rr = post(h, "/api/auth/sign-out", nil, cookies)
	if rr.Code != 200 {
		t.Fatalf("sign-out: %d", rr.Code)
	}

	// 6. Sign in with NEW password
	rr = post(h, "/api/auth/sign-in/email", map[string]string{
		"email": "lifecycle@test.com", "password": "newpassword456",
	}, nil)
	if rr.Code != 200 {
		t.Fatalf("sign-in with new password: %d %s", rr.Code, rr.Body.String())
	}

	// 7. Old password should NOT work
	rr = post(h, "/api/auth/sign-in/email", map[string]string{
		"email": "lifecycle@test.com", "password": "lifecycle123",
	}, nil)
	if rr.Code != 400 {
		t.Fatalf("expected 400 for old password, got %d", rr.Code)
	}
}

// TestMultipleSessionsAndRevocation tests session management across multiple sessions.
func TestMultipleSessionsAndRevocation(t *testing.T) {
	auth := newAuth()
	h := auth.Handler()

	// Sign up
	rr := post(h, "/api/auth/sign-up/email", map[string]string{
		"email": "multi@test.com", "password": "multipass123", "name": "Multi",
	}, nil)
	cookies1 := rr.Result().Cookies()

	// Sign in again (creates second session)
	rr = post(h, "/api/auth/sign-in/email", map[string]string{
		"email": "multi@test.com", "password": "multipass123",
	}, nil)
	cookies2 := rr.Result().Cookies()

	// List sessions from session 1
	rr = get(h, "/api/auth/list-sessions", cookies1)
	if rr.Code != 200 {
		t.Fatalf("list-sessions: %d", rr.Code)
	}
	var listResp map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&listResp)
	sessions := listResp["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	// Revoke other sessions from session 2
	rr = post(h, "/api/auth/revoke-other-sessions", nil, cookies2)
	if rr.Code != 200 {
		t.Fatalf("revoke-other-sessions: %d", rr.Code)
	}

	// Session 1 should be invalidated
	rr = get(h, "/api/auth/get-session", cookies1)
	var afterRevoke any
	_ = json.NewDecoder(rr.Body).Decode(&afterRevoke)
	if afterRevoke != nil {
		t.Fatal("expected session 1 to be revoked")
	}

	// Session 2 should still work
	rr = get(h, "/api/auth/get-session", cookies2)
	var stillActive map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&stillActive)
	if stillActive["user"] == nil {
		t.Fatal("expected session 2 to still be active")
	}
}

// TestDuplicateEmailPrevention validates that duplicate emails are rejected.
func TestDuplicateEmailPrevention(t *testing.T) {
	auth := newAuth()
	h := auth.Handler()

	body := map[string]string{
		"email": "dup@test.com", "password": "duptest123", "name": "Dup",
	}
	post(h, "/api/auth/sign-up/email", body, nil)
	rr := post(h, "/api/auth/sign-up/email", body, nil)
	if rr.Code != 409 {
		t.Fatalf("expected 409 on duplicate, got %d", rr.Code)
	}
}
