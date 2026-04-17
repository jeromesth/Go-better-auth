package betterauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/adapter/memory"
)

func newTestAuth() *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Test",
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
		RateLimit: &betterauth.RateLimitConfig{
			Enabled: false,
		},
	})
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
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

func getJSON(t *testing.T, handler http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestSignUpAndSignIn(t *testing.T) {
	auth := newTestAuth()
	h := auth.Handler()

	// Sign up
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    "test@example.com",
		"password": "password123",
		"name":     "Test User",
	}, nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var signUpResp map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&signUpResp)
	if signUpResp["user"] == nil {
		t.Fatal("expected user in sign-up response")
	}
	if signUpResp["session"] == nil {
		t.Fatal("expected session in sign-up response (AutoSignIn=true)")
	}

	// Get the session cookie
	cookies := rr.Result().Cookies()

	// Get session
	rr2 := getJSON(t, h, "/api/auth/get-session", cookies)
	if rr2.Code != http.StatusOK {
		t.Fatalf("get-session: expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var sessResp map[string]any
	_ = json.NewDecoder(rr2.Body).Decode(&sessResp)
	if sessResp["user"] == nil {
		t.Fatal("expected user in session response")
	}

	// Sign out
	rr3 := postJSON(t, h, "/api/auth/sign-out", nil, cookies)
	if rr3.Code != http.StatusOK {
		t.Fatalf("sign-out: expected 200, got %d", rr3.Code)
	}

	// Session should be gone
	rr4 := getJSON(t, h, "/api/auth/get-session", cookies)
	if rr4.Code != http.StatusOK {
		t.Fatalf("get-session after sign-out: expected 200, got %d", rr4.Code)
	}
	var afterLogout any
	_ = json.NewDecoder(rr4.Body).Decode(&afterLogout)
	if afterLogout != nil {
		t.Fatal("expected null session after sign-out")
	}
}

func TestSignUpDuplicateEmail(t *testing.T) {
	auth := newTestAuth()
	h := auth.Handler()

	body := map[string]string{
		"email":    "dup@example.com",
		"password": "password123",
		"name":     "User",
	}

	postJSON(t, h, "/api/auth/sign-up/email", body, nil)
	rr := postJSON(t, h, "/api/auth/sign-up/email", body, nil)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate email, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSignInWrongPassword(t *testing.T) {
	auth := newTestAuth()
	h := auth.Handler()

	postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    "wrong@example.com",
		"password": "correctpassword",
		"name":     "User",
	}, nil)

	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email":    "wrong@example.com",
		"password": "wrongpassword",
	}, nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on wrong password, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPasswordTooShort(t *testing.T) {
	auth := newTestAuth()
	h := auth.Handler()

	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    "short@example.com",
		"password": "abc",
		"name":     "User",
	}, nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on short password, got %d: %s", rr.Code, rr.Body.String())
	}
}

// signUp creates a new user account and returns the response recorder.
func signUp(t *testing.T, auth *betterauth.Auth, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	h := auth.Handler()
	return postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    email,
		"password": password,
		"name":     "Test User",
	}, nil)
}

func TestUpdateUser(t *testing.T) {
	auth := newTestAuth()
	h := auth.Handler()

	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    "update@example.com",
		"password": "password123",
		"name":     "Old Name",
	}, nil)
	cookies := rr.Result().Cookies()

	rr2 := postJSON(t, h, "/api/auth/update-user", map[string]string{
		"name": "New Name",
	}, cookies)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 on update-user, got %d: %s", rr2.Code, rr2.Body.String())
	}

	var resp map[string]any
	_ = json.NewDecoder(rr2.Body).Decode(&resp)
	user, _ := resp["user"].(map[string]any)
	if user["name"] != "New Name" {
		t.Fatalf("expected name to be updated, got: %v", user["name"])
	}
}

func TestRequestPasswordReset_UnknownEmail_Returns200(t *testing.T) {
	// Auth libraries must not leak whether an email is registered.
	a := newTestAuth()
	h := a.Handler()
	w := postJSON(t, h, "/api/auth/request-password-reset",
		map[string]any{"email": "nobody@example.com"}, nil)
	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200 — must not enumerate emails", w.Code)
	}
}

func TestRequestPasswordReset_KnownEmail_Returns200(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "user@example.com", "password123")
	h := a.Handler()
	w := postJSON(t, h, "/api/auth/request-password-reset",
		map[string]any{"email": "user@example.com"}, nil)
	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
}

func TestResetPassword_InvalidToken_Returns400(t *testing.T) {
	a := newTestAuth()
	h := a.Handler()
	w := postJSON(t, h, "/api/auth/reset-password",
		map[string]any{"token": "bogus-token", "newPassword": "newpass123"}, nil)
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 400 or 401 for invalid token", w.Code)
	}
}

func TestResetPassword_PasswordTooShort_Returns400(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "user@example.com", "password123")
	h := a.Handler()
	// Trigger a reset to generate a token.
	postJSON(t, h, "/api/auth/request-password-reset",
		map[string]any{"email": "user@example.com"}, nil)
	// Retrieve token from adapter (stored in "value" field of verification record).
	tokens, _ := a.InternalAdapter().Adapter().FindMany(t.Context(), "verification", adapter.Query{})
	if len(tokens) == 0 {
		t.Skip("no token generated — email provider not configured in test")
	}
	token, _ := tokens[0]["value"].(string)
	w := postJSON(t, h, "/api/auth/reset-password",
		map[string]any{"token": token, "newPassword": "x"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400 for short password", w.Code)
	}
}
