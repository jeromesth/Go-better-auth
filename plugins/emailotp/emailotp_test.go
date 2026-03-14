package emailotp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/emailotp"
)

// otpCapture captures the last OTP code sent.
type otpCapture struct {
	mu    sync.Mutex
	email string
	code  string
}

func (c *otpCapture) sendOTP(_ context.Context, email, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.email = email
	c.code = code
	return nil
}

func (c *otpCapture) lastCode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

func (c *otpCapture) lastEmail() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.email
}

func newTestAuth(t *testing.T, p *emailotp.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "EmailOTP Test",
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

func postJSON(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
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

// registerUser creates a user via the standard email/password sign-up endpoint.
func registerUser(t *testing.T, h http.Handler, email string) {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email": email, "password": "password123", "name": "Test User",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestEmailOTPPlugin_ID(t *testing.T) {
	p := emailotp.New(emailotp.Options{
		SendOTP: func(_ context.Context, _, _ string) error { return nil },
	})
	if p.ID() != "emailotp" {
		t.Errorf("expected ID=emailotp, got %s", p.ID())
	}
}

func TestSendOTP_HappyPath(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP: capture.sendOTP,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}

	// Verify callback was called with correct email and a 6-digit code.
	if capture.lastEmail() != "alice@test.com" {
		t.Errorf("expected email=alice@test.com, got %s", capture.lastEmail())
	}
	code := capture.lastCode()
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q (len=%d)", code, len(code))
	}
}

func TestSendOTP_UnknownEmail(t *testing.T) {
	called := false
	p := emailotp.New(emailotp.Options{
		SendOTP: func(_ context.Context, _, _ string) error {
			called = true
			return nil
		},
	})
	_, h := newTestAuth(t, p)

	// Send OTP to an email that does not exist.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "nobody@test.com",
	})
	// Should return 200 to prevent user enumeration.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if called {
		t.Error("SendOTP should not be called for unknown email")
	}
}

func TestVerifyOTP_HappyPath(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP: capture.sendOTP,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	// Send OTP.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("send OTP failed: %d %s", rr.Code, rr.Body.String())
	}

	code := capture.lastCode()
	if code == "" {
		t.Fatal("no OTP code captured")
	}

	// Verify OTP.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  code,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["user"] == nil {
		t.Fatal("expected user in response")
	}
	if resp["session"] == nil {
		t.Fatal("expected session in response")
	}

	// Verify session cookie is set.
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected at least one cookie to be set")
	}
}

func TestVerifyOTP_WrongCode(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP: capture.sendOTP,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	// Send OTP.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("send OTP failed: %d %s", rr.Code, rr.Body.String())
	}

	// Use a deterministically wrong code.
	wrongCode := "000000"
	if capture.lastCode() == wrongCode {
		wrongCode = "111111"
	}

	// Verify with wrong code.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  wrongCode,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong code, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_CODE" {
		t.Errorf("expected code=INVALID_CODE, got %v", resp["code"])
	}
}

func TestVerifyOTP_ExpiredCode(t *testing.T) {
	capture := &otpCapture{}
	memAdapter := memory.New()
	p := emailotp.New(emailotp.Options{
		SendOTP: capture.sendOTP,
	})
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "EmailOTP Expiry Test",
		BasePath: "/api/auth",
		Secret:   "test-secret",
		Database: &betterauth.DatabaseConfig{
			Adapter: memAdapter,
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
	h := a.Handler()

	registerUser(t, h, "alice@test.com")

	// Send OTP.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("send OTP failed: %d %s", rr.Code, rr.Body.String())
	}
	code := capture.lastCode()
	if code == "" {
		t.Fatal("no OTP code captured")
	}

	// Deterministically expire the verification record by setting expires_at to the past.
	_, _ = memAdapter.Update(context.Background(), "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("identifier", "email-otp:alice@test.com")},
	}, map[string]any{
		"expires_at": time.Now().Add(-1 * time.Hour),
	})

	// Verify with the now-expired code.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  code,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired code, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "CODE_EXPIRED" {
		t.Errorf("expected code=CODE_EXPIRED, got %v", resp["code"])
	}
}

func TestSendOTP_MissingEmail(t *testing.T) {
	p := emailotp.New(emailotp.Options{
		SendOTP: func(_ context.Context, _, _ string) error { return nil },
	})
	_, h := newTestAuth(t, p)

	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "MISSING_EMAIL" {
		t.Errorf("expected code=MISSING_EMAIL, got %v", resp["code"])
	}
}

func TestVerifyOTP_MissingFields(t *testing.T) {
	p := emailotp.New(emailotp.Options{
		SendOTP: func(_ context.Context, _, _ string) error { return nil },
	})
	_, h := newTestAuth(t, p)

	t.Run("missing email", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
			"code": "123456",
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing email, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "MISSING_FIELDS" {
			t.Errorf("expected code=MISSING_FIELDS, got %v", resp["code"])
		}
	})

	t.Run("missing code", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
			"email": "alice@test.com",
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing code, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "MISSING_FIELDS" {
			t.Errorf("expected code=MISSING_FIELDS, got %v", resp["code"])
		}
	})
}

func TestSendOTP_CustomCodeLength(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP:    capture.sendOTP,
		CodeLength: 8,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	code := capture.lastCode()
	if len(code) != 8 {
		t.Errorf("expected 8-digit code, got %q (len=%d)", code, len(code))
	}
}

func TestVerifyOTP_CustomCodeLength(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP:    capture.sendOTP,
		CodeLength: 8,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	// Send OTP.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("send OTP failed: %d %s", rr.Code, rr.Body.String())
	}

	code := capture.lastCode()

	// Verify with the 8-digit code.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  code,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with custom code length, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["user"] == nil {
		t.Fatal("expected user in response")
	}
	if resp["session"] == nil {
		t.Fatal("expected session in response")
	}
}

func TestVerifyOTP_ReplayAttack(t *testing.T) {
	capture := &otpCapture{}
	p := emailotp.New(emailotp.Options{
		SendOTP: capture.sendOTP,
	})
	_, h := newTestAuth(t, p)

	registerUser(t, h, "alice@test.com")

	// Send OTP.
	rr := postJSON(t, h, "/api/auth/email-otp/send", map[string]string{
		"email": "alice@test.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("send OTP failed: %d %s", rr.Code, rr.Body.String())
	}

	code := capture.lastCode()
	if code == "" {
		t.Fatal("no OTP code captured")
	}

	// First verification should succeed.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  code,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("first verify expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Replay: second verification with the same code should fail.
	rr = postJSON(t, h, "/api/auth/email-otp/verify", map[string]string{
		"email": "alice@test.com",
		"code":  code,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("replay attack: expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSendOTP_InvalidJSON(t *testing.T) {
	p := emailotp.New(emailotp.Options{
		SendOTP: func(_ context.Context, _, _ string) error { return nil },
	})
	_, h := newTestAuth(t, p)

	// Send malformed JSON.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/email-otp/send", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeResp(t, rr)
	if resp["code"] != "INVALID_JSON" {
		t.Errorf("expected code=INVALID_JSON, got %v", resp["code"])
	}
}
