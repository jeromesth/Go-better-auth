package totp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/totp"
)

// --- TOTP math tests ---

func TestGenerateTOTP(t *testing.T) {
	t.Parallel()
	// RFC 6238 test vector: secret = "12345678901234567890" (ASCII), T=59s → last 6 digits of 94287082 = 287082
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // base32 of "12345678901234567890"
	ts := time.Unix(59, 0).UTC()
	code, err := totp.GenerateTOTP(secret, ts)
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Errorf("want 287082, got %s", code)
	}
}

func TestVerifyTOTP(t *testing.T) {
	t.Parallel()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ts := time.Unix(59, 0).UTC()
	code, _ := totp.GenerateTOTP(secret, ts)
	if !totp.VerifyTOTP(secret, code, ts) {
		t.Fatal("valid code should verify")
	}
	if totp.VerifyTOTP(secret, "000000", ts) {
		t.Fatal("wrong code should not verify")
	}
}

func TestVerifyTOTPTolerance(t *testing.T) {
	t.Parallel()
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// Generate code in window counter=1 (seconds 30-59)
	ts := time.Unix(31, 0).UTC()
	code, _ := totp.GenerateTOTP(secret, ts)
	// Verify at T=71 (counter=2): delta=-1 checks counter=1 → accepted
	laterTs := time.Unix(71, 0).UTC()
	if !totp.VerifyTOTP(secret, code, laterTs) {
		t.Fatal("previous window code should be accepted within tolerance")
	}
}

func TestGenerateSecret(t *testing.T) {
	t.Parallel()
	s1, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := totp.GenerateSecret()
	if s1 == s2 {
		t.Fatal("secrets should be unique")
	}
	if len(s1) < 16 {
		t.Errorf("secret too short: %q", s1)
	}
}

// --- Integration test helpers ---

func newTestAuth(t *testing.T, totpPlugin *totp.Plugin) (*betterauth.Auth, http.Handler) {
	t.Helper()
	a := betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "TOTP Test",
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
		Plugins:   []plugin.Plugin{totpPlugin},
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

func decodeResp(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

func signUp(t *testing.T, h http.Handler, email, password string) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    email,
		"password": password,
		"name":     "Test User",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func signIn(t *testing.T, h http.Handler, email, password string) (*http.Response, []*http.Cookie) {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	return rr.Result(), rr.Result().Cookies()
}

// --- Integration tests ---

func TestTOTPStatusNotConfigured(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	rr := getJSON(t, h, "/api/auth/totp/status", cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	if resp["enabled"] != false {
		t.Errorf("want enabled=false, got %v", resp["enabled"])
	}
}

func TestTOTPGenerateAndEnable(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Generate
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	secret, ok := resp["secret"].(string)
	if !ok || secret == "" {
		t.Fatalf("expected secret in response, got: %v", resp)
	}
	otpauthURL, _ := resp["otpauthURL"].(string)
	if otpauthURL == "" {
		t.Error("expected otpauthURL in response")
	}

	// Enable with valid code
	code, err := totp.GenerateTOTP(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rr = postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = decodeResp(t, rr)
	if resp["enabled"] != true {
		t.Errorf("want enabled=true, got %v", resp["enabled"])
	}

	// Status should now be enabled
	rr = getJSON(t, h, "/api/auth/totp/status", cookies)
	resp = decodeResp(t, rr)
	if resp["enabled"] != true {
		t.Errorf("status: want enabled=true, got %v", resp["enabled"])
	}
}

func TestSignInRequiresTOTP(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Generate and enable TOTP
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	secret := decodeResp(t, rr)["secret"].(string)
	code, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)

	// Sign out
	postJSON(t, h, "/api/auth/sign-out", nil, cookies)

	// Sign in should now return TOTP_REQUIRED
	resp, _ := signIn(t, h, "user@example.com", "password123")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != "TOTP_REQUIRED" {
		t.Errorf("want TOTP_REQUIRED, got %v", body["code"])
	}
	challengeToken, _ := body["challengeToken"].(string)
	if challengeToken == "" {
		t.Error("expected challengeToken in response")
	}
}

func TestTOTPVerifyFlow(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Generate and enable TOTP
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	secret := decodeResp(t, rr)["secret"].(string)
	code, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)

	// Sign out
	postJSON(t, h, "/api/auth/sign-out", nil, cookies)

	// Sign in → get challenge token
	resp, _ := signIn(t, h, "user@example.com", "password123")
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	challengeToken := body["challengeToken"].(string)

	// Verify with correct code
	verifyCode, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	rr = postJSON(t, h, "/api/auth/totp/verify", map[string]string{
		"challengeToken": challengeToken,
		"code":           verifyCode,
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	verifyResp := decodeResp(t, rr)
	if verifyResp["user"] == nil {
		t.Error("expected user in verify response")
	}
	if verifyResp["session"] == nil {
		t.Error("expected session in verify response")
	}
	// Session cookie should be set
	setCookie := rr.Result().Cookies()
	hasCookie := false
	for _, c := range setCookie {
		if c.Name == "better-auth.session_token" || c.Name == "session_token" {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Log("note: session cookie name may differ, checking for any cookie")
		if len(setCookie) == 0 {
			t.Error("expected session cookie to be set")
		}
	}
}

func TestTOTPVerifyInvalidCode(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Enable TOTP
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	secret := decodeResp(t, rr)["secret"].(string)
	code, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)

	postJSON(t, h, "/api/auth/sign-out", nil, cookies)

	// Get challenge token
	resp, _ := signIn(t, h, "user@example.com", "password123")
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	challengeToken := body["challengeToken"].(string)

	// Verify with wrong code
	rr = postJSON(t, h, "/api/auth/totp/verify", map[string]string{
		"challengeToken": challengeToken,
		"code":           "000000",
	}, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
	resp2 := decodeResp(t, rr)
	if resp2["code"] != "INVALID_TOTP_CODE" {
		t.Errorf("want INVALID_TOTP_CODE, got %v", resp2["code"])
	}
}

func TestTOTPVerifyExpiredChallenge(t *testing.T) {
	t.Parallel()
	// Use a very short challenge expiry
	_, h := newTestAuth(t, totp.New(&totp.Options{ChallengeExpiresIn: -1}))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Enable TOTP
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	secret := decodeResp(t, rr)["secret"].(string)
	code, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)

	postJSON(t, h, "/api/auth/sign-out", nil, cookies)

	// Get challenge token (which immediately expires)
	resp, _ := signIn(t, h, "user@example.com", "password123")
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	challengeToken := body["challengeToken"].(string)

	// Verify should fail with expired challenge
	verifyCode, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	rr = postJSON(t, h, "/api/auth/totp/verify", map[string]string{
		"challengeToken": challengeToken,
		"code":           verifyCode,
	}, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
	resp2 := decodeResp(t, rr)
	if resp2["code"] != "CHALLENGE_EXPIRED" {
		t.Errorf("want CHALLENGE_EXPIRED, got %v", resp2["code"])
	}
}

func TestTOTPDisable(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	// Enable TOTP
	rr := postJSON(t, h, "/api/auth/totp/generate", nil, cookies)
	secret := decodeResp(t, rr)["secret"].(string)
	code, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": code}, cookies)

	// Disable TOTP
	disableCode, _ := totp.GenerateTOTP(secret, time.Now().UTC())
	rr = postJSON(t, h, "/api/auth/totp/disable", map[string]string{"code": disableCode}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Sign out then sign in normally (no TOTP challenge)
	postJSON(t, h, "/api/auth/sign-out", nil, cookies)
	resp, newCookies := signIn(t, h, "user@example.com", "password123")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in after disable: want 200, got %d", resp.StatusCode)
	}
	_ = newCookies

	// Status should be disabled
	rr = getJSON(t, h, "/api/auth/totp/status", newCookies)
	resp2 := decodeResp(t, rr)
	if resp2["enabled"] != false {
		t.Errorf("status after disable: want enabled=false, got %v", resp2["enabled"])
	}
}

func TestTOTPGenerateRequiresAuth(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))

	rr := postJSON(t, h, "/api/auth/totp/generate", nil, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestTOTPEnableWithoutGenerate(t *testing.T) {
	t.Parallel()
	_, h := newTestAuth(t, totp.New(nil))
	cookies := signUp(t, h, "user@example.com", "password123")

	rr := postJSON(t, h, "/api/auth/totp/enable", map[string]string{"code": "123456"}, cookies)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	if resp["code"] != "TOTP_NOT_CONFIGURED" {
		t.Errorf("want TOTP_NOT_CONFIGURED, got %v", resp["code"])
	}
}
