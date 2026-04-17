// Package testutil provides test helpers for go-better-auth.
package testutil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
)

// NewTestAuth creates an Auth instance backed by an in-memory adapter.
// Optional modifier functions can be used to customize the options.
func NewTestAuth(modifiers ...func(*betterauth.BetterAuthOptions)) *betterauth.Auth {
	opts := betterauth.BetterAuthOptions{
		AppName:  "Test App",
		BasePath: "/api/auth",
		Secret:   "test-secret-key",
		Database: &betterauth.DatabaseConfig{
			Adapter: memory.New(),
		},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled:           true,
			MinPasswordLength: 8,
			MaxPasswordLength: 128,
			AutoSignIn:        true,
		},
	}
	for _, m := range modifiers {
		m(&opts)
	}
	return betterauth.New(opts)
}

// TestClient wraps an httptest server and maintains cookies across requests,
// simulating a real browser session.
type TestClient struct {
	server  *httptest.Server
	cookies []*http.Cookie
}

// NewTestClient creates a TestClient that sends requests to the given Auth handler.
func NewTestClient(auth *betterauth.Auth) *TestClient {
	server := httptest.NewServer(auth.Handler())
	return &TestClient{server: server}
}

// Close shuts down the test server.
func (c *TestClient) Close() {
	c.server.Close()
}

// Do performs an HTTP request, preserving cookies.
func (c *TestClient) Do(req *http.Request) (*http.Response, error) {
	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	c.cookies = append(c.cookies, resp.Cookies()...)
	return resp, nil
}

// BaseURL returns the test server's base URL.
func (c *TestClient) BaseURL() string {
	return c.server.URL
}

// PostJSON sends a POST request with a JSON-encoded body to the given handler.
// Cookies, if provided, are attached to the request.
func PostJSON(t *testing.T, h http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
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

// GetJSON sends a GET request to the given handler with optional cookies.
func GetJSON(t *testing.T, h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// DecodeResp decodes the JSON body of a response recorder into a map.
// The test is failed immediately if decoding fails.
func DecodeResp(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

// SignUp registers a new user via the email/password sign-up endpoint and
// returns the session cookies from the response. The test is failed immediately
// if the request does not return HTTP 200.
func SignUp(t *testing.T, h http.Handler, basePath, email, password string) []*http.Cookie {
	t.Helper()
	rr := PostJSON(t, h, basePath+"/sign-up/email", map[string]string{
		"email":    email,
		"password": password,
		"name":     "Test User",
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

// SignIn authenticates a user via the email/password sign-in endpoint and
// returns the raw response and session cookies.
func SignIn(t *testing.T, h http.Handler, basePath, email, password string) (*http.Response, []*http.Cookie) {
	t.Helper()
	rr := PostJSON(t, h, basePath+"/sign-in/email", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	return rr.Result(), rr.Result().Cookies()
}
