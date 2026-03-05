// Package testutil provides test helpers for go-better-auth.
package testutil

import (
	"net/http"
	"net/http/httptest"

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
