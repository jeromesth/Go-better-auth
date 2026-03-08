package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestTwitterProvider_ID(t *testing.T) {
	p := social.Twitter{}
	if p.ID() != "twitter" {
		t.Errorf("expected ID=twitter, got %s", p.ID())
	}
}

func TestTwitterProvider_AuthorizationURL(t *testing.T) {
	p := social.Twitter{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "verifier123", cfg)

	if !strings.Contains(authURL, "twitter.com/i/oauth2/authorize") {
		t.Errorf("expected Twitter auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client123") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state123") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("expected code_challenge_method=S256 in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "code_challenge=") {
		t.Errorf("expected code_challenge in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "users.read") {
		t.Errorf("expected users.read scope, got %q", authURL)
	}
	if !strings.Contains(authURL, "tweet.read") {
		t.Errorf("expected tweet.read scope, got %q", authURL)
	}
	if !strings.Contains(authURL, "offline.access") {
		t.Errorf("expected offline.access scope, got %q", authURL)
	}
}

func TestTwitterProvider_AuthorizationURL_NoVerifier(t *testing.T) {
	p := social.Twitter{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "", cfg)

	if !strings.Contains(authURL, "twitter.com/i/oauth2/authorize") {
		t.Errorf("expected Twitter auth URL, got %q", authURL)
	}
	if strings.Contains(authURL, "code_challenge=") {
		t.Errorf("expected no code_challenge when verifier is empty, got %q", authURL)
	}
}

func TestTwitterProvider_CustomScopes(t *testing.T) {
	p := social.Twitter{}
	cfg := social.ProviderConfig{
		ClientID: "client123",
		Scopes:   []string{"users.read"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)

	if !strings.Contains(authURL, "users.read") {
		t.Error("expected users.read in custom scopes URL")
	}
}
