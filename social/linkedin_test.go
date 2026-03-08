package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestLinkedInProvider_ID(t *testing.T) {
	p := social.LinkedIn{}
	if p.ID() != "linkedin" {
		t.Errorf("expected ID=linkedin, got %s", p.ID())
	}
}

func TestLinkedInProvider_AuthorizationURL(t *testing.T) {
	p := social.LinkedIn{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "", cfg)

	if !strings.Contains(authURL, "linkedin.com/oauth/v2/authorization") {
		t.Errorf("expected LinkedIn auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client123") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state123") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "openid") {
		t.Errorf("expected openid scope, got %q", authURL)
	}
}

func TestLinkedInProvider_CustomScopes(t *testing.T) {
	p := social.LinkedIn{}
	cfg := social.ProviderConfig{
		ClientID: "client123",
		Scopes:   []string{"openid", "email"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "profile") {
		t.Error("expected custom scopes to override defaults")
	}
}
