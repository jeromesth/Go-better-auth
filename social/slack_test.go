package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestSlackProvider_ID(t *testing.T) {
	p := social.Slack{}
	if p.ID() != "slack" {
		t.Errorf("expected ID=slack, got %s", p.ID())
	}
}

func TestSlackProvider_AuthorizationURL(t *testing.T) {
	p := social.Slack{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "", cfg)

	if !strings.Contains(authURL, "slack.com/openid/connect/authorize") {
		t.Errorf("expected Slack auth URL, got %q", authURL)
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

func TestSlackProvider_CustomScopes(t *testing.T) {
	p := social.Slack{}
	cfg := social.ProviderConfig{
		ClientID: "client123",
		Scopes:   []string{"openid", "email"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "profile") {
		t.Error("expected custom scopes to override defaults")
	}
}
