package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestMicrosoftProvider_ID(t *testing.T) {
	p := social.Microsoft{}
	if p.ID() != "microsoft" {
		t.Errorf("expected ID=microsoft, got %s", p.ID())
	}
}

func TestMicrosoftProvider_AuthorizationURL(t *testing.T) {
	p := social.Microsoft{}
	cfg := social.ProviderConfig{
		ClientID:    "client456",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state456", "", cfg)

	if !strings.Contains(authURL, "login.microsoftonline.com") {
		t.Errorf("expected Microsoft auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client456") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state456") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "User.Read") {
		t.Errorf("expected User.Read scope, got %q", authURL)
	}
}

func TestMicrosoftProvider_CustomScopes(t *testing.T) {
	p := social.Microsoft{}
	cfg := social.ProviderConfig{
		ClientID: "client456",
		Scopes:   []string{"openid", "email"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "User.Read") {
		t.Error("expected custom scopes to override defaults")
	}
}
