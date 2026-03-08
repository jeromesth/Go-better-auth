package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestDiscordProvider_ID(t *testing.T) {
	p := social.Discord{}
	if p.ID() != "discord" {
		t.Errorf("expected ID=discord, got %s", p.ID())
	}
}

func TestDiscordProvider_AuthorizationURL(t *testing.T) {
	p := social.Discord{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "", cfg)

	if !strings.Contains(authURL, "discord.com/api/oauth2/authorize") {
		t.Errorf("expected Discord auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client123") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state123") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "identify") {
		t.Errorf("expected identify scope, got %q", authURL)
	}
	if !strings.Contains(authURL, "email") {
		t.Errorf("expected email scope, got %q", authURL)
	}
}

func TestDiscordProvider_CustomScopes(t *testing.T) {
	p := social.Discord{}
	cfg := social.ProviderConfig{
		ClientID: "client123",
		Scopes:   []string{"identify"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "email") {
		t.Error("expected custom scopes to override defaults")
	}
}
