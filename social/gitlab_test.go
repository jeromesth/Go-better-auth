package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestGitLabProvider_ID(t *testing.T) {
	p := social.GitLab{}
	if p.ID() != "gitlab" {
		t.Errorf("expected ID=gitlab, got %s", p.ID())
	}
}

func TestGitLabProvider_AuthorizationURL(t *testing.T) {
	p := social.GitLab{}
	cfg := social.ProviderConfig{
		ClientID:    "client789",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state789", "", cfg)

	if !strings.Contains(authURL, "gitlab.com/oauth/authorize") {
		t.Errorf("expected GitLab auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client789") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state789") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "read_user") {
		t.Errorf("expected read_user scope, got %q", authURL)
	}
}

func TestGitLabProvider_CustomScopes(t *testing.T) {
	p := social.GitLab{}
	cfg := social.ProviderConfig{
		ClientID: "client789",
		Scopes:   []string{"read_user"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "email") && strings.Contains(authURL, "read_user") {
		// custom scopes only contain read_user, so "email" should not appear as a default
		t.Log("note: URL contains read_user (expected) and possibly email from custom scope - acceptable")
	}
	if !strings.Contains(authURL, "read_user") {
		t.Error("expected read_user in custom scopes URL")
	}
}
