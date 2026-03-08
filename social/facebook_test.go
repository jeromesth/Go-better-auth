package social_test

import (
	"strings"
	"testing"

	"github.com/jeromesth/go-better-auth/social"
)

func TestFacebookProvider_ID(t *testing.T) {
	p := social.Facebook{}
	if p.ID() != "facebook" {
		t.Errorf("expected ID=facebook, got %s", p.ID())
	}
}

func TestFacebookProvider_AuthorizationURL(t *testing.T) {
	p := social.Facebook{}
	cfg := social.ProviderConfig{
		ClientID:    "client123",
		RedirectURI: "https://example.com/callback",
	}
	authURL := p.AuthorizationURL("state123", "", cfg)

	if !strings.Contains(authURL, "facebook.com/v19.0/dialog/oauth") {
		t.Errorf("expected Facebook auth URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=client123") {
		t.Errorf("expected client_id in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "state=state123") {
		t.Errorf("expected state in URL, got %q", authURL)
	}
	if !strings.Contains(authURL, "email") {
		t.Errorf("expected email scope, got %q", authURL)
	}
	if !strings.Contains(authURL, "public_profile") {
		t.Errorf("expected public_profile scope, got %q", authURL)
	}
}

func TestFacebookProvider_CustomScopes(t *testing.T) {
	p := social.Facebook{}
	cfg := social.ProviderConfig{
		ClientID: "client123",
		Scopes:   []string{"email"},
	}
	authURL := p.AuthorizationURL("s", "", cfg)
	if strings.Contains(authURL, "public_profile") {
		t.Error("expected custom scopes to override defaults")
	}
}
