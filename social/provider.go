// Package social defines the SocialProvider interface and OAuth user types.
package social

import "context"

// ProviderConfig holds OAuth client credentials for a social provider.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// OAuthTokens holds tokens returned from an OAuth token exchange.
type OAuthTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
	Scope        string
}

// OAuthUser holds normalized user info retrieved from a social provider.
type OAuthUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         string
	RawData       map[string]any
}

// SocialProvider is the interface each social login provider must implement.
type SocialProvider interface {
	// ID returns the unique provider identifier (e.g. "google", "github").
	ID() string

	// AuthorizationURL returns the URL to redirect the user to for authorization.
	AuthorizationURL(state, codeVerifier string, cfg ProviderConfig) string

	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, code, codeVerifier string, cfg ProviderConfig) (*OAuthTokens, error)

	// GetUserInfo retrieves the authenticated user's profile.
	GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error)
}
