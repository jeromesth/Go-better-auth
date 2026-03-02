package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Apple implements the SocialProvider interface for Sign in with Apple.
type Apple struct{}

func (Apple) ID() string { return "apple" }

func (Apple) AuthorizationURL(state, _ string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {state},
		"scope":         {strings.Join(defaultScopes(cfg.Scopes, []string{"name", "email"}), " ")},
		"response_mode": {"form_post"},
	}
	return "https://appleid.apple.com/auth/authorize?" + params.Encode()
}

func (Apple) ExchangeCode(ctx context.Context, code, _ string, cfg ProviderConfig) (*OAuthTokens, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://appleid.apple.com/auth/token",
		strings.NewReader(url.Values{
			"code":          {code},
			"client_id":     {cfg.ClientID},
			"client_secret": {cfg.ClientSecret},
			"redirect_uri":  {cfg.RedirectURI},
			"grant_type":    {"authorization_code"},
		}.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &OAuthTokens{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

// GetUserInfo decodes the ID token JWT claims for Apple (no separate userinfo endpoint).
// Note: For production use, the ID token should be verified with Apple's public keys.
func (Apple) GetUserInfo(_ context.Context, accessToken string) (*OAuthUser, error) {
	// Apple does not provide a userinfo endpoint; user data comes from the ID token.
	// This is a stub that returns minimal info from the access token (non-standard).
	// In production, decode and verify the id_token JWT instead.
	return &OAuthUser{
		ID:            accessToken, // placeholder
		Email:         "",
		EmailVerified: false,
		Name:          "",
	}, nil
}
