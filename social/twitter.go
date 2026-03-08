package social

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Twitter implements the SocialProvider interface for Twitter/X OAuth 2.0 with PKCE.
type Twitter struct{}

func (Twitter) ID() string { return "twitter" }

func (Twitter) AuthorizationURL(state, codeVerifier string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {state},
		"scope":         {strings.Join(defaultScopes(cfg.Scopes, []string{"users.read", "tweet.read", "offline.access"}), " ")},
	}
	if codeVerifier != "" {
		h := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])
		params.Set("code_challenge", challenge)
		params.Set("code_challenge_method", "S256")
	}
	return "https://twitter.com/i/oauth2/authorize?" + params.Encode()
}

func (Twitter) ExchangeCode(ctx context.Context, code, codeVerifier string, cfg ProviderConfig) (*OAuthTokens, error) {
	form := url.Values{
		"code":         {code},
		"client_id":    {cfg.ClientID},
		"redirect_uri": {cfg.RedirectURI},
		"grant_type":   {"authorization_code"},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/2/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientSecret != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &OAuthTokens{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		Scope:        result.Scope,
	}, nil
}

func (Twitter) GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decoding user info: %w", err)
	}

	raw := envelope.Data
	if raw == nil {
		return nil, fmt.Errorf("twitter user info: empty data")
	}

	// Twitter does not return email by default; use username as fallback.
	email := str(raw, "email")
	if email == "" {
		username := str(raw, "username")
		if username != "" {
			email = username + "@twitter.com"
		}
	}

	return &OAuthUser{
		ID:            str(raw, "id"),
		Email:         email,
		EmailVerified: false, // Twitter does not guarantee email verification
		Name:          str(raw, "name"),
		Image:         str(raw, "profile_image_url"),
		RawData:       raw,
	}, nil
}
