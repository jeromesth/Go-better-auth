package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GitHub implements the SocialProvider interface for GitHub OAuth 2.0.
type GitHub struct{}

func (GitHub) ID() string { return "github" }

func (GitHub) AuthorizationURL(state, _ string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":    {cfg.ClientID},
		"redirect_uri": {cfg.RedirectURI},
		"state":        {state},
		"scope":        {strings.Join(defaultScopes(cfg.Scopes, []string{"read:user", "user:email"}), " ")},
	}
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (GitHub) ExchangeCode(ctx context.Context, code, _ string, cfg ProviderConfig) (*OAuthTokens, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token",
		strings.NewReader(url.Values{
			"code":          {code},
			"client_id":     {cfg.ClientID},
			"client_secret": {cfg.ClientSecret},
			"redirect_uri":  {cfg.RedirectURI},
		}.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &OAuthTokens{
		AccessToken: result.AccessToken,
		Scope:       result.Scope,
	}, nil
}

func (GitHub) GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding user: %w", err)
	}

	email := str(raw, "email")
	if email == "" {
		email = fetchGitHubPrimaryEmail(ctx, accessToken)
	}

	id := ""
	if v, ok := raw["id"].(float64); ok {
		id = fmt.Sprintf("%.0f", v)
	}

	return &OAuthUser{
		ID:            id,
		Email:         email,
		EmailVerified: true,
		Name:          str(raw, "name"),
		Image:         str(raw, "avatar_url"),
		RawData:       raw,
	}, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) string {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary {
			return e.Email
		}
	}
	if len(emails) > 0 {
		return emails[0].Email
	}
	return ""
}
