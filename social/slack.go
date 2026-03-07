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

// Slack implements the SocialProvider interface for Slack OpenID Connect.
type Slack struct{}

func (Slack) ID() string { return "slack" }

func (Slack) AuthorizationURL(state, _ string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {state},
		"scope":         {strings.Join(defaultScopes(cfg.Scopes, []string{"openid", "email", "profile"}), " ")},
	}
	return "https://slack.com/openid/connect/authorize?" + params.Encode()
}

func (Slack) ExchangeCode(ctx context.Context, code, _ string, cfg ProviderConfig) (*OAuthTokens, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/openid.connect.token",
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
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
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

func (Slack) GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://slack.com/api/openid.connect.userInfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching user info: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding user info: %w", err)
	}

	return &OAuthUser{
		ID:            str(raw, "sub"),
		Email:         str(raw, "email"),
		EmailVerified: boolVal(raw, "email_verified"),
		Name:          str(raw, "name"),
		Image:         str(raw, "picture"),
		RawData:       raw,
	}, nil
}
