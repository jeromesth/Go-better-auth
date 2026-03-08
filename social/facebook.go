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

// Facebook implements the SocialProvider interface for Facebook OAuth 2.0.
type Facebook struct{}

func (Facebook) ID() string { return "facebook" }

func (Facebook) AuthorizationURL(state, _ string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {state},
		"scope":         {strings.Join(defaultScopes(cfg.Scopes, []string{"email", "public_profile"}), " ")},
	}
	return "https://www.facebook.com/v19.0/dialog/oauth?" + params.Encode()
}

func (Facebook) ExchangeCode(ctx context.Context, code, _ string, cfg ProviderConfig) (*OAuthTokens, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://graph.facebook.com/v19.0/oauth/access_token",
		strings.NewReader(url.Values{
			"code":          {code},
			"client_id":     {cfg.ClientID},
			"client_secret": {cfg.ClientSecret},
			"redirect_uri":  {cfg.RedirectURI},
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
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &OAuthTokens{
		AccessToken: result.AccessToken,
		ExpiresIn:   result.ExpiresIn,
	}, nil
}

func (Facebook) GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://graph.facebook.com/me?fields=id,name,email,picture.type(large)", nil)
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

	image := ""
	if picture, ok := raw["picture"].(map[string]any); ok {
		if data, ok := picture["data"].(map[string]any); ok {
			image = str(data, "url")
		}
	}

	return &OAuthUser{
		ID:            str(raw, "id"),
		Email:         str(raw, "email"),
		EmailVerified: true,
		Name:          str(raw, "name"),
		Image:         image,
		RawData:       raw,
	}, nil
}
