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

// Discord implements the SocialProvider interface for Discord OAuth 2.0.
type Discord struct{}

func (Discord) ID() string { return "discord" }

func (Discord) AuthorizationURL(state, _ string, cfg ProviderConfig) string {
	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {cfg.RedirectURI},
		"response_type": {"code"},
		"state":         {state},
		"scope":         {strings.Join(defaultScopes(cfg.Scopes, []string{"identify", "email"}), " ")},
	}
	return "https://discord.com/api/oauth2/authorize?" + params.Encode()
}

func (Discord) ExchangeCode(ctx context.Context, code, _ string, cfg ProviderConfig) (*OAuthTokens, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://discord.com/api/oauth2/token",
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

func (Discord) GetUserInfo(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/users/@me", nil)
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

	id := str(raw, "id")
	avatar := str(raw, "avatar")
	image := discordAvatarURL(id, avatar)

	name := str(raw, "global_name")
	if name == "" {
		name = str(raw, "username")
	}

	return &OAuthUser{
		ID:            id,
		Email:         str(raw, "email"),
		EmailVerified: boolVal(raw, "verified"),
		Name:          name,
		Image:         image,
		RawData:       raw,
	}, nil
}

func discordAvatarURL(userID, avatarHash string) string {
	if avatarHash == "" {
		return "https://cdn.discordapp.com/embed/avatars/0.png"
	}
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userID, avatarHash)
}
