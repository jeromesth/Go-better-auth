# Social OAuth Authentication

Go Better Auth supports OAuth 2.0 social login with built-in providers for Google, GitHub, and Apple. Custom providers can be added via the `SocialProvider` interface.

## Setup

```go
auth := betterauth.New(betterauth.BetterAuthOptions{
    // ...
    SocialProviders: map[string]social.ProviderConfig{
        "google": {
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            RedirectURI:  "https://myapp.com/api/auth/callback/google",
        },
        "github": {
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
            RedirectURI:  "https://myapp.com/api/auth/callback/github",
        },
    },
})
```

## API Endpoints

### Initiate OAuth Flow

```
POST /api/auth/sign-in/{provider}
```

Redirects the user to the provider's authorization page.

### OAuth Callback

```
GET /api/auth/callback/{provider}?code=...&state=...
```

Handles the provider's redirect. On success, creates a session and redirects to the callback URL.

### Link Social Account

Requires an active session.

```
POST /api/auth/link-social
```

```json
{
    "provider": "github",
    "callbackURL": "https://myapp.com/settings"
}
```

## Built-in Providers

| Provider | ID | Scopes |
|----------|----|--------|
| Google | `google` | `openid email profile` |
| GitHub | `github` | `read:user user:email` |
| Apple | `apple` | `name email` |

## Custom Providers

Implement the `social.SocialProvider` interface and register it:

```go
auth.RegisterSocialProvider(myCustomProvider)
```
