# Configuration

Go Better Auth is configured through the `BetterAuthOptions` struct passed to `betterauth.New()`.

## Full Configuration

```go
auth := betterauth.New(betterauth.BetterAuthOptions{
    // Application name (default: "Better Auth")
    AppName: "My App",

    // Public-facing base URL
    BaseURL: "https://myapp.com",

    // API path prefix (default: "/api/auth")
    BasePath: "/api/auth",

    // Secret key for signing tokens and cookies (required)
    Secret: os.Getenv("AUTH_SECRET"),

    // Database configuration (required)
    Database: &betterauth.DatabaseConfig{
        Adapter: myAdapter,
    },

    // Email/password authentication
    EmailAndPassword: &betterauth.EmailPassConfig{
        Enabled:           true,
        MinPasswordLength: 8,   // default: 8
        MaxPasswordLength: 128, // default: 128
        AutoSignIn:        true, // auto sign-in after registration
    },

    // Session configuration
    Session: &betterauth.SessionConfig{
        ExpiresIn: 7 * 24 * 60 * 60, // 7 days (default)
        UpdateAge: 24 * 60 * 60,      // refresh after 1 day (default)
    },

    // Rate limiting
    RateLimit: &betterauth.RateLimitConfig{
        Enabled: true,
        Window:  10,  // 10 second window
        Max:     100, // 100 requests per window
    },

    // Social OAuth providers
    SocialProviders: map[string]social.ProviderConfig{
        "google": {
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        },
        "github": {
            ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
            ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
        },
    },

    // Trusted origins for CORS/CSRF
    TrustedOrigins: []string{
        "https://myapp.com",
        "*.myapp.com",
    },
})
```

## Configuration Sections

### Session

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ExpiresIn` | `int` | `604800` | Session TTL in seconds (7 days) |
| `UpdateAge` | `int` | `86400` | Refresh session after this many seconds |
| `FreshAge` | `int` | `86400` | Session is "fresh" for this duration |
| `DisableSessionRefresh` | `bool` | `false` | Disable automatic session refresh |

### Email and Password

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable email/password auth |
| `MinPasswordLength` | `int` | `8` | Minimum password length |
| `MaxPasswordLength` | `int` | `128` | Maximum password length |
| `AutoSignIn` | `bool` | `true` | Auto sign-in after registration |
| `RequireEmailVerification` | `bool` | `false` | Require email verification before sign-in |
| `DisableSignUp` | `bool` | `false` | Disable new registrations |

### Rate Limiting

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable rate limiting |
| `Window` | `int` | `10` | Window size in seconds |
| `Max` | `int` | `100` | Max requests per window |
| `Storage` | `string` | `"memory"` | Rate limit storage backend |
