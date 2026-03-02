# Plugin System

Go Better Auth uses an interface-based plugin system. Plugins can extend the auth server with additional endpoints, database tables, middleware, hooks, and rate limit rules.

## Plugin Interface

Every plugin must implement the base `Plugin` interface:

```go
type Plugin interface {
    ID() string
}
```

Additional capabilities are added by implementing optional interfaces:

| Interface | Purpose |
|-----------|---------|
| `Initializer` | Run setup logic on startup |
| `EndpointProvider` | Add HTTP endpoints |
| `SchemaProvider` | Extend the database schema |
| `HookProvider` | Run code before/after endpoint handlers |
| `MiddlewareProvider` | Add HTTP middleware |
| `RateLimitProvider` | Add custom rate limit rules |

## Example Plugin

```go
package twofactor

import (
    "net/http"
    "github.com/jeromesth/go-better-auth/packages/betterauth/plugin"
)

type TwoFactor struct{}

func New() *TwoFactor { return &TwoFactor{} }

func (t *TwoFactor) ID() string { return "two-factor" }

func (t *TwoFactor) Endpoints() []plugin.Endpoint {
    return []plugin.Endpoint{
        {Method: "POST", Path: "/two-factor/setup", Handler: t.handleSetup},
        {Method: "POST", Path: "/two-factor/verify", Handler: t.handleVerify},
    }
}

func (t *TwoFactor) Schema() map[string]plugin.TableSchema {
    return map[string]plugin.TableSchema{
        "two_factor": {
            Fields: []plugin.FieldDef{
                {Name: "id", Type: "text", Required: true},
                {Name: "user_id", Type: "text", Required: true, Ref: "user.id"},
                {Name: "secret", Type: "text", Required: true},
            },
        },
    }
}

func (t *TwoFactor) handleSetup(w http.ResponseWriter, r *http.Request) { /* ... */ }
func (t *TwoFactor) handleVerify(w http.ResponseWriter, r *http.Request) { /* ... */ }
```

## Registering Plugins

```go
auth := betterauth.New(betterauth.BetterAuthOptions{
    // ...
    Plugins: []plugin.Plugin{
        twofactor.New(),
    },
})
```
