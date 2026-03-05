# Installation

## Requirements

- Go 1.22 or later

## Install

Add Go Better Auth to your project:

```bash
go get github.com/jeromesth/go-better-auth
```

## Basic Setup

```go
package main

import (
    "net/http"
    "os"

    betterauth "github.com/jeromesth/go-better-auth"
    "github.com/jeromesth/go-better-auth/adapter/memory"
)

func main() {
    auth := betterauth.New(betterauth.BetterAuthOptions{
        BaseURL:  "http://localhost:3000",
        BasePath: "/api/auth",
        Secret:   os.Getenv("AUTH_SECRET"),
        Database: &betterauth.DatabaseConfig{
            Adapter: memory.New(), // Replace with a real adapter in production
        },
        EmailAndPassword: &betterauth.EmailPassConfig{
            Enabled: true,
        },
    })

    http.Handle("/api/auth/", auth.Handler())
    http.ListenAndServe(":3000", nil)
}
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AUTH_SECRET` | Secret key for signing tokens and cookies | Yes |
| `AUTH_BASE_URL` | Public-facing base URL of your application | Yes |

## Next Steps

- [Configuration](./configuration.md) - Full configuration reference
- [Authentication](../authentication/email-password.md) - Email/password setup
- [Adapters](../adapters/overview.md) - Database adapter setup
