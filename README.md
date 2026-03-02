<p align="center">
  <h1 align="center">Go Better Auth</h1>
</p>

<p align="center">
  The most comprehensive authentication library for Go
</p>

<p align="center">
  <a href="https://github.com/jeromesth/Go-better-auth/blob/main/docs/content/docs/introduction.md">Docs</a> |
  <a href="https://github.com/jeromesth/Go-better-auth/issues">Issues</a> |
  <a href="https://github.com/jeromesth/Go-better-auth/blob/main/CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/jeromesth/go-better-auth/packages/betterauth"><img src="https://pkg.go.dev/badge/github.com/jeromesth/go-better-auth/packages/betterauth.svg" alt="Go Reference"></a>
  <a href="https://github.com/jeromesth/Go-better-auth/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/jeromesth/Go-better-auth/stargazers"><img src="https://img.shields.io/github/stars/jeromesth/Go-better-auth?style=flat-square" alt="GitHub Stars"></a>
</p>

---

## About

Go Better Auth is a Go port of the [better-auth](https://github.com/better-auth/better-auth) TypeScript authentication framework. It provides a comprehensive set of authentication features as a single Go library with a plugin ecosystem for advanced functionality.

**Key benefits over the TypeScript original:**

- **Single binary** - No Node.js runtime, no `node_modules`. Ship one binary.
- **20MB Docker images** - Down from ~1GB with Node.js.
- **Native concurrency** - Goroutines handle thousands of concurrent sessions efficiently.
- **Production crypto** - Go's stdlib `crypto` package, used by Kubernetes and Docker.
- **Cross-compilation** - `GOOS=linux GOARCH=arm64 go build` - deploy anywhere.

## Features

- Email/password authentication (scrypt hashing, configurable)
- OAuth 2.0 social login (Google, GitHub, Apple)
- Session management (cookie + Bearer token)
- Email verification and password reset
- Rate limiting
- Plugin system (endpoints, schemas, hooks, middleware)
- Database adapter interface (in-memory included, bring your own for production)

## Quick Start

```bash
go get github.com/jeromesth/go-better-auth/packages/betterauth
```

```go
package main

import (
    "net/http"
    "os"

    betterauth "github.com/jeromesth/go-better-auth/packages/betterauth"
    "github.com/jeromesth/go-better-auth/packages/betterauth/adapter/memory"
)

func main() {
    auth := betterauth.New(betterauth.BetterAuthOptions{
        BaseURL:  "http://localhost:3000",
        BasePath: "/api/auth",
        Secret:   os.Getenv("AUTH_SECRET"),
        Database: &betterauth.DatabaseConfig{
            Adapter: memory.New(),
        },
        EmailAndPassword: &betterauth.EmailPassConfig{
            Enabled: true,
        },
    })

    http.Handle("/api/auth/", auth.Handler())
    http.ListenAndServe(":3000", nil)
}
```

## Project Structure

```
go-better-auth/
├── packages/
│   ├── betterauth/     # Core authentication library
│   └── testutil/       # Test utilities
├── e2e/                # End-to-end tests
│   ├── adapter/        # Database adapter tests
│   ├── integration/    # Full integration tests
│   └── smoke/          # Quick smoke tests
├── docs/               # Documentation
│   └── content/docs/   # Doc pages (getting started, API reference, etc.)
├── go.work             # Go workspace configuration
├── Makefile            # Build, test, lint commands
└── PLAN.md             # Architecture & implementation plan
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sign-up/email` | Register with email/password |
| `POST` | `/sign-in/email` | Login with email/password |
| `POST` | `/sign-out` | Logout (revoke session) |
| `GET` | `/get-session` | Get current session + user |
| `GET` | `/list-sessions` | List active sessions |
| `POST` | `/change-password` | Change password |
| `POST` | `/request-password-reset` | Request password reset |
| `POST` | `/reset-password` | Reset password with token |
| `POST` | `/verify-email` | Verify email |
| `POST` | `/update-user` | Update user profile |
| `POST` | `/sign-in/{provider}` | Initiate OAuth flow |
| `GET` | `/callback/{provider}` | OAuth callback |

See the full [API Reference](docs/content/docs/reference/api.md).

## Contributing

Go Better Auth is MIT licensed and welcomes contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

There are two main ways to contribute:

1. **Code** - Open a PR with bug fixes, new features, or adapter implementations
2. **Issues** - Report bugs or request features via [GitHub Issues](https://github.com/jeromesth/Go-better-auth/issues)

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](SECURITY.md) for details.

## License

[MIT](LICENSE.md)
