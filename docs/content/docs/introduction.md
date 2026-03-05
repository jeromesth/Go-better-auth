# Introduction

Go Better Auth is a Go port of the [better-auth](https://github.com/better-auth/better-auth) TypeScript authentication framework. It provides a comprehensive, self-hosted authentication server as a single Go library.

## Why Go Better Auth?

- **Single binary deployment** - No runtime dependencies. Ship one binary. Docker images go from ~1GB to ~20MB.
- **Native performance** - Go's compiled nature and goroutine concurrency model provide excellent throughput for auth workloads.
- **Production-hardened crypto** - Built on Go's stdlib `crypto` package, the same primitives used by Kubernetes, Docker, and HashiCorp Vault.
- **Plugin system** - Interface-based plugin architecture for extending functionality without modifying core code.
- **Framework agnostic** - Works with any Go HTTP framework via standard `net/http` handlers.

## Features

- Email/password authentication with configurable hashing (scrypt default)
- Session management with cookie and Bearer token support
- OAuth 2.0 social login (Google, GitHub, Apple)
- Email verification and password reset flows
- Rate limiting (in-memory, pluggable)
- Plugin system for extending endpoints, schemas, and hooks
- Database adapter interface with in-memory adapter included

## Quick Start

```go
package main

import (
    "net/http"

    betterauth "github.com/jeromesth/go-better-auth"
    "github.com/jeromesth/go-better-auth/adapter/memory"
)

func main() {
    auth := betterauth.New(betterauth.BetterAuthOptions{
        BaseURL:  "http://localhost:3000",
        BasePath: "/api/auth",
        Secret:   "your-secret-key",
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
