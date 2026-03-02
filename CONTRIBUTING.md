# Contributing to Go Better Auth

Thank you for your interest in contributing to Go Better Auth! This guide will help you get started.

## Project Structure

```
go-better-auth/
├── packages/betterauth/    # Core authentication library
│   ├── adapter/            # Database adapter interface + memory adapter
│   ├── crypto/             # Password hashing, tokens, HMAC
│   ├── internal/           # Internal utilities
│   ├── models/             # Data models (User, Session, Account, etc.)
│   ├── oauth/              # OAuth state management
│   ├── plugin/             # Plugin system interfaces
│   ├── ratelimit/          # Rate limiting
│   ├── session/            # Session management
│   ├── social/             # Social login providers
│   └── handler_*.go        # HTTP endpoint handlers
├── packages/testutil/      # Shared test utilities
├── e2e/                    # End-to-end tests
│   ├── adapter/            # Adapter conformance tests
│   ├── integration/        # Full integration tests
│   └── smoke/              # Quick smoke tests
└── docs/                   # Documentation
```

## Development Setup

### Prerequisites

- Go 1.22 or later

### Getting Started

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/<your-username>/Go-better-auth.git
   cd Go-better-auth
   ```

2. **Build all packages**

   ```bash
   make build
   ```

3. **Run all tests**

   ```bash
   make test
   ```

4. **Run just the e2e tests**

   ```bash
   make e2e
   ```

## Branch Naming

When creating a branch for your contribution, use one of these prefixes:

- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or improvements
- `chore/` - Maintenance tasks

Example: `feat/postgres-adapter`, `fix/session-refresh-bug`

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Prefer interfaces for extensibility
- Keep functions focused and small
- Write table-driven tests where appropriate
- Do not add unnecessary dependencies

## Testing

- **Unit tests** go next to the code they test (e.g., `crypto/crypto_test.go`)
- **Integration tests** go in `e2e/integration/`
- **Adapter conformance tests** go in `e2e/adapter/`
- Use the `testutil` package for creating test auth instances
- All PRs must pass existing tests and include tests for new functionality

## Pull Request Process

1. Create a branch from `main` with the appropriate prefix
2. Make your changes
3. Ensure all tests pass: `make test`
4. Ensure code is formatted: `gofmt -w .`
5. Write a clear PR description explaining what and why
6. Link any related issues

## Commit Messages

Use clear, descriptive commit messages:

```
feat: add PostgreSQL adapter

Implements the adapter.Adapter interface for PostgreSQL using sqlx.
Supports all CRUD operations with parameterized queries.
```

Prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`

## Adding a Database Adapter

To contribute a new database adapter:

1. Create a new package (e.g., `packages/postgres-adapter/`)
2. Implement the `adapter.Adapter` interface
3. Add tests in `e2e/adapter/` using the `adapterTestSuite` helper
4. Add documentation in `docs/content/docs/adapters/`

## Adding a Social Provider

To contribute a new OAuth provider:

1. Implement `social.SocialProvider` in `packages/betterauth/social/`
2. Add tests
3. Register it as a built-in in `auth.go`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
