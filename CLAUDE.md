# go-better-auth — Claude Code Guidelines

## Repository Structure

This is a Go monorepo using `go.work`. The main package is `packages/betterauth` (its own Go module). Run tests and the linter from that directory.

## Commands

```bash
# Tests
cd packages/betterauth && go test ./...

# Linter (gofmt — required before any PR)
gofmt -l packages/ e2e/          # list files with issues
gofmt -w packages/ e2e/          # fix all issues

# Makefile shortcuts (from repo root)
make test
make lint   # runs gofmt check
```

## Rules

### Always run `gofmt` before finishing a task or opening a PR

Run `gofmt -l packages/ e2e/` before committing. If it lists any files, fix them with `gofmt -w packages/ e2e/` and include the formatting fix in the same commit or a separate `style:` commit before pushing.

This is checked in CI — a PR with formatting issues will fail.

## Project Layout

| Path | Description |
|------|-------------|
| `packages/betterauth/` | Core auth library (main module) |
| `packages/betterauth/plugin/` | Plugin interface + `ErrHandled` sentinel |
| `packages/betterauth/plugins/admin/` | Admin plugin |
| `packages/betterauth/plugins/organization/` | Organization plugin |
| `packages/betterauth/plugins/totp/` | TOTP/2FA plugin |
| `packages/betterauth/adapter/` | Adapter interface |
| `packages/betterauth/adapter/memory/` | In-memory adapter (used in tests) |
| `packages/testutil/` | Shared test utilities |
| `e2e/` | End-to-end tests |
| `.worktrees/` | Git worktrees (gitignored) |

## Plugin Development

New plugins go in `packages/betterauth/plugins/<name>/`. See the admin or TOTP plugin for reference patterns:

- Implement `plugin.Plugin` (requires `ID() string`)
- Implement `plugin.AuthAware` to receive the `*Auth` reference via `SetAuth`
- Implement `plugin.SchemaProvider`, `plugin.EndpointProvider`, `plugin.SessionCreateHookProvider`, etc. as needed
- Use `plugin.ErrHandled` in session hooks when the hook has already written the HTTP response
