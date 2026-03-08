# Go Better Auth — Next Priorities Analysis

## Current State of the Project

### What's Built & Merged (on `main`)
- **Core auth**: Email/password sign-up, sign-in, sign-out
- **Session management**: Cookie-based sessions, bearer tokens, revocation, listing, refresh
- **OAuth 2.0**: Google, GitHub, Apple providers with account linking
- **Email verification** and **password reset** flows
- **User management**: Update profile, delete account, change email
- **Rate limiting**: In-memory sliding-window per-IP
- **Plugin system**: Full interface-based architecture (init, endpoints, schema, hooks, middleware)
- **Admin plugin**: RBAC, user banning with expiry, impersonation, 16 admin endpoints
- **Database adapters**: Memory adapter (testing), PostgreSQL example adapter
- **Working example**: Backend with Docker Compose + PostgreSQL
- **Documentation**: 9 docs covering installation, configuration, API reference, concepts
- **CI**: GitHub Actions workflow

### In-Progress (Open Branch, Not Yet Merged)
- **Organization plugin** (`claude/build-organization-plugin-vPD9p`): RBAC, invitations, member management — 3,500+ lines of new code including tests

---

## PR Feedback: Structural Issues to Address Before Next Feature Work

### 1. Package Naming & Folder Structure

**Current problem**: Import paths are verbose and stutter:
```go
import betterauth "github.com/jeromesth/go-better-auth"
import "github.com/jeromesth/go-better-auth/plugins/admin"
```

The `packages/betterauth/` nesting serves no purpose and creates confusion with the existing TypeScript `better-auth` library name.

#### Recommended new structure

Rename the module from `packages/betterauth` to a short, clear Go module name. Two options:

**Option A — Flat module (recommended for Go libraries)**:
```
go-better-auth/
├── auth.go                     # package betterauth (root = the library)
├── adapter/
│   ├── adapter.go
│   ├── memory/
│   └── sqlx/                   # future
├── crypto/
├── session/
├── social/
├── oauth/
├── plugin/
├── plugins/
│   ├── admin/
│   └── organization/
├── models/
├── ratelimit/
├── internal/
├── cmd/                        # future CLI tools
├── examples/
│   └── backend/
├── e2e/
└── docs/
```

Import paths become clean:
```go
import "github.com/jeromesth/go-better-auth"
import "github.com/jeromesth/go-better-auth/plugins/admin"
import "github.com/jeromesth/go-better-auth/adapter/memory"
```

**Option B — Keep `packages/` but rename inner dir**:
```
packages/auth/          (module: github.com/jeromesth/go-better-auth/packages/auth)
packages/testutil/
```

**Recommendation**: Option A. The `packages/` directory is not a Go convention — it comes from the TypeScript monorepo world. In Go, the repository root *is* the package. Major Go projects (kubernetes, docker, terraform, chi, echo) all put their main package at the root.

### 2. The `src/` Question

**No — Go projects do not use `src/`**. This is explicitly discouraged by the Go community.

The `$GOPATH` workspace has a `src/` directory, but individual projects never create one. The Go team (Russ Cox specifically) has stated that even `cmd/`, `pkg/`, `docs/` are not required standard directories — the simpler the better.

What Go **does** use:
- **`internal/`** — Private packages (enforced by the Go toolchain — other modules literally cannot import from it)
- **`cmd/`** — Entry points for multiple binaries
- **`testdata/`** — Test fixtures (ignored by Go toolchain)

Reference: [Official Go module layout guide](https://go.dev/doc/modules/layout)

### 3. Test File Standards

**Go has strict, non-negotiable conventions for test files:**

| Rule | Convention |
|------|-----------|
| **File suffix** | `_test.go` (NOT `.test.go`) — this is enforced by `go test` |
| **Placement** | Same directory as the code being tested |
| **Package name** | Same package (white-box) OR `package foo_test` (black-box) |
| **No test code in non-test files** | Test helpers, assertions, mocks — all go in `_test.go` files |
| **Test function names** | `func TestXxx(t *testing.T)` — prefix must be `Test` |

**Audit result**: The current codebase is actually clean — no test code is mixed into non-test files. All test functions are properly in `_test.go` files. The concern may have come from seeing `access.go` alongside `admin_test.go` — but `access.go` is production RBAC code, not test code.

**Current test file layout (correct)**:
```
admin/
├── access.go        ← Production RBAC logic (Statements, Roles, HasPermission)
├── admin.go         ← Plugin struct, Options, New(), Schema(), Endpoints()
├── admin_test.go    ← Tests for all of the above
├── errors.go        ← Error constants
└── routes.go        ← HTTP handlers
```

**One improvement**: For large plugins, split tests by concern:
```
admin/
├── ...
├── admin_test.go        ← Core plugin tests
├── access_test.go       ← RBAC/permission unit tests
└── routes_test.go       ← HTTP handler integration tests
```

---

## PR Feedback: Organization Plugin Structural Issues

### 4. Missing: `access/statement.ts` Equivalent

The Go org plugin has `access.go` which **does** contain the statement-based RBAC equivalent:
- `Statements` type (map of resource → actions)
- `Role` struct with `Authorize()` method
- `DefaultStatements` and `DefaultRoles()`
- `HasPermission()` and `CanManageRole()`

**However**, compared to the TypeScript version, it's **missing**:
- **Dynamic access control** — loading roles from the DB at runtime (the TS version has `crud-access-control.ts` with CRUD endpoints for org roles)
- **Permission caching** — the TS `has-permission.ts` caches resolved roles in memory
- **Team permissions** — the TS `defaultStatements` includes `team` and `ac` resources

**Recommendation**: The `access.go` file is a good start but should be expanded. Consider splitting into an `access/` subdirectory once dynamic AC is added:
```
organization/
├── access/
│   ├── statement.go         # DefaultStatements, DefaultRoles
│   └── resolver.go          # Dynamic role resolution + caching
```

### 5. Route Splitting — Yes, Absolutely Do This

The current `routes.go` is **1,353 lines** with 21 handler functions. The TypeScript version splits by entity domain:

| TypeScript File | Handlers |
|----------------|----------|
| `crud-org.ts` | createOrganization, updateOrganization, deleteOrganization, setActive, getFullOrganization, listOrganizations, checkSlug |
| `crud-members.ts` | addMember, removeMember, updateMemberRole, leaveOrganization, listMembers, getActiveMember |
| `crud-invites.ts` | createInvitation, acceptInvitation, rejectInvitation, cancelInvitation, getInvitation, listInvitations |
| `crud-team.ts` | (future) team management |
| `crud-access-control.ts` | (future) dynamic role CRUD |

**This is perfectly valid and encouraged in Go.** Multiple files in the same directory share the same package. Go doesn't care how you split files within a package — it's one compilation unit.

**Recommended Go equivalent**:
```
organization/
├── routes_org.go            # Organization CRUD handlers
├── routes_members.go        # Member management handlers
├── routes_invitations.go    # Invitation handlers
├── routes_teams.go          # (future) Team handlers
├── routes_access_control.go # (future) Dynamic role CRUD
```

### 6. Adapter/Repository Pattern — Separate DB Calls

The TypeScript version has a dedicated `adapter.ts` with 40+ named query functions. Route handlers never call the DB directly — they go through the adapter layer.

Our Go org plugin currently calls `p.auth.InternalAdapter().FindOne(...)` directly in every handler.

**Recommendation**: Create a `repository.go` (or `adapter.go`) that encapsulates all DB operations:

```go
// organization/repository.go
package organization

type repository struct {
    adapter adapter.Adapter
}

func (r *repository) FindOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) { ... }
func (r *repository) CreateMember(ctx context.Context, m *Member) (*Member, error) { ... }
func (r *repository) ListPendingInvitations(ctx context.Context, orgID string) ([]*Invitation, error) { ... }
// ... etc
```

Benefits:
- Route handlers become shorter and more readable
- DB logic is independently testable
- Easier to optimize queries later without touching handler logic

### 7. Utility Separation — `has_permission.go`

The TypeScript version has a dedicated `has-permission.ts` file. Our `access.go` combines Statements, Roles, and HasPermission in one file. This works fine at current size (109 lines), but as dynamic access control is added, splitting makes sense:

```
organization/
├── access.go            # Statements type, Role struct, DefaultStatements, DefaultRoles
├── has_permission.go    # HasPermission(), CanManageRole(), permission resolution logic
```

---

## RBAC Libraries in Go (CASL Equivalent)

### Top Contenders

| Library | GitHub Stars | Model | Architecture | Best For |
|---------|-------------|-------|-------------|----------|
| **[Casbin](https://github.com/casbin/casbin)** | 18k+ | ACL/RBAC/ABAC | Embedded library (stateless) | Flexible in-app authorization, config-driven policies |
| **[OpenFGA](https://github.com/openfga/openfga)** | 3k+ | ReBAC (Zanzibar) | Centralized engine | Relationship-based permissions, distributed systems |
| **[Permify](https://github.com/Permify/permify)** | 5k+ | ReBAC/RBAC/ABAC | Centralized service | Google Zanzibar-inspired, gRPC-first |
| **[Oso / Polar](https://github.com/osohq/oso)** | 3.4k+ | Policy language | Embedded library | Declarative policies, complex business rules |

### Comparison to CASL

CASL is an isomorphic JS library for **attribute-based access control** that defines abilities as `can(action, subject, conditions)`. The closest Go equivalents:

- **Casbin** is the most direct analog — it's an embedded library (not a service), supports RBAC/ABAC/ACL via config files, and has 16+ language SDKs. It uses a PERM metamodel similar to CASL's ability definitions.
- **OpenFGA** is more powerful but heavier — it's a full authorization engine you run as a service, inspired by Google's Zanzibar. Overkill for simple RBAC but great for complex relationship-based permissions.

### Adapter Pattern Recommendation

Rather than hard-coupling to any RBAC library, we could define a simple `Authorizer` interface:

```go
// plugin/authz.go
type Authorizer interface {
    // Can checks if subject can perform action on resource
    Can(ctx context.Context, subject string, action string, resource string) (bool, error)
}
```

Then provide optional adapters:
```go
import "github.com/jeromesth/go-better-auth/authz/casbinadapter"
import "github.com/jeromesth/go-better-auth/authz/openfgaadapter"

// Users bring their own:
auth := betterauth.New(betterauth.BetterAuthOptions{
    Authorizer: casbinadapter.New(enforcer),
    // OR
    Authorizer: openfgaadapter.New(client),
})
```

This is a **food-for-thought** item — not a priority for the next sprint, but worth designing the interface now so plugins use it instead of rolling their own permission checks.

### Implementation Roadmap: RBAC Authorization Adapters

**Current state**: The admin and organization plugins use a built-in RBAC system (`Statements`, `Role`, `HasPermission`) that is zero-dependency and covers most use cases. This remains the default.

**Future direction**: Keep the built-in RBAC as the zero-dependency default, while offering optional adapter packages for advanced authorization engines.

#### Tier 1: Casbin Adapter (Medium Priority)

The clear #1 choice for users who need flexible, config-driven RBAC/ABAC:
- **19.9k GitHub stars**, 1,700+ dependent Go packages
- Native Go library (embeddable, minimal dependency footprint)
- 50+ storage adapters (Postgres, MySQL, Redis, GORM, etc.)
- Middleware for Gin, Echo, Chi, go-kit, and more
- API maps directly to our pattern: `e.Enforce(subject, resource, action)` ≈ `HasPermission(role, resource, action)`
- Model-agnostic — users can evolve from RBAC to ABAC without code changes

#### Tier 2: OpenFGA Adapter (Low Priority)

For enterprise users who need Zanzibar-style relationship-based access control:
- CNCF Incubating project, backed by Auth0/Okta
- Relationship tuples: `(user, relation, object)` model
- Ideal for complex permission hierarchies (org → team → project → document)
- Can be embedded as a Go library with in-memory/SQLite backends
- Heavier dependency than Casbin

#### Not Recommended as Adapters

- **OPA**: Heavy dependency footprint, Rego learning curve — only for users already using OPA in their infrastructure
- **SpiceDB/Permify**: Services, not libraries — users should integrate at the application level
- **goRBAC**: Not actively maintained, our built-in RBAC is already equivalent
- **Oso**: Deprecated

#### Proposed Interface

```go
// Authorizer defines the external authorization adapter interface.
type Authorizer interface {
    Can(ctx context.Context, subject, action, resource string) (bool, error)
    CanWithContext(ctx context.Context, subject, action, resource string, attrs map[string]any) (bool, error)
}
```

#### Implementation Approach

1. Define the `Authorizer` interface in the core package
2. Optional adapter packages (`authz/casbin/`, `authz/openfga/`) — imported only when needed
3. Admin and organization plugins accept an optional `Authorizer` — when nil, use the built-in RBAC
4. Zero dependency overhead for users who don't need external authorization engines

---

## Gap Analysis: Go Port vs TypeScript better-auth

### Authentication Providers
| Provider | TypeScript | Go Port |
|----------|-----------|---------|
| Email/Password | ✅ | ✅ |
| Google | ✅ | ✅ |
| GitHub | ✅ | ✅ |
| Apple | ✅ | ✅ |
| Discord | ✅ | planned |
| Microsoft | ✅ | ✅ |
| Facebook | ✅ | planned |
| Twitter/X | ✅ | planned |
| LinkedIn | ✅ | planned |
| Slack | ✅ | ✅ |
| GitLab | ✅ | ✅ |
| 25+ others | ✅ | planned |

### Plugins
| Plugin | TypeScript | Go Port |
|--------|-----------|---------|
| Admin | ✅ | ✅ |
| Organization | ✅ | 🔄 (in PR) |
| Two-Factor (2FA/TOTP) | ✅ | ✅ |
| Magic Link | ✅ | ✅ |
| API Key | ✅ | ✅ |
| JWT | ✅ | ✅ |
| Email OTP | ✅ | planned |
| Passkey (WebAuthn) | ✅ | planned |
| Username | ✅ | planned |
| Bearer | ✅ | planned |
| Multi-Session | ✅ | planned |
| Anonymous | ✅ | planned |
| Phone Number | ✅ | planned |
| SSO (SAML) | ✅ | future |
| OIDC Provider | ✅ | future |
| OAuth 2.1 Provider | ✅ | future |
| One-Time Token | ✅ | future |
| Generic OAuth | ✅ | future |
| Captcha | ✅ | future |
| Have I Been Pwned | ✅ | future |
| Open API | ✅ | future |
| i18n | ✅ | future |
| Stripe (payments) | ✅ | future |

### Core Concepts
| Concept | TypeScript | Go Port |
|---------|-----------|---------|
| Session Management | ✅ | ✅ |
| Database / Adapters | ✅ | ✅ (memory + Postgres example) |
| Rate Limiting | ✅ | ✅ |
| Hooks | ✅ | ✅ |
| Plugins | ✅ | ✅ |
| OAuth | ✅ | ✅ |
| Cookies | ✅ | ✅ |
| Email (sending) | ✅ | ⚠️ (callback-based, no built-in) |
| API reference | ✅ | ✅ |
| CLI | ✅ | ❌ (N/A for Go) |
| Client SDK | ✅ | ❌ (N/A - server library) |
| User & Accounts | ✅ | ✅ |
| Dynamic Base URL | ✅ | ❌ |
| Secondary Storage | ✅ | ❌ (interface defined, not implemented) |

### Database Adapters
| Adapter | TypeScript | Go Port |
|---------|-----------|---------|
| PostgreSQL | ✅ | ✅ (sqlx) |
| MySQL | ✅ | ✅ (sqlx) |
| SQLite | ✅ | ✅ (sqlx) |
| MongoDB | ✅ | future |
| In-Memory | ✅ | ✅ |

### Framework Integrations (Go-Relevant)
| Framework | Status |
|-----------|--------|
| net/http (stdlib) | ✅ Works natively |
| Chi | ✅ framework/chi |
| Gin | ✅ framework/gin |
| Echo | planned |
| Fiber | planned |
| gorilla/mux | planned |

---

---

## Sprint 1 Completion — Foundation & Core (Completed)

| Item | PR | Status |
|------|----|--------|
| Core auth (email/password, sessions, OAuth) | — | ✅ Merged |
| Admin plugin (RBAC, user management, impersonation) | #5 | ✅ Merged |
| Organization plugin (multi-tenancy, members, invitations) | #5, #8, #9 | ✅ Merged |
| Security hardening (open redirect, IP config, org invariants) | — | ✅ Merged |

## Sprint 2 Completion — Next-Version Implementation (March 2026)

All PRs from Sprint 2 are now merged:

| Item | PR | Status |
|------|----|--------|
| Restructure repo (flatten packages/betterauth) | #9 | ✅ Merged |
| Refactor org plugin (split routes, add repository layer) | #10 | ✅ Merged |
| Two-Factor Auth (TOTP) plugin | #9 | ✅ Merged |
| sqlx adapter (Postgres/MySQL/SQLite) | #11 | ✅ Merged |
| JWT plugin | #12 | ✅ Merged |
| API Key plugin | #13 | ✅ Merged |
| Chi framework adapter | #14 | ✅ Merged |
| Gin framework adapter | #14 | ✅ Merged |
| Microsoft, Slack, GitLab OAuth providers | #15 | ✅ Merged |
| Magic Link plugin | #16 | ✅ Merged |
| Bump Go minimum to 1.25.0, fix Makefile | #18 | ✅ Merged |

---

## Recommended Priority Order (Updated)

### Priority 1: Remaining OAuth Providers
**Why first**: Low effort, high adoption impact. Microsoft/Slack/GitLab are done. Remaining:

**Order**: Discord → Twitter/X → LinkedIn → Facebook

Discord is highest priority — the developer community is heavily Discord-based.

### Priority 2: Echo + Fiber Framework Adapters
**Why second**: Chi and Gin are done. Echo and Fiber complete the major Go web framework coverage.

### Priority 3: Username Plugin
**Why third**: Simple feature — allow users to authenticate with username instead of / in addition to email. Low effort, commonly requested.

### Priority 4: Email OTP Plugin
Similar to Magic Link but delivers a short numeric code instead of a URL. Useful for mobile apps.

### Priority 5: Passkey / WebAuthn Plugin
**Why fifth**: Higher effort but growing adoption. The Web Authentication API is now supported in all major browsers.

**Dependencies**: `github.com/go-webauthn/webauthn`

### Priority 6: Core Concept Completeness
- **Secondary storage (Redis)** — session caching, rate limit state
- **Dynamic base URL** — multi-tenant setups where base URL varies per request
- **Multi-session plugin** — allow multiple active sessions per user with device tracking
- **Anonymous plugin** — temporary anonymous sessions that can be upgraded

### Priority 7: Authorization Adapter
Define the `Authorizer` interface in core and ship an optional Casbin adapter (`authz/casbin/`).
The built-in RBAC in admin/org plugins remains the zero-dependency default.

---

## Gap Analysis (Updated)

### Authentication Providers

| Provider | TypeScript | Go Port |
|----------|-----------|---------|
| Email/Password | ✅ | ✅ |
| Google | ✅ | ✅ |
| GitHub | ✅ | ✅ |
| Apple | ✅ | ✅ |
| Microsoft | ✅ | ✅ |
| Slack | ✅ | ✅ |
| GitLab | ✅ | ✅ |
| Discord | ✅ | planned |
| Twitter/X | ✅ | planned |
| LinkedIn | ✅ | planned |
| Facebook | ✅ | planned |

### Plugins

| Plugin | TypeScript | Go Port |
|--------|-----------|---------|
| Admin | ✅ | ✅ |
| Organization | ✅ | ✅ |
| Two-Factor (TOTP) | ✅ | ✅ |
| Magic Link | ✅ | ✅ |
| API Key | ✅ | ✅ |
| JWT | ✅ | ✅ |
| Email OTP | ✅ | planned |
| Passkey (WebAuthn) | ✅ | planned |
| Username | ✅ | planned |
| Multi-Session | ✅ | planned |
| Anonymous | ✅ | planned |
| Phone Number | ✅ | planned |
| SSO (SAML) | ✅ | future |
| OIDC Provider | ✅ | future |

### Database Adapters

| Adapter | TypeScript | Go Port |
|---------|-----------|---------|
| PostgreSQL | ✅ | ✅ (sqlx) |
| MySQL | ✅ | ✅ (sqlx) |
| SQLite | ✅ | ✅ (sqlx) |
| MongoDB | ✅ | future |
| In-Memory | ✅ | ✅ |

### Framework Integrations

| Framework | Status |
|-----------|--------|
| net/http (stdlib) | ✅ |
| Chi | ✅ |
| Gin | ✅ |
| Echo | planned |
| Fiber | planned |
| gorilla/mux | planned |

---

## Current State Assessment (March 8, 2026)

### Codebase Metrics
- **64 source files**, **20 test files**, **~9,650 lines of Go** (excluding tests)
- **6 plugins** shipped: Admin, Organization, TOTP, Magic Link, API Key, JWT
- **6 OAuth providers**: Google, GitHub, Apple, Microsoft, Slack, GitLab
- **2 database adapters**: Memory (testing), sqlx (PostgreSQL/MySQL/SQLite)
- **2 framework adapters**: Chi, Gin (plus native net/http)
- **Repo structure**: Clean flat layout at root, Go workspace with `go.work`

### What's Strong
- Core auth flows are complete and tested (sign-up, sign-in, sign-out, sessions, password reset, email verification)
- Plugin architecture is mature — interface-based with hooks, schemas, endpoints, middleware
- Good variety of plugins covering the most common auth needs
- Production database support via sqlx (3 engines)
- Framework adapter pattern is established and easy to extend

### What's Missing (vs TypeScript better-auth)
- **4 OAuth providers** remain: Discord, Twitter/X, LinkedIn, Facebook
- **2 framework adapters**: Echo, Fiber
- **6 planned plugins**: Username, Email OTP, Passkey/WebAuthn, Multi-Session, Anonymous, Phone Number
- **Core gaps**: Secondary storage (Redis), dynamic base URL
- **No e2e tests** currently (directory exists but is empty of real tests)
- **Test coverage** could be deeper — some plugins have minimal tests

---

## Sprint 3 Proposal — Recommended Next Tasks

### Batch A: Quick Wins (Low Effort, High Impact)

These can all be done in parallel — each is self-contained and follows established patterns.

| # | Task | Effort | Impact | Notes |
|---|------|--------|--------|-------|
| A1 | **Discord OAuth provider** | Low | High | Developer community standard. Follow `social/github.go` pattern. |
| A2 | **Twitter/X OAuth provider** | Low | Medium | OAuth 2.0 (not 1.0a). Follow same pattern. |
| A3 | **LinkedIn OAuth provider** | Low | Medium | Standard OAuth 2.0. |
| A4 | **Facebook OAuth provider** | Low | Medium | Standard OAuth 2.0. |
| A5 | **Echo framework adapter** | Low | Medium | Follow `framework/chi/` pattern. Echo is the #3 Go web framework. |
| A6 | **Fiber framework adapter** | Low | Medium | Follow same pattern. Fiber uses fasthttp (not net/http) — needs slightly different approach. |

**Estimated batch effort**: 1 sprint. All 6 items follow existing patterns closely.

### Batch B: Simple Plugins (Low-Medium Effort)

| # | Task | Effort | Impact | Notes |
|---|------|--------|--------|-------|
| B1 | **Username plugin** | Low | Medium | Allow username-based auth alongside email. Add `username` field to user model. |
| B2 | **Email OTP plugin** | Low | Medium | Like Magic Link but sends a 6-digit code. Shares verification infrastructure. |
| B3 | **Anonymous plugin** | Low | Low | Temporary sessions upgradeable to full accounts. Simple session hook. |

### Batch C: Higher-Effort Features

| # | Task | Effort | Impact | Notes |
|---|------|--------|--------|-------|
| C1 | **Passkey/WebAuthn plugin** | High | High | Depends on `go-webauthn/webauthn`. Registration + authentication ceremonies. Most complex plugin. |
| C2 | **Secondary storage (Redis)** | Medium | Medium | Define `SecondaryStorage` interface, ship Redis adapter. Enables session caching and distributed rate limiting. |
| C3 | **Multi-Session plugin** | Medium | Medium | Device tracking, concurrent session limits. Extends session model with device info. |
| C4 | **Improve test coverage** | Medium | High | Add integration tests for sqlx adapter, framework adapters, and deeper plugin testing. Populate `e2e/` directory. |

### Batch D: Future (Not This Sprint)

| # | Task | Effort | Notes |
|---|------|--------|-------|
| D1 | Casbin authorization adapter | Medium | Define `Authorizer` interface first |
| D2 | Phone Number plugin | Medium | Needs SMS provider integration |
| D3 | SSO (SAML) plugin | High | Enterprise feature |
| D4 | OIDC Provider plugin | High | Turn the library into an OIDC provider |
| D5 | MongoDB adapter | Medium | Different query model |

---

## Recommended Sprint 3 Execution Order

**Phase 1** (parallelize): A1-A4 (4 OAuth providers) + A5 (Echo adapter)
**Phase 2** (parallelize): A6 (Fiber adapter) + B1 (Username plugin) + B2 (Email OTP plugin)
**Phase 3**: C4 (Test coverage improvements)
**Phase 4**: C1 (Passkey/WebAuthn) — this is the flagship feature for Sprint 3

### Summary: Sprint 3 Execution Sequence

| Order | Item | Category | Effort | Impact |
|-------|------|----------|--------|--------|
| 1 | Discord OAuth | Auth Provider | Low | High |
| 2 | Twitter/X OAuth | Auth Provider | Low | Medium |
| 3 | LinkedIn OAuth | Auth Provider | Low | Medium |
| 4 | Facebook OAuth | Auth Provider | Low | Medium |
| 5 | Echo adapter | Integration | Low | Medium |
| 6 | Fiber adapter | Integration | Low | Medium |
| 7 | Username plugin | Plugin | Low | Medium |
| 8 | Email OTP plugin | Plugin | Low | Medium |
| 9 | Test coverage improvements | Quality | Medium | High |
| 10 | Passkey/WebAuthn plugin | Plugin | High | High |
| 11 | Anonymous plugin | Plugin | Low | Low |
| 12 | Secondary Storage (Redis) | Core | Medium | Medium |
