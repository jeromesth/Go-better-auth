# Go Better Auth - Project Plan & Feasibility Analysis

## 1. Feasibility Analysis: TypeScript → Go Conversion

### 1.1 Benefits of Go Conversion

| Benefit | Details |
|---------|---------|
| **Single binary deployment** | No Node.js runtime, no `node_modules`. Ship one binary. Dramatically simpler deployment (Docker images go from ~1GB → ~20MB). |
| **Performance** | Go's compiled nature, goroutine-based concurrency, and lower memory footprint provide significantly better throughput for auth workloads (password hashing, token validation, DB queries). |
| **Concurrency model** | Goroutines + channels are a natural fit for auth servers handling many concurrent sessions. No event-loop bottleneck. |
| **Type safety at compile time** | Go catches type errors at compile time without needing a build step. No runtime type coercion surprises. |
| **Memory efficiency** | Go's garbage collector is optimized for low-latency. Auth servers processing thousands of sessions benefit from predictable memory usage. |
| **Native crypto** | Go's `crypto` stdlib is production-hardened (used in Kubernetes, Docker, Vault). No dependency on native Node.js bindings. |
| **Cross-compilation** | `GOOS=linux GOARCH=arm64 go build` - trivial cross-compilation for any platform. |
| **Ecosystem fit** | Most infrastructure tools (Kubernetes, Terraform, Docker) are Go. Auth servers often live in this ecosystem. |

### 1.2 Challenges & Pitfalls

| Challenge | Severity | Mitigation |
|-----------|----------|------------|
| **No union types** | Medium | Use interfaces with concrete types + type switches. For config options that accept multiple types (e.g., `database` field), use separate fields or interface types. |
| **No TypeScript-style generics inference** | Medium | Go 1.18+ generics cover most cases. Plugin type inference (`$Infer`) won't translate directly - use interfaces instead. |
| **Plugin type composition** | High | TS's `BetterAuthPlugin` relies heavily on mapped/conditional types for schema inference. Go needs a different approach: interface-based registration with runtime type assertions. |
| **Callback-heavy config** | Low | Go handles function fields in structs natively. Callback signatures translate cleanly. |
| **No `async/await`** | Low | Go's goroutines + channels are actually simpler. All async TS code becomes synchronous Go code (the runtime handles scheduling). |
| **No client-side library** | N/A | Out of scope - this is a server-side auth library. Client SDKs are separate concerns. |
| **Social provider ecosystem** | Medium | Each OAuth provider needs manual implementation. Start with Google/GitHub/Apple, expand later. |
| **Test framework differences** | Low | Go's `testing` package + `testify` cover all needs. Table-driven tests replace TS parameterized tests naturally. |

### 1.3 Architectural Differences

| TypeScript Pattern | Go Equivalent |
|-------------------|---------------|
| `AsyncLocalStorage` for request context | `context.Context` (first-class in Go) |
| `better-call` middleware framework | `net/http` middleware chain (HandlerFunc wrapping) |
| Kysely query builder | `sqlx` with raw SQL + adapter interface |
| Zod validation | Struct tags + custom validation functions |
| `WeakMap` caching | `sync.Map` or typed cache structs |
| `Promise<T>` | Direct return values (Go is synchronous by default) |
| TypeScript decorators/metadata | Go interfaces + struct embedding |
| `Record<string, any>` | `map[string]any` |
| Union types (`string \| object`) | Separate config fields or interface types |

### 1.4 Risk Assessment

- **Overall Risk: MEDIUM** - The core auth logic is straightforward to port. The main complexity is in the plugin system's type-level composition, which needs a Go-idiomatic redesign.
- **Timeline Impact**: Plugin system redesign adds ~20% overhead vs a naive port.
- **Recommendation**: **PROCEED** - The benefits significantly outweigh the challenges. The most complex parts (plugin type inference) are TypeScript-specific and don't need 1:1 replication in Go.

---

## 2. Project Structure

```
go-better-auth/
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── PLAN.md
│
├── auth.go                    # Main entry point: New() constructor, Auth type
├── options.go                 # BetterAuthOptions struct + defaults
├── context.go                 # AuthContext type
├── errors.go                  # Error codes and APIError type
│
├── models/                    # Core data models
│   ├── user.go                # User model
│   ├── session.go             # Session model
│   ├── account.go             # Account model
│   ├── verification.go        # Verification token model
│   └── rate_limit.go          # Rate limit model
│
├── adapter/                   # Database adapter interface
│   ├── adapter.go             # Core Adapter interface
│   ├── sqlx/                  # sqlx adapter (default)
│   │   ├── sqlx.go
│   │   ├── postgres.go
│   │   ├── mysql.go
│   │   ├── sqlite.go
│   │   └── sqlx_test.go
│   └── memory/                # In-memory adapter (for testing)
│       ├── memory.go
│       └── memory_test.go
│
├── crypto/                    # Cryptographic utilities
│   ├── hash.go                # Password hashing (scrypt/bcrypt)
│   ├── token.go               # Token generation
│   ├── hmac.go                # HMAC signing
│   └── crypto_test.go
│
├── session/                   # Session management
│   ├── session.go             # Session creation, validation, refresh
│   ├── cookie.go              # Cookie management
│   ├── cache.go               # Cookie-based session caching
│   └── session_test.go
│
├── api/                       # REST API endpoints
│   ├── router.go              # HTTP router setup
│   ├── middleware.go           # CSRF, rate limiting, auth middleware
│   ├── sign_up.go             # POST /sign-up/email
│   ├── sign_in.go             # POST /sign-in/email
│   ├── sign_out.go            # POST /sign-out
│   ├── session.go             # GET /get-session
│   ├── password.go            # Password reset/change endpoints
│   ├── email_verification.go  # Email verification endpoints
│   ├── oauth.go               # OAuth sign-in + callback
│   ├── user.go                # User management endpoints
│   └── api_test.go
│
├── oauth/                     # OAuth 2.0 implementation
│   ├── oauth.go               # Core OAuth2 flow
│   ├── providers.go           # Provider registry
│   ├── state.go               # State management
│   └── oauth_test.go
│
├── social/                    # Social login providers
│   ├── provider.go            # SocialProvider interface
│   ├── google.go
│   ├── github.go
│   ├── apple.go
│   └── social_test.go
│
├── plugin/                    # Plugin system
│   ├── plugin.go              # Plugin interface + registry
│   ├── hooks.go               # Hook system (before/after)
│   ├── schema.go              # Plugin schema extension
│   └── plugin_test.go
│
├── ratelimit/                 # Rate limiting
│   ├── ratelimit.go           # Rate limiter implementation
│   ├── memory.go              # In-memory rate limit storage
│   └── ratelimit_test.go
│
├── internal/                  # Internal utilities
│   ├── id.go                  # ID generation
│   ├── ip.go                  # IP address extraction
│   ├── url.go                 # URL validation + trusted origins
│   └── cookie.go              # Low-level cookie helpers
│
└── testutil/                  # Test utilities (exported for plugin authors)
    ├── testutil.go            # Test auth instance factory
    ├── mock_db.go             # Mock database adapter
    └── http.go                # HTTP test helpers
```

**Module path**: `github.com/jeromesth/go-better-auth`

---

## 3. Implementation Phases

### Phase 1: Foundation (Data Model + DB Adapter)

**Goal**: Core types, database adapter interface, and in-memory adapter for testing.

1. Initialize Go module (`go mod init`)
2. Define core models: `User`, `Session`, `Account`, `Verification`, `RateLimit`
3. Define `Adapter` interface:
   ```go
   type Adapter interface {
       FindOne(ctx context.Context, model string, query Query) (map[string]any, error)
       FindMany(ctx context.Context, model string, query Query) ([]map[string]any, error)
       Create(ctx context.Context, model string, data map[string]any) (map[string]any, error)
       Update(ctx context.Context, model string, query Query, data map[string]any) (map[string]any, error)
       Delete(ctx context.Context, model string, query Query) error
       CreateMany(ctx context.Context, model string, data []map[string]any) error
       UpdateMany(ctx context.Context, model string, query Query, data map[string]any) error
       DeleteMany(ctx context.Context, model string, query Query) error
       Count(ctx context.Context, model string, query Query) (int64, error)
   }
   ```
4. Implement `memory.Adapter` for testing
5. Define `InternalAdapter` (higher-level typed methods wrapping the raw adapter)
6. Write tests for adapter operations

### Phase 2: Configuration & Core Auth

**Goal**: `BetterAuthOptions` struct, password hashing, session management.

1. Define `BetterAuthOptions` struct matching the TypeScript shape:
   ```go
   type BetterAuthOptions struct {
       AppName              string
       BaseURL              string
       BasePath             string                    // default: "/api/auth"
       Secret               string
       Database             DatabaseConfig
       EmailAndPassword     *EmailPasswordConfig
       EmailVerification    *EmailVerificationConfig
       SocialProviders      map[string]SocialProvider
       Plugins              []Plugin
       User                 *UserConfig
       Session              *SessionConfig
       Account              *AccountConfig
       RateLimit            *RateLimitConfig
       Advanced             *AdvancedConfig
       TrustedOrigins       []string
       SecondaryStorage     SecondaryStorage
   }
   ```
2. Implement `New(opts BetterAuthOptions) *Auth` constructor with defaults
3. Implement password hashing (scrypt default, pluggable)
4. Implement session management (create, validate, refresh, revoke)
5. Implement cookie management (set, get, parse, clear)
6. Implement token generation (verification tokens, reset tokens)
7. Write tests

### Phase 3: REST API Endpoints

**Goal**: All core HTTP endpoints with middleware.

1. Implement HTTP router using `net/http` ServeMux (Go 1.22+)
2. Implement middleware chain: CSRF check, rate limiting, session resolution
3. Implement endpoints:
   - `POST /sign-up/email` - Email/password registration
   - `POST /sign-in/email` - Email/password login
   - `POST /sign-out` - Session revocation
   - `GET /get-session` - Get current session + user
   - `POST /change-password` - Change password
   - `POST /request-password-reset` - Send reset email
   - `POST /reset-password` - Reset with token
   - `POST /send-verification-email` - Send verification
   - `GET /verify-email` - Verify email token
   - `POST /revoke-session` - Revoke specific session
   - `POST /revoke-other-sessions` - Revoke all but current
   - `POST /update-user` - Update user profile
   - `POST /delete-user` - Delete user account
   - `POST /change-email` - Change email
4. Implement error handling (APIError → JSON response)
5. Write integration tests

### Phase 4: OAuth & Social Providers

**Goal**: OAuth 2.0 flow + initial social providers.

1. Implement OAuth 2.0 authorization code flow
2. Implement state management (CSRF protection for OAuth)
3. Implement provider interface:
   ```go
   type SocialProvider interface {
       ID() string
       AuthorizationURL(state, codeVerifier string) string
       ExchangeCode(ctx context.Context, code string) (*OAuthTokens, error)
       GetUserInfo(ctx context.Context, token string) (*OAuthUser, error)
   }
   ```
4. Implement Google, GitHub, Apple providers (most common)
5. Implement endpoints:
   - `POST /sign-in/{provider}` - Initiate OAuth flow
   - `GET /callback/{provider}` - OAuth callback
   - `POST /link-social` - Link social account
6. Write tests

### Phase 5: Plugin System Framework

**Goal**: Plugin interface, hook system, schema extension.

1. Define Plugin interface:
   ```go
   type Plugin interface {
       ID() string
   }

   // Optional interfaces plugins can implement
   type PluginWithInit interface {
       Init(ctx *AuthContext) error
   }
   type PluginWithEndpoints interface {
       Endpoints() map[string]Endpoint
   }
   type PluginWithSchema interface {
       Schema() map[string]ModelSchema
   }
   type PluginWithHooks interface {
       Hooks() Hooks
   }
   type PluginWithMiddleware interface {
       Middlewares() []MiddlewareConfig
   }
   type PluginWithRateLimit interface {
       RateLimitRules() []RateLimitRule
   }
   ```
2. Implement plugin registration and lifecycle
3. Implement hook system (before/after for each endpoint)
4. Implement schema merging (plugin tables added to core schema)
5. Implement plugin-provided endpoints merged into router
6. Write tests

### Phase 6: sqlx Database Adapter

**Goal**: Production-ready database adapter using sqlx.

1. Implement `sqlx.Adapter` for PostgreSQL
2. Implement `sqlx.Adapter` for MySQL
3. Implement `sqlx.Adapter` for SQLite
4. Implement auto-migration from schema definitions
5. Write integration tests with test containers

---

## 4. Test Conversion Strategy

### 4.1 Approach

1. **Read each TypeScript test file** and understand what behavior it validates
2. **Write equivalent Go tests** using Go conventions (table-driven tests, `testing.T`)
3. **Use `testify/assert`** for assertions (closest to TS `expect()`)
4. **Build test infrastructure first** (test helpers, mock DB, HTTP test client)

### 4.2 Test Infrastructure

```go
// testutil/testutil.go
package testutil

// NewTestAuth creates an Auth instance with in-memory DB for testing
func NewTestAuth(opts ...func(*BetterAuthOptions)) *Auth

// NewTestClient creates an HTTP test client that maintains cookies
func NewTestClient(auth *Auth) *TestClient

// TestClient wraps httptest for session-aware testing
type TestClient struct { ... }
func (c *TestClient) SignUp(email, password, name string) (*http.Response, error)
func (c *TestClient) SignIn(email, password string) (*http.Response, error)
func (c *TestClient) GetSession() (*http.Response, error)
```

### 4.3 Test Priority Order

| Priority | Test Area | TS Source Files | Reason |
|----------|-----------|-----------------|--------|
| 1 | Password hashing | `crypto/` tests | Security-critical |
| 2 | Session CRUD | `session/` tests | Core functionality |
| 3 | Sign up/in/out | `api/` tests | Primary user flows |
| 4 | Email verification | `api/` tests | Common requirement |
| 5 | Password reset | `api/` tests | Common requirement |
| 6 | OAuth flow | `oauth2/` tests | Complex integration |
| 7 | Rate limiting | `ratelimit/` tests | Security feature |
| 8 | Plugin system | `plugin/` tests | Extensibility |
| 9 | DB adapter | `db/` tests | Data integrity |

### 4.4 Key TS Test Files to Convert

From `packages/better-auth/src/`:
- `api/` - Core API endpoint tests
- `db/db.test.ts` - Database operations
- `db/internal-adapter.test.ts` - Internal adapter operations
- `db/get-migration-schema.test.ts` - Schema migration
- `db/secondary-storage.test.ts` - Secondary storage
- `db/to-zod.test.ts` - Validation (→ struct validation in Go)

From `packages/core/src/`:
- Core context, session, and crypto tests

---

## 5. Configuration Design

### 5.1 Go Config Struct (mirrors TypeScript BetterAuthOptions)

The Go configuration uses nested structs that mirror the TypeScript type shape as closely as possible. Field names use Go conventions (PascalCase) but JSON tags match the original camelCase.

```go
type BetterAuthOptions struct {
    AppName           string             `json:"appName"`
    BaseURL           string             `json:"baseURL"`
    BasePath          string             `json:"basePath"`
    Secret            string             `json:"secret"`
    Database          *DatabaseConfig    `json:"database"`
    SecondaryStorage  SecondaryStorage   `json:"secondaryStorage"`
    EmailVerification *EmailVerifConfig  `json:"emailVerification"`
    EmailAndPassword  *EmailPassConfig   `json:"emailAndPassword"`
    SocialProviders   map[string]SocialProviderConfig `json:"socialProviders"`
    Plugins           []Plugin           `json:"plugins"`
    User              *UserConfig        `json:"user"`
    Session           *SessionConfig     `json:"session"`
    Account           *AccountConfig     `json:"account"`
    RateLimit         *RateLimitConfig   `json:"rateLimit"`
    Advanced          *AdvancedConfig    `json:"advanced"`
    TrustedOrigins    []string           `json:"trustedOrigins"`
}

type DatabaseConfig struct {
    Adapter              Adapter    `json:"-"`     // The adapter instance (not serialized)
    DefaultFindManyLimit int        `json:"defaultFindManyLimit"`
    GenerateID           GenerateIDFn `json:"-"`
}

type SessionConfig struct {
    ExpiresIn             int              `json:"expiresIn"`       // seconds, default 604800 (7 days)
    UpdateAge             int              `json:"updateAge"`       // seconds, default 86400 (1 day)
    DisableSessionRefresh bool             `json:"disableSessionRefresh"`
    CookieCache           *CookieCacheConfig `json:"cookieCache"`
    FreshAge              int              `json:"freshAge"`        // seconds, default 86400
    ModelName             string           `json:"modelName"`
    Fields                map[string]string `json:"fields"`
    AdditionalFields      map[string]FieldAttribute `json:"additionalFields"`
}

type EmailPassConfig struct {
    Enabled                    bool   `json:"enabled"`
    DisableSignUp              bool   `json:"disableSignUp"`
    RequireEmailVerification   bool   `json:"requireEmailVerification"`
    MaxPasswordLength          int    `json:"maxPasswordLength"` // default 128
    MinPasswordLength          int    `json:"minPasswordLength"` // default 8
    AutoSignIn                 bool   `json:"autoSignIn"`        // default true
    RevokeSessionsOnReset      bool   `json:"revokeSessionsOnPasswordReset"`
    // Callbacks
    SendResetPassword  func(data ResetPasswordData, r *http.Request) error `json:"-"`
    OnPasswordReset    func(data UserData, r *http.Request) error          `json:"-"`
    Password           *PasswordHashConfig                                  `json:"-"`
}
```

### 5.2 Default Values

```go
func DefaultOptions() BetterAuthOptions {
    return BetterAuthOptions{
        AppName:  "Better Auth",
        BasePath: "/api/auth",
        Session: &SessionConfig{
            ExpiresIn: 7 * 24 * 60 * 60,  // 7 days
            UpdateAge: 24 * 60 * 60,       // 1 day
            FreshAge:  24 * 60 * 60,       // 1 day
        },
        EmailAndPassword: &EmailPassConfig{
            MaxPasswordLength: 128,
            MinPasswordLength: 8,
            AutoSignIn:        true,
        },
        RateLimit: &RateLimitConfig{
            Window:  10,
            Max:     100,
            Storage: "memory",
        },
    }
}
```

### 5.3 Usage Example (mirrors TS developer experience)

**TypeScript original:**
```typescript
const auth = betterAuth({
    database: new Pool({ connectionString: "..." }),
    emailAndPassword: { enabled: true },
    socialProviders: {
        google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        },
    },
    plugins: [twoFactor()],
});
```

**Go equivalent:**
```go
auth := betterauth.New(betterauth.BetterAuthOptions{
    Database: &betterauth.DatabaseConfig{
        Adapter: sqlxadapter.New(db, sqlxadapter.Postgres),
    },
    EmailAndPassword: &betterauth.EmailPassConfig{
        Enabled: true,
    },
    SocialProviders: map[string]betterauth.SocialProviderConfig{
        "google": {
            ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
            ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        },
    },
    Plugins: []betterauth.Plugin{
        twofactor.New(),
    },
})

// Mount the auth handler
http.Handle("/api/auth/", auth.Handler())
```

---

## 6. Core Data Model (SQL Schema)

Matching better-auth's default schema:

```sql
-- Users table
CREATE TABLE "user" (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    image           TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE "session" (
    id          TEXT PRIMARY KEY,
    token       TEXT NOT NULL UNIQUE,
    user_id     TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    expires_at  TIMESTAMP NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Accounts table (OAuth + password)
CREATE TABLE "account" (
    id                      TEXT PRIMARY KEY,
    user_id                 TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    account_id              TEXT NOT NULL,
    provider_id             TEXT NOT NULL,
    access_token            TEXT,
    refresh_token           TEXT,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scope                   TEXT,
    id_token                TEXT,
    password                TEXT,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Verification tokens
CREATE TABLE "verification" (
    id          TEXT PRIMARY KEY,
    identifier  TEXT NOT NULL,
    value       TEXT NOT NULL,
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Rate limiting
CREATE TABLE "rate_limit" (
    id          TEXT PRIMARY KEY,
    key         TEXT NOT NULL,
    count       INTEGER NOT NULL,
    last_request BIGINT NOT NULL
);
```

---

## 7. API Endpoint Specification

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| POST | `/sign-up/email` | Register with email/password | No |
| POST | `/sign-in/email` | Login with email/password | No |
| POST | `/sign-out` | Logout (revoke session) | Yes |
| GET | `/get-session` | Get current session + user | Yes |
| POST | `/change-password` | Change password | Yes |
| POST | `/request-password-reset` | Request password reset email | No |
| POST | `/reset-password` | Reset password with token | No |
| POST | `/send-verification-email` | Send email verification | No |
| GET | `/verify-email` | Verify email with token | No |
| POST | `/revoke-session` | Revoke a specific session | Yes |
| POST | `/revoke-other-sessions` | Revoke all other sessions | Yes |
| POST | `/update-user` | Update user profile | Yes |
| POST | `/delete-user` | Delete user account | Yes |
| POST | `/change-email` | Change email address | Yes |
| POST | `/sign-in/{provider}` | Initiate OAuth flow | No |
| GET | `/callback/{provider}` | OAuth callback | No |
| POST | `/link-social` | Link social account | Yes |
| GET | `/list-sessions` | List user's active sessions | Yes |

---

## 8. Plugin System Design

### Interface-Based Approach (Go-Idiomatic)

```go
// Core plugin interface - all plugins must implement this
type Plugin interface {
    ID() string
}

// Optional capability interfaces
type PluginInitializer interface {
    Init(ctx *AuthContext) (*PluginContext, error)
}

type EndpointProvider interface {
    Endpoints() map[string]Endpoint
}

type SchemaProvider interface {
    Schema() map[string]TableSchema
}

type HookProvider interface {
    Hooks() HookConfig
}

type MiddlewareProvider interface {
    Middlewares() []MiddlewareConfig
}

type RequestInterceptor interface {
    OnRequest(r *http.Request, ctx *AuthContext) (*http.Request, *http.Response, error)
}

type ResponseInterceptor interface {
    OnResponse(w http.ResponseWriter, ctx *AuthContext) error
}

type RateLimitProvider interface {
    RateLimitRules() []RateLimitRule
}

type AdapterOverride interface {
    AdapterMethods() map[string]any
}
```

### Plugin Registration Flow

1. `Auth.New()` iterates over `opts.Plugins`
2. For each plugin, check which optional interfaces it implements
3. Merge schemas, register endpoints, install hooks
4. Call `Init()` for plugins implementing `PluginInitializer`
5. Plugin endpoints are prefixed and added to the router

---

## 9. Implementation Priority & Milestones

### Milestone 1: "Hello Auth" (Phase 1-2)
- [ ] Go module initialized
- [ ] Core models defined
- [ ] Memory adapter working
- [ ] Options struct defined with defaults
- [ ] Password hashing working
- [ ] Session CRUD working
- [ ] Basic tests passing

### Milestone 2: "API Complete" (Phase 3)
- [ ] All core endpoints implemented
- [ ] CSRF protection
- [ ] Rate limiting
- [ ] Cookie management
- [ ] Integration tests passing

### Milestone 3: "Social Login" (Phase 4)
- [ ] OAuth 2.0 flow
- [ ] Google, GitHub, Apple providers
- [ ] Account linking

### Milestone 4: "Extensible" (Phase 5)
- [ ] Plugin interface defined
- [ ] Hook system working
- [ ] Schema extension working
- [ ] Plugin endpoints merged

### Milestone 5: "Production Ready" (Phase 6)
- [ ] sqlx adapter (Postgres, MySQL, SQLite)
- [ ] Auto-migration
- [ ] Full test coverage
