# Sprint 3 Implementation Plan

## Current State (March 14, 2026)

### Already Implemented (on `master`)
- **Core auth**: Email/password, sessions, OAuth, password reset, email verification
- **6 plugins**: Admin, Organization, TOTP, Magic Link, API Key, JWT
- **7 OAuth providers**: Google, GitHub, Apple, Microsoft, Slack, GitLab
- **DB adapters**: Memory, sqlx (PostgreSQL/MySQL/SQLite)
- **Framework adapters**: Chi, Gin
- **E2e tests**: Smoke (116 lines), integration (187 lines), adapter (132 lines)

### Already Implemented (on `master`, but listed as "planned" in NEXT_PRIORITIES.md)
These items exist in the codebase already — they were implemented as part of Sprint 2 or early Sprint 3 work:

| Item | Status | Notes |
|------|--------|-------|
| Discord OAuth | ✅ Implemented | `social/discord.go` + `discord_test.go` (104 lines) |
| Twitter/X OAuth | ✅ Implemented | `social/twitter.go` + `twitter_test.go` (121 lines) |
| LinkedIn OAuth | ✅ Implemented | `social/linkedin.go` + `linkedin_test.go` (86 lines) |
| Facebook OAuth | ✅ Implemented | `social/facebook.go` + `facebook_test.go` (91 lines) |
| Echo adapter | ✅ Implemented | `framework/echo/echo.go` + `echo_test.go` (14 lines) |
| Username plugin | ✅ Implemented | `plugins/username/username.go` (325 lines, **no tests**) |
| Email OTP plugin | ✅ Implemented | `plugins/emailotp/emailotp.go` (263 lines, **no tests**) |

### Not Yet Implemented
| Item | Priority | Effort |
|------|----------|--------|
| Fiber framework adapter | Medium | Low |
| Username plugin tests | High | Low |
| Email OTP plugin tests | High | Low |
| Passkey/WebAuthn plugin | High | High |
| Secondary storage (Redis) | Medium | Medium |
| Multi-Session plugin | Medium | Medium |
| Anonymous plugin | Low | Low |
| Deeper test coverage | High | Medium |

---

## Sprint 3 Implementation Plan

### Phase 1: Test Coverage for Existing Untested Code (Priority: HIGH)

Two plugins shipped without tests. This is a quality gap that must be addressed first.

#### 1a. Username Plugin Tests (`plugins/username/username_test.go`)

Test cases:
- **Sign-up happy path**: Register with username + email + password, verify session cookie returned
- **Sign-in happy path**: Sign in with correct username/password, verify session returned
- **Username too short**: Reject usernames shorter than `MinLength`
- **Username too long**: Reject usernames longer than `MaxLength`
- **Duplicate username**: Return 409 when username is taken
- **Duplicate email**: Return 409 when email is already in use
- **Missing fields**: Return 400 for missing username, email, password
- **Wrong password on sign-in**: Return 401
- **Unknown username on sign-in**: Return 401

#### 1b. Email OTP Plugin Tests (`plugins/emailotp/emailotp_test.go`)

Test cases:
- **Send OTP happy path**: Send OTP to a registered email, verify `SendOTP` callback called with 6-digit code
- **Send OTP to unknown email**: Should return success (no user enumeration)
- **Verify OTP happy path**: Valid code creates a session
- **Verify wrong code**: Return 401
- **Verify expired code**: Return 401
- **Verify consumed code**: Cannot reuse the same code after verification
- **Missing fields**: Return 400 for missing email or code
- **Custom code length**: Verify `CodeLength` option works

### Phase 2: Fiber Framework Adapter (Priority: MEDIUM)

**File**: `framework/fiber/fiber.go`

Fiber uses `fasthttp` instead of `net/http`, so it can't simply wrap `auth.Handler()`. It needs an adapter that:
1. Converts Fiber's `*fiber.Ctx` to `net/http` request/response
2. Uses `fasthttpadaptor` to bridge the two
3. Mounts all auth routes under a configurable path

**File**: `framework/fiber/fiber_test.go`

Test that auth endpoints work through the Fiber adapter (sign-up, sign-in, get-session round-trip).

**Dependencies**: `github.com/gofiber/fiber/v3` (or v2)

### Phase 3: Anonymous Plugin (Priority: LOW-MEDIUM)

**Directory**: `plugins/anonymous/`

A simple plugin that creates temporary anonymous sessions that can later be upgraded to full accounts via linking credentials.

**Files**:
- `plugins/anonymous/anonymous.go` — Plugin struct, endpoints
- `plugins/anonymous/anonymous_test.go` — Tests

**Endpoints**:
- `POST /sign-in/anonymous` — Creates a temporary user and session
- `POST /anonymous/link` — Links credentials (email/password) to an anonymous user, upgrading them

**Schema extensions**:
- Add `is_anonymous` boolean field to the `user` table

**Behavior**:
- Anonymous users get a temporary name (e.g., "Guest-abc123")
- Sessions work identically to regular sessions (cookies, expiry)
- Linking credentials removes the `is_anonymous` flag
- Optional: auto-expire anonymous users after configurable duration

### Phase 4: Passkey/WebAuthn Plugin (Priority: HIGH, Effort: HIGH)

This is the flagship feature for Sprint 3. Uses the `go-webauthn/webauthn` library.

**Directory**: `plugins/passkey/`

**Files**:
- `plugins/passkey/passkey.go` — Plugin struct, options, schema
- `plugins/passkey/routes.go` — HTTP handlers
- `plugins/passkey/passkey_test.go` — Tests

**Schema** (new `passkey` table):
```sql
CREATE TABLE passkey (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL UNIQUE,
    public_key      BLOB NOT NULL,
    counter         INTEGER NOT NULL DEFAULT 0,
    device_type     TEXT,
    backed_up       BOOLEAN NOT NULL DEFAULT FALSE,
    transports      TEXT,  -- JSON array
    name            TEXT,  -- user-friendly name
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

**Endpoints**:
- `POST /passkey/register/begin` — Start registration ceremony (returns challenge + options)
- `POST /passkey/register/finish` — Complete registration (store credential)
- `POST /passkey/login/begin` — Start authentication ceremony (returns challenge)
- `POST /passkey/login/finish` — Complete authentication (verify assertion, create session)
- `GET /passkey/list` — List registered passkeys for current user
- `DELETE /passkey/{id}` — Remove a passkey

**Implementation approach**:
1. Store challenges in the `verification` table (reuse existing infrastructure)
2. Implement `webauthn.User` interface adapter for our User model
3. Registration flow: begin → browser creates credential → finish stores it
4. Authentication flow: begin → browser signs challenge → finish verifies and creates session
5. Support multiple passkeys per user

**Dependencies**: `github.com/go-webauthn/webauthn`

### Phase 5: Secondary Storage Interface + Redis Adapter (Priority: MEDIUM)

**Purpose**: Enable session caching and distributed rate limiting via Redis.

**Files**:
- `storage/storage.go` — `SecondaryStorage` interface definition
- `storage/redis/redis.go` — Redis implementation
- `storage/redis/redis_test.go` — Tests (use miniredis for testing)

**Interface**:
```go
type SecondaryStorage interface {
    Get(ctx context.Context, key string) (string, error)
    Set(ctx context.Context, key string, value string, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}
```

**Integration points**:
- Session resolution: Check cache before hitting DB
- Rate limiting: Store counters in Redis for distributed deployments
- TOTP challenges, WebAuthn challenges: Store ephemeral state

**Dependencies**: `github.com/redis/go-redis/v9`

### Phase 6: Multi-Session Plugin (Priority: MEDIUM)

**Directory**: `plugins/multisession/`

**Purpose**: Track device info per session and enforce concurrent session limits.

**Files**:
- `plugins/multisession/multisession.go`
- `plugins/multisession/multisession_test.go`

**Schema extension** (additional fields on `session` table):
- `device_name` TEXT
- `device_type` TEXT (mobile/desktop/tablet)
- `os` TEXT
- `browser` TEXT

**Endpoints**:
- `GET /multi-session/list` — List active sessions with device info
- `POST /multi-session/revoke` — Revoke a specific session by ID
- `POST /multi-session/revoke-all-others` — Revoke all but current

**Options**:
- `MaxSessions int` — Maximum concurrent sessions (0 = unlimited)
- `OnMaxSessionsReached` — Callback: "revoke-oldest" or "deny-new"

**Behavior**:
- Parses User-Agent to extract device/browser/OS info
- Enforces `MaxSessions` limit on session creation (via session-create hook)

---

## Execution Order

| Order | Phase | Items | Effort | Impact |
|-------|-------|-------|--------|--------|
| 1 | Phase 1a | Username plugin tests | Low | High (quality) |
| 2 | Phase 1b | Email OTP plugin tests | Low | High (quality) |
| 3 | Phase 2 | Fiber framework adapter | Low | Medium |
| 4 | Phase 3 | Anonymous plugin | Low | Low-Medium |
| 5 | Phase 4 | Passkey/WebAuthn plugin | High | High |
| 6 | Phase 5 | Secondary storage + Redis | Medium | Medium |
| 7 | Phase 6 | Multi-Session plugin | Medium | Medium |

**Phases 1a + 1b** can be parallelized.
**Phases 2 + 3** can be parallelized (independent features).
**Phases 5 + 6** can be parallelized.
**Phase 4** (Passkey) is the largest item and should be the primary focus once tests are in place.

---

## Out of Scope (Sprint 4+)

- Phone Number plugin (needs SMS provider integration)
- SSO/SAML plugin (enterprise feature, high effort)
- OIDC Provider plugin (turn library into an OIDC provider)
- MongoDB adapter (different query paradigm)
- Casbin authorization adapter (define `Authorizer` interface first)
- gorilla/mux adapter (community can contribute; deprecated upstream)
