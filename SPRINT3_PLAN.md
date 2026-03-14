# Sprint 3 — Next Phase Plan

## Current State (March 14, 2026)

### On `master`
- **Core auth**: Email/password, sessions, OAuth, password reset, email verification
- **8 plugins**: Admin, Organization, TOTP, Magic Link, API Key, JWT, Username, Email OTP
- **11 OAuth providers**: Google, GitHub, Apple, Microsoft, Slack, GitLab, Discord, Twitter/X, LinkedIn, Facebook
- **DB adapters**: Memory, sqlx (PostgreSQL/MySQL/SQLite)
- **Framework adapters**: Chi, Gin, Echo

### On Feature Branches (not yet merged)

| Branch | Content | Status |
|--------|---------|--------|
| `claude/sprint3-test-coverage-Jy5kV` | Username + Email OTP plugin tests | Ready for merge |
| `claude/sprint3-fiber-anonymous-Jy5kV` | Fiber adapter + Anonymous plugin | Needs fixes |
| `claude/sprint3-passkey-webauthn-Jy5kV` | Passkey/WebAuthn plugin | Needs fixes |
| `claude/sprint3-storage-multisession-Jy5kV` | Storage layer + Multi-session plugin | Needs rework |
| `claude/sprint3-shared-fixes-Jy5kV` | Empty (only deletes test files) | Discard |

---

## Branch Issues & Required Fixes

### Issue: All feature branches delete test files
Every feature branch (`fiber-anonymous`, `passkey-webauthn`, `storage-multisession`) deletes `emailotp_test.go` and `username_test.go` from the test-coverage branch. This is a rebase/merge artifact. **Fix**: Rebase each branch on test-coverage preserving the test files.

### PR 1: Test Coverage (`sprint3-test-coverage`)
**Status**: Ready to merge as-is.
- Adds comprehensive tests for Username plugin (9 test cases)
- Adds comprehensive tests for Email OTP plugin (8 test cases)
- No code changes needed

### PR 2: Fiber + Anonymous (`sprint3-fiber-anonymous`)
**Fixes needed**:
1. **Restore deleted test files** — Rebase on test-coverage properly
2. **Fiber adapter is minimal and correct** (16 lines) — No changes needed
3. **Anonymous plugin looks solid** — No major issues found

### PR 3: Passkey/WebAuthn (`sprint3-passkey-webauthn`)
**Fixes needed**:
1. **Restore deleted test files** — Rebase on test-coverage properly
2. **Bug: `backed_up` field used for both `BackupState` and `BackupEligible`** — In `recordToCredential()`, the same `rec["backed_up"]` is assigned to both `cred.Flags.BackupState` and `cred.Flags.BackupEligible`. These are different WebAuthn flags. Fix: store `backup_eligible` separately, or derive from `device_type` (`multi_device` = backup eligible).
3. **Missing session-create hooks** — `handleLoginFinish` creates a session without running `RunSessionCreateHooks`. Other plugins (e.g., multi-session) won't intercept passkey logins.
4. **Login finish: `ValidateDiscoverableLogin` used as fallback for non-discoverable** — In the non-discoverable flow, the code tries `ValidateDiscoverableLogin` first, then falls back to `ValidateLogin`. It should just use `ValidateLogin` directly when `sessionData.UserID` is set.
5. **Delete endpoint path matching** — `extractPasskeyID` splits on `/` and takes the last segment, which works but is fragile. Consider a cleaner approach.

### PR 4: Multi-Session (reworked, **without** storage layer)
**Decision**: Split storage layer into a future PR. Ship multi-session standalone.

**Fixes needed**:
1. **Remove storage layer entirely** — Delete `storage/`, `storage/memory/`, `storage/redis/` directories. Remove `SecondaryStorage` from `BetterAuthOptions` (or mark as "not yet implemented").
2. **Fail-closed on errors** — Change `onSessionCreate` to return errors from `FindMany` and `Delete` instead of swallowing them. Matches TS behavior where errors propagate.
   ```go
   // Before (fail-open):
   if err != nil {
       return nil
   }
   // After (fail-closed):
   if err != nil {
       return fmt.Errorf("checking session count: %w", err)
   }
   ```
3. **Return delete errors** — Stop discarding `Delete` errors:
   ```go
   // Before:
   _ = adp.Delete(ctx, "session", ...)
   // After:
   if err := adp.Delete(ctx, "session", ...); err != nil {
       return fmt.Errorf("revoking oldest session: %w", err)
   }
   ```
4. **Remove device info schema columns** — The `device_name`, `device_type`, `os`, `browser` columns are never populated. Remove them from `Schema()`. Keep runtime UA parsing in `handleList` only.
5. **Accept TOCTOU race** — Match TS behavior: pre-creation check without locking. The session limit is a soft guarantee, not a hard security boundary. Document this clearly in the Options struct.
6. **Restore deleted test files** — Rebase on test-coverage properly.

---

## Future: Storage Layer (Separate PR, Sprint 4)

When there is a concrete consumer (session caching, rate limiting, challenge storage), ship the storage layer with:

1. **Unified interface** — Replace both `SecondaryStorage` in `options.go` and `storage.Store` with one interface:
   ```go
   type Store interface {
       Get(ctx context.Context, key string) (value string, found bool, err error)
       Set(ctx context.Context, key string, value string, ttl time.Duration) error
       SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
       Delete(ctx context.Context, key string) error
       Close() error
   }
   ```
2. **Fix memory store TOCTOU** — Re-verify under write lock before deleting expired entries
3. **Add `Close()` to Redis impl** — Prevent connection pool leaks
4. **Add Redis to `go.mod`** — Currently missing
5. **Wire into `Auth`** with a concrete consumer

---

## Merge Order

```
master
  └─ PR 1: test-coverage (merge first)
       └─ PR 2: fiber-anonymous (rebase on test-coverage, fix, merge)
       └─ PR 3: passkey-webauthn (rebase on test-coverage, fix, merge)
       └─ PR 4: multi-session (rework on test-coverage, merge)
```

PRs 2, 3, 4 are independent and can be worked on in parallel after PR 1 merges.

---

## Execution Plan

### Phase 1: Merge test coverage
1. Review and merge `sprint3-test-coverage` branch
2. Run `cd packages/betterauth && go test ./...` to confirm all green

### Phase 2: Fix and merge feature branches (parallelizable)

#### 2a: Fiber + Anonymous
1. Rebase on merged test-coverage (restore test files)
2. Run tests, format check
3. Open PR, merge

#### 2b: Passkey/WebAuthn
1. Rebase on merged test-coverage (restore test files)
2. Fix `BackupEligible` vs `BackupState` bug
3. Add `RunSessionCreateHooks` call in `handleLoginFinish`
4. Simplify login finish flow (remove discoverable fallback for known-user path)
5. Run tests, format check
6. Open PR, merge

#### 2c: Multi-Session (rework)
1. Create new branch from test-coverage
2. Copy multi-session plugin code (without storage layer)
3. Apply fail-closed fixes
4. Remove device info schema columns
5. Add clear documentation about TOCTOU behavior
6. Run tests, format check
7. Open PR, merge

### Phase 3: Sprint 4 planning
- Secondary storage layer (with concrete consumer)
- Phone Number plugin
- Deeper e2e test coverage
- Organization plugin route splitting + repository pattern (from NEXT_PRIORITIES.md)
