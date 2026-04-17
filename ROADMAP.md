# Roadmap

## Planned Features

### Secondary Storage
Add a `SecondaryStorage` interface to `BetterAuthOptions` for pluggable key-value stores (e.g. Redis).
This would support use cases like session caching, rate-limit counters, and OTP storage outside the primary database.

Proposed interface:
```go
type SecondaryStorage interface {
    Get(key string) ([]byte, error)
    Set(key string, value []byte, ttl int) error
    Delete(key string) error
}
```

Wire the interface into `BetterAuthOptions.SecondaryStorage` and update subsystems (rate limiting, session caching) to use it when configured.

### Atomic Max-Session Enforcement
The multisession plugin enforces `MaxSessions` via a read-then-delete pattern in `onSessionCreate`.
Two concurrent sign-ins for the same user can both observe `active == MaxSessions`, target the same
"oldest" row, and briefly exceed the cap (or attempt a duplicate delete). A proper fix requires
either a transactional adapter boundary or an advisory lock per user_id.
