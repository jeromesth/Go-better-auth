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
