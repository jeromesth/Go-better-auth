# Architecture

go-better-auth is a self-hosted authentication library for Go. It ships a
pluggable HTTP server: call `New(opts)`, mount `auth.Handler()`, done.

---

## Plugin System

Every plugin must satisfy one interface:

```go
type Plugin interface {
    ID() string
}
```

That is the only mandatory contract. Everything else is opt-in through
capability interfaces the plugin can choose to implement:

| Interface | What it provides |
|---|---|
| `AuthAware` | Receives the `*Auth` reference via `SetAuth` |
| `Initializer` | `Init()` runs once at startup; can return a fatal error |
| `SchemaProvider` | Declares extra database columns/tables |
| `EndpointProvider` | Registers HTTP routes into the main mux |
| `SessionCreateHookProvider` | Intercepts session creation |
| `UserCreateHookProvider` | Mutates the user-creation data map |
| `MiddlewareProvider` | Adds HTTP middleware to the chain |
| `RateLimitProvider` | Contributes per-path rate-limit rules |

**Why this over a single large interface?** A fat interface forces every plugin
to stub out methods it does not need, creating noise and compile-time coupling.
Opt-in composition means a plugin that only adds a database column implements
`SchemaProvider` and nothing else; a plugin that only guards endpoints
implements `SessionCreateHookProvider`. `New()` discovers capabilities at
startup with type assertions and collects the relevant slices — no registry, no
code generation.

---

## The `ErrHandled` Sentinel

Session-create hooks receive both the `http.ResponseWriter` and
`*http.Request`. A hook like the admin ban check may want to write a 403
directly to the client rather than bubbling a generic error message up to the
caller. When it does, it returns `plugin.ErrHandled`:

```go
var ErrHandled = errors.New("response already handled")
```

`RunSessionCreateHooks` propagates the error to the caller (a sign-in handler).
The caller checks `errors.Is(err, plugin.ErrHandled)`: if true, the response
is already written and it must not write again; if false, it owns the error and
must write its own response. Without this sentinel the caller would have no way
to distinguish "hook rejected and wrote 403" from "hook rejected with an
unhandled error I must surface".

---

## Adapter Interface

Storage is abstracted through a single interface operating on `map[string]any`
records:

```go
type Adapter interface {
    FindOne(ctx, model string, query Query) (map[string]any, error)
    Create(ctx, model string, data map[string]any) (map[string]any, error)
    Update(ctx, model string, query Query, data map[string]any) (map[string]any, error)
    Delete(ctx, model string, query Query) error
    // ... FindMany, CreateMany, UpdateMany, DeleteMany, Count
}
```

The generic `map[string]any` was chosen deliberately over typed repository
methods (e.g. `FindUserByEmail`). It means new plugins and schema extensions
can add columns without changing the interface; the in-memory adapter and the
sqlx adapter both implement the same contract with no generated code.

**Trade-off:** type safety is deferred to the call site. Every consumer must
type-assert values from the map. Mismatched field names are a runtime error,
not a compile error. That is an acceptable cost for an auth library where the
schema is user-extensible — a typed interface would need to anticipate every
possible plugin-added column.

---

## Request Lifecycle

```
Client Request
    └─ Rate Limiter middleware (fixed-window, optional)
        └─ http.ServeMux (built in buildRouter)
            └─ Core handler  (sign-in, sign-up, session, OAuth, ...)
               OR Plugin endpoint handler
                   └─ RunSessionCreateHooks  (on sign-in / OAuth callback)
                       └─ Each SessionCreateHookFn in registration order
                           ─ returns nil      → continue
                           ─ returns ErrHandled → abort, response already sent
                           ─ returns other error → abort, caller writes error
```

`buildRouter` registers core routes first, then iterates `opts.Plugins` and
mounts each `EndpointProvider`'s routes. Plugin routes are plain
`http.HandlerFunc` values — no framework coupling.

---

## Key Design Decisions

**`New()` panics on plugin `Init` failure.** A plugin that fails `Init` has
a misconfiguration (missing required option, bad credentials). Returning a
partially-configured `*Auth` would silently fail at request time in hard-to-debug
ways. Panicking at startup surfaces the problem immediately. The doc comment on
`New()` shows a `recover` wrapper for callers who need an error return instead.

**In-memory adapter for tests, sqlx for production.** The in-memory adapter
satisfies the full `Adapter` interface and is used in every unit and integration
test without mocking. Tests run fast and without a database process. The sqlx
adapter provides production persistence. No mock layer is needed because the
real in-memory implementation is cheap enough to use directly.

**Fixed-window rate limiter.** The rate limiter uses a simple fixed-window
counter (N requests per window). A sliding-window approach produces smoother
throttling but requires storing a timestamp ring per client, which increases
memory proportionally to traffic. Fixed-window is predictable, easy to reason
about, and sufficient for an auth server where the concern is brute-force
protection rather than precise fairness.
