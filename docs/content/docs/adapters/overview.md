# Database Adapters

Go Better Auth uses a generic adapter interface for all database operations. This allows you to use any database backend by implementing the `adapter.Adapter` interface.

## Adapter Interface

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

## Built-in Adapters

### Memory Adapter

The in-memory adapter is included for development and testing:

```go
import "github.com/jeromesth/go-better-auth/packages/betterauth/adapter/memory"

adapter := memory.New()
```

> **Note:** The memory adapter stores all data in-memory and is not suitable for production use. Data is lost when the process restarts.

## Database Schema

Go Better Auth uses four core tables:

| Table | Purpose |
|-------|---------|
| `user` | User accounts |
| `session` | Active sessions |
| `account` | OAuth accounts and credentials |
| `verification` | Verification tokens (email, password reset) |

See the [PLAN.md](https://github.com/jeromesth/Go-better-auth/blob/main/PLAN.md) for the full SQL schema.

## Implementing a Custom Adapter

To implement a custom adapter (e.g., for PostgreSQL with sqlx):

1. Implement all methods of the `adapter.Adapter` interface
2. Handle the `Query` struct for filtering, sorting, and pagination
3. Map the model names (`"user"`, `"session"`, etc.) to your table names
4. Return `nil, nil` from `FindOne` when no record is found (not an error)
