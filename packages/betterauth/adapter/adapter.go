package adapter

import "context"

// Query describes a database query for filtering and ordering records.
type Query struct {
	Where   []Where
	Limit   int
	Offset  int
	SortBy  string
	SortDir string // "asc" or "desc"
}

// Where describes a filter condition.
type Where struct {
	Field    string
	Operator string // "=", "!=", ">", "<", ">=", "<=", "in", "like"
	Value    any
}

// Adapter is the core database interface all adapters must implement.
// It operates on generic map[string]any records keyed by model name.
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

// EQ returns a simple equality Where clause.
func EQ(field string, value any) Where {
	return Where{Field: field, Operator: "=", Value: value}
}
