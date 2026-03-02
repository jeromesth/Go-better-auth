// Package plugin defines the Plugin interface and optional capability interfaces.
package plugin

import "net/http"

// Plugin is the base interface all plugins must implement.
type Plugin interface {
	ID() string
}

// Endpoint describes a single HTTP endpoint provided by a plugin.
type Endpoint struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// TableSchema describes a database table schema (for schema extension).
type TableSchema struct {
	Fields []FieldDef
}

// FieldDef describes a single database column.
type FieldDef struct {
	Name     string
	Type     string // "text", "boolean", "integer", "timestamp"
	Required bool
	Unique   bool
	Ref      string // foreign key reference (e.g. "user.id")
}

// HookFn is a function called before or after an endpoint handler.
type HookFn func(r *http.Request, w http.ResponseWriter) error

// Hooks maps endpoint paths to before/after hook functions.
type Hooks struct {
	Before map[string]HookFn
	After  map[string]HookFn
}

// MiddlewareConfig wraps a middleware function with metadata.
type MiddlewareConfig struct {
	Name       string
	Middleware func(http.Handler) http.Handler
}

// RateLimitRule describes a rate limit rule for a specific path pattern.
type RateLimitRule struct {
	PathMatcher string
	Window      int
	Max         int
}

// PluginContext holds plugin-specific context returned from Init.
type PluginContext struct {
	Tables map[string]TableSchema
}

// -- Optional capability interfaces plugins can implement --

// Initializer is implemented by plugins that need initialization.
type Initializer interface {
	Init() (*PluginContext, error)
}

// EndpointProvider is implemented by plugins that expose HTTP endpoints.
type EndpointProvider interface {
	Endpoints() []Endpoint
}

// SchemaProvider is implemented by plugins that extend the database schema.
type SchemaProvider interface {
	Schema() map[string]TableSchema
}

// HookProvider is implemented by plugins that register lifecycle hooks.
type HookProvider interface {
	Hooks() Hooks
}

// MiddlewareProvider is implemented by plugins that add HTTP middleware.
type MiddlewareProvider interface {
	Middlewares() []MiddlewareConfig
}

// RateLimitProvider is implemented by plugins that add rate limit rules.
type RateLimitProvider interface {
	RateLimitRules() []RateLimitRule
}
