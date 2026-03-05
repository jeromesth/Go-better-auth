// Package plugin defines the Plugin interface and optional capability interfaces.
package plugin

import (
	"errors"
	"net/http"
)

// ErrHandled is returned by hook functions that have already written
// the HTTP response. Callers must abort further writes after receiving it.
var ErrHandled = errors.New("response already handled")

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

// SessionCreateHookFn is called before a session is created.
// If it returns a non-nil error, session creation is aborted and the error
// message is returned to the client.
type SessionCreateHookFn func(ctx SessionCreateContext) error

// SessionCreateContext provides context for session creation hooks.
type SessionCreateContext struct {
	UserID  string
	Request *http.Request
	Writer  http.ResponseWriter
}

// UserCreateHookFn is called before a user record is created in the database.
// It can modify the data map to add extra fields (e.g., default role).
type UserCreateHookFn func(data map[string]any) map[string]any

// SessionCreateHookProvider is implemented by plugins that need to intercept session creation.
type SessionCreateHookProvider interface {
	SessionCreateHooks() []SessionCreateHookFn
}

// UserCreateHookProvider is implemented by plugins that need to intercept user creation.
type UserCreateHookProvider interface {
	UserCreateHooks() []UserCreateHookFn
}

// -- Optional capability interfaces plugins can implement --

// AuthAware is implemented by plugins that need a reference to the auth instance.
// The auth instance is passed as `any` to avoid circular imports.
// Plugins should type-assert to the concrete *Auth type.
type AuthAware interface {
	SetAuth(auth any)
}

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
