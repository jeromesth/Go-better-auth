package betterauth

import (
	"context"
	"net/http"

	"github.com/jeromesth/go-better-auth/packages/betterauth/models"
)

// AuthContext holds the full runtime context for the auth system,
// including the parsed options, internal adapter, and helper references.
type AuthContext struct {
	Options         *BetterAuthOptions
	InternalAdapter *InternalAdapter
}

// RequestContext carries per-request data attached to context.Context.
type RequestContext struct {
	User    *models.User
	Session *models.Session
	Request *http.Request
}

type contextKey string

const requestContextKey contextKey = "betterauth_request"

// WithRequestContext attaches a RequestContext to the provided context.Context.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey, rc)
}

// GetRequestContext retrieves the RequestContext from the provided context.Context.
func GetRequestContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(requestContextKey).(*RequestContext)
	return rc
}
