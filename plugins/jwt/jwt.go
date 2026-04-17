// Package jwt provides a JWT plugin for go-better-auth.
// It attaches a signed JWT to session creation responses and exposes a
// /jwt/verify endpoint for stateless token verification.
package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/plugin"
)

// Options configures the JWT plugin.
type Options struct {
	// Secret is the HMAC-SHA256 signing key (required).
	Secret []byte
	// Expiry is the JWT lifetime. Default: 24 hours.
	Expiry time.Duration
	// Issuer sets the "iss" claim. Optional.
	Issuer string
	// IncludeMetadata adds session/user metadata to claims when true.
	IncludeMetadata bool
}

// Plugin implements JWT signing/verification for go-better-auth.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
}

// New creates a JWT plugin. If opts.Expiry is zero, it defaults to 24 hours.
func New(opts Options) *Plugin {
	if opts.Expiry == 0 {
		opts.Expiry = 24 * time.Hour
	}
	return &Plugin{opts: opts}
}

// ID returns the unique identifier for this plugin.
func (p *Plugin) ID() string { return "jwt" }

// SetAuth injects the Auth instance so the plugin can access session and storage.
func (p *Plugin) SetAuth(auth any) {
	a, ok := auth.(*betterauth.Auth)
	if !ok {
		return
	}
	p.auth = a
}

// SessionCreateHooks returns a hook that appends a signed JWT to the response
// Authorization header immediately before the session response is written.
func (p *Plugin) SessionCreateHooks() []plugin.SessionCreateHookFn {
	return []plugin.SessionCreateHookFn{p.attachJWT}
}

func (p *Plugin) attachJWT(scc plugin.SessionCreateContext) error {
	token, err := p.sign(scc.UserID)
	if err != nil {
		return nil // non-fatal: skip JWT on signing error
	}
	scc.Writer.Header().Set("Authorization", "Bearer "+token)
	return nil
}

// Endpoints exposes /jwt/verify.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodGet, Path: "/jwt/verify", Handler: p.handleVerify},
	}
}

func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		httputil.WriteError(w, http.StatusUnauthorized, "MISSING_TOKEN", "Authorization header required")
		return
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := p.verify(raw)
	if err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_TOKEN", fmt.Sprintf("token invalid: %v", err))
		return
	}

	httputil.WriteJSON(w, http.StatusOK, claims)
}

// sign creates a signed JWT for the given userID.
func (p *Plugin) sign(userID string) (string, error) {
	now := time.Now()
	claims := gojwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(p.opts.Expiry).Unix(),
	}
	if p.opts.Issuer != "" {
		claims["iss"] = p.opts.Issuer
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	return token.SignedString(p.opts.Secret)
}

// verify parses and validates a JWT, returning its claims.
func (p *Plugin) verify(raw string) (map[string]any, error) {
	token, err := gojwt.Parse(raw, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return p.opts.Secret, nil
	}, gojwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return map[string]any(claims), nil
}
