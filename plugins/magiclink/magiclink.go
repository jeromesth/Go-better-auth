// Package magiclink provides passwordless magic link authentication for go-better-auth.
package magiclink

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

const identifierPrefix = "magic-link:"

// Options configures the magic link plugin.
type Options struct {
	// SendMagicLink is required. Called when a magic link is generated.
	SendMagicLink func(ctx context.Context, email, link string) error
	// TokenExpiry is the link lifetime. Default: 15 minutes.
	TokenExpiry time.Duration
	// BaseURL is used to build the verify URL. Example: "https://example.com/api/auth".
	BaseURL string
}

// Plugin implements passwordless magic-link authentication.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
}

// New creates a magic link plugin with the given options.
func New(opts Options) *Plugin {
	if opts.TokenExpiry == 0 {
		opts.TokenExpiry = 15 * time.Minute
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "magiclink" }

func (p *Plugin) SetAuth(auth *betterauth.Auth) {
	p.auth = auth
}

// Endpoints registers /magic-link/send and /magic-link/verify.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/magic-link/send", Handler: p.withMethod(http.MethodPost, p.handleSend)},
		{Method: http.MethodGet, Path: "/magic-link/verify", Handler: p.withMethod(http.MethodGet, p.handleVerify)},
	}
}

// handleSend generates a token and calls SendMagicLink.
func (p *Plugin) handleSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if r.Body == nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_REQUEST", "Request body required")
		return
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" {
		httputil.WriteError(w, http.StatusBadRequest, "MISSING_EMAIL", "email is required")
		return
	}

	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	user, err := ia.FindUserByEmail(ctx, req.Email)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}
	// Don't reveal whether the email exists — silently succeed.
	if user == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	token, err := crypto.GenerateVerificationToken()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate token")
		return
	}

	if _, err = ia.CreateVerification(ctx, identifierPrefix+req.Email, token, p.opts.TokenExpiry); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store token")
		return
	}

	link := p.buildVerifyURL(token)
	if p.opts.SendMagicLink != nil {
		if err := p.opts.SendMagicLink(ctx, req.Email, link); err != nil {
			// Log but don't fail — token is stored, sender may retry.
			_ = err
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleVerify validates the token and creates a session.
func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "MISSING_TOKEN", "token query parameter required")
		return
	}

	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	verif, err := ia.FindVerificationByValue(ctx, token)
	if err != nil || verif == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired magic link")
		return
	}
	if time.Now().After(verif.ExpiresAt) {
		_ = ia.DeleteVerification(ctx, verif.ID)
		httputil.WriteError(w, http.StatusUnauthorized, "TOKEN_EXPIRED", "Magic link has expired")
		return
	}
	if !strings.HasPrefix(verif.Identifier, identifierPrefix) {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid magic link")
		return
	}

	email := verif.Identifier[len(identifierPrefix):]
	user, err := ia.FindUserByEmail(ctx, email)
	if err != nil || user == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "USER_NOT_FOUND", "User not found")
		return
	}

	// Consume the token.
	_ = ia.DeleteVerification(ctx, verif.ID)

	// Run session create hooks.
	if err := p.auth.RunSessionCreateHooks(w, r, user.ID); err != nil {
		if !errors.Is(err, plugin.ErrHandled) {
			httputil.WriteError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		}
		return
	}

	ip := internal.GetClientIP(r, p.auth.IPHeader())
	ua := r.UserAgent()
	sess, err := p.auth.SessionManager().Create(ctx, user.ID, ip, ua)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

func (p *Plugin) buildVerifyURL(token string) string {
	base := strings.TrimRight(p.opts.BaseURL, "/")
	return base + "/magic-link/verify?token=" + token
}

func (p *Plugin) withMethod(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
