// Package anonymous adds anonymous (guest) authentication to go-better-auth.
// It allows users to sign in without credentials and optionally link their
// anonymous account to a real email/password identity later.
package anonymous

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/models"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the anonymous plugin.
type Options struct {
	// GuestNamePrefix is the prefix for generated guest names. Default: "Guest-"
	GuestNamePrefix string
	// EmailDomain is the fake email domain for anonymous users. Default: "anonymous.local"
	EmailDomain string
}

// Plugin adds anonymous sign-in and account linking.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
}

// New creates an anonymous plugin with the given options.
func New(opts Options) *Plugin {
	if opts.GuestNamePrefix == "" {
		opts.GuestNamePrefix = "Guest-"
	}
	if opts.EmailDomain == "" {
		opts.EmailDomain = "anonymous.local"
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "anonymous" }

func (p *Plugin) SetAuth(auth *betterauth.Auth) {
	p.auth = auth
}

// Schema extends the user table with an is_anonymous field.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"user": {
			Fields: []plugin.FieldDef{
				{Name: "is_anonymous", Type: "boolean", Required: false},
			},
		},
	}
}

// Endpoints registers /sign-in/anonymous and /anonymous/link.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/sign-in/anonymous", Handler: p.withMethod(http.MethodPost, p.handleSignInAnonymous)},
		{Method: http.MethodPost, Path: "/anonymous/link", Handler: p.withMethod(http.MethodPost, p.handleLink)},
	}
}

func (p *Plugin) handleSignInAnonymous(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	anonID := randomHex(16)
	email := "anon-" + anonID + "@" + p.opts.EmailDomain
	name := p.opts.GuestNamePrefix + anonID

	// Create anonymous user with is_anonymous = true.
	user, err := ia.CreateUserWithExtra(ctx, email, name, false, func(data map[string]any) map[string]any {
		data["is_anonymous"] = true
		return p.auth.RunUserCreateHooks(data)
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	// Run session-create hooks.
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user":    modelUserResponse(user, true),
		"session": sess,
	})
}

type linkRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (p *Plugin) handleLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	// Require an active session.
	token := session.GetSessionToken(r)
	if token == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	sess, err := p.auth.SessionManager().FindByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired session")
		return
	}

	// Get the current user and check if they are anonymous.
	userRec, err := ia.FindUserByIDRaw(ctx, sess.UserID)
	if err != nil || userRec == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	isAnon, _ := userRec["is_anonymous"].(bool)
	if !isAnon {
		httputil.WriteError(w, http.StatusBadRequest, "NOT_ANONYMOUS", "User is not anonymous")
		return
	}

	// Parse request body.
	var req linkRequest
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
	if req.Password == "" {
		httputil.WriteError(w, http.StatusBadRequest, "MISSING_PASSWORD", "password is required")
		return
	}

	// Validate password length against EmailAndPassword config.
	epCfg := p.auth.Options().EmailAndPassword
	if epCfg != nil {
		if epCfg.MinPasswordLength > 0 && len(req.Password) < epCfg.MinPasswordLength {
			httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT", fmt.Sprintf("password must be at least %d characters", epCfg.MinPasswordLength))
			return
		}
		if epCfg.MaxPasswordLength > 0 && len(req.Password) > epCfg.MaxPasswordLength {
			httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_TOO_LONG", fmt.Sprintf("password must be at most %d characters", epCfg.MaxPasswordLength))
			return
		}
	}

	// Check that the email isn't already in use.
	existing, err := ia.FindUserByEmail(ctx, req.Email)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}
	if existing != nil {
		httputil.WriteError(w, http.StatusConflict, "EMAIL_ALREADY_USED", "Email is already in use")
		return
	}

	// Hash the password.
	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	// Update the user: set real email, name, is_anonymous=false.
	updateData := map[string]any{
		"email":        req.Email,
		"is_anonymous": false,
	}
	if req.Name != "" {
		updateData["name"] = req.Name
	}

	updatedRec, err := ia.UpdateUserRaw(ctx, sess.UserID, updateData)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	// Create a credential account with the hashed password.
	if _, err = ia.CreateAccount(ctx, sess.UserID, sess.UserID, "credential", map[string]any{
		"password": hash,
	}); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user": rawUserResponse(updatedRec),
	})
}

// randomHex generates n random bytes and returns as hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// modelUserResponse builds a JSON-friendly user map from a models.User
// plus the is_anonymous flag (which is not part of models.User).
func modelUserResponse(u *models.User, isAnonymous bool) map[string]any {
	resp := map[string]any{
		"id":            u.ID,
		"email":         u.Email,
		"name":          u.Name,
		"emailVerified": u.EmailVerified,
		"isAnonymous":   isAnonymous,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	if u.Image != nil {
		resp["image"] = *u.Image
	}
	return resp
}

func rawUserResponse(r map[string]any) map[string]any {
	resp := map[string]any{
		"id":            r["id"],
		"email":         r["email"],
		"name":          r["name"],
		"emailVerified": r["email_verified"],
		"isAnonymous":   r["is_anonymous"],
	}
	if v, ok := r["image"]; ok {
		resp["image"] = v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		resp["createdAt"] = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		resp["updatedAt"] = v
	}
	return resp
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
