// Package username adds username-based authentication to go-better-auth.
// It extends the user model with a unique username field and provides
// a sign-in endpoint that accepts username instead of email.
package username

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/models"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the username plugin.
type Options struct {
	// MinLength is the minimum username length. Default: 3.
	MinLength int
	// MaxLength is the maximum username length. Default: 32.
	MaxLength int
}

// Plugin adds username-based sign-up and sign-in.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
}

// New creates a username plugin with the given options.
func New(opts Options) *Plugin {
	if opts.MinLength == 0 {
		opts.MinLength = 3
	}
	if opts.MaxLength == 0 {
		opts.MaxLength = 32
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "username" }

func (p *Plugin) SetAuth(auth any) {
	a, ok := auth.(*betterauth.Auth)
	if !ok {
		return
	}
	p.auth = a
}

// Schema extends the user table with a username field.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"user": {
			Fields: []plugin.FieldDef{
				{Name: "username", Type: "text", Required: false, Unique: true},
			},
		},
	}
}

// Endpoints registers /sign-up/username and /sign-in/username.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/sign-up/username", Handler: p.withMethod(http.MethodPost, p.handleSignUp)},
		{Method: http.MethodPost, Path: "/sign-in/username", Handler: p.withMethod(http.MethodPost, p.handleSignIn)},
	}
}

type signUpRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type signInRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p *Plugin) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req signUpRequest
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, "INVALID_REQUEST", "Request body required")
		return
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if err := p.validateUsername(req.Username); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_USERNAME", err.Error())
		return
	}
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "MISSING_EMAIL", "email is required")
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "MISSING_PASSWORD", "password is required")
		return
	}

	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	// Check username uniqueness.
	existing, err := p.findUserByUsername(ctx, ia, req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}
	if existing != nil {
		writeErr(w, http.StatusConflict, "USERNAME_TAKEN", "Username is already taken")
		return
	}

	// Check email uniqueness.
	existingEmail, err := ia.FindUserByEmail(ctx, req.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}
	if existingEmail != nil {
		writeErr(w, http.StatusConflict, "EMAIL_ALREADY_USED", "Email is already in use")
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	name := req.Name
	if name == "" {
		name = req.Username
	}

	// Create user with username via hook.
	user, err := ia.CreateUserWithExtra(ctx, req.Email, name, false, func(data map[string]any) map[string]any {
		data["username"] = req.Username
		return p.auth.RunUserCreateHooks(data)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	if _, err = ia.CreateAccount(ctx, user.ID, user.ID, "credential", map[string]any{
		"password": hash,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	// Run session-create hooks.
	if err := p.auth.RunSessionCreateHooks(w, r, user.ID); err != nil {
		if !errors.Is(err, plugin.ErrHandled) {
			writeErr(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		}
		return
	}

	ip := internal.GetClientIP(r, p.auth.IPHeader())
	ua := r.UserAgent()
	sess, err := p.auth.SessionManager().Create(ctx, user.ID, ip, ua)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

func (p *Plugin) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var req signInRequest
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, "INVALID_REQUEST", "Request body required")
		return
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, "MISSING_USERNAME", "username is required")
		return
	}

	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	user, err := p.findUserByUsername(ctx, ia, req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}
	if user == nil {
		writeErr(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}

	accounts, err := ia.FindAccountsByUserID(ctx, user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	var hash string
	for _, acc := range accounts {
		if acc.ProviderID == "credential" && acc.Password != nil {
			hash = *acc.Password
			break
		}
	}
	if hash == "" {
		writeErr(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}

	ok, err := crypto.VerifyPassword(hash, req.Password)
	if err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}

	if err := p.auth.RunSessionCreateHooks(w, r, user.ID); err != nil {
		if !errors.Is(err, plugin.ErrHandled) {
			writeErr(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		}
		return
	}

	ip := internal.GetClientIP(r, p.auth.IPHeader())
	ua := r.UserAgent()
	sess, err := p.auth.SessionManager().Create(ctx, user.ID, ip, ua)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

func (p *Plugin) findUserByUsername(ctx context.Context, ia *betterauth.InternalAdapter, username string) (*models.User, error) {
	rec, err := ia.Adapter().FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("username", username)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToUser(rec), nil
}

func recordToUser(r map[string]any) *models.User {
	u := &models.User{}
	u.ID, _ = r["id"].(string)
	u.Email, _ = r["email"].(string)
	u.Name, _ = r["name"].(string)
	u.EmailVerified, _ = r["email_verified"].(bool)
	if v, ok := r["image"].(string); ok {
		u.Image = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		u.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		u.UpdatedAt = v
	}
	return u
}

func (p *Plugin) validateUsername(username string) error {
	if len(username) < p.opts.MinLength {
		return errors.New("username too short")
	}
	if len(username) > p.opts.MaxLength {
		return errors.New("username too long")
	}
	return nil
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

func writeErr(w http.ResponseWriter, status int, code, message string) {
	httputil.WriteError(w, status, code, message)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	httputil.WriteJSON(w, status, v)
}
