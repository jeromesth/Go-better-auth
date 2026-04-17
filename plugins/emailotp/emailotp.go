// Package emailotp provides email-based one-time password authentication for go-better-auth.
// It delivers a short numeric code (instead of a link) for passwordless sign-in.
package emailotp

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
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

const identifierPrefix = "email-otp:"

// Options configures the email OTP plugin.
type Options struct {
	// SendOTP is required. Called when an OTP code is generated.
	SendOTP func(ctx context.Context, email, code string) error
	// CodeLength is the number of digits. Default: 6.
	CodeLength int
	// TokenExpiry is the OTP lifetime. Default: 10 minutes.
	TokenExpiry time.Duration
}

// Plugin implements email OTP authentication.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
}

// New creates an email OTP plugin with the given options.
func New(opts Options) *Plugin {
	if opts.CodeLength == 0 {
		opts.CodeLength = 6
	}
	if opts.TokenExpiry == 0 {
		opts.TokenExpiry = 10 * time.Minute
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "emailotp" }

func (p *Plugin) SetAuth(auth any) {
	a, ok := auth.(*betterauth.Auth)
	if !ok {
		return
	}
	p.auth = a
}

// Endpoints registers /email-otp/send and /email-otp/verify.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/email-otp/send", Handler: p.withMethod(http.MethodPost, p.handleSend)},
		{Method: http.MethodPost, Path: "/email-otp/verify", Handler: p.withMethod(http.MethodPost, p.handleVerify)},
	}
}

// handleSend generates an OTP code and calls SendOTP.
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

	code, err := generateOTP(p.opts.CodeLength)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate code")
		return
	}

	// Hash the OTP before storing it so it's not in plaintext.
	hashedCode, err := crypto.HashPassword(code)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal error")
		return
	}

	if _, err = ia.CreateVerification(ctx, identifierPrefix+req.Email, hashedCode, p.opts.TokenExpiry); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store code")
		return
	}

	if p.opts.SendOTP != nil {
		if err := p.opts.SendOTP(ctx, req.Email, code); err != nil {
			_ = err // Log but don't fail — code is stored.
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleVerify validates the OTP code and creates a session.
func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
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
	req.Code = strings.TrimSpace(req.Code)
	if req.Email == "" || req.Code == "" {
		httputil.WriteError(w, http.StatusBadRequest, "MISSING_FIELDS", "email and code are required")
		return
	}

	ctx := r.Context()
	ia := p.auth.InternalAdapter()

	verif, err := p.findVerificationByIdentifier(ctx, identifierPrefix+req.Email)
	if err != nil || verif == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CODE", "Invalid or expired code")
		return
	}
	if time.Now().After(verif.ExpiresAt) {
		_ = ia.DeleteVerification(ctx, verif.ID)
		httputil.WriteError(w, http.StatusUnauthorized, "CODE_EXPIRED", "Code has expired")
		return
	}

	// Verify the hashed OTP.
	ok, err := crypto.VerifyPassword(verif.Value, req.Code)
	if err != nil || !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CODE", "Invalid or expired code")
		return
	}

	user, err := ia.FindUserByEmail(ctx, req.Email)
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

func (p *Plugin) findVerificationByIdentifier(ctx context.Context, identifier string) (*models.Verification, error) {
	rec, err := p.auth.InternalAdapter().Adapter().FindOne(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("identifier", identifier)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToVerification(rec), nil
}

func recordToVerification(r map[string]any) *models.Verification {
	v := &models.Verification{}
	v.ID, _ = r["id"].(string)
	v.Identifier, _ = r["identifier"].(string)
	v.Value, _ = r["value"].(string)
	if t, ok := r["expires_at"].(time.Time); ok {
		v.ExpiresAt = t
	}
	if t, ok := r["created_at"].(time.Time); ok {
		v.CreatedAt = t
	}
	if t, ok := r["updated_at"].(time.Time); ok {
		v.UpdatedAt = t
	}
	return v
}

// generateOTP generates a cryptographically random numeric OTP of the given length.
func generateOTP(length int) (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := cryptorand.Int(cryptorand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", length, n), nil
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
