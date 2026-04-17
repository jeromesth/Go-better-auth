// Package totp implements a TOTP-based two-factor authentication plugin for go-better-auth.
package totp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the TOTP plugin.
type Options struct {
	// Issuer is the app name shown in authenticator apps. Defaults to Auth.AppName.
	Issuer string
	// ChallengeExpiresIn is seconds until a TOTP challenge expires. Default: 300 (5 min).
	ChallengeExpiresIn int
}

// Plugin implements TOTP-based 2FA for go-better-auth.
type Plugin struct {
	opts *Options
	auth *betterauth.Auth
}

// New creates a new TOTP plugin with the given options.
func New(opts *Options) *Plugin {
	if opts == nil {
		opts = &Options{}
	}
	if opts.ChallengeExpiresIn == 0 {
		opts.ChallengeExpiresIn = 300
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "totp" }

func (p *Plugin) SetAuth(auth any) {
	a, ok := auth.(*betterauth.Auth)
	if !ok {
		return
	}
	p.auth = a
}

// Schema extends the database with a totp table.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"totp": {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "user_id", Type: "text", Required: true, Ref: "user.id"},
				{Name: "secret", Type: "text", Required: true},
				{Name: "enabled", Type: "boolean", Required: true},
				{Name: "created_at", Type: "timestamp", Required: true},
				{Name: "updated_at", Type: "timestamp", Required: true},
			},
		},
	}
}

// SessionCreateHooks intercepts sign-in for users with TOTP enabled.
func (p *Plugin) SessionCreateHooks() []plugin.SessionCreateHookFn {
	return []plugin.SessionCreateHookFn{p.checkTOTPOnSessionCreate}
}

func (p *Plugin) checkTOTPOnSessionCreate(scc plugin.SessionCreateContext) error {
	if p.auth == nil {
		return nil
	}
	ctx := context.Background()
	if scc.Request != nil {
		ctx = scc.Request.Context()
	}

	rec, err := p.findTOTPRecord(ctx, scc.UserID)
	if err != nil || rec == nil {
		return nil
	}
	enabled, _ := rec["enabled"].(bool)
	if !enabled {
		return nil
	}

	// Generate a short-lived challenge token.
	challengeToken := internal.NewID()
	expiresAt := time.Now().UTC().Add(time.Duration(p.opts.ChallengeExpiresIn) * time.Second)
	now := time.Now().UTC()
	_, err = p.auth.InternalAdapter().Adapter().Create(ctx, "verification", map[string]any{
		"id":         internal.NewID(),
		"identifier": "totp:" + scc.UserID,
		"value":      challengeToken,
		"expires_at": expiresAt,
		"created_at": now,
		"updated_at": now,
	})
	if err != nil {
		return err
	}

	// Write the TOTP_REQUIRED response and signal that we've handled it.
	httputil.WriteJSON(scc.Writer, http.StatusForbidden, map[string]any{
		"code":           "TOTP_REQUIRED",
		"challengeToken": challengeToken,
	})
	return plugin.ErrHandled
}

// Endpoints returns all TOTP API endpoints.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/totp/generate", Handler: p.withMethod(http.MethodPost, p.handleGenerate)},
		{Method: http.MethodPost, Path: "/totp/enable", Handler: p.withMethod(http.MethodPost, p.handleEnable)},
		{Method: http.MethodPost, Path: "/totp/disable", Handler: p.withMethod(http.MethodPost, p.handleDisable)},
		{Method: http.MethodGet, Path: "/totp/status", Handler: p.withMethod(http.MethodGet, p.handleStatus)},
		{Method: http.MethodPost, Path: "/totp/verify", Handler: p.withMethod(http.MethodPost, p.handleVerify)},
	}
}

// handleGenerate generates a new TOTP secret for the authenticated user.
func (p *Plugin) handleGenerate(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	secret, err := GenerateSecret()
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate secret")
		return
	}

	issuer := p.issuer()
	userRec, _ := p.auth.InternalAdapter().FindUserByIDRaw(ctx, userID)
	email := ""
	if userRec != nil {
		email, _ = userRec["email"].(string)
	}
	otpauthURL := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, email, secret, issuer,
	)

	// Upsert the TOTP record (disabled until first verification).
	existing, _ := p.findTOTPRecord(ctx, userID)
	now := time.Now().UTC()
	if existing != nil {
		_, _ = p.auth.InternalAdapter().Adapter().Update(ctx, "totp", adapter.Query{
			Where: []adapter.Where{adapter.EQ("user_id", userID)},
		}, map[string]any{"secret": secret, "enabled": false, "updated_at": now})
	} else {
		_, _ = p.auth.InternalAdapter().Adapter().Create(ctx, "totp", map[string]any{
			"id":         internal.NewID(),
			"user_id":    userID,
			"secret":     secret,
			"enabled":    false,
			"created_at": now,
			"updated_at": now,
		})
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"secret":     secret,
		"otpauthURL": otpauthURL,
	})
}

// handleEnable verifies the first TOTP code and enables 2FA.
func (p *Plugin) handleEnable(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	ctx := r.Context()

	rec, err := p.findTOTPRecord(ctx, userID)
	if err != nil || rec == nil {
		httputil.WriteError(w, http.StatusBadRequest, "TOTP_NOT_CONFIGURED", "TOTP not configured. Call /totp/generate first.")
		return
	}
	secret, _ := rec["secret"].(string)
	if !VerifyTOTP(secret, req.Code, time.Now().UTC()) {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOTP_CODE", "Invalid TOTP code")
		return
	}

	_, _ = p.auth.InternalAdapter().Adapter().Update(ctx, "totp", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	}, map[string]any{"enabled": true, "updated_at": time.Now().UTC()})

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": true})
}

// handleDisable verifies the TOTP code and disables 2FA.
func (p *Plugin) handleDisable(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	ctx := r.Context()

	rec, err := p.findTOTPRecord(ctx, userID)
	if err != nil || rec == nil {
		httputil.WriteError(w, http.StatusBadRequest, "TOTP_NOT_CONFIGURED", "TOTP is not configured")
		return
	}
	enabled, _ := rec["enabled"].(bool)
	if !enabled {
		httputil.WriteError(w, http.StatusBadRequest, "TOTP_NOT_ENABLED", "TOTP is not enabled")
		return
	}
	secret, _ := rec["secret"].(string)
	if !VerifyTOTP(secret, req.Code, time.Now().UTC()) {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_TOTP_CODE", "Invalid TOTP code")
		return
	}

	_ = p.auth.InternalAdapter().Adapter().Delete(ctx, "totp", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

// handleStatus returns TOTP enabled status for the authenticated user.
func (p *Plugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	rec, err := p.findTOTPRecord(ctx, userID)
	if err != nil || rec == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": false})
		return
	}
	enabled, _ := rec["enabled"].(bool)
	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
}

// handleVerify exchanges a challenge token + TOTP code for a real session.
func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeToken string `json:"challengeToken"`
		Code           string `json:"code"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if req.ChallengeToken == "" || req.Code == "" {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_REQUEST", "challengeToken and code are required")
		return
	}

	ctx := r.Context()

	// Find the pending challenge in the verification table.
	chalRec, err := p.auth.InternalAdapter().Adapter().FindOne(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("value", req.ChallengeToken)},
	})
	if err != nil || chalRec == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CHALLENGE", "Invalid or expired challenge token")
		return
	}

	// Check expiry.
	if exp, ok := chalRec["expires_at"].(time.Time); ok && time.Now().UTC().After(exp) {
		_ = p.auth.InternalAdapter().Adapter().Delete(ctx, "verification", adapter.Query{
			Where: []adapter.Where{adapter.EQ("value", req.ChallengeToken)},
		})
		httputil.WriteError(w, http.StatusUnauthorized, "CHALLENGE_EXPIRED", "Challenge token has expired")
		return
	}

	// Extract userID from identifier "totp:<userID>".
	identifier, _ := chalRec["identifier"].(string)
	if !strings.HasPrefix(identifier, "totp:") {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_CHALLENGE", "Invalid challenge token")
		return
	}
	userID := strings.TrimPrefix(identifier, "totp:")

	// Look up the TOTP record and verify the code.
	totpRec, err := p.findTOTPRecord(ctx, userID)
	if err != nil || totpRec == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "TOTP_NOT_CONFIGURED", "TOTP not configured")
		return
	}
	secret, _ := totpRec["secret"].(string)
	if !VerifyTOTP(secret, req.Code, time.Now().UTC()) {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_TOTP_CODE", "Invalid TOTP code")
		return
	}

	// Delete the used challenge token.
	_ = p.auth.InternalAdapter().Adapter().Delete(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("value", req.ChallengeToken)},
	})

	// Create the real session.
	ip := internal.GetClientIP(r, p.auth.IPHeader())
	ua := r.UserAgent()
	sess, err := p.auth.SessionManager().Create(ctx, userID, ip, ua)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	user, err := p.auth.InternalAdapter().FindUserByID(ctx, userID)
	if err != nil || user == nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

// --- Helpers ---

func (p *Plugin) findTOTPRecord(ctx context.Context, userID string) (map[string]any, error) {
	return p.auth.InternalAdapter().Adapter().FindOne(ctx, "totp", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

func (p *Plugin) getAuthenticatedUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := session.GetSessionToken(r)
	if token == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	ctx := r.Context()
	sess, err := p.auth.SessionManager().FindByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	return sess.UserID, true
}

func (p *Plugin) issuer() string {
	if p.opts.Issuer != "" {
		return p.opts.Issuer
	}
	if p.auth != nil {
		return p.auth.Options().AppName
	}
	return "App"
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

// --- TOTP math (RFC 6238 / HOTP RFC 4226) ---

// GenerateSecret creates a cryptographically random base32-encoded TOTP secret.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateTOTP computes the 6-digit TOTP code for the given base32 secret and time.
func GenerateTOTP(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	counter := uint64(t.Unix()) / 30
	msg := binary.BigEndian.AppendUint64(nil, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000), nil
}

// VerifyTOTP checks code against the secret at time t, accepting ±1 time window.
func VerifyTOTP(secret, code string, t time.Time) bool {
	for _, delta := range []int64{-1, 0, 1} {
		adjusted := t.Add(time.Duration(delta*30) * time.Second)
		expected, err := GenerateTOTP(secret, adjusted)
		if err == nil && expected == code {
			return true
		}
	}
	return false
}
