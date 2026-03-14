// Package passkey implements WebAuthn/Passkey authentication for go-better-auth.
// It supports passkey registration and authentication ceremonies using the
// github.com/go-webauthn/webauthn library.
package passkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/models"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	modelPasskey    = "passkey"
	challengeExpiry = 5 * time.Minute
	regIdentPrefix  = "passkey-reg:"
	authIdentPrefix = "passkey-auth:"
)

// Options configures the Passkey/WebAuthn plugin.
type Options struct {
	// RPDisplayName is the human-readable name of the Relying Party (required).
	RPDisplayName string
	// RPID is the Relying Party identifier, typically the domain (required).
	RPID string
	// RPOrigins is the list of allowed origins for WebAuthn ceremonies (required).
	RPOrigins []string

	// AttestationType controls attestation conveyance preference. Default: "none".
	AttestationType string
	// AuthenticatorSelection configures authenticator requirements.
	AuthenticatorSelection *AuthenticatorSelection
}

// AuthenticatorSelection configures authenticator requirements for registration.
type AuthenticatorSelection struct {
	// AuthenticatorAttachment limits to "platform" or "cross-platform" authenticators.
	AuthenticatorAttachment string
	// RequireResidentKey indicates if a resident key (discoverable credential) is required.
	RequireResidentKey bool
	// ResidentKey preference: "required", "preferred", or "discouraged".
	ResidentKey string
	// UserVerification preference: "required", "preferred", or "discouraged".
	UserVerification string
}

// Plugin implements WebAuthn/Passkey authentication for go-better-auth.
type Plugin struct {
	opts     *Options
	auth     *betterauth.Auth
	webauthn *webauthn.WebAuthn
}

// New creates a new Passkey plugin with the given options.
func New(opts *Options) *Plugin {
	if opts == nil {
		opts = &Options{}
	}
	if opts.AttestationType == "" {
		opts.AttestationType = "none"
	}
	return &Plugin{opts: opts}
}

// ID returns the plugin identifier.
func (p *Plugin) ID() string { return "passkey" }

// SetAuth receives the auth instance from the framework.
func (p *Plugin) SetAuth(auth any) {
	p.auth = auth.(*betterauth.Auth)
	p.initWebAuthn()
}

// initWebAuthn creates the WebAuthn instance from plugin options.
func (p *Plugin) initWebAuthn() {
	cfg := &webauthn.Config{
		RPDisplayName: p.opts.RPDisplayName,
		RPID:          p.opts.RPID,
		RPOrigins:     p.opts.RPOrigins,
	}

	if p.opts.AttestationType != "" {
		cfg.AttestationPreference = protocol.ConveyancePreference(p.opts.AttestationType)
	}

	if sel := p.opts.AuthenticatorSelection; sel != nil {
		authSel := protocol.AuthenticatorSelection{}
		if sel.AuthenticatorAttachment != "" {
			authSel.AuthenticatorAttachment = protocol.AuthenticatorAttachment(sel.AuthenticatorAttachment)
		}
		if sel.RequireResidentKey {
			rk := true
			authSel.RequireResidentKey = &rk
		}
		if sel.ResidentKey != "" {
			authSel.ResidentKey = protocol.ResidentKeyRequirement(sel.ResidentKey)
		}
		if sel.UserVerification != "" {
			authSel.UserVerification = protocol.UserVerificationRequirement(sel.UserVerification)
		}
		cfg.AuthenticatorSelection = authSel
	}

	wa, err := webauthn.New(cfg)
	if err != nil {
		// If config is invalid, store nil; endpoints will return errors.
		p.webauthn = nil
		return
	}
	p.webauthn = wa
}

// Schema registers the passkey table.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		modelPasskey: {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "user_id", Type: "text", Required: true, Ref: "user.id"},
				{Name: "credential_id", Type: "text", Required: true, Unique: true},
				{Name: "public_key", Type: "text", Required: true},
				{Name: "counter", Type: "integer", Required: true},
				{Name: "device_type", Type: "text"},
				{Name: "backed_up", Type: "boolean"},
				{Name: "transports", Type: "text"},
				{Name: "name", Type: "text"},
				{Name: "created_at", Type: "timestamp", Required: true},
			},
		},
	}
}

// Endpoints returns the passkey HTTP endpoints.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/passkey/register/begin", Handler: p.withMethod(http.MethodPost, p.handleRegisterBegin)},
		{Method: http.MethodPost, Path: "/passkey/register/finish", Handler: p.withMethod(http.MethodPost, p.handleRegisterFinish)},
		{Method: http.MethodPost, Path: "/passkey/login/begin", Handler: p.withMethod(http.MethodPost, p.handleLoginBegin)},
		{Method: http.MethodPost, Path: "/passkey/login/finish", Handler: p.withMethod(http.MethodPost, p.handleLoginFinish)},
		{Method: http.MethodGet, Path: "/passkey/list", Handler: p.withMethod(http.MethodGet, p.handleList)},
		{Method: http.MethodDelete, Path: "/passkey/", Handler: p.handleDeletePasskey},
	}
}

// --- WebAuthnUser adapter ---

// WebAuthnUser wraps a models.User to implement the webauthn.User interface.
type WebAuthnUser struct {
	User        *models.User
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user's opaque ID as bytes.
func (u *WebAuthnUser) WebAuthnID() []byte {
	if u.User == nil {
		return nil
	}
	return []byte(u.User.ID)
}

// WebAuthnName returns the user's login name (email).
func (u *WebAuthnUser) WebAuthnName() string {
	if u.User == nil {
		return ""
	}
	return u.User.Email
}

// WebAuthnDisplayName returns the user's display name.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.User == nil {
		return ""
	}
	return u.User.Name
}

// WebAuthnCredentials returns the user's registered credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// --- Repository helpers ---

func (p *Plugin) findPasskeysByUserID(ctx context.Context, userID string) ([]map[string]any, error) {
	return p.auth.InternalAdapter().Adapter().FindMany(ctx, modelPasskey, adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

func (p *Plugin) findPasskeyByCredentialID(ctx context.Context, credentialID string) (map[string]any, error) {
	return p.auth.InternalAdapter().Adapter().FindOne(ctx, modelPasskey, adapter.Query{
		Where: []adapter.Where{adapter.EQ("credential_id", credentialID)},
	})
}

func (p *Plugin) createPasskey(ctx context.Context, data map[string]any) error {
	_, err := p.auth.InternalAdapter().Adapter().Create(ctx, modelPasskey, data)
	return err
}

func (p *Plugin) deletePasskey(ctx context.Context, id, userID string) error {
	return p.auth.InternalAdapter().Adapter().Delete(ctx, modelPasskey, adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", id),
			adapter.EQ("user_id", userID),
		},
	})
}

func (p *Plugin) updatePasskeyCounter(ctx context.Context, id string, counter uint32) error {
	_, err := p.auth.InternalAdapter().Adapter().Update(ctx, modelPasskey, adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	}, map[string]any{"counter": int(counter)})
	return err
}

// recordsToCredentials converts DB passkey records to webauthn.Credential slice.
func recordsToCredentials(records []map[string]any) []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(records))
	for _, rec := range records {
		cred := recordToCredential(rec)
		if cred != nil {
			creds = append(creds, *cred)
		}
	}
	return creds
}

func recordToCredential(rec map[string]any) *webauthn.Credential {
	credIDStr, _ := rec["credential_id"].(string)
	pubKeyStr, _ := rec["public_key"].(string)

	credID, err := base64.RawURLEncoding.DecodeString(credIDStr)
	if err != nil {
		return nil
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil
	}

	counter := uint32(0)
	if v, ok := rec["counter"].(int); ok {
		counter = uint32(v)
	}

	cred := &webauthn.Credential{
		ID:              credID,
		PublicKey:       pubKey,
		AttestationType: "",
		Authenticator: webauthn.Authenticator{
			SignCount: counter,
		},
	}

	// Parse transports if available.
	if transportsJSON, ok := rec["transports"].(string); ok && transportsJSON != "" {
		var transports []string
		if json.Unmarshal([]byte(transportsJSON), &transports) == nil {
			for _, t := range transports {
				cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
			}
		}
	}

	if bu, ok := rec["backed_up"].(bool); ok {
		cred.Flags.BackupState = bu
	}
	if dt, ok := rec["device_type"].(string); ok {
		cred.Flags.BackupEligible = dt == "multi_device"
	}

	return cred
}

// --- Session/Challenge storage ---

func (p *Plugin) storeChallenge(ctx context.Context, identifier string, sessionData *webauthn.SessionData) error {
	data, err := json.Marshal(sessionData)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = p.auth.InternalAdapter().Adapter().Create(ctx, "verification", map[string]any{
		"id":         internal.NewID(),
		"identifier": identifier,
		"value":      string(data),
		"expires_at": now.Add(challengeExpiry),
		"created_at": now,
		"updated_at": now,
	})
	return err
}

func (p *Plugin) loadChallenge(ctx context.Context, identifier string) (*webauthn.SessionData, error) {
	rec, err := p.auth.InternalAdapter().Adapter().FindOne(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("identifier", identifier)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}

	// Check expiry.
	if exp, ok := rec["expires_at"].(time.Time); ok && time.Now().UTC().After(exp) {
		p.deleteChallenge(ctx, identifier)
		return nil, nil
	}

	value, _ := rec["value"].(string)
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(value), &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

func (p *Plugin) deleteChallenge(ctx context.Context, identifier string) {
	_ = p.auth.InternalAdapter().Adapter().Delete(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("identifier", identifier)},
	})
}

// --- Auth helpers ---

func (p *Plugin) getAuthenticatedUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := session.GetSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	ctx := r.Context()
	sess, err := p.auth.SessionManager().FindByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	return sess.UserID, true
}

func (p *Plugin) getWebAuthnUser(ctx context.Context, userID string) (*WebAuthnUser, error) {
	user, err := p.auth.InternalAdapter().FindUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	records, err := p.findPasskeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &WebAuthnUser{
		User:        user,
		Credentials: recordsToCredentials(records),
	}, nil
}

// --- HTTP helpers ---

func (p *Plugin) withMethod(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// extractPasskeyID extracts the passkey ID from DELETE /passkey/{id} paths.
func extractPasskeyID(path string) string {
	// Path could be /api/auth/passkey/{id} or /passkey/{id}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return false
	}
	return true
}
