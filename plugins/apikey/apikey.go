// Package apikey provides API key authentication for go-better-auth.
// Keys are stored as SHA-256 hashes; the plaintext is only returned at creation.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the API key plugin.
type Options struct {
	// Prefix is prepended to every generated key, e.g. "ak_". Default: "ak_".
	Prefix string
	// KeyLength is the number of random bytes before hex-encoding. Default: 32.
	KeyLength int
	// DefaultTTL is the key lifetime. Zero means no expiry.
	DefaultTTL time.Duration
}

// Plugin implements API key authentication for go-better-auth.
type Plugin struct {
	opts Options
	auth *betterauth.Auth
	repo *repository
}

// New creates an API key plugin with the given options.
func New(opts Options) *Plugin {
	if opts.Prefix == "" {
		opts.Prefix = "ak_"
	}
	if opts.KeyLength == 0 {
		opts.KeyLength = 32
	}
	return &Plugin{opts: opts}
}

// ID returns the unique identifier for this plugin.
func (p *Plugin) ID() string { return "apikey" }

// SetAuth injects the Auth instance so the plugin can access session and storage.
func (p *Plugin) SetAuth(auth any) {
	a, ok := auth.(*betterauth.Auth)
	if !ok {
		return
	}
	p.auth = a
	p.repo = newRepository(p.auth)
}

// Schema registers the apiKey table.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"apiKey": {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "user_id", Type: "text", Required: true, Ref: "user.id"},
				{Name: "key_hash", Type: "text", Required: true, Unique: true},
				{Name: "name", Type: "text", Required: true},
				{Name: "prefix", Type: "text", Required: true},
				{Name: "expires_at", Type: "timestamp"},
				{Name: "last_used_at", Type: "timestamp"},
				{Name: "created_at", Type: "timestamp", Required: true},
				{Name: "updated_at", Type: "timestamp", Required: true},
			},
		},
	}
}

// Endpoints registers all API key routes.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/api-key/create", Handler: p.withMethod(http.MethodPost, p.handleCreate)},
		{Method: http.MethodGet, Path: "/api-key/list", Handler: p.withMethod(http.MethodGet, p.handleList)},
		{Method: http.MethodDelete, Path: "/api-key/{id}", Handler: p.withMethod(http.MethodDelete, p.handleDelete)},
		{Method: http.MethodPost, Path: "/api-key/verify", Handler: p.withMethod(http.MethodPost, p.handleVerify)},
	}
}

// handleCreate generates a new API key for the authenticated user.
func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.requireSession(w, r)
	if !ok {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		_ = httputil.DecodeJSON(r, &req)
	}
	if req.Name == "" {
		req.Name = "API Key"
	}

	rawKey, err := generateKey(p.opts.KeyLength)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate key")
		return
	}
	fullKey := p.opts.Prefix + rawKey
	keyHash := hashKey(fullKey)

	var expiresAt *time.Time
	if p.opts.DefaultTTL > 0 {
		t := time.Now().UTC().Add(p.opts.DefaultTTL)
		expiresAt = &t
	}

	rec, err := p.repo.create(r.Context(), userID, req.Name, p.opts.Prefix, keyHash, expiresAt)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store key")
		return
	}

	// Return the full plaintext key — only time it's visible.
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"id":         rec["id"],
		"name":       rec["name"],
		"prefix":     rec["prefix"],
		"key":        fullKey,
		"expires_at": rec["expires_at"],
		"created_at": rec["created_at"],
	})
}

// handleList returns all API keys for the authenticated user (no plaintext).
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.requireSession(w, r)
	if !ok {
		return
	}

	recs, err := p.repo.listByUser(r.Context(), userID)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list keys")
		return
	}

	keys := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		keys = append(keys, sanitize(rec))
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// handleDelete revokes a key by ID.
func (p *Plugin) handleDelete(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.requireSession(w, r)
	if !ok {
		return
	}

	// Extract ID from path: /api-key/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api-key/")
	// Strip any base path prefix that the router might have left
	if idx := strings.LastIndex(id, "/"); idx >= 0 {
		id = id[idx+1:]
	}
	// Also handle the full path pattern
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) > 0 {
		id = parts[len(parts)-1]
	}

	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "MISSING_ID", "Key ID is required")
		return
	}

	if err := p.repo.deleteByID(r.Context(), id, userID); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke key")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleVerify validates an API key from the Authorization header.
func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		httputil.WriteError(w, http.StatusUnauthorized, "MISSING_KEY", "Authorization: Bearer <key> required")
		return
	}
	fullKey := strings.TrimPrefix(authHeader, "Bearer ")

	keyHash := hashKey(fullKey)
	rec, err := p.repo.findByHash(r.Context(), keyHash)
	if err != nil || rec == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "INVALID_KEY", "Invalid API key")
		return
	}

	// Check expiry if set.
	if exp, ok := rec["expires_at"].(time.Time); ok && time.Now().UTC().After(exp) {
		httputil.WriteError(w, http.StatusUnauthorized, "KEY_EXPIRED", "API key has expired")
		return
	}

	// Detach from the request context so this survives response completion.
	go p.repo.touchLastUsed(context.WithoutCancel(r.Context()), rec["id"].(string))

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"valid":   true,
		"user_id": rec["user_id"],
		"name":    rec["name"],
	})
}

// --- helpers ---

func (p *Plugin) requireSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := session.GetSessionToken(r)
	if token == "" {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	sess, err := p.auth.SessionManager().FindByToken(r.Context(), token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		httputil.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", false
	}
	return sess.UserID, true
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

func generateKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// sanitize strips sensitive fields before returning to the client.
func sanitize(rec map[string]any) map[string]any {
	out := make(map[string]any, len(rec))
	for k, v := range rec {
		out[k] = v
	}
	delete(out, "key_hash")
	delete(out, "key")
	return out
}
