// Package multisession implements a multi-session management plugin for go-better-auth.
// It provides device info parsing, concurrent session limits, and session listing/revocation
// with device metadata.
package multisession

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the multi-session plugin.
type Options struct {
	// MaxSessions is the maximum number of concurrent sessions per user. 0 = unlimited.
	MaxSessions int
	// OnMaxReached defines behavior when max sessions is reached.
	// "revoke-oldest" (default) or "deny-new".
	OnMaxReached string
}

// SessionInfo represents a session with device metadata for the list endpoint.
type SessionInfo struct {
	ID         string    `json:"id"`
	DeviceName string    `json:"deviceName,omitempty"`
	DeviceType string    `json:"deviceType,omitempty"`
	OS         string    `json:"os,omitempty"`
	Browser    string    `json:"browser,omitempty"`
	IPAddress  string    `json:"ipAddress,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	IsCurrent  bool      `json:"isCurrent"`
}

// Plugin implements the multi-session plugin for go-better-auth.
type Plugin struct {
	opts *Options
	auth *betterauth.Auth
}

// New creates a new multi-session plugin with the given options.
func New(opts *Options) *Plugin {
	if opts == nil {
		opts = &Options{}
	}
	if opts.OnMaxReached == "" {
		opts.OnMaxReached = "revoke-oldest"
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "multi-session" }

func (p *Plugin) SetAuth(auth *betterauth.Auth) {
	p.auth = auth
}

// Schema returns the database schema extensions for the multi-session plugin.
// Device info (device_name, device_type, os, browser) is parsed at read time
// from the user_agent field rather than stored in dedicated columns.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{}
}

// Endpoints returns all multi-session API endpoints.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodGet, Path: "/multi-session/list", Handler: p.withMethod(http.MethodGet, p.handleList)},
		{Method: http.MethodPost, Path: "/multi-session/revoke", Handler: p.withMethod(http.MethodPost, p.handleRevoke)},
		{Method: http.MethodPost, Path: "/multi-session/revoke-all-others", Handler: p.withMethod(http.MethodPost, p.handleRevokeAllOthers)},
	}
}

// SessionCreateHooks returns hooks that enforce max sessions and store device info.
func (p *Plugin) SessionCreateHooks() []plugin.SessionCreateHookFn {
	return []plugin.SessionCreateHookFn{p.onSessionCreate}
}

func (p *Plugin) onSessionCreate(scc plugin.SessionCreateContext) error {
	if p.auth == nil {
		return nil
	}
	if p.opts.MaxSessions <= 0 {
		return nil
	}

	ctx := context.Background()
	if scc.Request != nil {
		ctx = scc.Request.Context()
	}

	adp := p.auth.InternalAdapter().Adapter()
	sessions, err := adp.FindMany(ctx, "session", adapter.Query{
		Where:   []adapter.Where{adapter.EQ("user_id", scc.UserID)},
		SortBy:  "created_at",
		SortDir: "asc",
	})
	if err != nil {
		return fmt.Errorf("checking session count: %w", err)
	}

	// Filter to only non-expired sessions.
	now := time.Now().UTC()
	var active []map[string]any
	for _, s := range sessions {
		if exp, ok := s["expires_at"].(time.Time); ok && exp.After(now) {
			active = append(active, s)
		}
	}

	if len(active) < p.opts.MaxSessions {
		return nil
	}

	switch p.opts.OnMaxReached {
	case "deny-new":
		return fmt.Errorf("maximum number of sessions (%d) reached", p.opts.MaxSessions)
	default: // "revoke-oldest"
		// Delete oldest sessions until we're one below the limit (to make room for the new one).
		toRemove := len(active) - p.opts.MaxSessions + 1
		for i := 0; i < toRemove && i < len(active); i++ {
			id, _ := active[i]["id"].(string)
			if id != "" {
				if err := adp.Delete(ctx, "session", adapter.Query{
					Where: []adapter.Where{adapter.EQ("id", id)},
				}); err != nil {
					return fmt.Errorf("revoking oldest session: %w", err)
				}
			}
		}
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

// handleList returns all active sessions for the current user with device info.
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request) {
	currentSession := p.requireSession(w, r)
	if currentSession == nil {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	records, err := adp.FindMany(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", currentSession["user_id"])},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions")
		return
	}

	currentToken, _ := currentSession["token"].(string)
	now := time.Now().UTC()
	var sessions []SessionInfo
	for _, rec := range records {
		// Skip expired sessions.
		if exp, ok := rec["expires_at"].(time.Time); ok && exp.Before(now) {
			continue
		}

		info := SessionInfo{}
		info.ID, _ = rec["id"].(string)
		if ip, ok := rec["ip_address"].(string); ok {
			info.IPAddress = ip
		}
		if ca, ok := rec["created_at"].(time.Time); ok {
			info.CreatedAt = ca
		}

		token, _ := rec["token"].(string)
		info.IsCurrent = token == currentToken

		// Use stored device info fields if available.
		info.DeviceName, _ = rec["device_name"].(string)
		info.DeviceType, _ = rec["device_type"].(string)
		info.OS, _ = rec["os"].(string)
		info.Browser, _ = rec["browser"].(string)

		// If device info fields are empty, parse from user_agent.
		if info.Browser == "" || info.OS == "" || info.DeviceType == "" {
			if ua, ok := rec["user_agent"].(string); ok && ua != "" {
				browser, os, deviceType := ParseUserAgent(ua)
				if info.Browser == "" {
					info.Browser = browser
				}
				if info.OS == "" {
					info.OS = os
				}
				if info.DeviceType == "" {
					info.DeviceType = deviceType
				}
			}
		}

		// Build device name from browser + OS if not stored.
		if info.DeviceName == "" && (info.Browser != "" || info.OS != "") {
			parts := []string{}
			if info.Browser != "" {
				parts = append(parts, info.Browser)
			}
			if info.OS != "" {
				parts = append(parts, "on "+info.OS)
			}
			info.DeviceName = strings.Join(parts, " ")
		}

		sessions = append(sessions, info)
	}

	if sessions == nil {
		sessions = []SessionInfo{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": sessions})
}

// handleRevoke revokes a specific session by ID.
func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request) {
	currentSession := p.requireSession(w, r)
	if currentSession == nil {
		return
	}

	var req struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_SESSION_ID", "sessionId is required")
		return
	}

	currentID, _ := currentSession["id"].(string)
	if req.SessionID == currentID {
		writeError(w, http.StatusBadRequest, "CANNOT_REVOKE_CURRENT", "Cannot revoke your current session")
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()
	currentUserID, _ := currentSession["user_id"].(string)

	// Scope lookup to the current user so a non-existent session and a session
	// owned by another user are indistinguishable.
	target, err := adp.FindOne(ctx, "session", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", req.SessionID),
			adapter.EQ("user_id", currentUserID),
		},
	})
	if err != nil || target == nil {
		writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found")
		return
	}

	if err := adp.Delete(ctx, "session", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", req.SessionID),
			adapter.EQ("user_id", currentUserID),
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke session")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleRevokeAllOthers revokes all sessions except the current one.
func (p *Plugin) handleRevokeAllOthers(w http.ResponseWriter, r *http.Request) {
	currentSession := p.requireSession(w, r)
	if currentSession == nil {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()
	currentUserID, _ := currentSession["user_id"].(string)
	currentToken, _ := currentSession["token"].(string)

	records, err := adp.FindMany(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", currentUserID)},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions")
		return
	}

	revoked := 0
	for _, rec := range records {
		token, _ := rec["token"].(string)
		if token == currentToken {
			continue
		}
		id, _ := rec["id"].(string)
		if id == "" {
			continue
		}
		if err := adp.Delete(ctx, "session", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", id)},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke session")
			return
		}
		revoked++
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "revoked": revoked})
}

// requireSession validates the session token and returns the raw session record.
// Returns nil and writes an error if unauthorized.
func (p *Plugin) requireSession(w http.ResponseWriter, r *http.Request) map[string]any {
	token := session.GetSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return nil
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	rec, err := adp.FindOne(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", token)},
	})
	if err != nil || rec == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return nil
	}

	// Check expiry.
	if exp, ok := rec["expires_at"].(time.Time); ok {
		if time.Now().UTC().After(exp) {
			writeError(w, http.StatusUnauthorized, "SESSION_EXPIRED", "Session has expired")
			return nil
		}
	}

	return rec
}

// ParseUserAgent extracts browser, OS, and device type from a User-Agent string.
// It uses simple substring matching and is not intended to be comprehensive.
func ParseUserAgent(ua string) (browser, os, deviceType string) {
	// Device type detection.
	switch {
	case strings.Contains(ua, "iPad"):
		deviceType = "tablet"
	case strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile"):
		deviceType = "tablet"
	case strings.Contains(ua, "Mobile") || strings.Contains(ua, "iPhone"):
		deviceType = "mobile"
	default:
		deviceType = "desktop"
	}

	// Browser detection (order matters: more specific first).
	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "Edge/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		browser = "Safari"
	default:
		browser = "Unknown"
	}

	// OS detection (order matters: check iOS before macOS since iOS UAs contain "Mac OS X").
	switch {
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	default:
		os = "Unknown"
	}

	return browser, os, deviceType
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}
