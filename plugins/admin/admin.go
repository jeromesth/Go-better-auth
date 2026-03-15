// Package admin implements the admin plugin for go-better-auth.
// It provides user management, role-based access control, banning,
// impersonation, and session management for admin users.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

// Options configures the admin plugin.
type Options struct {
	// DefaultRole is the default role assigned to new users. Default: "user".
	DefaultRole string
	// AdminRoles lists which roles are considered admin roles. Default: ["admin"].
	AdminRoles []string
	// DefaultBanReason is used when no ban reason is provided. Default: "No reason".
	DefaultBanReason string
	// DefaultBanExpiresIn is the default ban duration in seconds. 0 = permanent.
	DefaultBanExpiresIn int
	// ImpersonationSessionDuration is the impersonation session duration in seconds. Default: 3600.
	ImpersonationSessionDuration int
	// Roles maps role names to their permission sets.
	Roles map[string]*Role
	// AdminUserIds is a list of user IDs that always have admin access.
	AdminUserIds []string
	// BannedUserMessage is the error message for banned users.
	BannedUserMessage string
	// AllowImpersonatingAdmins allows impersonating other admins.
	AllowImpersonatingAdmins bool
}

// UserWithRole extends the base user with admin-specific fields.
type UserWithRole struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	EmailVerified bool       `json:"emailVerified"`
	Image         *string    `json:"image,omitempty"`
	Role          string     `json:"role,omitempty"`
	Banned        bool       `json:"banned"`
	BanReason     *string    `json:"banReason,omitempty"`
	BanExpires    *time.Time `json:"banExpires,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// SessionWithImpersonation extends the base session with impersonation info.
type SessionWithImpersonation struct {
	ID             string    `json:"id"`
	Token          string    `json:"token"`
	UserID         string    `json:"userId"`
	ExpiresAt      time.Time `json:"expiresAt"`
	IPAddress      *string   `json:"ipAddress,omitempty"`
	UserAgent      *string   `json:"userAgent,omitempty"`
	ImpersonatedBy *string   `json:"impersonatedBy,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Plugin implements the admin plugin for go-better-auth.
type Plugin struct {
	opts *Options
	auth *betterauth.Auth
	repo *repository
}

// New creates a new admin plugin with the given options.
func New(opts *Options) *Plugin {
	if opts == nil {
		opts = &Options{}
	}
	if opts.DefaultRole == "" {
		opts.DefaultRole = "user"
	}
	if len(opts.AdminRoles) == 0 {
		opts.AdminRoles = []string{"admin"}
	}
	if opts.BannedUserMessage == "" {
		opts.BannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."
	}
	if opts.ImpersonationSessionDuration == 0 {
		opts.ImpersonationSessionDuration = 3600 // 1 hour
	}
	if opts.DefaultBanReason == "" {
		opts.DefaultBanReason = "No reason"
	}
	if opts.Roles == nil {
		opts.Roles = DefaultRoles
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "admin" }

func (p *Plugin) SetAuth(auth *betterauth.Auth) {
	p.auth = auth
	p.repo = newRepository(p.auth)
}

// Schema returns the database schema extensions for the admin plugin.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"user": {
			Fields: []plugin.FieldDef{
				{Name: "role", Type: "text"},
				{Name: "banned", Type: "boolean"},
				{Name: "ban_reason", Type: "text"},
				{Name: "ban_expires", Type: "timestamp"},
			},
		},
		"session": {
			Fields: []plugin.FieldDef{
				{Name: "impersonated_by", Type: "text"},
			},
		},
	}
}

// SessionCreateHooks returns hooks that check ban status before session creation.
func (p *Plugin) SessionCreateHooks() []plugin.SessionCreateHookFn {
	return []plugin.SessionCreateHookFn{p.checkBanOnSessionCreate}
}

// UserCreateHooks returns hooks that set the default role on user creation.
func (p *Plugin) UserCreateHooks() []plugin.UserCreateHookFn {
	return []plugin.UserCreateHookFn{p.setDefaultRoleOnCreate}
}

func (p *Plugin) setDefaultRoleOnCreate(data map[string]any) map[string]any {
	if _, ok := data["role"]; !ok {
		data["role"] = p.opts.DefaultRole
	}
	return data
}

func (p *Plugin) checkBanOnSessionCreate(scc plugin.SessionCreateContext) error {
	if p.auth == nil {
		return nil
	}
	ctx := context.Background()
	if scc.Request != nil {
		ctx = scc.Request.Context()
	}

	rec, err := p.repo.FindUserByID(ctx, scc.UserID)
	if err != nil || rec == nil {
		return nil
	}

	banned, _ := rec["banned"].(bool)
	if !banned {
		return nil
	}

	// Check if ban has expired.
	if banExpires, ok := rec["ban_expires"].(time.Time); ok && !banExpires.IsZero() {
		if time.Now().UTC().After(banExpires) {
			// Ban expired, unban the user.
			_, _ = p.repo.UpdateUser(ctx, scc.UserID, map[string]any{
				"banned":      false,
				"ban_reason":  nil,
				"ban_expires": nil,
			})
			return nil
		}
	}

	return fmt.Errorf("%s", p.opts.BannedUserMessage)
}

// Endpoints returns all admin API endpoints.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/admin/create-user", Handler: p.withMethod(http.MethodPost, p.handleCreateUser)},
		{Method: http.MethodGet, Path: "/admin/get-user", Handler: p.withMethod(http.MethodGet, p.handleGetUser)},
		{Method: http.MethodPost, Path: "/admin/update-user", Handler: p.withMethod(http.MethodPost, p.handleUpdateUser)},
		{Method: http.MethodGet, Path: "/admin/list-users", Handler: p.withMethod(http.MethodGet, p.handleListUsers)},
		{Method: http.MethodPost, Path: "/admin/set-role", Handler: p.withMethod(http.MethodPost, p.handleSetRole)},
		{Method: http.MethodPost, Path: "/admin/set-user-password", Handler: p.withMethod(http.MethodPost, p.handleSetUserPassword)},
		{Method: http.MethodPost, Path: "/admin/remove-user", Handler: p.withMethod(http.MethodPost, p.handleRemoveUser)},
		{Method: http.MethodPost, Path: "/admin/ban-user", Handler: p.withMethod(http.MethodPost, p.handleBanUser)},
		{Method: http.MethodPost, Path: "/admin/unban-user", Handler: p.withMethod(http.MethodPost, p.handleUnbanUser)},
		{Method: http.MethodPost, Path: "/admin/list-user-sessions", Handler: p.withMethod(http.MethodPost, p.handleListUserSessions)},
		{Method: http.MethodPost, Path: "/admin/revoke-user-session", Handler: p.withMethod(http.MethodPost, p.handleRevokeUserSession)},
		{Method: http.MethodPost, Path: "/admin/revoke-user-sessions", Handler: p.withMethod(http.MethodPost, p.handleRevokeUserSessions)},
		{Method: http.MethodPost, Path: "/admin/impersonate-user", Handler: p.withMethod(http.MethodPost, p.handleImpersonateUser)},
		{Method: http.MethodPost, Path: "/admin/stop-impersonating", Handler: p.withMethod(http.MethodPost, p.handleStopImpersonating)},
		{Method: http.MethodPost, Path: "/admin/has-permission", Handler: p.withMethod(http.MethodPost, p.handleHasPermission)},
	}
}

// --- Helper methods ---

func (p *Plugin) withMethod(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// getAdminSession validates the session and returns the user with role info.
// Returns nil and writes an error if unauthorized.
func (p *Plugin) getAdminSession(w http.ResponseWriter, r *http.Request) *UserWithRole {
	token := session.GetSessionToken(r)
	if token == "" {
		writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return nil
	}

	ctx := r.Context()
	sess, err := p.repo.FindSessionByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return nil
	}

	rec, err := p.repo.FindUserByID(ctx, sess.UserID)
	if err != nil || rec == nil {
		writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return nil
	}

	user := recordToUserWithRole(rec)

	// Check if user has admin privileges.
	isAdmin := p.isUserAdmin(user)
	if !isAdmin {
		return user // Return user but caller must check permissions
	}

	return user
}

// isUserAdmin checks if a user has admin privileges.
func (p *Plugin) isUserAdmin(user *UserWithRole) bool {
	// Check adminUserIds.
	for _, id := range p.opts.AdminUserIds {
		if id == user.ID {
			return true
		}
	}

	// Check admin roles.
	userRoles := splitRoles(user.Role)
	for _, ur := range userRoles {
		for _, ar := range p.opts.AdminRoles {
			if strings.EqualFold(ur, ar) {
				return true
			}
		}
	}
	return false
}

func recordToUserWithRole(r map[string]any) *UserWithRole {
	u := &UserWithRole{}
	u.ID, _ = r["id"].(string)
	u.Email, _ = r["email"].(string)
	u.Name, _ = r["name"].(string)
	u.EmailVerified, _ = r["email_verified"].(bool)
	if v, ok := r["image"].(string); ok {
		u.Image = &v
	}
	u.Role, _ = r["role"].(string)
	u.Banned, _ = r["banned"].(bool)
	if v, ok := r["ban_reason"].(string); ok {
		u.BanReason = &v
	}
	if v, ok := r["ban_expires"].(time.Time); ok {
		u.BanExpires = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		u.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		u.UpdatedAt = v
	}
	return u
}

func recordToSessionWithImpersonation(r map[string]any) *SessionWithImpersonation {
	s := &SessionWithImpersonation{}
	s.ID, _ = r["id"].(string)
	s.Token, _ = r["token"].(string)
	s.UserID, _ = r["user_id"].(string)
	if v, ok := r["expires_at"].(time.Time); ok {
		s.ExpiresAt = v
	}
	if v, ok := r["ip_address"].(string); ok {
		s.IPAddress = &v
	}
	if v, ok := r["user_agent"].(string); ok {
		s.UserAgent = &v
	}
	if v, ok := r["impersonated_by"].(string); ok {
		s.ImpersonatedBy = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		s.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		s.UpdatedAt = v
	}
	return s
}

func writeAdminError(w http.ResponseWriter, status int, code, message string) {
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
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeAdminError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return false
	}
	return true
}

// parseRoles converts a role value (string or []string) to a comma-separated string.
func parseRoles(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []string:
		return strings.Join(val, ",")
	case []any:
		var roles []string
		for _, r := range val {
			if s, ok := r.(string); ok {
				roles = append(roles, s)
			}
		}
		return strings.Join(roles, ",")
	default:
		return fmt.Sprintf("%v", v)
	}
}
