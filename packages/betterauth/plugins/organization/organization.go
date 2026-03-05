// Package organization implements the organization plugin for go-better-auth.
// It provides multi-tenant organization management with members, invitations,
// role-based access control, and session-scoped active organization context.
package organization

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/jeromesth/go-better-auth/packages/betterauth"
	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter"
	"github.com/jeromesth/go-better-auth/packages/betterauth/internal"
	"github.com/jeromesth/go-better-auth/packages/betterauth/plugin"
	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

// Options configures the organization plugin.
type Options struct {
	// AllowUserToCreateOrganization controls whether users can create orgs.
	// Default: true (all users can create).
	AllowUserToCreateOrganization *bool
	// OrganizationLimit limits orgs per user. 0 = unlimited.
	OrganizationLimit int
	// CreatorRole is the role assigned to the org creator. Default: "owner".
	CreatorRole string
	// MembershipLimit limits members per org. 0 = unlimited.
	MembershipLimit int
	// InvitationExpiresIn is seconds until an invitation expires. Default: 172800 (48h).
	InvitationExpiresIn int
	// InvitationLimit limits pending invitations per org. 0 = unlimited.
	InvitationLimit int
	// CancelPendingInvitationsOnReInvite cancels old invitations when re-inviting.
	CancelPendingInvitationsOnReInvite bool
	// Roles defines the permission system. If nil, DefaultRoles is used.
	Roles map[string]*Role
	// SendInvitationEmail is called when an invitation is created.
	SendInvitationEmail func(data InvitationEmailData) error
}

// InvitationEmailData is passed to the SendInvitationEmail callback.
type InvitationEmailData struct {
	Email            string
	InviterName      string
	OrganizationName string
	InvitationID     string
}

// Organization represents an organization record.
type Organization struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	Logo      *string        `json:"logo,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
}

// Member represents a member record in an organization.
type Member struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	OrganizationID string    `json:"organizationId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Invitation represents an invitation record.
type Invitation struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	InviterID        string    `json:"inviterId"`
	OrganizationID   string    `json:"organizationId"`
	OrganizationName string    `json:"organizationName,omitempty"`
	OrganizationSlug string    `json:"organizationSlug,omitempty"`
	Role             string    `json:"role"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expiresAt"`
	CreatedAt        time.Time `json:"createdAt"`
}

// FullOrganization is returned by getFullOrganization.
type FullOrganization struct {
	Organization
	Members     []*Member     `json:"members"`
	Invitations []*Invitation `json:"invitations,omitempty"`
}

// Plugin implements the organization plugin for go-better-auth.
type Plugin struct {
	opts *Options
	auth *betterauth.Auth
}

// New creates a new organization plugin with the given options.
func New(opts *Options) *Plugin {
	if opts == nil {
		opts = &Options{}
	}
	if opts.CreatorRole == "" {
		opts.CreatorRole = "owner"
	}
	if opts.InvitationExpiresIn == 0 {
		opts.InvitationExpiresIn = 172800 // 48 hours
	}
	if opts.Roles == nil {
		opts.Roles = DefaultRoles()
	}
	return &Plugin{opts: opts}
}

func (p *Plugin) ID() string { return "organization" }

func (p *Plugin) SetAuth(auth any) {
	p.auth = auth.(*betterauth.Auth)
}

// Schema returns the database schema extensions for the organization plugin.
func (p *Plugin) Schema() map[string]plugin.TableSchema {
	return map[string]plugin.TableSchema{
		"organization": {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "name", Type: "text", Required: true},
				{Name: "slug", Type: "text", Required: true, Unique: true},
				{Name: "logo", Type: "text"},
				{Name: "metadata", Type: "text"},
				{Name: "created_at", Type: "timestamp", Required: true},
			},
		},
		"member": {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "user_id", Type: "text", Required: true, Ref: "user.id"},
				{Name: "organization_id", Type: "text", Required: true, Ref: "organization.id"},
				{Name: "role", Type: "text", Required: true},
				{Name: "created_at", Type: "timestamp", Required: true},
			},
		},
		"invitation": {
			Fields: []plugin.FieldDef{
				{Name: "id", Type: "text", Required: true},
				{Name: "email", Type: "text", Required: true},
				{Name: "inviter_id", Type: "text", Required: true, Ref: "user.id"},
				{Name: "organization_id", Type: "text", Required: true, Ref: "organization.id"},
				{Name: "role", Type: "text", Required: true},
				{Name: "status", Type: "text", Required: true},
				{Name: "expires_at", Type: "timestamp", Required: true},
				{Name: "created_at", Type: "timestamp", Required: true},
			},
		},
		"session": {
			Fields: []plugin.FieldDef{
				{Name: "active_organization_id", Type: "text"},
			},
		},
	}
}

// Endpoints returns all organization API endpoints.
func (p *Plugin) Endpoints() []plugin.Endpoint {
	return []plugin.Endpoint{
		{Method: http.MethodPost, Path: "/organization/create", Handler: p.withMethod(http.MethodPost, p.handleCreateOrganization)},
		{Method: http.MethodPost, Path: "/organization/update", Handler: p.withMethod(http.MethodPost, p.handleUpdateOrganization)},
		{Method: http.MethodPost, Path: "/organization/delete", Handler: p.withMethod(http.MethodPost, p.handleDeleteOrganization)},
		{Method: http.MethodGet, Path: "/organization/check-slug", Handler: p.withMethod(http.MethodGet, p.handleCheckSlug)},
		{Method: http.MethodGet, Path: "/organization/list", Handler: p.withMethod(http.MethodGet, p.handleListOrganizations)},
		{Method: http.MethodPost, Path: "/organization/set-active", Handler: p.withMethod(http.MethodPost, p.handleSetActiveOrganization)},
		{Method: http.MethodGet, Path: "/organization/get-full-organization", Handler: p.withMethod(http.MethodGet, p.handleGetFullOrganization)},
		{Method: http.MethodPost, Path: "/organization/invite-member", Handler: p.withMethod(http.MethodPost, p.handleInviteMember)},
		{Method: http.MethodPost, Path: "/organization/accept-invitation", Handler: p.withMethod(http.MethodPost, p.handleAcceptInvitation)},
		{Method: http.MethodPost, Path: "/organization/reject-invitation", Handler: p.withMethod(http.MethodPost, p.handleRejectInvitation)},
		{Method: http.MethodPost, Path: "/organization/cancel-invitation", Handler: p.withMethod(http.MethodPost, p.handleCancelInvitation)},
		{Method: http.MethodGet, Path: "/organization/get-invitation", Handler: p.withMethod(http.MethodGet, p.handleGetInvitation)},
		{Method: http.MethodGet, Path: "/organization/list-invitations", Handler: p.withMethod(http.MethodGet, p.handleListInvitations)},
		{Method: http.MethodGet, Path: "/organization/list-user-invitations", Handler: p.withMethod(http.MethodGet, p.handleListUserInvitations)},
		{Method: http.MethodPost, Path: "/organization/remove-member", Handler: p.withMethod(http.MethodPost, p.handleRemoveMember)},
		{Method: http.MethodPost, Path: "/organization/update-member-role", Handler: p.withMethod(http.MethodPost, p.handleUpdateMemberRole)},
		{Method: http.MethodGet, Path: "/organization/get-active-member", Handler: p.withMethod(http.MethodGet, p.handleGetActiveMember)},
		{Method: http.MethodPost, Path: "/organization/leave", Handler: p.withMethod(http.MethodPost, p.handleLeaveOrganization)},
		{Method: http.MethodPost, Path: "/organization/has-permission", Handler: p.withMethod(http.MethodPost, p.handleHasPermission)},
		{Method: http.MethodGet, Path: "/organization/list-members", Handler: p.withMethod(http.MethodGet, p.handleListMembers)},
		{Method: http.MethodPost, Path: "/organization/add-member", Handler: p.withMethod(http.MethodPost, p.handleAddMember)},
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

// getAuthenticatedUser validates the session and returns the user ID and session data.
func (p *Plugin) getAuthenticatedUser(w http.ResponseWriter, r *http.Request) (userID string, sessRaw map[string]any, ok bool) {
	token := session.GetSessionToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", nil, false
	}

	ctx := r.Context()
	sess, err := p.auth.SessionManager().FindByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return "", nil, false
	}

	// Get raw session for active_organization_id.
	rawSess, _ := p.auth.InternalAdapter().Adapter().FindOne(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", token)},
	})

	return sess.UserID, rawSess, true
}

// findMemberByUserAndOrg returns the member record for a user in an org.
func (p *Plugin) findMemberByUserAndOrg(ctx context.Context, userID, orgID string) (map[string]any, error) {
	return p.auth.InternalAdapter().Adapter().FindOne(ctx, "member", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("user_id", userID),
			adapter.EQ("organization_id", orgID),
		},
	})
}

// getActiveOrgID extracts the active organization ID from a raw session.
func getActiveOrgID(sessRaw map[string]any) string {
	if sessRaw == nil {
		return ""
	}
	id, _ := sessRaw["active_organization_id"].(string)
	return id
}

// setActiveOrgOnSession updates the active_organization_id on the session.
func (p *Plugin) setActiveOrgOnSession(ctx context.Context, sessionToken, orgID string) error {
	_, err := p.auth.InternalAdapter().Adapter().Update(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", sessionToken)},
	}, map[string]any{
		"active_organization_id": orgID,
		"updated_at":             time.Now().UTC(),
	})
	return err
}

// countUserOrganizations returns the number of organizations a user belongs to.
func (p *Plugin) countUserOrganizations(ctx context.Context, userID string) (int64, error) {
	return p.auth.InternalAdapter().Adapter().Count(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

// countOrgMembers returns the number of members in an organization.
func (p *Plugin) countOrgMembers(ctx context.Context, orgID string) (int64, error) {
	return p.auth.InternalAdapter().Adapter().Count(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
}

// countPendingInvitations returns the number of pending invitations for an org.
func (p *Plugin) countPendingInvitations(ctx context.Context, orgID string) (int64, error) {
	return p.auth.InternalAdapter().Adapter().Count(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("organization_id", orgID),
			adapter.EQ("status", "pending"),
		},
	})
}

// isLastOwner checks if a member is the last owner of an organization.
func (p *Plugin) isLastOwner(ctx context.Context, orgID, memberRole string) bool {
	roles := splitRoles(memberRole)
	isOwner := false
	for _, r := range roles {
		if r == "owner" {
			isOwner = true
			break
		}
	}
	if !isOwner {
		return false
	}

	// Count owners.
	members, err := p.auth.InternalAdapter().Adapter().FindMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
	if err != nil {
		return true // assume last owner on error
	}

	ownerCount := 0
	for _, m := range members {
		role, _ := m["role"].(string)
		for _, r := range splitRoles(role) {
			if r == "owner" {
				ownerCount++
				break
			}
		}
	}
	return ownerCount <= 1
}

// --- Record converters ---

func recordToOrganization(r map[string]any) *Organization {
	o := &Organization{}
	o.ID, _ = r["id"].(string)
	o.Name, _ = r["name"].(string)
	o.Slug, _ = r["slug"].(string)
	if v, ok := r["logo"].(string); ok && v != "" {
		o.Logo = &v
	}
	if v, ok := r["metadata"].(string); ok && v != "" {
		var meta map[string]any
		if json.Unmarshal([]byte(v), &meta) == nil {
			o.Metadata = meta
		}
	}
	if v, ok := r["metadata"].(map[string]any); ok {
		o.Metadata = v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		o.CreatedAt = v
	}
	return o
}

func recordToMember(r map[string]any) *Member {
	m := &Member{}
	m.ID, _ = r["id"].(string)
	m.UserID, _ = r["user_id"].(string)
	m.OrganizationID, _ = r["organization_id"].(string)
	m.Role, _ = r["role"].(string)
	if v, ok := r["created_at"].(time.Time); ok {
		m.CreatedAt = v
	}
	return m
}

func recordToInvitation(r map[string]any) *Invitation {
	inv := &Invitation{}
	inv.ID, _ = r["id"].(string)
	inv.Email, _ = r["email"].(string)
	inv.InviterID, _ = r["inviter_id"].(string)
	inv.OrganizationID, _ = r["organization_id"].(string)
	inv.Role, _ = r["role"].(string)
	inv.Status, _ = r["status"].(string)
	if v, ok := r["expires_at"].(time.Time); ok {
		inv.ExpiresAt = v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		inv.CreatedAt = v
	}
	return inv
}

// --- JSON helpers ---

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
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
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

func splitRoles(s string) []string {
	if s == "" {
		return nil
	}
	var roles []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			r := s[start:i]
			if r != "" {
				roles = append(roles, r)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		roles = append(roles, s[start:])
	}
	return roles
}

func containsRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}
	return false
}

// rolesExist reports whether all roles in the comma-separated value exist in plugin options.
func (p *Plugin) rolesExist(roleStr string) bool {
	roles := splitRoles(roleStr)
	if len(roles) == 0 {
		return false
	}
	for _, role := range roles {
		if _, ok := p.opts.Roles[role]; !ok {
			return false
		}
	}
	return true
}

// getUserEmail returns a user's email by ID.
func (p *Plugin) getUserEmail(ctx context.Context, userID string) (string, error) {
	userRec, err := p.auth.InternalAdapter().FindUserByIDRaw(ctx, userID)
	if err != nil || userRec == nil {
		return "", err
	}
	email, _ := userRec["email"].(string)
	return strings.ToLower(strings.TrimSpace(email)), nil
}

func removeRole(roleStr, target string) string {
	roles := splitRoles(roleStr)
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		if role == target {
			continue
		}
		out = append(out, role)
	}
	return strings.Join(out, ",")
}

func (p *Plugin) defaultRoleAfterOwnerTransfer() string {
	if _, ok := p.opts.Roles["admin"]; ok {
		return "admin"
	}
	if _, ok := p.opts.Roles["member"]; ok {
		return "member"
	}
	for role := range p.opts.Roles {
		if role != "owner" {
			return role
		}
	}
	return "member"
}

// generateID generates a unique ID.
func generateID() string {
	return internal.NewID()
}

// metadataToString serializes metadata to a JSON string for storage.
func metadataToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
