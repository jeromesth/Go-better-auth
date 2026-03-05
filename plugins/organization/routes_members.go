package organization

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/session"
)

// --- POST /organization/remove-member ---

func (p *Plugin) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MemberID       string `json:"memberId,omitempty"`
		Email          string `json:"email,omitempty"`
		OrganizationID string `json:"organizationId,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := req.OrganizationID
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check caller's membership and permissions.
	callerMember, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || callerMember == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	callerRole, _ := callerMember["role"].(string)
	if !HasPermission(callerRole, map[string][]string{"member": {"delete"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToRemove.Status, ErrNotAllowedToRemove.Code, ErrNotAllowedToRemove.Message)
		return
	}

	// Find the target member.
	var targetMember map[string]any

	if req.MemberID != "" {
		targetMember, _ = adp.FindOne(ctx, "member", adapter.Query{
			Where: []adapter.Where{
				adapter.EQ("id", req.MemberID),
				adapter.EQ("organization_id", orgID),
			},
		})
	} else if req.Email != "" {
		email := strings.ToLower(strings.TrimSpace(req.Email))
		user, _ := p.auth.InternalAdapter().FindUserByEmail(ctx, email)
		if user != nil {
			targetMember, _ = p.findMemberByUserAndOrg(ctx, user.ID, orgID)
		}
	}

	if targetMember == nil {
		writeError(w, ErrMemberNotFound.Status, ErrMemberNotFound.Code, ErrMemberNotFound.Message)
		return
	}

	targetRole, _ := targetMember["role"].(string)

	// Check if this is the last owner.
	if p.isLastOwner(ctx, orgID, targetRole) {
		writeError(w, ErrCannotRemoveLastOwner.Status, ErrCannotRemoveLastOwner.Code, ErrCannotRemoveLastOwner.Message)
		return
	}

	// Non-owners cannot remove owners.
	if !CanManageRole(callerRole, targetRole) {
		writeError(w, ErrNotAllowedToRemove.Status, ErrNotAllowedToRemove.Code, ErrNotAllowedToRemove.Message)
		return
	}

	memberID, _ := targetMember["id"].(string)
	_ = adp.Delete(ctx, "member", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", memberID),
			adapter.EQ("organization_id", orgID),
		},
	})

	writeJSON(w, http.StatusOK, recordToMember(targetMember))
}

// --- POST /organization/update-member-role ---

func (p *Plugin) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MemberID       string `json:"memberId"`
		Role           any    `json:"role"`
		OrganizationID string `json:"organizationId,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := req.OrganizationID
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check caller's membership and permissions.
	callerMember, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || callerMember == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	callerRole, _ := callerMember["role"].(string)
	if !HasPermission(callerRole, map[string][]string{"member": {"update"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToUpdateRole.Status, ErrNotAllowedToUpdateRole.Code, ErrNotAllowedToUpdateRole.Message)
		return
	}

	// Find target member.
	targetMember, err := adp.FindOne(ctx, "member", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", req.MemberID),
			adapter.EQ("organization_id", orgID),
		},
	})
	if err != nil || targetMember == nil {
		writeError(w, ErrMemberNotFound.Status, ErrMemberNotFound.Code, ErrMemberNotFound.Message)
		return
	}

	newRole := parseRoles(req.Role)
	if !p.rolesExist(newRole) {
		writeError(w, ErrInvalidRoleType.Status, ErrInvalidRoleType.Code, ErrInvalidRoleType.Message)
		return
	}

	targetRole, _ := targetMember["role"].(string)
	callerMemberID, _ := callerMember["id"].(string)
	targetMemberID, _ := targetMember["id"].(string)
	callerIsOwner := containsRole(splitRoles(callerRole), "owner")
	targetIsOwner := containsRole(splitRoles(targetRole), "owner")
	newHasOwner := containsRole(splitRoles(newRole), "owner")

	// Non-owners cannot update owners (unless updating themselves).
	if callerMemberID != targetMemberID && !CanManageRole(callerRole, targetRole) {
		writeError(w, ErrNotAllowedToUpdateRole.Status, ErrNotAllowedToUpdateRole.Code, ErrNotAllowedToUpdateRole.Message)
		return
	}

	// Single-owner invariant:
	// - Only the current owner can transfer ownership.
	// - Owner role cannot be dropped from the current owner without transfer.
	if newHasOwner && !callerIsOwner {
		writeError(w, ErrNotAllowedToUpdateRole.Status, ErrNotAllowedToUpdateRole.Code, ErrNotAllowedToUpdateRole.Message)
		return
	}
	if targetIsOwner && !newHasOwner {
		writeError(w, ErrCannotRemoveLastOwner.Status, ErrCannotRemoveLastOwner.Code, ErrCannotRemoveLastOwner.Message)
		return
	}
	if callerMemberID == targetMemberID && callerIsOwner && !newHasOwner {
		writeError(w, ErrCannotRemoveLastOwner.Status, ErrCannotRemoveLastOwner.Code, ErrCannotRemoveLastOwner.Message)
		return
	}

	rec, err := adp.Update(ctx, "member", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", req.MemberID),
			adapter.EQ("organization_id", orgID),
		},
	}, map[string]any{"role": newRole})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update member role")
		return
	}

	if newHasOwner && callerMemberID != targetMemberID {
		// Transfer ownership by demoting the previous owner in the same operation.
		demotedRole := removeRole(callerRole, "owner")
		if demotedRole == "" {
			demotedRole = p.defaultRoleAfterOwnerTransfer()
		}
		_, err = adp.Update(ctx, "member", adapter.Query{
			Where: []adapter.Where{
				adapter.EQ("id", callerMemberID),
				adapter.EQ("organization_id", orgID),
			},
		}, map[string]any{"role": demotedRole})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to transfer ownership")
			return
		}
	}

	writeJSON(w, http.StatusOK, recordToMember(rec))
}

// --- GET /organization/get-active-member ---

func (p *Plugin) handleGetActiveMember(w http.ResponseWriter, r *http.Request) {
	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	orgID := getActiveOrgID(sessRaw)
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, "No active organization")
		return
	}

	ctx := r.Context()
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrMemberNotFound.Status, ErrMemberNotFound.Code, ErrMemberNotFound.Message)
		return
	}

	writeJSON(w, http.StatusOK, recordToMember(memberRec))
}

// --- POST /organization/leave ---

func (p *Plugin) handleLeaveOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := req.OrganizationID
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)

	// Check if this is the last owner.
	if p.isLastOwner(ctx, orgID, memberRole) {
		writeError(w, ErrCannotRemoveLastOwner.Status, ErrCannotRemoveLastOwner.Code, ErrCannotRemoveLastOwner.Message)
		return
	}

	memberID, _ := memberRec["id"].(string)
	_ = adp.Delete(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", memberID)},
	})

	// Clear active organization from session.
	token := session.GetSessionToken(r)
	_ = p.setActiveOrgOnSession(ctx, token, "")

	writeJSON(w, http.StatusOK, recordToMember(memberRec))
}

// --- POST /organization/has-permission ---

func (p *Plugin) handleHasPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string              `json:"organizationId,omitempty"`
		Permissions    map[string][]string `json:"permissions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	if req.Permissions == nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "permissions are required")
		return
	}

	ctx := r.Context()

	orgID := req.OrganizationID
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": nil, "success": false})
		return
	}

	memberRole, _ := memberRec["role"].(string)
	result := HasPermission(memberRole, req.Permissions, p.opts.Roles)

	writeJSON(w, http.StatusOK, map[string]any{"error": nil, "success": result})
}

// --- GET /organization/list-members ---

func (p *Plugin) handleListMembers(w http.ResponseWriter, r *http.Request) {
	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := r.URL.Query().Get("organizationId")
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check membership.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRecs, _ := adp.FindMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})

	var members []*Member
	for _, m := range memberRecs {
		members = append(members, recordToMember(m))
	}
	if members == nil {
		members = []*Member{}
	}

	writeJSON(w, http.StatusOK, members)
}

// --- POST /organization/add-member ---

func (p *Plugin) handleAddMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId,omitempty"`
		UserID         string `json:"userId"`
		Role           any    `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	callerID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := req.OrganizationID
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}
	if orgID == "" {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check caller's membership and permissions.
	callerMember, err := p.findMemberByUserAndOrg(ctx, callerID, orgID)
	if err != nil || callerMember == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	callerRole, _ := callerMember["role"].(string)
	if !HasPermission(callerRole, map[string][]string{"member": {"create"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToInvite.Status, ErrNotAllowedToInvite.Code, ErrNotAllowedToInvite.Message)
		return
	}

	// Check if user is already a member.
	existingMember, _ := p.findMemberByUserAndOrg(ctx, req.UserID, orgID)
	if existingMember != nil {
		writeError(w, ErrUserAlreadyMember.Status, ErrUserAlreadyMember.Code, ErrUserAlreadyMember.Message)
		return
	}

	// Check membership limit.
	if p.opts.MembershipLimit > 0 {
		count, err := p.countOrgMembers(ctx, orgID)
		if err == nil && count >= int64(p.opts.MembershipLimit) {
			writeError(w, ErrMembershipLimitReached.Status, ErrMembershipLimitReached.Code, ErrMembershipLimitReached.Message)
			return
		}
	}

	roleStr := parseRoles(req.Role)
	if !p.rolesExist(roleStr) {
		writeError(w, ErrInvalidRoleType.Status, ErrInvalidRoleType.Code, ErrInvalidRoleType.Message)
		return
	}
	if containsRole(splitRoles(roleStr), "owner") {
		writeError(w, ErrNotAllowedToInviteRole.Status, ErrNotAllowedToInviteRole.Code, ErrNotAllowedToInviteRole.Message)
		return
	}
	now := time.Now().UTC()
	memberID := generateID()

	memberRec, err := adp.Create(ctx, "member", map[string]any{
		"id":              memberID,
		"user_id":         req.UserID,
		"organization_id": orgID,
		"role":            roleStr,
		"created_at":      now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to add member")
		return
	}

	writeJSON(w, http.StatusOK, recordToMember(memberRec))
}
