package organization

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/session"
)

// --- POST /organization/create ---

func (p *Plugin) handleCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Slug     string `json:"slug"`
		Logo     string `json:"logo,omitempty"`
		Metadata any    `json:"metadata,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	// Check if user is allowed to create organizations.
	if p.opts.AllowUserToCreateOrganization != nil && !*p.opts.AllowUserToCreateOrganization {
		writeError(w, ErrNotAllowedToCreate.Status, ErrNotAllowedToCreate.Code, ErrNotAllowedToCreate.Message)
		return
	}

	slug := strings.TrimSpace(req.Slug)
	name := strings.TrimSpace(req.Name)

	if slug == "" {
		writeError(w, ErrEmptySlug.Status, ErrEmptySlug.Code, ErrEmptySlug.Message)
		return
	}
	if name == "" {
		writeError(w, ErrEmptyName.Status, ErrEmptyName.Code, ErrEmptyName.Message)
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	// Check organization limit.
	if p.opts.OrganizationLimit > 0 {
		count, err := p.countUserOrganizations(ctx, userID)
		if err == nil && count >= int64(p.opts.OrganizationLimit) {
			writeError(w, ErrOrganizationLimitReached.Status, ErrOrganizationLimitReached.Code, ErrOrganizationLimitReached.Message)
			return
		}
	}

	// Check slug uniqueness.
	existing, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("slug", slug)},
	})
	if err == nil && existing != nil {
		writeError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
		return
	}

	now := time.Now().UTC()
	orgID := generateID()

	orgData := map[string]any{
		"id":         orgID,
		"name":       name,
		"slug":       slug,
		"created_at": now,
	}
	if req.Logo != "" {
		orgData["logo"] = req.Logo
	}
	if req.Metadata != nil {
		orgData["metadata"] = metadataToString(req.Metadata)
	}

	orgRec, err := adp.Create(ctx, "organization", orgData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create organization")
		return
	}

	// Create the creator as a member with the creator role.
	memberID := generateID()
	_, err = adp.Create(ctx, "member", map[string]any{
		"id":              memberID,
		"user_id":         userID,
		"organization_id": orgID,
		"role":            p.opts.CreatorRole,
		"created_at":      now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create member")
		return
	}

	// Set the active organization on the session.
	token := session.GetSessionToken(r)
	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	writeJSON(w, http.StatusOK, recordToOrganization(orgRec))
}

// --- POST /organization/update ---

func (p *Plugin) handleUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId"`
		Data           struct {
			Name     *string `json:"name,omitempty"`
			Slug     *string `json:"slug,omitempty"`
			Logo     *string `json:"logo,omitempty"`
			Metadata any     `json:"metadata,omitempty"`
		} `json:"data"`
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

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"organization": {"update"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToUpdate.Status, ErrNotAllowedToUpdate.Code, ErrNotAllowedToUpdate.Message)
		return
	}

	updates := map[string]any{"updated_at": time.Now().UTC()}

	if req.Data.Name != nil {
		name := strings.TrimSpace(*req.Data.Name)
		if name == "" {
			writeError(w, ErrEmptyName.Status, ErrEmptyName.Code, ErrEmptyName.Message)
			return
		}
		updates["name"] = name
	}
	if req.Data.Slug != nil {
		slug := strings.TrimSpace(*req.Data.Slug)
		if slug == "" {
			writeError(w, ErrEmptySlug.Status, ErrEmptySlug.Code, ErrEmptySlug.Message)
			return
		}
		// Check slug uniqueness (not counting current org).
		existing, err := adp.FindOne(ctx, "organization", adapter.Query{
			Where: []adapter.Where{adapter.EQ("slug", slug)},
		})
		if err == nil && existing != nil {
			existingID, _ := existing["id"].(string)
			if existingID != orgID {
				writeError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
				return
			}
		}
		updates["slug"] = slug
	}
	if req.Data.Logo != nil {
		updates["logo"] = *req.Data.Logo
	}
	if req.Data.Metadata != nil {
		updates["metadata"] = metadataToString(req.Data.Metadata)
	}

	rec, err := adp.Update(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	}, updates)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update organization")
		return
	}

	writeJSON(w, http.StatusOK, recordToOrganization(rec))
}

// --- POST /organization/delete ---

func (p *Plugin) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId"`
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

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"organization": {"delete"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToDelete.Status, ErrNotAllowedToDelete.Code, ErrNotAllowedToDelete.Message)
		return
	}

	// Delete all members and invitations.
	_ = adp.DeleteMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
	_ = adp.DeleteMany(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
	err = adp.Delete(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete organization")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// --- GET /organization/check-slug ---

func (p *Plugin) handleCheckSlug(w http.ResponseWriter, r *http.Request) {
	_, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	slug := r.URL.Query().Get("slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}

	ctx := r.Context()
	existing, err := p.auth.InternalAdapter().Adapter().FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("slug", slug)},
	})
	if err != nil || existing == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": true})
		return
	}

	writeError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
}

// --- GET /organization/list ---

func (p *Plugin) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	// Find all memberships for this user.
	members, err := adp.FindMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	var orgs []*Organization
	for _, m := range members {
		orgID, _ := m["organization_id"].(string)
		orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", orgID)},
		})
		if err != nil || orgRec == nil {
			continue
		}
		orgs = append(orgs, recordToOrganization(orgRec))
	}

	if orgs == nil {
		orgs = []*Organization{}
	}

	writeJSON(w, http.StatusOK, orgs)
}

// --- POST /organization/set-active ---

func (p *Plugin) handleSetActiveOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID   string `json:"organizationId,omitempty"`
		OrganizationSlug string `json:"organizationSlug,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()
	token := session.GetSessionToken(r)

	var orgID string

	if req.OrganizationID != "" {
		orgID = req.OrganizationID
	} else if req.OrganizationSlug != "" {
		orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
			Where: []adapter.Where{adapter.EQ("slug", req.OrganizationSlug)},
		})
		if err != nil || orgRec == nil {
			writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
			return
		}
		orgID, _ = orgRec["id"].(string)
	}

	if orgID == "" {
		// Clear active organization.
		_ = p.setActiveOrgOnSession(ctx, token, "")
		writeJSON(w, http.StatusOK, map[string]any{"session": map[string]any{"activeOrganizationId": nil}})
		return
	}

	// Verify membership.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	// Return the full organization.
	orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if err != nil || orgRec == nil {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	org := recordToOrganization(orgRec)

	// Get members.
	memberRecs, _ := adp.FindMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
	var members []*Member
	for _, m := range memberRecs {
		members = append(members, recordToMember(m))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"organization": org,
		"members":      members,
		"session": map[string]any{
			"activeOrganizationId": orgID,
		},
	})
}

// --- GET /organization/get-full-organization ---

func (p *Plugin) handleGetFullOrganization(w http.ResponseWriter, r *http.Request) {
	userID, sessRaw, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	orgID := r.URL.Query().Get("organizationId")
	if orgID == "" {
		orgSlug := r.URL.Query().Get("organizationSlug")
		if orgSlug != "" {
			orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
				Where: []adapter.Where{adapter.EQ("slug", orgSlug)},
			})
			if err == nil && orgRec != nil {
				orgID, _ = orgRec["id"].(string)
			}
		}
	}
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
		writeError(w, ErrNotAllowedToUpdate.Status, "FORBIDDEN", "You are not a member of this organization")
		return
	}

	orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if err != nil || orgRec == nil {
		writeError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	org := recordToOrganization(orgRec)

	// Get members.
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

	// Get invitations.
	invRecs, _ := adp.FindMany(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("organization_id", orgID),
			adapter.EQ("status", "pending"),
		},
	})
	var invitations []*Invitation
	for _, inv := range invRecs {
		invitations = append(invitations, recordToInvitation(inv))
	}

	full := &FullOrganization{
		Organization: *org,
		Members:      members,
		Invitations:  invitations,
	}

	writeJSON(w, http.StatusOK, full)
}

// --- POST /organization/invite-member ---

func (p *Plugin) handleInviteMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId,omitempty"`
		Email          string `json:"email"`
		Role           any    `json:"role"`
		Resend         bool   `json:"resend,omitempty"`
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

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"invitation": {"create"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToInvite.Status, ErrNotAllowedToInvite.Code, ErrNotAllowedToInvite.Message)
		return
	}

		email := strings.ToLower(strings.TrimSpace(req.Email))
		if email == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "email is required")
			return
		}
		roleStr := parseRoles(req.Role)
		if !p.rolesExist(roleStr) {
			writeError(w, ErrInvalidRoleType.Status, ErrInvalidRoleType.Code, ErrInvalidRoleType.Message)
			return
		}

		// Single-owner invariant: owner role is only assigned via explicit transfer.
		invitedRoles := splitRoles(roleStr)
		if containsRole(invitedRoles, "owner") {
			writeError(w, ErrNotAllowedToInviteRole.Status, ErrNotAllowedToInviteRole.Code, ErrNotAllowedToInviteRole.Message)
			return
		}

	// Check if user is already a member (case-insensitive email match).
	existingUser, _ := p.auth.InternalAdapter().FindUserByEmail(ctx, email)
	if existingUser != nil {
		existingMember, _ := p.findMemberByUserAndOrg(ctx, existingUser.ID, orgID)
		if existingMember != nil {
			writeError(w, ErrUserAlreadyMember.Status, ErrUserAlreadyMember.Code, ErrUserAlreadyMember.Message)
			return
		}
	}

	// Check for existing pending invitation (case-insensitive).
	existingInvitations, _ := adp.FindMany(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("organization_id", orgID),
			adapter.EQ("status", "pending"),
		},
	})

	for _, inv := range existingInvitations {
		invEmail, _ := inv["email"].(string)
		if strings.EqualFold(invEmail, email) {
			if req.Resend {
				// Return existing invitation.
				writeJSON(w, http.StatusOK, recordToInvitation(inv))
				return
			}
			if p.opts.CancelPendingInvitationsOnReInvite {
				// Cancel existing invitation.
				invID, _ := inv["id"].(string)
				_, _ = adp.Update(ctx, "invitation", adapter.Query{
					Where: []adapter.Where{adapter.EQ("id", invID)},
				}, map[string]any{"status": "cancelled"})
				break
			}
			writeError(w, ErrUserAlreadyInvited.Status, ErrUserAlreadyInvited.Code, ErrUserAlreadyInvited.Message)
			return
		}
	}

	// Check invitation limit.
	if p.opts.InvitationLimit > 0 {
		count, err := p.countPendingInvitations(ctx, orgID)
		if err == nil && count >= int64(p.opts.InvitationLimit) {
			writeError(w, ErrInvitationLimitReached.Status, ErrInvitationLimitReached.Code, ErrInvitationLimitReached.Message)
			return
		}
	}

	// Check membership limit.
	if p.opts.MembershipLimit > 0 {
		count, err := p.countOrgMembers(ctx, orgID)
		if err == nil && count >= int64(p.opts.MembershipLimit) {
			writeError(w, ErrMembershipLimitReached.Status, ErrMembershipLimitReached.Code, ErrMembershipLimitReached.Message)
			return
		}
	}

	now := time.Now().UTC()
	invID := generateID()
	expiresAt := now.Add(time.Duration(p.opts.InvitationExpiresIn) * time.Second)

	invData := map[string]any{
		"id":              invID,
		"email":           email,
		"inviter_id":      userID,
		"organization_id": orgID,
		"role":            roleStr,
		"status":          "pending",
		"expires_at":      expiresAt,
		"created_at":      now,
	}

	invRec, err := adp.Create(ctx, "invitation", invData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create invitation")
		return
	}

	// Send invitation email if configured.
	if p.opts.SendInvitationEmail != nil {
		orgRec, _ := adp.FindOne(ctx, "organization", adapter.Query{
			Where: []adapter.Where{adapter.EQ("id", orgID)},
		})
		orgName := ""
		if orgRec != nil {
			orgName, _ = orgRec["name"].(string)
		}
		userRec, _ := p.auth.InternalAdapter().FindUserByIDRaw(ctx, userID)
		inviterName := ""
		if userRec != nil {
			inviterName, _ = userRec["name"].(string)
		}
		_ = p.opts.SendInvitationEmail(InvitationEmailData{
			Email:            email,
			InviterName:      inviterName,
			OrganizationName: orgName,
			InvitationID:     invID,
		})
	}

	writeJSON(w, http.StatusOK, recordToInvitation(invRec))
}

// --- POST /organization/accept-invitation ---

func (p *Plugin) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	invRec, err := adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	})
	if err != nil || invRec == nil {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	status, _ := invRec["status"].(string)
	if status != "pending" {
		writeError(w, ErrInvitationAlreadyAccepted.Status, ErrInvitationAlreadyAccepted.Code, "Invitation is no longer pending")
		return
	}

	// Invitations are email-bound: only the invited email can accept.
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	invitationEmail, _ := invRec["email"].(string)
	if !strings.EqualFold(invitationEmail, userEmail) {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	// Check expiration.
	expiresAt, _ := invRec["expires_at"].(time.Time)
	if !expiresAt.IsZero() && time.Now().UTC().After(expiresAt) {
		writeError(w, ErrInvitationExpired.Status, ErrInvitationExpired.Code, ErrInvitationExpired.Message)
		return
	}

	orgID, _ := invRec["organization_id"].(string)
	role, _ := invRec["role"].(string)

	// Check if user is already a member.
	existingMember, _ := p.findMemberByUserAndOrg(ctx, userID, orgID)
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

	// Create member.
	now := time.Now().UTC()
	memberID := generateID()
	memberRec, err := adp.Create(ctx, "member", map[string]any{
		"id":              memberID,
		"user_id":         userID,
		"organization_id": orgID,
		"role":            role,
		"created_at":      now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create member")
		return
	}

	// Update invitation status.
	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "accepted"})

	// Set active organization.
	token := session.GetSessionToken(r)
	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	writeJSON(w, http.StatusOK, map[string]any{
		"member":     recordToMember(memberRec),
		"invitation": recordToInvitation(invRec),
	})
}

// --- POST /organization/reject-invitation ---

func (p *Plugin) handleRejectInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	invRec, err := adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	})
	if err != nil || invRec == nil {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	// Invitations are email-bound: only the invited email can reject.
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	invitationEmail, _ := invRec["email"].(string)
	if !strings.EqualFold(invitationEmail, userEmail) {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "rejected"})

	inv := recordToInvitation(invRec)
	inv.Status = "rejected"

	writeJSON(w, http.StatusOK, inv)
}

// --- POST /organization/cancel-invitation ---

func (p *Plugin) handleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
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

	invRec, err := adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	})
	if err != nil || invRec == nil {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	orgID, _ := invRec["organization_id"].(string)
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		writeError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"invitation": {"cancel"}}, p.opts.Roles) {
		writeError(w, ErrNotAllowedToCancelInvitation.Status, ErrNotAllowedToCancelInvitation.Code, ErrNotAllowedToCancelInvitation.Message)
		return
	}

	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "cancelled"})

	inv := recordToInvitation(invRec)
	inv.Status = "cancelled"

	writeJSON(w, http.StatusOK, inv)
}

// --- GET /organization/get-invitation ---

func (p *Plugin) handleGetInvitation(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	invID := r.URL.Query().Get("invitationId")
	if invID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invitationId is required")
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	invRec, err := adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", invID)},
	})
	if err != nil || invRec == nil {
		writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	inv := recordToInvitation(invRec)
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	// The invitation is visible to the invitee or organization members only.
	if !strings.EqualFold(inv.Email, userEmail) {
		memberRec, err := p.findMemberByUserAndOrg(ctx, userID, inv.OrganizationID)
		if err != nil || memberRec == nil {
			writeError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
			return
		}
	}

	// Enrich with organization name/slug.
	orgID := inv.OrganizationID
	orgRec, _ := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if orgRec != nil {
		inv.OrganizationName, _ = orgRec["name"].(string)
		inv.OrganizationSlug, _ = orgRec["slug"].(string)
	}

	writeJSON(w, http.StatusOK, inv)
}

// --- GET /organization/list-invitations ---

func (p *Plugin) handleListInvitations(w http.ResponseWriter, r *http.Request) {
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

	invRecs, _ := adp.FindMany(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})

	var invitations []*Invitation
	for _, inv := range invRecs {
		invitations = append(invitations, recordToInvitation(inv))
	}
	if invitations == nil {
		invitations = []*Invitation{}
	}

	writeJSON(w, http.StatusOK, invitations)
}

// --- GET /organization/list-user-invitations ---

func (p *Plugin) handleListUserInvitations(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	// Email is always derived from authenticated user to prevent invitation enumeration.
	email, err := p.getUserEmail(ctx, userID)
	if err != nil || email == "" {
		writeJSON(w, http.StatusOK, []*Invitation{})
		return
	}

	// Find pending invitations by matching email case-insensitively.
	allInvitations, _ := adp.FindMany(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("status", "pending")},
	})

	var invitations []*Invitation
	for _, inv := range allInvitations {
		invEmail, _ := inv["email"].(string)
		if strings.EqualFold(invEmail, email) {
			invitation := recordToInvitation(inv)
			// Enrich with org name.
			orgID := invitation.OrganizationID
			orgRec, _ := adp.FindOne(ctx, "organization", adapter.Query{
				Where: []adapter.Where{adapter.EQ("id", orgID)},
			})
			if orgRec != nil {
				invitation.OrganizationName, _ = orgRec["name"].(string)
				invitation.OrganizationSlug, _ = orgRec["slug"].(string)
			}
			invitations = append(invitations, invitation)
		}
	}
	if invitations == nil {
		invitations = []*Invitation{}
	}

	writeJSON(w, http.StatusOK, invitations)
}

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
