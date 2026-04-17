package organization

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/session"
)

// --- POST /organization/invite-member ---

func (p *Plugin) handleInviteMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId,omitempty"`
		Email          string `json:"email"`
		Role           any    `json:"role"`
		Resend         bool   `json:"resend,omitempty"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
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
		httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		httputil.WriteError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"invitation": {"create"}}, p.opts.Roles) {
		httputil.WriteError(w, ErrNotAllowedToInvite.Status, ErrNotAllowedToInvite.Code, ErrNotAllowedToInvite.Message)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		httputil.WriteError(w, http.StatusBadRequest, "BAD_REQUEST", "email is required")
		return
	}
	roleStr := parseRoles(req.Role)
	if !p.rolesExist(roleStr) {
		httputil.WriteError(w, ErrInvalidRoleType.Status, ErrInvalidRoleType.Code, ErrInvalidRoleType.Message)
		return
	}

	// Single-owner invariant: owner role is only assigned via explicit transfer.
	invitedRoles := splitRoles(roleStr)
	if containsRole(invitedRoles, "owner") {
		httputil.WriteError(w, ErrNotAllowedToInviteRole.Status, ErrNotAllowedToInviteRole.Code, ErrNotAllowedToInviteRole.Message)
		return
	}

	// Check if user is already a member (case-insensitive email match).
	existingUser, _ := p.auth.InternalAdapter().FindUserByEmail(ctx, email)
	if existingUser != nil {
		existingMember, _ := p.findMemberByUserAndOrg(ctx, existingUser.ID, orgID)
		if existingMember != nil {
			httputil.WriteError(w, ErrUserAlreadyMember.Status, ErrUserAlreadyMember.Code, ErrUserAlreadyMember.Message)
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
				httputil.WriteJSON(w, http.StatusOK, recordToInvitation(inv))
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
			httputil.WriteError(w, ErrUserAlreadyInvited.Status, ErrUserAlreadyInvited.Code, ErrUserAlreadyInvited.Message)
			return
		}
	}

	// Check invitation limit.
	if p.opts.InvitationLimit > 0 {
		count, err := p.countPendingInvitations(ctx, orgID)
		if err == nil && count >= int64(p.opts.InvitationLimit) {
			httputil.WriteError(w, ErrInvitationLimitReached.Status, ErrInvitationLimitReached.Code, ErrInvitationLimitReached.Message)
			return
		}
	}

	// Check membership limit.
	if p.opts.MembershipLimit > 0 {
		count, err := p.countOrgMembers(ctx, orgID)
		if err == nil && count >= int64(p.opts.MembershipLimit) {
			httputil.WriteError(w, ErrMembershipLimitReached.Status, ErrMembershipLimitReached.Code, ErrMembershipLimitReached.Message)
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create invitation")
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

	httputil.WriteJSON(w, http.StatusOK, recordToInvitation(invRec))
}

// --- POST /organization/accept-invitation ---

func (p *Plugin) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
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
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	status, _ := invRec["status"].(string)
	if status != "pending" {
		httputil.WriteError(w, ErrInvitationAlreadyAccepted.Status, ErrInvitationAlreadyAccepted.Code, "Invitation is no longer pending")
		return
	}

	// Invitations are email-bound: only the invited email can accept.
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	invitationEmail, _ := invRec["email"].(string)
	if !strings.EqualFold(invitationEmail, userEmail) {
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	// Check expiration.
	expiresAt, _ := invRec["expires_at"].(time.Time)
	if !expiresAt.IsZero() && time.Now().UTC().After(expiresAt) {
		httputil.WriteError(w, ErrInvitationExpired.Status, ErrInvitationExpired.Code, ErrInvitationExpired.Message)
		return
	}

	orgID, _ := invRec["organization_id"].(string)
	role, _ := invRec["role"].(string)

	// Check if user is already a member.
	existingMember, _ := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if existingMember != nil {
		httputil.WriteError(w, ErrUserAlreadyMember.Status, ErrUserAlreadyMember.Code, ErrUserAlreadyMember.Message)
		return
	}

	// Check membership limit.
	if p.opts.MembershipLimit > 0 {
		count, err := p.countOrgMembers(ctx, orgID)
		if err == nil && count >= int64(p.opts.MembershipLimit) {
			httputil.WriteError(w, ErrMembershipLimitReached.Status, ErrMembershipLimitReached.Code, ErrMembershipLimitReached.Message)
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create member")
		return
	}

	// Update invitation status.
	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "accepted"})

	// Set active organization.
	token := session.GetSessionToken(r)
	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"member":     recordToMember(memberRec),
		"invitation": recordToInvitation(invRec),
	})
}

// --- POST /organization/reject-invitation ---

func (p *Plugin) handleRejectInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
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
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	// Invitations are email-bound: only the invited email can reject.
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	invitationEmail, _ := invRec["email"].(string)
	if !strings.EqualFold(invitationEmail, userEmail) {
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "rejected"})

	inv := recordToInvitation(invRec)
	inv.Status = "rejected"

	httputil.WriteJSON(w, http.StatusOK, inv)
}

// --- POST /organization/cancel-invitation ---

func (p *Plugin) handleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
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
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	orgID, _ := invRec["organization_id"].(string)
	if orgID == "" {
		orgID = getActiveOrgID(sessRaw)
	}

	// Check membership and permissions.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		httputil.WriteError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	memberRole, _ := memberRec["role"].(string)
	if !HasPermission(memberRole, map[string][]string{"invitation": {"cancel"}}, p.opts.Roles) {
		httputil.WriteError(w, ErrNotAllowedToCancelInvitation.Status, ErrNotAllowedToCancelInvitation.Code, ErrNotAllowedToCancelInvitation.Message)
		return
	}

	_, _ = adp.Update(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", req.InvitationID)},
	}, map[string]any{"status": "cancelled"})

	inv := recordToInvitation(invRec)
	inv.Status = "cancelled"

	httputil.WriteJSON(w, http.StatusOK, inv)
}

// --- GET /organization/get-invitation ---

func (p *Plugin) handleGetInvitation(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	invID := r.URL.Query().Get("invitationId")
	if invID == "" {
		httputil.WriteError(w, http.StatusBadRequest, "BAD_REQUEST", "invitationId is required")
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	invRec, err := adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", invID)},
	})
	if err != nil || invRec == nil {
		httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
		return
	}

	inv := recordToInvitation(invRec)
	userEmail, err := p.getUserEmail(ctx, userID)
	if err != nil || userEmail == "" {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}
	// The invitation is visible to the invitee or organization members only.
	if !strings.EqualFold(inv.Email, userEmail) {
		memberRec, err := p.findMemberByUserAndOrg(ctx, userID, inv.OrganizationID)
		if err != nil || memberRec == nil {
			httputil.WriteError(w, ErrInvitationNotFound.Status, ErrInvitationNotFound.Code, ErrInvitationNotFound.Message)
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

	httputil.WriteJSON(w, http.StatusOK, inv)
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
		httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check membership.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		httputil.WriteError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
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

	httputil.WriteJSON(w, http.StatusOK, invitations)
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
		httputil.WriteJSON(w, http.StatusOK, []*Invitation{})
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

	httputil.WriteJSON(w, http.StatusOK, invitations)
}
