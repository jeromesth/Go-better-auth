package organization

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal/httputil"
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
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	userID, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	// Check if user is allowed to create organizations.
	if p.opts.AllowUserToCreateOrganization != nil && !*p.opts.AllowUserToCreateOrganization {
		httputil.WriteError(w, ErrNotAllowedToCreate.Status, ErrNotAllowedToCreate.Code, ErrNotAllowedToCreate.Message)
		return
	}

	slug := strings.TrimSpace(req.Slug)
	name := strings.TrimSpace(req.Name)

	if slug == "" {
		httputil.WriteError(w, ErrEmptySlug.Status, ErrEmptySlug.Code, ErrEmptySlug.Message)
		return
	}
	if name == "" {
		httputil.WriteError(w, ErrEmptyName.Status, ErrEmptyName.Code, ErrEmptyName.Message)
		return
	}

	ctx := r.Context()
	adp := p.auth.InternalAdapter().Adapter()

	// Check organization limit.
	if p.opts.OrganizationLimit > 0 {
		count, err := p.countUserOrganizations(ctx, userID)
		if err == nil && count >= int64(p.opts.OrganizationLimit) {
			httputil.WriteError(w, ErrOrganizationLimitReached.Status, ErrOrganizationLimitReached.Code, ErrOrganizationLimitReached.Message)
			return
		}
	}

	// Check slug uniqueness.
	existing, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("slug", slug)},
	})
	if err == nil && existing != nil {
		httputil.WriteError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create organization")
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create member")
		return
	}

	// Set the active organization on the session.
	token := session.GetSessionToken(r)
	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	httputil.WriteJSON(w, http.StatusOK, recordToOrganization(orgRec))
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
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
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
	if !HasPermission(memberRole, map[string][]string{"organization": {"update"}}, p.opts.Roles) {
		httputil.WriteError(w, ErrNotAllowedToUpdate.Status, ErrNotAllowedToUpdate.Code, ErrNotAllowedToUpdate.Message)
		return
	}

	updates := map[string]any{"updated_at": time.Now().UTC()}

	if req.Data.Name != nil {
		name := strings.TrimSpace(*req.Data.Name)
		if name == "" {
			httputil.WriteError(w, ErrEmptyName.Status, ErrEmptyName.Code, ErrEmptyName.Message)
			return
		}
		updates["name"] = name
	}
	if req.Data.Slug != nil {
		slug := strings.TrimSpace(*req.Data.Slug)
		if slug == "" {
			httputil.WriteError(w, ErrEmptySlug.Status, ErrEmptySlug.Code, ErrEmptySlug.Message)
			return
		}
		// Check slug uniqueness (not counting current org).
		existing, err := adp.FindOne(ctx, "organization", adapter.Query{
			Where: []adapter.Where{adapter.EQ("slug", slug)},
		})
		if err == nil && existing != nil {
			existingID, _ := existing["id"].(string)
			if existingID != orgID {
				httputil.WriteError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update organization")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, recordToOrganization(rec))
}

// --- POST /organization/delete ---

func (p *Plugin) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organizationId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
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
	if !HasPermission(memberRole, map[string][]string{"organization": {"delete"}}, p.opts.Roles) {
		httputil.WriteError(w, ErrNotAllowedToDelete.Status, ErrNotAllowedToDelete.Code, ErrNotAllowedToDelete.Message)
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
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete organization")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// --- GET /organization/check-slug ---

func (p *Plugin) handleCheckSlug(w http.ResponseWriter, r *http.Request) {
	_, _, ok := p.getAuthenticatedUser(w, r)
	if !ok {
		return
	}

	slug := r.URL.Query().Get("slug")
	if slug == "" {
		httputil.WriteError(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
		return
	}

	ctx := r.Context()
	existing, err := p.auth.InternalAdapter().Adapter().FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("slug", slug)},
	})
	if err != nil || existing == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": true})
		return
	}

	httputil.WriteError(w, ErrSlugAlreadyTaken.Status, ErrSlugAlreadyTaken.Code, ErrSlugAlreadyTaken.Message)
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
		httputil.WriteJSON(w, http.StatusOK, []any{})
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

	httputil.WriteJSON(w, http.StatusOK, orgs)
}

// --- POST /organization/set-active ---

func (p *Plugin) handleSetActiveOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID   string `json:"organizationId,omitempty"`
		OrganizationSlug string `json:"organizationSlug,omitempty"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
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
			httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
			return
		}
		orgID, _ = orgRec["id"].(string)
	}

	if orgID == "" {
		// Clear active organization.
		_ = p.setActiveOrgOnSession(ctx, token, "")
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"session": map[string]any{"activeOrganizationId": nil}})
		return
	}

	// Verify membership.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		httputil.WriteError(w, ErrUserNotMember.Status, ErrUserNotMember.Code, ErrUserNotMember.Message)
		return
	}

	_ = p.setActiveOrgOnSession(ctx, token, orgID)

	// Return the full organization.
	orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if err != nil || orgRec == nil {
		httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
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

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
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
		httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
		return
	}

	// Check membership.
	memberRec, err := p.findMemberByUserAndOrg(ctx, userID, orgID)
	if err != nil || memberRec == nil {
		httputil.WriteError(w, ErrNotAllowedToUpdate.Status, "FORBIDDEN", "You are not a member of this organization")
		return
	}

	orgRec, err := adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", orgID)},
	})
	if err != nil || orgRec == nil {
		httputil.WriteError(w, ErrOrgNotFound.Status, ErrOrgNotFound.Code, ErrOrgNotFound.Message)
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

	httputil.WriteJSON(w, http.StatusOK, full)
}
