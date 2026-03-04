package admin

import (
	"net/http"
	"time"

	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

// --- POST /admin/list-user-sessions ---

func (p *Plugin) handleListUserSessions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"session": {"list"}},
	}) {
		writeAdminError(w, ErrNotAllowedToListSessions.Status, ErrNotAllowedToListSessions.Code, ErrNotAllowedToListSessions.Message)
		return
	}

	ctx := r.Context()
	recs, err := p.repo.FindSessionsByUserID(ctx, req.UserID)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions")
		return
	}

	sessions := make([]*SessionWithImpersonation, 0, len(recs))
	for _, rec := range recs {
		sessions = append(sessions, recordToSessionWithImpersonation(rec))
	}

	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// --- POST /admin/revoke-user-session ---

func (p *Plugin) handleRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionToken string `json:"sessionToken"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"session": {"revoke"}},
	}) {
		writeAdminError(w, ErrNotAllowedToRevokeSessions.Status, ErrNotAllowedToRevokeSessions.Code, ErrNotAllowedToRevokeSessions.Message)
		return
	}

	ctx := r.Context()
	if err := p.repo.RevokeSession(ctx, req.SessionToken); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// --- POST /admin/revoke-user-sessions ---

func (p *Plugin) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"session": {"revoke"}},
	}) {
		writeAdminError(w, ErrNotAllowedToRevokeSessions.Status, ErrNotAllowedToRevokeSessions.Code, ErrNotAllowedToRevokeSessions.Message)
		return
	}

	ctx := r.Context()
	if err := p.repo.RevokeAllUserSessions(ctx, req.UserID); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke sessions")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// --- POST /admin/impersonate-user ---

func (p *Plugin) handleImpersonateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	adminUser := p.getAdminSession(w, r)
	if adminUser == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      adminUser.ID,
		Role:        adminUser.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"impersonate"}},
	}) {
		writeAdminError(w, ErrNotAllowedToImpersonate.Status, ErrNotAllowedToImpersonate.Code, ErrNotAllowedToImpersonate.Message)
		return
	}

	ctx := r.Context()
	targetRec, err := p.repo.FindUserByID(ctx, req.UserID)
	if err != nil || targetRec == nil {
		writeAdminError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	targetUser := recordToUserWithRole(targetRec)

	// Check if target is an admin — requires impersonate-admins permission.
	if p.isUserAdmin(targetUser) {
		canImpersonateAdmins := p.opts.AllowImpersonatingAdmins || HasPermission(HasPermissionInput{
			UserID:      adminUser.ID,
			Role:        adminUser.Role,
			Options:     p.opts,
			Permissions: map[string][]string{"user": {"impersonate-admins"}},
		})
		if !canImpersonateAdmins {
			writeAdminError(w, ErrCannotImpersonateAdmins.Status, ErrCannotImpersonateAdmins.Code, ErrCannotImpersonateAdmins.Message)
			return
		}
	}

	// Get current admin session token.
	adminToken := session.GetSessionToken(r)

	// Create impersonation session.
	duration := time.Duration(p.opts.ImpersonationSessionDuration) * time.Second
	expiresAt := time.Now().UTC().Add(duration)

	sess, err := p.repo.CreateImpersonationSession(ctx, targetUser.ID, adminUser.ID, expiresAt)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create impersonation session")
		return
	}

	// Set the admin session cookie for later restoration.
	http.SetCookie(w, &http.Cookie{
		Name:     "better-auth.admin_session",
		Value:    adminToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   p.auth.Options().Advanced != nil && p.auth.Options().Advanced.UseSecureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	// Set the new session cookie for the impersonated user.
	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.Options().Advanced != nil && p.auth.Options().Advanced.UseSecureCookies)

	writeJSON(w, http.StatusOK, map[string]any{
		"session": sess,
		"user":    targetUser,
	})
}

// --- POST /admin/stop-impersonating ---

func (p *Plugin) handleStopImpersonating(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return
	}

	ctx := r.Context()
	sess, err := p.repo.FindSessionByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
		return
	}

	// Find the impersonated_by field from raw session record.
	rawSess, err := p.repo.FindRawSession(ctx, token)
	if err != nil || rawSess == nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to find session")
		return
	}

	impersonatedBy, _ := rawSess["impersonated_by"].(string)
	if impersonatedBy == "" {
		writeAdminError(w, http.StatusBadRequest, "BAD_REQUEST", "You are not impersonating anyone")
		return
	}

	// Find the admin user.
	adminRec, err := p.repo.FindUserByID(ctx, impersonatedBy)
	if err != nil || adminRec == nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to find admin user")
		return
	}

	// Get the admin session from cookie.
	adminCookie, err := r.Cookie("better-auth.admin_session")
	if err != nil || adminCookie.Value == "" {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to find admin session")
		return
	}

	adminSession, err := p.repo.FindSessionByToken(ctx, adminCookie.Value)
	if err != nil || adminSession == nil {
		writeAdminError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to find admin session")
		return
	}

	// Delete the impersonation session.
	_ = p.repo.RevokeSession(ctx, token)

	// Restore the admin session cookie.
	session.SetSessionCookie(w, adminSession.Token, adminSession.ExpiresAt, p.auth.Options().Advanced != nil && p.auth.Options().Advanced.UseSecureCookies)

	// Expire the admin_session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "better-auth.admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"session": adminSession,
		"user":    recordToUserWithRole(adminRec),
	})
}

// --- POST /admin/has-permission ---

func (p *Plugin) handleHasPermission(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string              `json:"userId,omitempty"`
		Role        string              `json:"role,omitempty"`
		Permissions map[string][]string `json:"permissions"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Permissions == nil {
		writeAdminError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid permission check. no permission(s) were passed.")
		return
	}

	// Try to get session (optional for this endpoint).
	token := session.GetSessionToken(r)
	var sessionUser *UserWithRole

	if token != "" {
		ctx := r.Context()
		sess, err := p.repo.FindSessionByToken(ctx, token)
		if err == nil && sess != nil && !session.IsExpired(sess) {
			rec, err := p.repo.FindUserByID(ctx, sess.UserID)
			if err == nil && rec != nil {
				sessionUser = recordToUserWithRole(rec)
			}
		}
	}

	if sessionUser == nil && req.UserID == "" && req.Role == "" {
		writeAdminError(w, http.StatusBadRequest, "BAD_REQUEST", "user id or role is required")
		return
	}

	// Determine user for permission check.
	var checkUserID, checkRole string

	if req.Role != "" {
		// Role takes priority.
		checkUserID = req.UserID
		checkRole = req.Role
	} else if sessionUser != nil {
		checkUserID = sessionUser.ID
		checkRole = sessionUser.Role
	} else if req.UserID != "" {
		// Look up the user.
		ctx := r.Context()
		rec, err := p.repo.FindUserByID(ctx, req.UserID)
		if err != nil || rec == nil {
			writeAdminError(w, http.StatusBadRequest, "BAD_REQUEST", "user not found")
			return
		}
		u := recordToUserWithRole(rec)
		checkUserID = u.ID
		checkRole = u.Role
	}

	result := HasPermission(HasPermissionInput{
		UserID:      checkUserID,
		Role:        checkRole,
		Options:     p.opts,
		Permissions: req.Permissions,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"error":   nil,
		"success": result,
	})
}
