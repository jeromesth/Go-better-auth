package betterauth

import (
	"net/http"

	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

func (a *Auth) handleSignOut(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	if err := a.sessionManager.Revoke(r.Context(), token); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	session.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *Auth) handleGetSession(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		writeJSON(w, http.StatusOK, nil)
		return
	}

	ctx := r.Context()
	sess, err := a.sessionManager.FindByToken(ctx, token)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}
	if sess == nil || session.IsExpired(sess) {
		session.ClearSessionCookie(w)
		writeJSON(w, http.StatusOK, nil)
		return
	}

	sess, err = a.sessionManager.RefreshIfNeeded(ctx, sess)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	user, err := a.internalAdapter.FindUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		ErrInternal.WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

func (a *Auth) handleListSessions(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	ctx := r.Context()
	sess, err := a.sessionManager.FindByToken(ctx, token)
	if err != nil || sess == nil || session.IsExpired(sess) {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	sessions, err := a.sessionManager.ListByUserID(ctx, sess.UserID)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (a *Auth) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	ctx := r.Context()
	current, err := a.sessionManager.FindByToken(ctx, token)
	if err != nil || current == nil || session.IsExpired(current) {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	var req struct {
		SessionID string `json:"sessionId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	target, err := a.sessionManager.FindByID(ctx, req.SessionID)
	if err != nil || target == nil || target.UserID != current.UserID {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	if err := a.sessionManager.RevokeByID(ctx, req.SessionID); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *Auth) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	token := session.GetSessionToken(r)
	if token == "" {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	ctx := r.Context()
	current, err := a.sessionManager.FindByToken(ctx, token)
	if err != nil || current == nil || session.IsExpired(current) {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	if err := a.sessionManager.RevokeAllForUser(ctx, current.UserID, token); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
