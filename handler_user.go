package betterauth

import (
	"net/http"

	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/session"
)

func (a *Auth) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
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

	var req map[string]any
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
		return
	}

	allowed := map[string]bool{"name": true, "image": true}
	updates := make(map[string]any)
	for k, v := range req {
		if allowed[k] {
			updates[k] = v
		}
	}

	if len(updates) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "NO_UPDATES", "No valid fields to update")
		return
	}

	user, err := a.internalAdapter.UpdateUser(ctx, sess.UserID, updates)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (a *Auth) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
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

	ia := a.internalAdapter
	userCfg := a.opts.User

	if userCfg != nil && userCfg.DeleteUser != nil && !userCfg.DeleteUser.Enabled {
		httputil.WriteError(w, http.StatusForbidden, "DELETE_DISABLED", "Account deletion is disabled")
		return
	}

	user, err := ia.FindUserByID(ctx, sess.UserID)
	if err != nil || user == nil {
		ErrUserNotFound.WriteJSON(w)
		return
	}

	if userCfg != nil && userCfg.DeleteUser != nil && userCfg.DeleteUser.BeforeDelete != nil {
		if err := userCfg.DeleteUser.BeforeDelete(*user, r); err != nil {
			httputil.WriteError(w, http.StatusForbidden, "DELETE_FORBIDDEN", err.Error())
			return
		}
	}

	_ = a.sessionManager.RevokeAllForUser(ctx, sess.UserID, "")
	session.ClearSessionCookie(w)

	if err := ia.DeleteUser(ctx, sess.UserID); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if userCfg != nil && userCfg.DeleteUser != nil && userCfg.DeleteUser.AfterDelete != nil {
		_ = userCfg.DeleteUser.AfterDelete(*user, r)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
