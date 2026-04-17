package betterauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/internal/httputil"
	"github.com/jeromesth/go-better-auth/session"
)

func (a *Auth) handleChangePassword(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		CurrentPassword     string `json:"currentPassword"`
		NewPassword         string `json:"newPassword"`
		RevokeOtherSessions bool   `json:"revokeOtherSessions"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
		return
	}

	epCfg := a.opts.EmailAndPassword
	if epCfg == nil || !epCfg.Enabled {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	if len(req.NewPassword) < epCfg.MinPasswordLength {
		ErrPasswordTooShort.WriteJSON(w)
		return
	}
	if len(req.NewPassword) > epCfg.MaxPasswordLength {
		ErrPasswordTooLong.WriteJSON(w)
		return
	}

	ia := a.internalAdapter
	accounts, err := ia.FindAccountsByUserID(ctx, sess.UserID)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	var accID, currentHash string
	for _, acc := range accounts {
		if acc.ProviderID == "credential" && acc.Password != nil {
			accID = acc.ID
			currentHash = *acc.Password
			break
		}
	}
	if accID == "" {
		ErrAccountNotFound.WriteJSON(w)
		return
	}

	var ok bool
	if epCfg.Password != nil && epCfg.Password.Verify != nil {
		ok, err = epCfg.Password.Verify(currentHash, req.CurrentPassword)
	} else {
		ok, err = crypto.VerifyPassword(currentHash, req.CurrentPassword)
	}
	if err != nil || !ok {
		ErrInvalidPassword.WriteJSON(w)
		return
	}

	var newHash string
	if epCfg.Password != nil && epCfg.Password.Hash != nil {
		newHash, err = epCfg.Password.Hash(req.NewPassword)
	} else {
		newHash, err = crypto.HashPassword(req.NewPassword)
	}
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if _, err = ia.UpdateAccount(ctx, accID, map[string]any{"password": newHash}); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if req.RevokeOtherSessions || epCfg.RevokeSessionsOnReset {
		_ = a.sessionManager.RevokeAllForUser(ctx, sess.UserID, token)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *Auth) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		RedirectURI string `json:"redirectURI"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = a.opts.BaseURL
	}
	if redirectURI != "" && (a.opts.BaseURL != "" || len(a.opts.TrustedOrigins) > 0) &&
		!internal.ValidateCallbackURL(redirectURI, a.opts.TrustedOrigins, a.opts.BaseURL) {
		ErrInvalidCallbackURL.WriteJSON(w)
		return
	}

	ctx := r.Context()
	ia := a.internalAdapter

	user, err := ia.FindUserByEmail(ctx, req.Email)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}
	// Don't reveal whether user exists.
	if user == nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	token, err := crypto.GenerateVerificationToken()
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if _, err = ia.CreateVerification(ctx, "password-reset:"+user.ID, token, time.Hour); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	epCfg := a.opts.EmailAndPassword
	if epCfg != nil && epCfg.SendResetPassword != nil {
		url := redirectURI + "?token=" + token
		_ = epCfg.SendResetPassword(ResetPasswordData{
			User:  *user,
			URL:   url,
			Token: token,
		}, r)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *Auth) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"newPassword"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid request body")
		return
	}

	epCfg := a.opts.EmailAndPassword
	if epCfg == nil || !epCfg.Enabled {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	if len(req.Password) < epCfg.MinPasswordLength {
		ErrPasswordTooShort.WriteJSON(w)
		return
	}

	ctx := r.Context()
	ia := a.internalAdapter

	verif, err := ia.FindVerificationByValue(ctx, req.Token)
	if err != nil || verif == nil {
		ErrInvalidToken.WriteJSON(w)
		return
	}
	if time.Now().After(verif.ExpiresAt) {
		_ = ia.DeleteVerification(ctx, verif.ID)
		ErrTokenExpired.WriteJSON(w)
		return
	}

	const prefix = "password-reset:"
	if len(verif.Identifier) <= len(prefix) {
		ErrInvalidToken.WriteJSON(w)
		return
	}
	userID := verif.Identifier[len(prefix):]

	accounts, err := ia.FindAccountsByUserID(ctx, userID)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	var accID string
	for _, acc := range accounts {
		if acc.ProviderID == "credential" {
			accID = acc.ID
			break
		}
	}
	if accID == "" {
		ErrAccountNotFound.WriteJSON(w)
		return
	}

	var newHash string
	if epCfg.Password != nil && epCfg.Password.Hash != nil {
		newHash, err = epCfg.Password.Hash(req.Password)
	} else {
		newHash, err = crypto.HashPassword(req.Password)
	}
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if _, err = ia.UpdateAccount(ctx, accID, map[string]any{"password": newHash}); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	_ = ia.DeleteVerification(ctx, verif.ID)

	if epCfg.RevokeSessionsOnReset {
		_ = a.sessionManager.RevokeAllForUser(ctx, userID, "")
	}

	if epCfg.OnPasswordReset != nil {
		user, _ := ia.FindUserByID(ctx, userID)
		if user != nil {
			_ = epCfg.OnPasswordReset(*user, r)
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
