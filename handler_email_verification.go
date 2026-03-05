package betterauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"
)

func (a *Auth) handleSendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		CallbackURL string `json:"callbackURL"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	callbackURL := req.CallbackURL
	if callbackURL == "" {
		callbackURL = a.opts.BaseURL
	}
	if callbackURL != "" && (a.opts.BaseURL != "" || len(a.opts.TrustedOrigins) > 0) &&
		!internal.ValidateCallbackURL(callbackURL, a.opts.TrustedOrigins, a.opts.BaseURL) {
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
	if user == nil {
		ErrUserNotFound.WriteJSON(w)
		return
	}
	if user.EmailVerified {
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	token, err := crypto.GenerateVerificationToken()
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if _, err = ia.CreateVerification(ctx, "email-verification:"+user.Email, token, 24*time.Hour); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	evCfg := a.opts.EmailVerification
	if evCfg != nil && evCfg.SendVerificationEmail != nil {
		url := callbackURL + "?token=" + token
		_ = evCfg.SendVerificationEmail(EmailVerificationData{
			User:  *user,
			URL:   url,
			Token: token,
		}, r)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *Auth) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		ErrInvalidToken.WriteJSON(w)
		return
	}

	ctx := r.Context()
	ia := a.internalAdapter

	verif, err := ia.FindVerificationByValue(ctx, token)
	if err != nil || verif == nil {
		ErrInvalidToken.WriteJSON(w)
		return
	}
	if time.Now().After(verif.ExpiresAt) {
		_ = ia.DeleteVerification(ctx, verif.ID)
		ErrTokenExpired.WriteJSON(w)
		return
	}

	const prefix = "email-verification:"
	if len(verif.Identifier) <= len(prefix) {
		ErrInvalidToken.WriteJSON(w)
		return
	}
	email := verif.Identifier[len(prefix):]

	user, err := ia.FindUserByEmail(ctx, email)
	if err != nil || user == nil {
		ErrUserNotFound.WriteJSON(w)
		return
	}

	if _, err = ia.UpdateUser(ctx, user.ID, map[string]any{"email_verified": true}); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}
	_ = ia.DeleteVerification(ctx, verif.ID)

	evCfg := a.opts.EmailVerification
	if evCfg != nil && evCfg.AutoSignInAfterVerification {
		if err := a.RunSessionCreateHooks(w, r, user.ID); err != nil {
			if !errors.Is(err, plugin.ErrHandled) {
				writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			}
			return
		}
		ip := internal.GetClientIP(r, a.ipHeader())
		ua := r.UserAgent()
		sess, err := a.sessionManager.Create(ctx, user.ID, ip, ua)
		if err == nil {
			session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, a.isSecure())
		}
	}

	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
