package betterauth

import (
	"net/http"
	"strings"

	"github.com/jeromesth/go-better-auth/packages/betterauth/crypto"
	"github.com/jeromesth/go-better-auth/packages/betterauth/internal"
	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

type signUpEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (a *Auth) handleSignUpEmail(w http.ResponseWriter, r *http.Request) {
	var req signUpEmailRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	epCfg := a.opts.EmailAndPassword
	if epCfg == nil || !epCfg.Enabled {
		ErrSignUpDisabled.WriteJSON(w)
		return
	}
	if epCfg.DisableSignUp {
		ErrSignUpDisabled.WriteJSON(w)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" {
		ErrInvalidEmail.WriteJSON(w)
		return
	}
	if len(req.Password) < epCfg.MinPasswordLength {
		ErrPasswordTooShort.WriteJSON(w)
		return
	}
	if len(req.Password) > epCfg.MaxPasswordLength {
		ErrPasswordTooLong.WriteJSON(w)
		return
	}

	ctx := r.Context()
	ia := a.internalAdapter

	existing, err := ia.FindUserByEmail(ctx, req.Email)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}
	if existing != nil {
		ErrEmailAlreadyUsed.WriteJSON(w)
		return
	}

	var hash string
	if epCfg.Password != nil && epCfg.Password.Hash != nil {
		hash, err = epCfg.Password.Hash(req.Password)
	} else {
		hash, err = crypto.HashPassword(req.Password)
	}
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	user, err := ia.CreateUserWithExtra(ctx, req.Email, req.Name, false, a.RunUserCreateHooks)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if _, err = ia.CreateAccount(ctx, user.ID, user.ID, "credential", map[string]any{
		"password": hash,
	}); err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	if epCfg.AutoSignIn {
		// Run session-create hooks (e.g., ban check from admin plugin).
		if err := a.RunSessionCreateHooks(w, r, user.ID); err != nil {
			writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
			ip := internal.GetClientIP(r, a.ipHeader())
		ua := r.UserAgent()
		sess, err := a.sessionManager.Create(ctx, user.ID, ip, ua)
		if err != nil {
			ErrInternal.WriteJSON(w)
			return
		}
		session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, a.isSecure())
		writeJSON(w, http.StatusOK, map[string]any{
			"user":    user,
			"session": sess,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}
