package betterauth

import (
	"net/http"
	"strings"

	"github.com/jeromesth/go-better-auth/packages/betterauth/crypto"
	"github.com/jeromesth/go-better-auth/packages/betterauth/internal"
	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

type signInEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *Auth) handleSignInEmail(w http.ResponseWriter, r *http.Request) {
	var req signInEmailRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	epCfg := a.opts.EmailAndPassword
	if epCfg == nil || !epCfg.Enabled {
		ErrUnauthorized.WriteJSON(w)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" {
		ErrInvalidEmail.WriteJSON(w)
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
		ErrInvalidPassword.WriteJSON(w)
		return
	}

	if epCfg.RequireEmailVerification && !user.EmailVerified {
		ErrEmailNotVerified.WriteJSON(w)
		return
	}

	accounts, err := ia.FindAccountsByUserID(ctx, user.ID)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	var hash string
	for _, acc := range accounts {
		if acc.ProviderID == "credential" && acc.Password != nil {
			hash = *acc.Password
			break
		}
	}
	if hash == "" {
		ErrInvalidPassword.WriteJSON(w)
		return
	}

	var ok bool
	if epCfg.Password != nil && epCfg.Password.Verify != nil {
		ok, err = epCfg.Password.Verify(hash, req.Password)
	} else {
		ok, err = crypto.VerifyPassword(hash, req.Password)
	}
	if err != nil || !ok {
		ErrInvalidPassword.WriteJSON(w)
		return
	}

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
}
