package betterauth

import (
	"net/http"
	"strings"

	"github.com/jeromesth/go-better-auth/packages/betterauth/internal"
	"github.com/jeromesth/go-better-auth/packages/betterauth/session"
)

func (a *Auth) handleOAuthSignIn(w http.ResponseWriter, r *http.Request) {
	basePath := strings.TrimRight(a.opts.BasePath, "/")
	providerID := strings.TrimPrefix(r.URL.Path, basePath+"/sign-in/")
	providerID = strings.Trim(providerID, "/")

	providerCfg, ok := a.opts.SocialProviders[providerID]
	if !ok {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	provider := a.SocialProvider(providerID)
	if provider == nil {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	callbackURL := r.URL.Query().Get("callbackURL")
	if callbackURL == "" {
		callbackURL = a.opts.BaseURL
	}

	state, err := a.stateStore.Generate(callbackURL, "")
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	authURL := provider.AuthorizationURL(state, "", providerCfg)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *Auth) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	basePath := strings.TrimRight(a.opts.BasePath, "/")
	providerID := strings.TrimPrefix(r.URL.Path, basePath+"/callback/")
	providerID = strings.Trim(providerID, "/")

	providerCfg, ok := a.opts.SocialProviders[providerID]
	if !ok {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	provider := a.SocialProvider(providerID)
	if provider == nil {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		ErrInvalidCallbackURL.WriteJSON(w)
		return
	}

	stateEntry := a.stateStore.Consume(state)
	if stateEntry == nil {
		ErrCSRFInvalid.WriteJSON(w)
		return
	}

	ctx := r.Context()
	tokens, err := provider.ExchangeCode(ctx, code, stateEntry.CodeVerifier, providerCfg)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	oauthUser, err := provider.GetUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	ia := a.internalAdapter

	account, err := ia.FindAccountByProviderAndID(ctx, providerID, oauthUser.ID)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	var userID string
	if account != nil {
		userID = account.UserID
	} else {
		user, err := ia.FindUserByEmail(ctx, oauthUser.Email)
		if err != nil {
			ErrInternal.WriteJSON(w)
			return
		}
		if user == nil {
			user, err = ia.CreateUser(ctx, oauthUser.Email, oauthUser.Name, oauthUser.EmailVerified)
			if err != nil {
				ErrInternal.WriteJSON(w)
				return
			}
		}
		userID = user.ID

		extra := map[string]any{}
		if tokens.AccessToken != "" {
			extra["access_token"] = tokens.AccessToken
		}
		if tokens.RefreshToken != "" {
			extra["refresh_token"] = tokens.RefreshToken
		}
		if tokens.IDToken != "" {
			extra["id_token"] = tokens.IDToken
		}
		if _, err = ia.CreateAccount(ctx, userID, oauthUser.ID, providerID, extra); err != nil {
			ErrInternal.WriteJSON(w)
			return
		}
	}

	_ = providerCfg

	ip := internal.GetClientIP(r, "")
	ua := r.UserAgent()
	sess, err := a.sessionManager.Create(ctx, userID, ip, ua)
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, a.isSecure())

	redirectURL := stateEntry.CallbackURL
	if redirectURL == "" {
		redirectURL = a.opts.BaseURL
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (a *Auth) handleLinkSocial(w http.ResponseWriter, r *http.Request) {
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
		Provider    string `json:"provider"`
		CallbackURL string `json:"callbackURL"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	providerCfg, ok := a.opts.SocialProviders[req.Provider]
	if !ok {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	provider := a.SocialProvider(req.Provider)
	if provider == nil {
		ErrOAuthProviderNotFound.WriteJSON(w)
		return
	}

	state, err := a.stateStore.Generate(req.CallbackURL, "")
	if err != nil {
		ErrInternal.WriteJSON(w)
		return
	}

	authURL := provider.AuthorizationURL(state, "", providerCfg)
	writeJSON(w, http.StatusOK, map[string]string{"url": authURL})
}
