package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/session"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// handleRegisterBegin starts a WebAuthn registration ceremony for the authenticated user.
// POST /passkey/register/begin
func (p *Plugin) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if p.webauthn == nil {
		writeError(w, http.StatusInternalServerError, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not configured")
		return
	}

	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	waUser, err := p.getWebAuthnUser(ctx, userID)
	if err != nil || waUser == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}

	// Build exclude list from existing credentials.
	excludeList := make([]protocol.CredentialDescriptor, 0, len(waUser.Credentials))
	for _, cred := range waUser.Credentials {
		excludeList = append(excludeList, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
			Transport:    cred.Transport,
		})
	}

	opts, sessionData, err := p.webauthn.BeginRegistration(
		waUser,
		webauthn.WithExclusions(excludeList),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "REGISTRATION_ERROR", "Failed to begin registration")
		return
	}

	// Store the session data as a challenge in the verification table.
	identifier := regIdentPrefix + userID
	// Delete any existing challenge for this user first.
	p.deleteChallenge(ctx, identifier)
	if err := p.storeChallenge(ctx, identifier, sessionData); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store challenge")
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// handleRegisterFinish completes a WebAuthn registration ceremony.
// POST /passkey/register/finish
func (p *Plugin) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if p.webauthn == nil {
		writeError(w, http.StatusInternalServerError, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not configured")
		return
	}

	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	waUser, err := p.getWebAuthnUser(ctx, userID)
	if err != nil || waUser == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}

	// Retrieve stored challenge.
	identifier := regIdentPrefix + userID
	sessionData, err := p.loadChallenge(ctx, identifier)
	if err != nil || sessionData == nil {
		writeError(w, http.StatusBadRequest, "INVALID_CHALLENGE", "No pending registration challenge found")
		return
	}

	// Parse and verify the attestation response from the request body.
	credential, err := p.webauthn.FinishRegistration(waUser, *sessionData, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "VERIFICATION_FAILED", "Registration verification failed: "+err.Error())
		return
	}

	// Clean up challenge.
	p.deleteChallenge(ctx, identifier)

	// Encode credential data for storage.
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	publicKey := base64.RawURLEncoding.EncodeToString(credential.PublicKey)

	// Serialize transports as JSON.
	var transportsJSON string
	if len(credential.Transport) > 0 {
		ts := make([]string, 0, len(credential.Transport))
		for _, t := range credential.Transport {
			ts = append(ts, string(t))
		}
		b, _ := json.Marshal(ts)
		transportsJSON = string(b)
	}

	// Parse optional name from request body (re-read is not possible, use query param or header).
	passkeyName := r.URL.Query().Get("name")
	if passkeyName == "" {
		passkeyName = "Passkey"
	}

	passkeyID := internal.NewID()
	now := time.Now().UTC()

	// Determine device type from backup eligibility.
	deviceType := "single_device"
	if credential.Flags.BackupEligible {
		deviceType = "multi_device"
	}

	if err := p.createPasskey(ctx, map[string]any{
		"id":            passkeyID,
		"user_id":       userID,
		"credential_id": credentialID,
		"public_key":    publicKey,
		"counter":       int(credential.Authenticator.SignCount),
		"device_type":   deviceType,
		"backed_up":     credential.Flags.BackupState,
		"transports":    transportsJSON,
		"name":          passkeyName,
		"created_at":    now,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store passkey")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          passkeyID,
		"name":        passkeyName,
		"device_type": deviceType,
		"created_at":  now,
	})
}

// handleLoginBegin starts a WebAuthn authentication ceremony.
// POST /passkey/login/begin
func (p *Plugin) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if p.webauthn == nil {
		writeError(w, http.StatusInternalServerError, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not configured")
		return
	}

	ctx := r.Context()

	// Optionally accept an email to find the user for non-discoverable credentials.
	var req struct {
		Email string `json:"email"`
	}
	// Body is optional; ignore decode errors.
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	var opts *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error

	// Look up the user's credentials when an email is supplied, but fall back
	// to the discoverable flow if the user is unknown or has no passkeys.
	// Returning the same shape in every branch keeps responses indistinguishable
	// and avoids leaking account existence, matching the pattern in
	// handler_password.go, plugins/magiclink, and plugins/emailotp.
	var waUser *WebAuthnUser
	if req.Email != "" {
		user, findErr := p.auth.InternalAdapter().FindUserByEmail(ctx, req.Email)
		if findErr == nil && user != nil {
			if u, getErr := p.getWebAuthnUser(ctx, user.ID); getErr == nil && u != nil && len(u.Credentials) > 0 {
				waUser = u
			}
		}
	}

	if waUser != nil {
		opts, sessionData, err = p.webauthn.BeginLogin(waUser)
	} else {
		opts, sessionData, err = p.webauthn.BeginDiscoverableLogin()
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, "LOGIN_ERROR", "Failed to begin login: "+err.Error())
		return
	}

	// Store challenge using challenge string as part of the identifier.
	identifier := authIdentPrefix + sessionData.Challenge

	if storeErr := p.storeChallenge(ctx, identifier, sessionData); storeErr != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store challenge")
		return
	}

	writeJSON(w, http.StatusOK, opts)
}

// handleLoginFinish completes a WebAuthn authentication ceremony.
// POST /passkey/login/finish
func (p *Plugin) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	if p.webauthn == nil {
		writeError(w, http.StatusInternalServerError, "WEBAUTHN_NOT_CONFIGURED", "WebAuthn is not configured")
		return
	}

	ctx := r.Context()

	// Parse the assertion response to extract the challenge.
	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RESPONSE", "Failed to parse assertion response: "+err.Error())
		return
	}

	// The challenge is in the client data (already base64url-encoded string).
	identifier := authIdentPrefix + parsedResponse.Response.CollectedClientData.Challenge

	sessionData, loadErr := p.loadChallenge(ctx, identifier)
	if loadErr != nil || sessionData == nil {
		writeError(w, http.StatusBadRequest, "INVALID_CHALLENGE", "No pending login challenge found")
		return
	}

	// Clean up challenge immediately.
	p.deleteChallenge(ctx, identifier)

	var userID string
	var credential *webauthn.Credential

	if sessionData.UserID != nil && len(sessionData.UserID) > 0 {
		// Non-discoverable flow: we know the user.
		userIDStr := string(sessionData.UserID)
		waUser, getErr := p.getWebAuthnUser(ctx, userIDStr)
		if getErr != nil || waUser == nil {
			writeError(w, http.StatusUnauthorized, "USER_NOT_FOUND", "User not found")
			return
		}

		credential, err = p.webauthn.ValidateLogin(waUser, *sessionData, parsedResponse)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "Authentication failed: "+err.Error())
			return
		}
		userID = userIDStr
	} else {
		// Discoverable credential flow: look up user by credential.
		credential, err = p.webauthn.ValidateDiscoverableLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				uid := string(userHandle)
				waUser, getErr := p.getWebAuthnUser(ctx, uid)
				if getErr != nil || waUser == nil {
					return nil, getErr
				}
				userID = uid
				return waUser, nil
			},
			*sessionData,
			parsedResponse,
		)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "Authentication failed: "+err.Error())
			return
		}
	}

	// Update counter for the matched credential.
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	passkeyRec, findErr := p.findPasskeyByCredentialID(ctx, credentialIDStr)
	if findErr == nil && passkeyRec != nil {
		passkeyID, _ := passkeyRec["id"].(string)
		_ = p.updatePasskeyCounter(ctx, passkeyID, credential.Authenticator.SignCount)
	}

	// Run session-create hooks (e.g., multi-session limits).
	if err := p.auth.RunSessionCreateHooks(w, r, userID); err != nil {
		if !errors.Is(err, plugin.ErrHandled) {
			writeError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		}
		return
	}

	// Create a session for the user.
	ip := internal.GetClientIP(r, p.auth.IPHeader())
	ua := r.UserAgent()
	sess, err := p.auth.SessionManager().Create(ctx, userID, ip, ua)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	user, err := p.auth.InternalAdapter().FindUserByID(ctx, userID)
	if err != nil || user == nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load user")
		return
	}

	session.SetSessionCookie(w, sess.Token, sess.ExpiresAt, p.auth.IsSecure())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    user,
		"session": sess,
	})
}

// handleList returns the authenticated user's registered passkeys.
// GET /passkey/list
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request) {
	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	records, err := p.findPasskeysByUserID(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list passkeys")
		return
	}

	passkeys := make([]map[string]any, 0, len(records))
	for _, rec := range records {
		passkeys = append(passkeys, map[string]any{
			"id":          rec["id"],
			"name":        rec["name"],
			"device_type": rec["device_type"],
			"backed_up":   rec["backed_up"],
			"created_at":  rec["created_at"],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"passkeys": passkeys})
}

// handleDeletePasskey removes a passkey belonging to the authenticated user.
// DELETE /passkey/{id}
func (p *Plugin) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := p.getAuthenticatedUserID(w, r)
	if !ok {
		return
	}

	passkeyID := extractPasskeyID(r.URL.Path)
	if passkeyID == "" || passkeyID == "passkey" {
		writeError(w, http.StatusBadRequest, "MISSING_ID", "Passkey ID is required")
		return
	}

	ctx := r.Context()
	if err := p.deletePasskey(ctx, passkeyID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete passkey")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
