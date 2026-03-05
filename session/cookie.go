package session

import (
	"net/http"
	"time"
)

const (
	sessionCookieName = "better-auth.session_token"
	cookiePath        = "/"
)

// SetSessionCookie writes the session token as an HTTP-only cookie.
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     cookiePath,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie removes the session cookie by setting MaxAge to -1.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// GetSessionToken extracts the session token from the request cookie or
// the Authorization: Bearer header (in that preference order).
func GetSessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	// Fall back to Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
