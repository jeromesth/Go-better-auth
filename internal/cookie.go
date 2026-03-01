package internal

import (
	"net/http"
	"strings"
)

// SetCookie is a thin wrapper around http.SetCookie that returns the cookie
// header value (useful for testing and cookie caching).
func SetCookie(w http.ResponseWriter, cookie *http.Cookie) {
	http.SetCookie(w, cookie)
}

// GetCookieValue extracts the value of a named cookie from the request,
// returning an empty string if not found.
func GetCookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// ParseBearerToken extracts the token from an Authorization: Bearer <token> header.
func ParseBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
