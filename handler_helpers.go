package betterauth

import (
	"net/http"

	"github.com/jeromesth/go-better-auth/internal/httputil"
)

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	httputil.WriteJSON(w, status, v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	httputil.WriteError(w, status, code, message)
}

// decodeJSON decodes the request body into v.
// Returns false and writes a 400 error if decoding fails.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := httputil.DecodeJSON(r, v); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return false
	}
	return true
}
