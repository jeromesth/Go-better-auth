// Package httputil provides small HTTP response helpers shared by the core
// library and its plugins.
package httputil

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes v as JSON with the given status. Encoding errors are silently
// swallowed — they can only happen if the caller passed a value that can't be
// marshalled, which is a programming error, not a runtime one.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes a standard error envelope: {"code": code, "message": message}.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]string{"code": code, "message": message})
}

// DecodeJSON decodes the request body into v. The caller is responsible for
// handling any error (e.g., by calling WriteError).
func DecodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
