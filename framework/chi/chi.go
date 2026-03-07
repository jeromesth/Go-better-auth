// Package chiauth provides a Chi router adapter for go-better-auth.
package chiauth

import (
	"github.com/go-chi/chi/v5"
	betterauth "github.com/jeromesth/go-better-auth"
)

// Mount registers all auth routes under pattern in the given Chi router.
// Example: chiauth.Mount(r, "/auth", authInstance)
func Mount(r chi.Router, pattern string, auth *betterauth.Auth) {
	r.Mount(pattern, auth.Handler())
}
