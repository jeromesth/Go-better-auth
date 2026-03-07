// Package ginauth provides a Gin router adapter for go-better-auth.
package ginauth

import (
	"github.com/gin-gonic/gin"
	betterauth "github.com/jeromesth/go-better-auth"
)

// Mount registers all auth routes under path in the given Gin engine.
// Example: ginauth.Mount(r, "/auth", authInstance)
func Mount(r *gin.Engine, path string, auth *betterauth.Auth) {
	r.Any(path+"/*action", gin.WrapH(auth.Handler()))
}
