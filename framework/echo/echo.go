// Package echoauth provides an Echo router adapter for go-better-auth.
package echoauth

import (
	"github.com/labstack/echo/v4"

	betterauth "github.com/jeromesth/go-better-auth"
)

// Mount registers all auth routes under path in the given Echo instance.
// Example: echoauth.Mount(e, "/auth", authInstance)
func Mount(e *echo.Echo, path string, auth *betterauth.Auth) {
	e.Any(path+"/*", echo.WrapHandler(auth.Handler()))
}
