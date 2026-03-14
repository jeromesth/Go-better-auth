// Package fiberauth provides a Fiber router adapter for go-better-auth.
package fiberauth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	betterauth "github.com/jeromesth/go-better-auth"
)

// Mount registers all auth routes under path in the given Fiber app.
// It adapts the net/http handler from auth to Fiber's fasthttp-based handler.
// Example: fiberauth.Mount(app, "/auth", authInstance)
func Mount(app *fiber.App, path string, auth *betterauth.Auth) {
	app.All(path+"/*", adaptor.HTTPHandler(auth.Handler()))
}
