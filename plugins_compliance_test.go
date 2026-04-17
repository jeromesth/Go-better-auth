package betterauth_test

import (
	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/admin"
	"github.com/jeromesth/go-better-auth/plugins/anonymous"
	"github.com/jeromesth/go-better-auth/plugins/apikey"
	"github.com/jeromesth/go-better-auth/plugins/emailotp"
	"github.com/jeromesth/go-better-auth/plugins/jwt"
	"github.com/jeromesth/go-better-auth/plugins/magiclink"
	"github.com/jeromesth/go-better-auth/plugins/multisession"
	"github.com/jeromesth/go-better-auth/plugins/organization"
	"github.com/jeromesth/go-better-auth/plugins/totp"
	"github.com/jeromesth/go-better-auth/plugins/username"
)

// Compile-time assertions that every built-in plugin satisfies
// plugin.AuthAware[*betterauth.Auth]. A plugin with a stale
// SetAuth(auth any) signature would silently be skipped at runtime
// (see auth.go's AuthAware type assertion), so we catch drift here.
var (
	_ plugin.AuthAware[*betterauth.Auth] = (*admin.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*anonymous.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*apikey.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*emailotp.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*jwt.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*magiclink.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*multisession.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*organization.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*totp.Plugin)(nil)
	_ plugin.AuthAware[*betterauth.Auth] = (*username.Plugin)(nil)
)
