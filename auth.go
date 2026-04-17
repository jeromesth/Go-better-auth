// Package betterauth is a Go port of the better-auth TypeScript library.
// It provides a pluggable, self-hosted authentication server with support
// for email/password, social OAuth, session management, and a plugin system.
package betterauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/oauth"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/ratelimit"
	"github.com/jeromesth/go-better-auth/session"
	"github.com/jeromesth/go-better-auth/social"
)

// Auth is the main entry point for go-better-auth.
// Create one with New() and mount its Handler() on your HTTP server.
type Auth struct {
	opts               BetterAuthOptions
	internalAdapter    *InternalAdapter
	sessionManager     *session.Manager
	stateStore         *oauth.StateStore
	rateLimiter        *ratelimit.RateLimiter
	socialProviders    map[string]social.SocialProvider
	handler            http.Handler
	sessionCreateHooks []plugin.SessionCreateHookFn
	userCreateHooks    []plugin.UserCreateHookFn
}

// New creates a new Auth instance with the provided options.
// Sensible defaults are applied for any unset fields.
//
// New panics if any plugin's Init method returns an error. Plugin initialization
// failures indicate a programming error (misconfiguration, missing dependency)
// rather than a recoverable runtime condition, so panicking at startup is
// preferable to returning a silently broken Auth instance. Wrap the call in a
// recover if you need to handle Init failures gracefully:
//
//	func newAuth(opts BetterAuthOptions) (a *Auth, err error) {
//	    defer func() {
//	        if r := recover(); r != nil {
//	            err = fmt.Errorf("auth init failed: %v", r)
//	        }
//	    }()
//	    return New(opts), nil
//	}
func New(opts BetterAuthOptions) *Auth {
	defaults := defaultOptions()

	if opts.AppName == "" {
		opts.AppName = defaults.AppName
	}
	if opts.BasePath == "" {
		opts.BasePath = defaults.BasePath
	}
	if opts.Session == nil {
		opts.Session = defaults.Session
	}
	if opts.EmailAndPassword == nil {
		opts.EmailAndPassword = defaults.EmailAndPassword
	}
	if opts.RateLimit == nil {
		opts.RateLimit = defaults.RateLimit
	}

	a := &Auth{
		opts:       opts,
		stateStore: oauth.NewStateStore(),
	}

	// Set up internal adapter.
	var generateID GenerateIDFn
	if opts.Database != nil && opts.Database.GenerateID != nil {
		generateID = opts.Database.GenerateID
	}
	if opts.Database != nil {
		a.internalAdapter = newInternalAdapter(opts.Database.Adapter, generateID)
	}

	// Set up session manager.
	expiresIn := 604800
	updateAge := 86400
	if opts.Session != nil {
		if opts.Session.ExpiresIn > 0 {
			expiresIn = opts.Session.ExpiresIn
		}
		if opts.Session.UpdateAge > 0 {
			updateAge = opts.Session.UpdateAge
		}
	}
	if opts.Database != nil {
		a.sessionManager = session.NewManager(opts.Database.Adapter, expiresIn, updateAge)
	}

	// Set up rate limiter.
	if opts.RateLimit != nil && opts.RateLimit.Enabled {
		a.rateLimiter = ratelimit.New(ratelimit.Config{
			Limit:  opts.RateLimit.Max,
			Window: time.Duration(opts.RateLimit.Window) * time.Second,
		})
	}

	// Register built-in social providers.
	a.socialProviders = map[string]social.SocialProvider{
		"google":    social.Google{},
		"github":    social.GitHub{},
		"apple":     social.Apple{},
		"microsoft": social.Microsoft{},
		"slack":     social.Slack{},
		"gitlab":    social.GitLab{},
		"discord":   social.Discord{},
		"twitter":   social.Twitter{},
		"linkedin":  social.LinkedIn{},
		"facebook":  social.Facebook{},
	}

	// Pass auth reference to AuthAware plugins before initialization.
	for _, p := range opts.Plugins {
		if aware, ok := p.(plugin.AuthAware); ok {
			aware.SetAuth(a)
		}
	}

	// Collect plugin hooks.
	for _, p := range opts.Plugins {
		if sh, ok := p.(plugin.SessionCreateHookProvider); ok {
			a.sessionCreateHooks = append(a.sessionCreateHooks, sh.SessionCreateHooks()...)
		}
		if uh, ok := p.(plugin.UserCreateHookProvider); ok {
			a.userCreateHooks = append(a.userCreateHooks, uh.UserCreateHooks()...)
		}
	}

	// Initialize plugins. Any Init error is treated as a programming error
	// (misconfiguration, missing dependency) and panics immediately rather than
	// allowing a partially configured Auth instance to be returned to the caller.
	for _, p := range opts.Plugins {
		if initializer, ok := p.(plugin.Initializer); ok {
			if _, err := initializer.Init(); err != nil {
				panic(fmt.Sprintf("go-better-auth: plugin %q initialization failed: %v", p.ID(), err))
			}
		}
	}

	// Build the HTTP router.
	a.handler = a.buildRouter()

	// Wrap with rate limiter if enabled.
	if a.rateLimiter != nil {
		a.handler = a.rateLimiter.Middleware(a.handler)
	}

	return a
}

// RunSessionCreateHooks runs all registered session-create hooks.
// Returns an error if any hook rejects the session creation.
func (a *Auth) RunSessionCreateHooks(w http.ResponseWriter, r *http.Request, userID string) error {
	for _, hook := range a.sessionCreateHooks {
		if err := hook(plugin.SessionCreateContext{
			UserID:  userID,
			Request: r,
			Writer:  w,
		}); err != nil {
			return err
		}
	}
	return nil
}

// RunUserCreateHooks runs all registered user-create hooks on the data map.
func (a *Auth) RunUserCreateHooks(data map[string]any) map[string]any {
	for _, hook := range a.userCreateHooks {
		data = hook(data)
	}
	return data
}

// buildRouter creates the HTTP mux with all auth endpoints registered.
func (a *Auth) buildRouter() http.Handler {
	mux := http.NewServeMux()
	bp := strings.TrimRight(a.opts.BasePath, "/")

	register := func(method, path string, h http.HandlerFunc) {
		mux.HandleFunc(bp+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != method {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		})
	}

	// Email + password
	register(http.MethodPost, "/sign-up/email", a.handleSignUpEmail)
	register(http.MethodPost, "/sign-in/email", a.handleSignInEmail)
	register(http.MethodPost, "/sign-out", a.handleSignOut)

	// Session
	mux.HandleFunc(bp+"/get-session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleGetSession(w, r)
	})
	register(http.MethodGet, "/list-sessions", a.handleListSessions)
	register(http.MethodPost, "/revoke-session", a.handleRevokeSession)
	register(http.MethodPost, "/revoke-other-sessions", a.handleRevokeOtherSessions)

	// Password
	register(http.MethodPost, "/change-password", a.handleChangePassword)
	register(http.MethodPost, "/request-password-reset", a.handleRequestPasswordReset)
	register(http.MethodPost, "/reset-password", a.handleResetPassword)

	// Email verification
	register(http.MethodPost, "/send-verification-email", a.handleSendVerificationEmail)
	register(http.MethodGet, "/verify-email", a.handleVerifyEmail)

	// User management
	register(http.MethodPost, "/update-user", a.handleUpdateUser)
	register(http.MethodPost, "/delete-user", a.handleDeleteUser)

	// OAuth - use prefix matching for dynamic provider paths
	mux.HandleFunc(bp+"/sign-in/", a.handleOAuthSignIn)
	mux.HandleFunc(bp+"/callback/", a.handleOAuthCallback)
	register(http.MethodPost, "/link-social", a.handleLinkSocial)

	// Plugin endpoints
	for _, p := range a.opts.Plugins {
		if ep, ok := p.(plugin.EndpointProvider); ok {
			for _, e := range ep.Endpoints() {
				full := bp + e.Path
				mux.HandleFunc(full, e.Handler)
			}
		}
	}

	return mux
}

// IsSecure returns true if cookies should be set with Secure flag.
func (a *Auth) IsSecure() bool {
	if a.opts.Advanced != nil {
		return a.opts.Advanced.UseSecureCookies
	}
	return strings.HasPrefix(a.opts.BaseURL, "https://")
}

// IPHeader returns the HTTP header used to extract the client IP address.
func (a *Auth) IPHeader() string {
	if a.opts.Advanced != nil {
		return a.opts.Advanced.IPHeader
	}
	return ""
}

// Handler returns the http.Handler that serves all auth endpoints.
// Mount this at your chosen base path:
//
//	http.Handle("/api/auth/", auth.Handler())
func (a *Auth) Handler() http.Handler {
	return a.handler
}

// Options returns the resolved configuration options.
func (a *Auth) Options() *BetterAuthOptions {
	return &a.opts
}

// InternalAdapter returns the typed internal adapter.
func (a *Auth) InternalAdapter() *InternalAdapter {
	return a.internalAdapter
}

// SessionManager returns the session manager.
func (a *Auth) SessionManager() *session.Manager {
	return a.sessionManager
}

// StateStore returns the OAuth state store.
func (a *Auth) StateStore() *oauth.StateStore {
	return a.stateStore
}

// SocialProvider returns the registered provider for the given ID, or nil.
func (a *Auth) SocialProvider(id string) social.SocialProvider {
	return a.socialProviders[id]
}

// RegisterSocialProvider adds or replaces a social provider by its ID.
func (a *Auth) RegisterSocialProvider(p social.SocialProvider) {
	a.socialProviders[p.ID()] = p
}
