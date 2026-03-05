package betterauth

import (
	"net/http"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/models"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/social"
)

// GenerateIDFn is a function that generates a unique ID for a given model.
type GenerateIDFn func(model string) string

// BetterAuthOptions is the main configuration struct for the auth system.
type BetterAuthOptions struct {
	AppName           string
	BaseURL           string
	BasePath          string // default: "/api/auth"
	Secret            string
	Database          *DatabaseConfig
	SecondaryStorage  SecondaryStorage
	EmailVerification *EmailVerifConfig
	EmailAndPassword  *EmailPassConfig
	SocialProviders   map[string]social.ProviderConfig
	Plugins           []plugin.Plugin
	User              *UserConfig
	Session           *SessionConfig
	Account           *AccountConfig
	RateLimit         *RateLimitConfig
	Advanced          *AdvancedConfig
	TrustedOrigins    []string
	Logger            Logger
}

// DatabaseConfig configures the database adapter and related settings.
type DatabaseConfig struct {
	Adapter              adapter.Adapter
	DefaultFindManyLimit int
	GenerateID           GenerateIDFn
}

// SecondaryStorage is an optional key-value store for session caching.
type SecondaryStorage interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte, ttl int) error
	Delete(key string) error
}

// SessionConfig configures session behavior.
type SessionConfig struct {
	ExpiresIn             int // seconds, default 604800 (7 days)
	UpdateAge             int // seconds, default 86400 (1 day)
	FreshAge              int // seconds, default 86400
	DisableSessionRefresh bool
	CookieCache           *CookieCacheConfig
	ModelName             string
	Fields                map[string]string
	AdditionalFields      map[string]FieldAttribute
}

// CookieCacheConfig configures cookie-based session caching.
type CookieCacheConfig struct {
	Enabled bool
	MaxAge  int // seconds
}

// FieldAttribute describes a schema field for plugin/extension purposes.
type FieldAttribute struct {
	Type     string
	Required bool
	Unique   bool
}

// EmailPassConfig configures email/password authentication.
type EmailPassConfig struct {
	Enabled                  bool
	DisableSignUp            bool
	RequireEmailVerification bool
	MaxPasswordLength        int // default 128
	MinPasswordLength        int // default 8
	AutoSignIn               bool
	RevokeSessionsOnReset    bool
	SendResetPassword        func(data ResetPasswordData, r *http.Request) error
	OnPasswordReset          func(data models.User, r *http.Request) error
	Password                 *PasswordHashConfig
}

// ResetPasswordData is passed to the SendResetPassword callback.
type ResetPasswordData struct {
	User  models.User
	URL   string
	Token string
}

// PasswordHashConfig allows plugging in a custom password hasher.
type PasswordHashConfig struct {
	Hash   func(password string) (string, error)
	Verify func(hash, password string) (bool, error)
}

// EmailVerifConfig configures email verification behavior.
type EmailVerifConfig struct {
	SendOnSignUp                bool
	AutoSignInAfterVerification bool
	SendVerificationEmail       func(data EmailVerificationData, r *http.Request) error
}

// EmailVerificationData is passed to the SendVerificationEmail callback.
type EmailVerificationData struct {
	User  models.User
	URL   string
	Token string
}

// UserConfig configures user model behavior.
type UserConfig struct {
	ModelName        string
	Fields           map[string]string
	AdditionalFields map[string]FieldAttribute
	ChangeEmail      *ChangeEmailConfig
	DeleteUser       *DeleteUserConfig
}

// ChangeEmailConfig configures the change-email flow.
type ChangeEmailConfig struct {
	Enabled                     bool
	SendChangeEmailVerification func(data ChangeEmailData, r *http.Request) error
}

// ChangeEmailData is passed to the SendChangeEmailVerification callback.
type ChangeEmailData struct {
	User     models.User
	NewEmail string
	URL      string
	Token    string
}

// DeleteUserConfig configures the delete-user flow.
type DeleteUserConfig struct {
	Enabled                       bool
	SendDeleteAccountVerification func(data DeleteAccountData, r *http.Request) error
	BeforeDelete                  func(user models.User, r *http.Request) error
	AfterDelete                   func(user models.User, r *http.Request) error
}

// DeleteAccountData is passed to the SendDeleteAccountVerification callback.
type DeleteAccountData struct {
	User  models.User
	URL   string
	Token string
}

// AccountConfig configures the account model.
type AccountConfig struct {
	ModelName        string
	Fields           map[string]string
	AdditionalFields map[string]FieldAttribute
	AccountLinking   *AccountLinkingConfig
}

// AccountLinkingConfig configures account linking behavior.
type AccountLinkingConfig struct {
	Enabled              bool
	TrustedProviders     []string
	AllowDifferentEmails bool
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	Window      int    // seconds
	Max         int    // max requests per window
	Storage     string // "memory" or "database"
	Enabled     bool
	CustomRules []RateLimitRule
}

// RateLimitRule defines a custom rate limit rule for a specific path.
type RateLimitRule struct {
	PathMatcher string // path prefix or exact match
	Window      int
	Max         int
}

// AdvancedConfig contains advanced/internal configuration options.
type AdvancedConfig struct {
	UseSecureCookies        bool
	CookiePrefix            string
	DefaultCookieAttributes *CookieAttributes
	CrossSubDomainCookies   *CrossSubDomainCookiesConfig
	GenerateID              GenerateIDFn
	IPHeader                string
	DisableCSRFCheck        bool
}

// CookieAttributes configures cookie properties.
type CookieAttributes struct {
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
	Path     string
	Domain   string
}

// CrossSubDomainCookiesConfig enables cookies shared across subdomains.
type CrossSubDomainCookiesConfig struct {
	Enabled           bool
	Domain            string
	AdditionalCookies []string
}

// Logger is an interface for logging within the auth system.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// defaultOptions returns a BetterAuthOptions with sensible defaults applied.
func defaultOptions() BetterAuthOptions {
	return BetterAuthOptions{
		AppName:  "Better Auth",
		BasePath: "/api/auth",
		Session: &SessionConfig{
			ExpiresIn: 7 * 24 * 60 * 60, // 7 days
			UpdateAge: 24 * 60 * 60,     // 1 day
			FreshAge:  24 * 60 * 60,     // 1 day
		},
		EmailAndPassword: &EmailPassConfig{
			Enabled:           true,
			MaxPasswordLength: 128,
			MinPasswordLength: 8,
			AutoSignIn:        true,
		},
		RateLimit: &RateLimitConfig{
			Window:  10,
			Max:     100,
			Storage: "memory",
			Enabled: true,
		},
	}
}
