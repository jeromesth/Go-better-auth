package internal

import (
	"net/url"
	"strings"
)

// IsTrustedOrigin checks whether the given origin is in the trusted list.
// It also handles localhost variations automatically.
func IsTrustedOrigin(origin string, trustedOrigins []string, baseURL string) bool {
	if origin == "" {
		return true
	}

	// Always trust same-origin requests.
	if baseURL != "" && strings.HasPrefix(origin, baseURL) {
		return true
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	for _, trusted := range trustedOrigins {
		if trusted == origin {
			return true
		}
		// Support wildcard subdomains: *.example.com
		if strings.HasPrefix(trusted, "*.") {
			domain := trusted[2:]
			if strings.HasSuffix(host, "."+domain) || host == domain {
				return true
			}
		}
	}
	return false
}

// ValidateCallbackURL ensures the callback URL is within trusted origins.
func ValidateCallbackURL(callbackURL string, trustedOrigins []string, baseURL string) bool {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return false
	}
	origin := u.Scheme + "://" + u.Host
	return IsTrustedOrigin(origin, trustedOrigins, baseURL)
}
