# Security Policy

## Reporting a Vulnerability

This is a portfolio/learning project. For any security concerns, please open a [GitHub issue](https://github.com/jeromesth/Go-better-auth/issues) or use GitHub's [private vulnerability reporting](https://github.com/jeromesth/Go-better-auth/security/advisories/new).

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Security Best Practices

When using Go Better Auth in production:

1. **Always set a strong `Secret`** - Use a cryptographically random string of at least 32 bytes
2. **Use HTTPS** - Set `UseSecureCookies: true` in `AdvancedConfig`
3. **Configure trusted origins** - Set `TrustedOrigins` to your domain(s)
4. **Enable rate limiting** - Enabled by default, do not disable in production
5. **Use a real database adapter** - The in-memory adapter is for development/testing only
6. **Keep dependencies updated** - Run `go get -u` regularly
