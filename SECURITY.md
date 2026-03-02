# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Go Better Auth, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@go-better-auth.dev**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **72 hours** - Initial acknowledgment
- **7 days** - Assessment and severity classification
- **90 days** - Coordinated disclosure deadline

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
