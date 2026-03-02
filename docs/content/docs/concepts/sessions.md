# Sessions

Go Better Auth uses token-based sessions stored in the database. Session tokens are delivered via HTTP-only cookies or Bearer tokens.

## How Sessions Work

1. On successful authentication, a cryptographically random session token is generated
2. The session is stored in the database with an expiry time
3. The token is set as an HTTP-only cookie (`better-auth.session_token`)
4. Subsequent requests include the cookie automatically
5. The server validates the token and resolves the session + user

## Session Lifecycle

### Creation
Sessions are created on sign-up (if `AutoSignIn` is enabled), sign-in, and OAuth callback.

### Refresh
By default, sessions are refreshed when accessed after `UpdateAge` seconds (default: 1 day). This extends the expiry without requiring re-authentication.

### Expiry
Sessions expire after `ExpiresIn` seconds (default: 7 days). Expired sessions return `null` from the get-session endpoint.

### Revocation
Sessions can be explicitly revoked via:
- `POST /sign-out` - revokes the current session
- `POST /revoke-session` - revokes a specific session by ID
- `POST /revoke-other-sessions` - revokes all sessions except the current one

## API Endpoints

### Get Session

```
GET /api/auth/get-session
```

Returns the current user and session, or `null` if not authenticated.

### List Sessions

```
GET /api/auth/list-sessions
```

Returns all active sessions for the current user.

## Bearer Token Support

For API clients that cannot use cookies, include the session token in the `Authorization` header:

```
Authorization: Bearer <session-token>
```
