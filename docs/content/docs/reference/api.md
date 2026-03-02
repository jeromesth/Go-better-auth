# API Reference

All endpoints are prefixed with the configured `BasePath` (default: `/api/auth`).

## Authentication Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sign-up/email` | No | Register with email/password |
| `POST` | `/sign-in/email` | No | Login with email/password |
| `POST` | `/sign-out` | Yes | Revoke current session |

## Session Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/get-session` | Yes | Get current session + user |
| `GET` | `/list-sessions` | Yes | List all active sessions |
| `POST` | `/revoke-session` | Yes | Revoke a specific session |
| `POST` | `/revoke-other-sessions` | Yes | Revoke all other sessions |

## Password Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/change-password` | Yes | Change password |
| `POST` | `/request-password-reset` | No | Send password reset email |
| `POST` | `/reset-password` | No | Reset password with token |

## Email Verification Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/send-verification-email` | No | Send verification email |
| `GET` | `/verify-email` | No | Verify email with token |

## User Management Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/update-user` | Yes | Update user profile |
| `POST` | `/delete-user` | Yes | Delete user account |

## OAuth Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/sign-in/{provider}` | No | Initiate OAuth flow |
| `GET` | `/callback/{provider}` | No | OAuth callback |
| `POST` | `/link-social` | Yes | Link social account |

## Error Responses

All errors are returned as JSON with a `code` and `message` field:

```json
{
    "code": "INVALID_PASSWORD",
    "message": "Invalid password"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `USER_NOT_FOUND` | 404 | User does not exist |
| `INVALID_EMAIL` | 400 | Invalid email format |
| `INVALID_PASSWORD` | 400 | Wrong password |
| `PASSWORD_TOO_SHORT` | 400 | Password below minimum length |
| `PASSWORD_TOO_LONG` | 400 | Password above maximum length |
| `EMAIL_ALREADY_USED` | 409 | Email already registered |
| `SIGN_UP_DISABLED` | 403 | Registration is disabled |
| `UNAUTHORIZED` | 401 | Not authenticated |
| `SESSION_EXPIRED` | 401 | Session has expired |
| `EMAIL_NOT_VERIFIED` | 403 | Email verification required |
| `TOKEN_EXPIRED` | 400 | Verification token expired |
| `INVALID_TOKEN` | 400 | Invalid verification token |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `CSRF_TOKEN_INVALID` | 403 | Invalid CSRF/OAuth state |
