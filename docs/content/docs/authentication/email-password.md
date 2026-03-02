# Email & Password Authentication

Email/password is the most common authentication method. Go Better Auth provides registration, login, password reset, and password change flows out of the box.

## Setup

```go
auth := betterauth.New(betterauth.BetterAuthOptions{
    // ...
    EmailAndPassword: &betterauth.EmailPassConfig{
        Enabled: true,
    },
})
```

## API Endpoints

### Sign Up

```
POST /api/auth/sign-up/email
```

```json
{
    "email": "user@example.com",
    "password": "securepassword",
    "name": "John Doe"
}
```

### Sign In

```
POST /api/auth/sign-in/email
```

```json
{
    "email": "user@example.com",
    "password": "securepassword"
}
```

### Change Password

Requires an active session.

```
POST /api/auth/change-password
```

```json
{
    "currentPassword": "oldpassword",
    "newPassword": "newpassword",
    "revokeOtherSessions": true
}
```

### Request Password Reset

```
POST /api/auth/request-password-reset
```

```json
{
    "email": "user@example.com",
    "redirectURI": "https://myapp.com/reset-password"
}
```

### Reset Password

```
POST /api/auth/reset-password
```

```json
{
    "token": "reset-token-from-email",
    "newPassword": "newsecurepassword"
}
```

## Custom Password Hashing

By default, Go Better Auth uses scrypt for password hashing. You can provide a custom hasher:

```go
EmailAndPassword: &betterauth.EmailPassConfig{
    Enabled: true,
    Password: &betterauth.PasswordHashConfig{
        Hash: func(password string) (string, error) {
            // Your custom hashing logic
        },
        Verify: func(hash, password string) (bool, error) {
            // Your custom verification logic
        },
    },
},
```
