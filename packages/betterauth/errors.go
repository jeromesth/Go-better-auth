package betterauth

import (
	"encoding/json"
	"net/http"
)

// APIError represents an error returned as a JSON HTTP response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string {
	return e.Message
}

// WriteJSON writes the error as a JSON response.
func (e *APIError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}

// Predefined errors matching better-auth error codes.
var (
	ErrUserNotFound          = &APIError{Code: "USER_NOT_FOUND", Message: "User not found", Status: http.StatusNotFound}
	ErrInvalidEmail          = &APIError{Code: "INVALID_EMAIL", Message: "Invalid email address", Status: http.StatusBadRequest}
	ErrInvalidPassword       = &APIError{Code: "INVALID_PASSWORD", Message: "Invalid password", Status: http.StatusBadRequest}
	ErrPasswordTooShort      = &APIError{Code: "PASSWORD_TOO_SHORT", Message: "Password is too short", Status: http.StatusBadRequest}
	ErrPasswordTooLong       = &APIError{Code: "PASSWORD_TOO_LONG", Message: "Password is too long", Status: http.StatusBadRequest}
	ErrEmailAlreadyUsed      = &APIError{Code: "EMAIL_ALREADY_USED", Message: "Email is already in use", Status: http.StatusConflict}
	ErrSignUpDisabled        = &APIError{Code: "SIGN_UP_DISABLED", Message: "Sign up is disabled", Status: http.StatusForbidden}
	ErrSessionExpired        = &APIError{Code: "SESSION_EXPIRED", Message: "Session has expired", Status: http.StatusUnauthorized}
	ErrUnauthorized          = &APIError{Code: "UNAUTHORIZED", Message: "Unauthorized", Status: http.StatusUnauthorized}
	ErrEmailNotVerified      = &APIError{Code: "EMAIL_NOT_VERIFIED", Message: "Email is not verified", Status: http.StatusForbidden}
	ErrTokenExpired          = &APIError{Code: "TOKEN_EXPIRED", Message: "Token has expired", Status: http.StatusBadRequest}
	ErrInvalidToken          = &APIError{Code: "INVALID_TOKEN", Message: "Invalid token", Status: http.StatusBadRequest}
	ErrRateLimitExceeded     = &APIError{Code: "RATE_LIMIT_EXCEEDED", Message: "Too many requests", Status: http.StatusTooManyRequests}
	ErrCSRFInvalid           = &APIError{Code: "CSRF_TOKEN_INVALID", Message: "CSRF token is invalid", Status: http.StatusForbidden}
	ErrInvalidCallbackURL    = &APIError{Code: "INVALID_CALLBACK_URL", Message: "Invalid callback URL", Status: http.StatusBadRequest}
	ErrOAuthProviderNotFound = &APIError{Code: "OAUTH_PROVIDER_NOT_FOUND", Message: "OAuth provider not found", Status: http.StatusBadRequest}
	ErrAccountNotFound       = &APIError{Code: "ACCOUNT_NOT_FOUND", Message: "Account not found", Status: http.StatusNotFound}
	ErrInternal              = &APIError{Code: "INTERNAL_ERROR", Message: "Internal server error", Status: http.StatusInternalServerError}
)

// NewAPIError creates a new APIError with the given code, message, and status.
func NewAPIError(code, message string, status int) *APIError {
	return &APIError{Code: code, Message: message, Status: status}
}
