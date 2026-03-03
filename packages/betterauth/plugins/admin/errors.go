package admin

import "net/http"

// AdminError represents an admin plugin error with code, message, and HTTP status.
type AdminError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *AdminError) Error() string {
	return e.Message
}

// Admin-specific error codes matching the TypeScript better-auth admin plugin.
var (
	ErrFailedToCreateUser = &AdminError{
		Code: "FAILED_TO_CREATE_USER", Message: "Failed to create user", Status: http.StatusInternalServerError}
	ErrUserAlreadyExists = &AdminError{
		Code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", Message: "User already exists. Use another email.", Status: http.StatusBadRequest}
	ErrCannotBanYourself = &AdminError{
		Code: "YOU_CANNOT_BAN_YOURSELF", Message: "You cannot ban yourself", Status: http.StatusBadRequest}
	ErrNotAllowedToChangeRole = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", Message: "You are not allowed to change users role", Status: http.StatusForbidden}
	ErrNotAllowedToCreateUsers = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS", Message: "You are not allowed to create users", Status: http.StatusForbidden}
	ErrNotAllowedToListUsers = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", Message: "You are not allowed to list users", Status: http.StatusForbidden}
	ErrNotAllowedToListSessions = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS", Message: "You are not allowed to list users sessions", Status: http.StatusForbidden}
	ErrNotAllowedToBan = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", Message: "You are not allowed to ban users", Status: http.StatusForbidden}
	ErrNotAllowedToImpersonate = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS", Message: "You are not allowed to impersonate users", Status: http.StatusForbidden}
	ErrNotAllowedToRevokeSessions = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", Message: "You are not allowed to revoke users sessions", Status: http.StatusForbidden}
	ErrNotAllowedToDelete = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS", Message: "You are not allowed to delete users", Status: http.StatusForbidden}
	ErrNotAllowedToSetPassword = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD", Message: "You are not allowed to set users password", Status: http.StatusForbidden}
	ErrBannedUser = &AdminError{
		Code: "BANNED_USER", Message: "You have been banned from this application", Status: http.StatusForbidden}
	ErrNotAllowedToGetUser = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_GET_USER", Message: "You are not allowed to get user", Status: http.StatusForbidden}
	ErrNoDataToUpdate = &AdminError{
		Code: "NO_DATA_TO_UPDATE", Message: "No data to update", Status: http.StatusBadRequest}
	ErrNotAllowedToUpdate = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS", Message: "You are not allowed to update users", Status: http.StatusForbidden}
	ErrCannotRemoveYourself = &AdminError{
		Code: "YOU_CANNOT_REMOVE_YOURSELF", Message: "You cannot remove yourself", Status: http.StatusBadRequest}
	ErrNonExistentRole = &AdminError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE", Message: "You are not allowed to set a non-existent role value", Status: http.StatusBadRequest}
	ErrCannotImpersonateAdmins = &AdminError{
		Code: "YOU_CANNOT_IMPERSONATE_ADMINS", Message: "You cannot impersonate admins", Status: http.StatusForbidden}
	ErrInvalidRoleType = &AdminError{
		Code: "INVALID_ROLE_TYPE", Message: "Invalid role type", Status: http.StatusBadRequest}
)
