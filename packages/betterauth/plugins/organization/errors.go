package organization

import "net/http"

// OrgError represents an organization plugin error with code, message, and HTTP status.
type OrgError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *OrgError) Error() string {
	return e.Message
}

// Organization-specific error codes matching the TypeScript better-auth organization plugin.
var (
	ErrOrgNotFound = &OrgError{
		Code: "ORGANIZATION_NOT_FOUND", Message: "Organization not found", Status: http.StatusNotFound}
	ErrSlugAlreadyTaken = &OrgError{
		Code: "ORGANIZATION_SLUG_ALREADY_TAKEN", Message: "Organization slug is already taken", Status: http.StatusBadRequest}
	ErrUserNotMember = &OrgError{
		Code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", Message: "User is not a member of the organization", Status: http.StatusBadRequest}
	ErrNotAllowedToCreate = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_CREATE_ORGANIZATIONS", Message: "You are not allowed to create organizations", Status: http.StatusForbidden}
	ErrOrganizationLimitReached = &OrgError{
		Code: "ORGANIZATION_LIMIT_REACHED", Message: "Organization limit reached", Status: http.StatusForbidden}
	ErrNotAllowedToUpdate = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION", Message: "You are not allowed to update this organization", Status: http.StatusForbidden}
	ErrNotAllowedToDelete = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION", Message: "You are not allowed to delete this organization", Status: http.StatusForbidden}
	ErrNotAllowedToInvite = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_INVITE_MEMBERS", Message: "You are not allowed to invite members", Status: http.StatusForbidden}
	ErrNotAllowedToInviteRole = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE", Message: "You are not allowed to invite user with this role", Status: http.StatusForbidden}
	ErrInvitationNotFound = &OrgError{
		Code: "INVITATION_NOT_FOUND", Message: "Invitation not found", Status: http.StatusNotFound}
	ErrInvitationExpired = &OrgError{
		Code: "INVITATION_EXPIRED", Message: "Invitation has expired", Status: http.StatusBadRequest}
	ErrInvitationAlreadyAccepted = &OrgError{
		Code: "INVITATION_ALREADY_ACCEPTED", Message: "Invitation has already been accepted", Status: http.StatusBadRequest}
	ErrUserAlreadyInvited = &OrgError{
		Code: "USER_ALREADY_INVITED", Message: "User has already been invited to this organization", Status: http.StatusBadRequest}
	ErrUserAlreadyMember = &OrgError{
		Code: "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION", Message: "User is already a member of this organization", Status: http.StatusBadRequest}
	ErrInvitationLimitReached = &OrgError{
		Code: "INVITATION_LIMIT_REACHED", Message: "Invitation limit reached for this organization", Status: http.StatusForbidden}
	ErrMembershipLimitReached = &OrgError{
		Code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED", Message: "Organization membership limit reached", Status: http.StatusForbidden}
	ErrNotAllowedToRemove = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_REMOVE_MEMBERS", Message: "You are not allowed to remove members", Status: http.StatusForbidden}
	ErrCannotRemoveLastOwner = &OrgError{
		Code: "CANNOT_REMOVE_LAST_OWNER", Message: "Cannot remove the last owner of the organization", Status: http.StatusBadRequest}
	ErrNotAllowedToUpdateRole = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_UPDATE_MEMBER_ROLE", Message: "You are not allowed to update member role", Status: http.StatusForbidden}
	ErrMemberNotFound = &OrgError{
		Code: "MEMBER_NOT_FOUND", Message: "Member not found", Status: http.StatusNotFound}
	ErrEmptySlug = &OrgError{
		Code: "EMPTY_SLUG", Message: "Organization slug cannot be empty", Status: http.StatusBadRequest}
	ErrEmptyName = &OrgError{
		Code: "EMPTY_NAME", Message: "Organization name cannot be empty", Status: http.StatusBadRequest}
	ErrNotAllowedToCancelInvitation = &OrgError{
		Code: "YOU_ARE_NOT_ALLOWED_TO_CANCEL_INVITATIONS", Message: "You are not allowed to cancel invitations", Status: http.StatusForbidden}
)
