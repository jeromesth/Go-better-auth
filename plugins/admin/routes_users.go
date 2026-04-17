package admin

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/crypto"
	"github.com/jeromesth/go-better-auth/internal/httputil"
)

// --- POST /admin/create-user ---

func (p *Plugin) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string         `json:"email"`
		Password string         `json:"password,omitempty"`
		Name     string         `json:"name"`
		Role     any            `json:"role,omitempty"`
		Data     map[string]any `json:"data,omitempty"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"create"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToCreateUsers.Status, ErrNotAllowedToCreateUsers.Code, ErrNotAllowedToCreateUsers.Message)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_EMAIL", "Invalid email address")
		return
	}

	ctx := r.Context()

	existing, err := p.repo.FindUserByEmail(ctx, email)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}
	if existing != nil {
		httputil.WriteError(w, ErrUserAlreadyExists.Status, ErrUserAlreadyExists.Code, ErrUserAlreadyExists.Message)
		return
	}

	// Determine role.
	roleStr := p.opts.DefaultRole
	if req.Role != nil {
		roleStr = parseRoles(req.Role)
	}

	// Build user data.
	data := map[string]any{
		"email":          email,
		"name":           req.Name,
		"email_verified": false,
		"role":           roleStr,
		"banned":         false,
	}
	// Merge extra data fields.
	for k, v := range req.Data {
		data[k] = v
	}

	rec, err := p.repo.CreateUser(ctx, data)
	if err != nil {
		httputil.WriteError(w, ErrFailedToCreateUser.Status, ErrFailedToCreateUser.Code, ErrFailedToCreateUser.Message)
		return
	}

	// Create credential account if password provided.
	if req.Password != "" {
		hash, err := crypto.HashPassword(req.Password)
		if err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
			return
		}
		userID, _ := rec["id"].(string)
		if err := p.repo.CreateCredentialAccount(ctx, userID, hash); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create account")
			return
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user": recordToUserWithRole(rec),
	})
}

// --- GET /admin/get-user ---

func (p *Plugin) handleGetUser(w http.ResponseWriter, r *http.Request) {
	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"get"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToGetUser.Status, ErrNotAllowedToGetUser.Code, ErrNotAllowedToGetUser.Message)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		httputil.WriteError(w, http.StatusBadRequest, "BAD_REQUEST", "Missing id parameter")
		return
	}

	ctx := r.Context()
	rec, err := p.repo.FindUserByID(ctx, id)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}
	if rec == nil {
		httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, recordToUserWithRole(rec))
}

// --- POST /admin/update-user ---

func (p *Plugin) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string         `json:"userId"`
		Data   map[string]any `json:"data"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"update"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToUpdate.Status, ErrNotAllowedToUpdate.Code, ErrNotAllowedToUpdate.Message)
		return
	}

	if len(req.Data) == 0 {
		httputil.WriteError(w, ErrNoDataToUpdate.Status, ErrNoDataToUpdate.Code, ErrNoDataToUpdate.Message)
		return
	}

	// If data includes "role", require set-role permission and validate roles.
	if _, hasRole := req.Data["role"]; hasRole {
		if !HasPermission(HasPermissionInput{
			UserID:      user.ID,
			Role:        user.Role,
			Options:     p.opts,
			Permissions: map[string][]string{"user": {"set-role"}},
		}) {
			httputil.WriteError(w, ErrNotAllowedToChangeRole.Status, ErrNotAllowedToChangeRole.Code, ErrNotAllowedToChangeRole.Message)
			return
		}

		roleVal := req.Data["role"]
		inputRoles := toStringSlice(roleVal)
		if p.opts.Roles != nil {
			for _, role := range inputRoles {
				if _, ok := p.opts.Roles[role]; !ok {
					httputil.WriteError(w, ErrNonExistentRole.Status, ErrNonExistentRole.Code, ErrNonExistentRole.Message)
					return
				}
			}
		}
		req.Data["role"] = parseRoles(roleVal)
	}

	ctx := r.Context()
	rec, err := p.repo.UpdateUser(ctx, req.UserID, req.Data)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, recordToUserWithRole(rec))
}

// --- GET /admin/list-users ---

func (p *Plugin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"list"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToListUsers.Status, ErrNotAllowedToListUsers.Code, ErrNotAllowedToListUsers.Message)
		return
	}

	q := r.URL.Query()
	var where []adapter.Where

	// Search support.
	if searchVal := q.Get("searchValue"); searchVal != "" {
		field := q.Get("searchField")
		if field == "" {
			field = "email"
		}
		op := q.Get("searchOperator")
		if op == "" {
			op = "contains"
		}
		where = append(where, adapter.Where{
			Field:    field,
			Operator: mapSearchOperator(op),
			Value:    searchVal,
		})
	}

	// Filter support.
	if filterVal := q.Get("filterValue"); filterVal != "" {
		field := q.Get("filterField")
		if field == "" {
			field = "email"
		}
		op := q.Get("filterOperator")
		if op == "" {
			op = "="
		}
		where = append(where, adapter.Where{
			Field:    mapFieldName(field),
			Operator: mapFilterOperator(op),
			Value:    parseFilterValue(filterVal),
		})
	}

	limit := 0
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}
	sortBy := q.Get("sortBy")
	sortDir := q.Get("sortDirection")

	ctx := r.Context()

	query := adapter.Query{
		Where:   where,
		Limit:   limit,
		Offset:  offset,
		SortBy:  mapFieldName(sortBy),
		SortDir: sortDir,
	}

	recs, err := p.repo.ListUsers(ctx, query)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"users": []any{},
			"total": 0,
		})
		return
	}

	total, err := p.repo.CountUsers(ctx, where)
	if err != nil {
		total = int64(len(recs))
	}

	users := make([]*UserWithRole, 0, len(recs))
	for _, rec := range recs {
		users = append(users, recordToUserWithRole(rec))
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// --- POST /admin/set-role ---

func (p *Plugin) handleSetRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
		Role   any    `json:"role"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"set-role"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToChangeRole.Status, ErrNotAllowedToChangeRole.Code, ErrNotAllowedToChangeRole.Message)
		return
	}

	// Validate roles if roles are defined.
	inputRoles := toStringSlice(req.Role)
	if p.opts.Roles != nil {
		for _, role := range inputRoles {
			if _, ok := p.opts.Roles[role]; !ok {
				httputil.WriteError(w, ErrNonExistentRole.Status, ErrNonExistentRole.Code, ErrNonExistentRole.Message)
				return
			}
		}
	}

	roleStr := parseRoles(req.Role)

	ctx := r.Context()
	rec, err := p.repo.UpdateUser(ctx, req.UserID, map[string]any{
		"role": roleStr,
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user": recordToUserWithRole(rec),
	})
}

// --- POST /admin/set-user-password ---

func (p *Plugin) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"userId"`
		NewPassword string `json:"newPassword"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	if req.UserID == "" || req.NewPassword == "" {
		httputil.WriteError(w, http.StatusBadRequest, "BAD_REQUEST", "userId and newPassword are required")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"set-password"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToSetPassword.Status, ErrNotAllowedToSetPassword.Code, ErrNotAllowedToSetPassword.Message)
		return
	}

	// Validate password length.
	epCfg := p.auth.Options().EmailAndPassword
	minLen := 8
	maxLen := 128
	if epCfg != nil {
		if epCfg.MinPasswordLength > 0 {
			minLen = epCfg.MinPasswordLength
		}
		if epCfg.MaxPasswordLength > 0 {
			maxLen = epCfg.MaxPasswordLength
		}
	}
	if len(req.NewPassword) < minLen {
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT", "Password too short")
		return
	}
	if len(req.NewPassword) > maxLen {
		httputil.WriteError(w, http.StatusBadRequest, "PASSWORD_TOO_LONG", "Password too long")
		return
	}

	hash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
		return
	}

	ctx := r.Context()
	if err := p.repo.UpdatePassword(ctx, req.UserID, hash); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update password")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": true})
}

// --- POST /admin/remove-user ---

func (p *Plugin) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"delete"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToDelete.Status, ErrNotAllowedToDelete.Code, ErrNotAllowedToDelete.Message)
		return
	}

	if req.UserID == user.ID {
		httputil.WriteError(w, ErrCannotRemoveYourself.Status, ErrCannotRemoveYourself.Code, ErrCannotRemoveYourself.Message)
		return
	}

	ctx := r.Context()

	target, err := p.repo.FindUserByID(ctx, req.UserID)
	if err != nil || target == nil {
		httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	if err := p.repo.DeleteUser(ctx, req.UserID); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete user")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"success": true})
}

// --- POST /admin/ban-user ---

func (p *Plugin) handleBanUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID       string `json:"userId"`
		BanReason    string `json:"banReason,omitempty"`
		BanExpiresIn int    `json:"banExpiresIn,omitempty"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"ban"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToBan.Status, ErrNotAllowedToBan.Code, ErrNotAllowedToBan.Message)
		return
	}

	ctx := r.Context()

	// Check user exists.
	target, err := p.repo.FindUserByID(ctx, req.UserID)
	if err != nil || target == nil {
		httputil.WriteError(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		return
	}

	if req.UserID == user.ID {
		httputil.WriteError(w, ErrCannotBanYourself.Status, ErrCannotBanYourself.Code, ErrCannotBanYourself.Message)
		return
	}

	banReason := req.BanReason
	if banReason == "" {
		banReason = p.opts.DefaultBanReason
	}

	updates := map[string]any{
		"banned":     true,
		"ban_reason": banReason,
	}

	if req.BanExpiresIn > 0 {
		updates["ban_expires"] = time.Now().UTC().Add(time.Duration(req.BanExpiresIn) * time.Second)
	} else if p.opts.DefaultBanExpiresIn > 0 {
		updates["ban_expires"] = time.Now().UTC().Add(time.Duration(p.opts.DefaultBanExpiresIn) * time.Second)
	}

	rec, err := p.repo.UpdateUser(ctx, req.UserID, updates)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to ban user")
		return
	}

	// Revoke all sessions.
	_ = p.repo.RevokeAllUserSessions(ctx, req.UserID)

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user": recordToUserWithRole(rec),
	})
}

// --- POST /admin/unban-user ---

func (p *Plugin) handleUnbanUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"userId"`
	}
	if err := httputil.DecodeJSON(r, &req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	user := p.getAdminSession(w, r)
	if user == nil {
		return
	}

	if !HasPermission(HasPermissionInput{
		UserID:      user.ID,
		Role:        user.Role,
		Options:     p.opts,
		Permissions: map[string][]string{"user": {"ban"}},
	}) {
		httputil.WriteError(w, ErrNotAllowedToBan.Status, ErrNotAllowedToBan.Code, ErrNotAllowedToBan.Message)
		return
	}

	ctx := r.Context()
	rec, err := p.repo.UpdateUser(ctx, req.UserID, map[string]any{
		"banned":      false,
		"ban_expires": nil,
		"ban_reason":  nil,
	})
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to unban user")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"user": recordToUserWithRole(rec),
	})
}

// --- Helper functions ---

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []any:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return []string{strings.TrimSpace(strings.Trim(strings.Trim(strings.TrimSpace(parseRoles(v)), "["), "]"))}
	}
}

func mapSearchOperator(op string) string {
	switch op {
	case "contains", "starts_with", "ends_with":
		return "like"
	default:
		return "like"
	}
}

func mapFilterOperator(op string) string {
	switch op {
	case "eq":
		return "="
	case "ne":
		return "!="
	case "lt":
		return "<"
	case "lte":
		return "<="
	case "gt":
		return ">"
	case "gte":
		return ">="
	case "contains":
		return "like"
	case "starts_with":
		return "like"
	case "ends_with":
		return "like"
	default:
		return "="
	}
}

func mapFieldName(field string) string {
	switch field {
	case "createdAt":
		return "created_at"
	case "updatedAt":
		return "updated_at"
	case "emailVerified":
		return "email_verified"
	case "banReason":
		return "ban_reason"
	case "banExpires":
		return "ban_expires"
	case "_id":
		return "id"
	default:
		return field
	}
}

func parseFilterValue(v string) any {
	if v == "true" {
		return true
	}
	if v == "false" {
		return false
	}
	if i, err := strconv.Atoi(v); err == nil {
		return i
	}
	return v
}
