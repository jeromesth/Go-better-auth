package admin

// Statements defines the available resource-action permissions.
type Statements map[string][]string

// Role represents a set of allowed actions per resource.
type Role struct {
	statements Statements
}

// NewRole creates a Role with the given permission statements.
func NewRole(statements Statements) *Role {
	return &Role{statements: statements}
}

// Authorize checks if this role has all the requested permissions.
// Returns true if every requested action for every resource is allowed.
func (r *Role) Authorize(requested map[string][]string) bool {
	for resource, actions := range requested {
		allowed, ok := r.statements[resource]
		if !ok {
			return false
		}
		for _, action := range actions {
			if !contains(allowed, action) {
				return false
			}
		}
	}
	return true
}

// AccessControl provides a typed permission system.
type AccessControl struct {
	Statements Statements
}

// NewAccessControl creates an AccessControl from the given statements.
func NewAccessControl(statements Statements) *AccessControl {
	return &AccessControl{Statements: statements}
}

// NewRole creates a Role with the given permission subset.
func (ac *AccessControl) NewRole(statements Statements) *Role {
	return NewRole(statements)
}

// DefaultStatements defines the default permission actions for the admin plugin.
var DefaultStatements = Statements{
	"user":    {"create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "get", "update"},
	"session": {"list", "revoke", "delete"},
}

var defaultAC = NewAccessControl(DefaultStatements)

// DefaultAdminRole has all permissions except impersonate-admins.
var DefaultAdminRole = defaultAC.NewRole(Statements{
	"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "get", "update"},
	"session": {"list", "revoke", "delete"},
})

// DefaultUserRole has no admin permissions.
var DefaultUserRole = defaultAC.NewRole(Statements{
	"user":    {},
	"session": {},
})

// DefaultRoles maps role names to their default permission sets.
var DefaultRoles = map[string]*Role{
	"admin": DefaultAdminRole,
	"user":  DefaultUserRole,
}

// HasPermission checks if a user has the requested permissions based on their role.
func HasPermission(opts HasPermissionInput) bool {
	// If user ID is in the admin user IDs list, grant all permissions.
	if opts.UserID != "" && opts.Options != nil {
		for _, id := range opts.Options.AdminUserIds {
			if id == opts.UserID {
				return true
			}
		}
	}

	if opts.Permissions == nil {
		return false
	}

	// Split comma-separated roles.
	roleStr := opts.Role
	if roleStr == "" {
		if opts.Options != nil && opts.Options.DefaultRole != "" {
			roleStr = opts.Options.DefaultRole
		} else {
			roleStr = "user"
		}
	}

	roles := splitRoles(roleStr)
	acRoles := DefaultRoles
	if opts.Options != nil && opts.Options.Roles != nil {
		acRoles = opts.Options.Roles
	}

	for _, roleName := range roles {
		role, ok := acRoles[roleName]
		if !ok {
			continue
		}
		if role.Authorize(opts.Permissions) {
			return true
		}
	}
	return false
}

// HasPermissionInput is the input to HasPermission.
type HasPermissionInput struct {
	UserID      string
	Role        string
	Options     *Options
	Permissions map[string][]string
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func splitRoles(s string) []string {
	if s == "" {
		return nil
	}
	var roles []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			r := s[start:i]
			if r != "" {
				roles = append(roles, r)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		roles = append(roles, s[start:])
	}
	return roles
}
