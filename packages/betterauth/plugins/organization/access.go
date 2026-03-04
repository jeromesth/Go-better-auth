package organization

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
func (r *Role) Authorize(requested map[string][]string) bool {
	for resource, actions := range requested {
		allowed, ok := r.statements[resource]
		if !ok {
			return false
		}
		for _, action := range actions {
			if !strContains(allowed, action) {
				return false
			}
		}
	}
	return true
}

// DefaultStatements defines the default permission actions for the organization plugin.
var DefaultStatements = Statements{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
}

// DefaultRoles returns the default role definitions.
func DefaultRoles() map[string]*Role {
	return map[string]*Role{
		"owner": NewRole(Statements{
			"organization": {"update", "delete"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
		}),
		"admin": NewRole(Statements{
			"organization": {"update"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
		}),
		"member": NewRole(Statements{
			"organization": {},
			"member":       {},
			"invitation":   {},
		}),
	}
}

// HasPermission checks if a role has the requested permissions.
func HasPermission(roleName string, requested map[string][]string, roles map[string]*Role) bool {
	if requested == nil {
		return false
	}

	// Split comma-separated roles and check each.
	roleNames := splitRoles(roleName)
	for _, name := range roleNames {
		role, ok := roles[name]
		if !ok {
			continue
		}
		if role.Authorize(requested) {
			return true
		}
	}
	return false
}

// CanManageRole checks if a user with sourceRole can manage a member with targetRole.
// Owners can manage anyone. Admins can manage members but not owners.
func CanManageRole(sourceRole, targetRole string) bool {
	sourceRoles := splitRoles(sourceRole)
	targetRoles := splitRoles(targetRole)

	isSourceOwner := strContains(sourceRoles, "owner")

	// Owners can manage anyone.
	if isSourceOwner {
		return true
	}

	// Non-owners cannot manage owners.
	if strContains(targetRoles, "owner") {
		return false
	}

	// Admins can manage members.
	return strContains(sourceRoles, "admin")
}

func strContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
