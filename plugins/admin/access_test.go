package admin

import "testing"

func TestNewRole(t *testing.T) {
	stmts := Statements{
		"user": {"create", "read"},
	}
	role := NewRole(stmts)
	if role == nil {
		t.Fatal("expected non-nil role")
	}
	if len(role.statements) != 1 {
		t.Errorf("expected 1 resource, got %d", len(role.statements))
	}
}

func TestRoleAuthorize(t *testing.T) {
	role := NewRole(Statements{
		"user":    {"create", "read", "update", "delete"},
		"session": {"list", "revoke"},
	})

	tests := []struct {
		name      string
		requested map[string][]string
		want      bool
	}{
		{
			name:      "all permissions match",
			requested: map[string][]string{"user": {"create", "read"}},
			want:      true,
		},
		{
			name:      "single permission match",
			requested: map[string][]string{"session": {"list"}},
			want:      true,
		},
		{
			name:      "multiple resources match",
			requested: map[string][]string{"user": {"create"}, "session": {"revoke"}},
			want:      true,
		},
		{
			name:      "unknown resource",
			requested: map[string][]string{"post": {"create"}},
			want:      false,
		},
		{
			name:      "unknown action on known resource",
			requested: map[string][]string{"user": {"ban"}},
			want:      false,
		},
		{
			name:      "one valid one invalid resource",
			requested: map[string][]string{"user": {"create"}, "post": {"read"}},
			want:      false,
		},
		{
			name:      "empty requested permissions",
			requested: map[string][]string{},
			want:      true,
		},
		{
			name:      "nil requested permissions",
			requested: nil,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := role.Authorize(tt.requested)
			if got != tt.want {
				t.Errorf("Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoleAuthorize_EmptyRole(t *testing.T) {
	role := NewRole(Statements{})

	t.Run("empty role denies any resource", func(t *testing.T) {
		if role.Authorize(map[string][]string{"user": {"create"}}) {
			t.Error("expected empty role to deny access")
		}
	})

	t.Run("empty role allows empty request", func(t *testing.T) {
		if !role.Authorize(map[string][]string{}) {
			t.Error("expected empty role to allow empty request")
		}
	})
}

func TestRoleAuthorize_EmptyActions(t *testing.T) {
	role := NewRole(Statements{
		"user": {},
	})

	t.Run("resource exists but no actions allowed", func(t *testing.T) {
		if role.Authorize(map[string][]string{"user": {"create"}}) {
			t.Error("expected role with empty actions to deny access")
		}
	})

	t.Run("resource exists with empty request actions", func(t *testing.T) {
		if !role.Authorize(map[string][]string{"user": {}}) {
			t.Error("expected role to allow empty action list")
		}
	})
}

func TestNewAccessControl(t *testing.T) {
	ac := NewAccessControl(Statements{
		"user": {"create", "read"},
	})
	if ac == nil {
		t.Fatal("expected non-nil access control")
	}
	if len(ac.Statements) != 1 {
		t.Errorf("expected 1 resource, got %d", len(ac.Statements))
	}

	role := ac.NewRole(Statements{
		"user": {"create"},
	})
	if role == nil {
		t.Fatal("expected non-nil role from AC")
	}
	if !role.Authorize(map[string][]string{"user": {"create"}}) {
		t.Error("expected role to allow user:create")
	}
	if role.Authorize(map[string][]string{"user": {"delete"}}) {
		t.Error("expected role to deny user:delete")
	}
}

func TestDefaultStatements(t *testing.T) {
	if len(DefaultStatements) != 2 {
		t.Errorf("expected 2 resources in DefaultStatements, got %d", len(DefaultStatements))
	}

	userActions := DefaultStatements["user"]
	if len(userActions) != 10 {
		t.Errorf("expected 10 user actions, got %d: %v", len(userActions), userActions)
	}

	sessionActions := DefaultStatements["session"]
	if len(sessionActions) != 3 {
		t.Errorf("expected 3 session actions, got %d: %v", len(sessionActions), sessionActions)
	}
}

func TestDefaultRoles(t *testing.T) {
	if len(DefaultRoles) != 2 {
		t.Errorf("expected 2 default roles, got %d", len(DefaultRoles))
	}

	admin, ok := DefaultRoles["admin"]
	if !ok {
		t.Fatal("expected admin role")
	}
	user, ok := DefaultRoles["user"]
	if !ok {
		t.Fatal("expected user role")
	}

	// Admin can create users.
	if !admin.Authorize(map[string][]string{"user": {"create"}}) {
		t.Error("expected admin to have user:create")
	}

	// Admin can do all session operations.
	if !admin.Authorize(map[string][]string{"session": {"list", "revoke", "delete"}}) {
		t.Error("expected admin to have all session permissions")
	}

	// Admin cannot impersonate admins (intentional restriction).
	if admin.Authorize(map[string][]string{"user": {"impersonate-admins"}}) {
		t.Error("expected admin to NOT have user:impersonate-admins")
	}

	// User has no permissions.
	if user.Authorize(map[string][]string{"user": {"create"}}) {
		t.Error("expected user to NOT have user:create")
	}
	if user.Authorize(map[string][]string{"session": {"list"}}) {
		t.Error("expected user to NOT have session:list")
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		item  string
		want  bool
	}{
		{"found", []string{"a", "b", "c"}, "b", true},
		{"not found", []string{"a", "b", "c"}, "d", false},
		{"empty slice", []string{}, "a", false},
		{"nil slice", nil, "a", false},
		{"exact match", []string{"create"}, "create", true},
		{"case sensitive", []string{"Create"}, "create", false},
		{"empty item in non-empty slice", []string{"a", "b"}, "", false},
		{"empty item in slice with empty", []string{"a", ""}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.slice, tt.item)
			if got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitRoles(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single role", "admin", []string{"admin"}},
		{"two roles", "admin,user", []string{"admin", "user"}},
		{"three roles", "admin,moderator,user", []string{"admin", "moderator", "user"}},
		{"empty string", "", nil},
		{"trailing comma", "admin,", []string{"admin"}},
		{"leading comma", ",admin", []string{"admin"}},
		{"double comma", "admin,,user", []string{"admin", "user"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitRoles(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitRoles(%q) = %v (len %d), want %v (len %d)",
					tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitRoles(%q)[%d] = %q, want %q",
						tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHasPermission_Defaults(t *testing.T) {
	t.Run("nil permissions returns false", func(t *testing.T) {
		if HasPermission(HasPermissionInput{
			Role:        "admin",
			Permissions: nil,
		}) {
			t.Error("expected false for nil permissions")
		}
	})

	t.Run("empty role defaults to user", func(t *testing.T) {
		// User role has no permissions, so this should fail.
		if HasPermission(HasPermissionInput{
			Role:        "",
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected false for default user role")
		}
	})

	t.Run("custom default role", func(t *testing.T) {
		customRoles := map[string]*Role{
			"member": NewRole(Statements{"user": {"list"}}),
		}
		if !HasPermission(HasPermissionInput{
			Role: "",
			Options: &Options{
				DefaultRole: "member",
				Roles:       customRoles,
			},
			Permissions: map[string][]string{"user": {"list"}},
		}) {
			t.Error("expected custom default role 'member' to have list permission")
		}
	})

	t.Run("nil options uses defaults", func(t *testing.T) {
		if !HasPermission(HasPermissionInput{
			Role:        "admin",
			Options:     nil,
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected admin with nil options to have create permission using DefaultRoles")
		}
	})
}

func TestHasPermission_MultiRole(t *testing.T) {
	customRoles := map[string]*Role{
		"viewer":    NewRole(Statements{"user": {"list", "get"}}),
		"moderator": NewRole(Statements{"user": {"ban"}}),
	}

	t.Run("multi-role grants access from any matching role", func(t *testing.T) {
		if !HasPermission(HasPermissionInput{
			Role: "viewer,moderator",
			Options: &Options{
				Roles: customRoles,
			},
			Permissions: map[string][]string{"user": {"ban"}},
		}) {
			t.Error("expected moderator part of multi-role to grant ban")
		}
	})

	t.Run("unknown role in multi-role is skipped", func(t *testing.T) {
		if !HasPermission(HasPermissionInput{
			Role: "nonexistent,viewer",
			Options: &Options{
				Roles: customRoles,
			},
			Permissions: map[string][]string{"user": {"list"}},
		}) {
			t.Error("expected viewer to grant list even with unknown role present")
		}
	})

	t.Run("all unknown roles deny access", func(t *testing.T) {
		if HasPermission(HasPermissionInput{
			Role: "unknown1,unknown2",
			Options: &Options{
				Roles: customRoles,
			},
			Permissions: map[string][]string{"user": {"list"}},
		}) {
			t.Error("expected all-unknown roles to deny access")
		}
	})
}

func TestHasPermission_AdminUserIDs(t *testing.T) {
	t.Run("admin user ID bypasses role check", func(t *testing.T) {
		if !HasPermission(HasPermissionInput{
			UserID: "user-123",
			Role:   "user",
			Options: &Options{
				AdminUserIds: []string{"user-123"},
			},
			Permissions: map[string][]string{
				"user":    {"create", "delete", "ban"},
				"session": {"list", "revoke"},
			},
		}) {
			t.Error("expected admin user ID to bypass role check")
		}
	})

	t.Run("non-admin user ID does not bypass", func(t *testing.T) {
		if HasPermission(HasPermissionInput{
			UserID: "user-456",
			Role:   "user",
			Options: &Options{
				AdminUserIds: []string{"user-123"},
			},
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected non-admin user ID to not bypass role check")
		}
	})

	t.Run("empty user ID does not match admin list", func(t *testing.T) {
		if HasPermission(HasPermissionInput{
			UserID: "",
			Role:   "user",
			Options: &Options{
				AdminUserIds: []string{"user-123"},
			},
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected empty user ID to not match admin list")
		}
	})

	t.Run("multiple admin user IDs", func(t *testing.T) {
		opts := &Options{
			AdminUserIds: []string{"id-1", "id-2", "id-3"},
		}
		if !HasPermission(HasPermissionInput{
			UserID:      "id-2",
			Role:        "user",
			Options:     opts,
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected second admin user ID to bypass")
		}
		if HasPermission(HasPermissionInput{
			UserID:      "id-999",
			Role:        "user",
			Options:     opts,
			Permissions: map[string][]string{"user": {"create"}},
		}) {
			t.Error("expected non-listed user ID to not bypass")
		}
	})
}
