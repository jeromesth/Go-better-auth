package organization

import "testing"

func TestNewRole(t *testing.T) {
	stmts := Statements{
		"member": {"create", "update"},
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
		"organization": {"update", "delete"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
	})

	tests := []struct {
		name      string
		requested map[string][]string
		want      bool
	}{
		{
			name:      "all permissions match",
			requested: map[string][]string{"member": {"create", "update"}},
			want:      true,
		},
		{
			name:      "single permission match",
			requested: map[string][]string{"invitation": {"create"}},
			want:      true,
		},
		{
			name:      "multiple resources match",
			requested: map[string][]string{"member": {"delete"}, "invitation": {"cancel"}},
			want:      true,
		},
		{
			name:      "unknown resource",
			requested: map[string][]string{"post": {"create"}},
			want:      false,
		},
		{
			name:      "unknown action on known resource",
			requested: map[string][]string{"member": {"ban"}},
			want:      false,
		},
		{
			name:      "one valid one invalid resource",
			requested: map[string][]string{"member": {"create"}, "post": {"read"}},
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
		if role.Authorize(map[string][]string{"member": {"create"}}) {
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
		"member": {},
	})

	t.Run("resource exists but no actions allowed", func(t *testing.T) {
		if role.Authorize(map[string][]string{"member": {"create"}}) {
			t.Error("expected role with empty actions to deny access")
		}
	})

	t.Run("resource exists with empty request actions", func(t *testing.T) {
		if !role.Authorize(map[string][]string{"member": {}}) {
			t.Error("expected role to allow empty action list")
		}
	})
}

func TestDefaultStatements(t *testing.T) {
	if len(DefaultStatements) != 3 {
		t.Errorf("expected 3 resources in DefaultStatements, got %d", len(DefaultStatements))
	}

	orgActions := DefaultStatements["organization"]
	if len(orgActions) != 2 {
		t.Errorf("expected 2 organization actions, got %d: %v", len(orgActions), orgActions)
	}

	memberActions := DefaultStatements["member"]
	if len(memberActions) != 3 {
		t.Errorf("expected 3 member actions, got %d: %v", len(memberActions), memberActions)
	}

	invitationActions := DefaultStatements["invitation"]
	if len(invitationActions) != 2 {
		t.Errorf("expected 2 invitation actions, got %d: %v", len(invitationActions), invitationActions)
	}
}

func TestDefaultRoles(t *testing.T) {
	roles := DefaultRoles()
	if len(roles) != 3 {
		t.Errorf("expected 3 default roles, got %d", len(roles))
	}

	owner, ok := roles["owner"]
	if !ok {
		t.Fatal("expected owner role")
	}
	admin, ok := roles["admin"]
	if !ok {
		t.Fatal("expected admin role")
	}
	member, ok := roles["member"]
	if !ok {
		t.Fatal("expected member role")
	}

	// Owner can do everything.
	if !owner.Authorize(map[string][]string{"organization": {"update", "delete"}}) {
		t.Error("expected owner to have organization:update,delete")
	}
	if !owner.Authorize(map[string][]string{"member": {"create", "update", "delete"}}) {
		t.Error("expected owner to have all member permissions")
	}
	if !owner.Authorize(map[string][]string{"invitation": {"create", "cancel"}}) {
		t.Error("expected owner to have all invitation permissions")
	}

	// Admin cannot delete organization.
	if admin.Authorize(map[string][]string{"organization": {"delete"}}) {
		t.Error("expected admin to NOT have organization:delete")
	}
	if !admin.Authorize(map[string][]string{"organization": {"update"}}) {
		t.Error("expected admin to have organization:update")
	}
	if !admin.Authorize(map[string][]string{"member": {"create", "update", "delete"}}) {
		t.Error("expected admin to have all member permissions")
	}

	// Member has no permissions.
	if member.Authorize(map[string][]string{"organization": {"update"}}) {
		t.Error("expected member to NOT have organization:update")
	}
	if member.Authorize(map[string][]string{"member": {"create"}}) {
		t.Error("expected member to NOT have member:create")
	}
	if member.Authorize(map[string][]string{"invitation": {"create"}}) {
		t.Error("expected member to NOT have invitation:create")
	}
}

func TestHasPermission(t *testing.T) {
	roles := DefaultRoles()

	t.Run("nil permissions returns false", func(t *testing.T) {
		if HasPermission("owner", nil, roles) {
			t.Error("expected false for nil permissions")
		}
	})

	t.Run("owner has all permissions", func(t *testing.T) {
		if !HasPermission("owner", map[string][]string{"organization": {"delete"}}, roles) {
			t.Error("expected owner to have organization:delete")
		}
	})

	t.Run("admin lacks organization delete", func(t *testing.T) {
		if HasPermission("admin", map[string][]string{"organization": {"delete"}}, roles) {
			t.Error("expected admin to NOT have organization:delete")
		}
	})

	t.Run("member has no permissions", func(t *testing.T) {
		if HasPermission("member", map[string][]string{"member": {"create"}}, roles) {
			t.Error("expected member to NOT have member:create")
		}
	})

	t.Run("unknown role denies access", func(t *testing.T) {
		if HasPermission("superadmin", map[string][]string{"organization": {"update"}}, roles) {
			t.Error("expected unknown role to deny access")
		}
	})

	t.Run("multi-role grants access from any matching role", func(t *testing.T) {
		if !HasPermission("member,admin", map[string][]string{"organization": {"update"}}, roles) {
			t.Error("expected admin part of multi-role to grant update")
		}
	})

	t.Run("unknown role in multi-role is skipped", func(t *testing.T) {
		if !HasPermission("nonexistent,owner", map[string][]string{"organization": {"delete"}}, roles) {
			t.Error("expected owner to grant delete even with unknown role present")
		}
	})

	t.Run("all unknown roles deny access", func(t *testing.T) {
		if HasPermission("unknown1,unknown2", map[string][]string{"member": {"create"}}, roles) {
			t.Error("expected all-unknown roles to deny access")
		}
	})

	t.Run("empty role name denies access", func(t *testing.T) {
		if HasPermission("", map[string][]string{"member": {"create"}}, roles) {
			t.Error("expected empty role to deny access")
		}
	})
}

func TestCanManageRole(t *testing.T) {
	tests := []struct {
		name       string
		sourceRole string
		targetRole string
		want       bool
	}{
		{
			name:       "owner can manage member",
			sourceRole: "owner",
			targetRole: "member",
			want:       true,
		},
		{
			name:       "owner can manage admin",
			sourceRole: "owner",
			targetRole: "admin",
			want:       true,
		},
		{
			name:       "owner can manage owner",
			sourceRole: "owner",
			targetRole: "owner",
			want:       true,
		},
		{
			name:       "admin can manage member",
			sourceRole: "admin",
			targetRole: "member",
			want:       true,
		},
		{
			name:       "admin cannot manage owner",
			sourceRole: "admin",
			targetRole: "owner",
			want:       false,
		},
		{
			name:       "admin can manage another admin",
			sourceRole: "admin",
			targetRole: "admin",
			want:       true,
		},
		{
			name:       "member cannot manage member",
			sourceRole: "member",
			targetRole: "member",
			want:       false,
		},
		{
			name:       "member cannot manage admin",
			sourceRole: "member",
			targetRole: "admin",
			want:       false,
		},
		{
			name:       "member cannot manage owner",
			sourceRole: "member",
			targetRole: "owner",
			want:       false,
		},
		{
			name:       "multi-role with owner can manage anyone",
			sourceRole: "member,owner",
			targetRole: "admin",
			want:       true,
		},
		{
			name:       "multi-role admin,member can manage member",
			sourceRole: "admin,member",
			targetRole: "member",
			want:       true,
		},
		{
			name:       "multi-role admin,member cannot manage owner",
			sourceRole: "admin,member",
			targetRole: "owner",
			want:       false,
		},
		{
			name:       "empty source role cannot manage anyone",
			sourceRole: "",
			targetRole: "member",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanManageRole(tt.sourceRole, tt.targetRole)
			if got != tt.want {
				t.Errorf("CanManageRole(%q, %q) = %v, want %v", tt.sourceRole, tt.targetRole, got, tt.want)
			}
		})
	}
}

func TestStrContains(t *testing.T) {
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
			got := strContains(tt.slice, tt.item)
			if got != tt.want {
				t.Errorf("strContains() = %v, want %v", got, tt.want)
			}
		})
	}
}
