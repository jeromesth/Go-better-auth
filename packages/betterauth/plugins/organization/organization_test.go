package organization_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth/packages/betterauth"
	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter/memory"
	"github.com/jeromesth/go-better-auth/packages/betterauth/plugin"
	"github.com/jeromesth/go-better-auth/packages/betterauth/plugins/organization"
)

// --- Test helpers ---

func newTestAuth(orgPlugin *organization.Plugin) *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Org Test",
		BasePath: "/api/auth",
		Secret:   "test-secret",
		Database: &betterauth.DatabaseConfig{
			Adapter: memory.New(),
		},
		EmailAndPassword: &betterauth.EmailPassConfig{
			Enabled:           true,
			MinPasswordLength: 8,
			MaxPasswordLength: 128,
			AutoSignIn:        true,
		},
		RateLimit: &betterauth.RateLimitConfig{Enabled: false},
		Plugins:   []plugin.Plugin{orgPlugin},
	})
}

func postJSON(t *testing.T, h http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func getJSON(t *testing.T, h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func decodeResp(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

func decodeArray(t *testing.T, rr *httptest.ResponseRecorder) []any {
	t.Helper()
	var arr []any
	if err := json.NewDecoder(rr.Body).Decode(&arr); err != nil {
		t.Fatalf("decode array response: %v (body: %s)", err, rr.Body.String())
	}
	return arr
}

func signUpUser(t *testing.T, h http.Handler, email, password, name string) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-up/email", map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-up failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func signInUser(t *testing.T, h http.Handler, email, password string) []*http.Cookie {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("sign-in failed: %d %s", rr.Code, rr.Body.String())
	}
	return rr.Result().Cookies()
}

func getUserID(t *testing.T, h http.Handler, cookies []*http.Cookie) string {
	t.Helper()
	rr := getJSON(t, h, "/api/auth/get-session", cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("get-session failed: %d %s", rr.Code, rr.Body.String())
	}
	resp := decodeResp(t, rr)
	user, _ := resp["user"].(map[string]any)
	id, _ := user["id"].(string)
	if id == "" {
		t.Fatal("expected user id from session")
	}
	return id
}

func createOrg(t *testing.T, h http.Handler, cookies []*http.Cookie, name, slug string) map[string]any {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
		"name": name,
		"slug": slug,
	}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("create org failed: %d %s", rr.Code, rr.Body.String())
	}
	return decodeResp(t, rr)
}

func inviteMember(t *testing.T, h http.Handler, cookies []*http.Cookie, email, role string) map[string]any {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
		"email": email,
		"role":  role,
	}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("invite-member failed: %d %s", rr.Code, rr.Body.String())
	}
	return decodeResp(t, rr)
}

func acceptInvitation(t *testing.T, h http.Handler, cookies []*http.Cookie, invitationID string) map[string]any {
	t.Helper()
	rr := postJSON(t, h, "/api/auth/organization/accept-invitation", map[string]any{
		"invitationId": invitationID,
	}, cookies)
	if rr.Code != http.StatusOK {
		t.Fatalf("accept-invitation failed: %d %s", rr.Code, rr.Body.String())
	}
	return decodeResp(t, rr)
}

// --- Tests: Organization CRUD ---

func TestCreateOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")

	t.Run("creates organization", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
			"name":     "Test Org",
			"slug":     "test",
			"metadata": map[string]any{"key": "value"},
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["name"] != "Test Org" {
			t.Errorf("expected name 'Test Org', got %v", resp["name"])
		}
		if resp["slug"] != "test" {
			t.Errorf("expected slug 'test', got %v", resp["slug"])
		}
		if resp["id"] == nil || resp["id"] == "" {
			t.Error("expected non-empty id")
		}
		// Verify metadata.
		meta, _ := resp["metadata"].(map[string]any)
		if meta == nil || meta["key"] != "value" {
			t.Errorf("expected metadata {key: value}, got %v", resp["metadata"])
		}
	})

	t.Run("creator becomes owner member", func(t *testing.T) {
		// Get full organization to check members.
		rr := getJSON(t, h, "/api/auth/organization/get-full-organization", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		members, _ := resp["members"].([]any)
		if len(members) != 1 {
			t.Fatalf("expected 1 member, got %d", len(members))
		}
		member, _ := members[0].(map[string]any)
		if member["role"] != "owner" {
			t.Errorf("expected role 'owner', got %v", member["role"])
		}
	})

	t.Run("sets active organization on session", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-active-member", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "owner" {
			t.Errorf("expected active member role 'owner', got %v", resp["role"])
		}
	})

	t.Run("prevents empty slug", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
			"name": "No Slug",
			"slug": "",
		}, cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("prevents empty name", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
			"name": "",
			"slug": "noname",
		}, cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCheckSlug(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")
	createOrg(t, h, cookies, "Test Org", "test-slug")

	t.Run("returns true for unused slug", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/check-slug?slug=unused-slug", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["status"] != true {
			t.Errorf("expected status true, got %v", resp["status"])
		}
	})

	t.Run("returns error for existing slug", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/check-slug?slug=test-slug", cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "ORGANIZATION_SLUG_ALREADY_TAKEN" {
			t.Errorf("expected ORGANIZATION_SLUG_ALREADY_TAKEN, got %v", resp["code"])
		}
	})
}

func TestListOrganizations(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")
	createOrg(t, h, cookies, "Org 1", "org-1")
	createOrg(t, h, cookies, "Org 2", "org-2")

	t.Run("lists all user organizations", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/list", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		orgs := decodeArray(t, rr)
		if len(orgs) != 2 {
			t.Errorf("expected 2 organizations, got %d", len(orgs))
		}
	})
}

func TestUpdateOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")
	org := createOrg(t, h, cookies, "Test Org", "test-slug")
	orgID, _ := org["id"].(string)

	t.Run("updates organization name", func(t *testing.T) {
		newName := "Updated Name"
		rr := postJSON(t, h, "/api/auth/organization/update", map[string]any{
			"organizationId": orgID,
			"data":           map[string]any{"name": newName},
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["name"] != newName {
			t.Errorf("expected name '%s', got %v", newName, resp["name"])
		}
	})

	t.Run("prevents duplicate slug on update", func(t *testing.T) {
		createOrg(t, h, cookies, "Other Org", "other-slug")
		rr := postJSON(t, h, "/api/auth/organization/update", map[string]any{
			"organizationId": orgID,
			"data":           map[string]any{"slug": "other-slug"},
		}, cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("updates metadata", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update", map[string]any{
			"organizationId": orgID,
			"data":           map[string]any{"metadata": map[string]any{"updated": true}},
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		meta, _ := resp["metadata"].(map[string]any)
		if meta == nil || meta["updated"] != true {
			t.Errorf("expected updated metadata, got %v", resp["metadata"])
		}
	})

	t.Run("prevents empty slug on update", func(t *testing.T) {
		emptySlug := ""
		rr := postJSON(t, h, "/api/auth/organization/update", map[string]any{
			"organizationId": orgID,
			"data":           map[string]any{"slug": emptySlug},
		}, cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("prevents empty name on update", func(t *testing.T) {
		emptyName := ""
		rr := postJSON(t, h, "/api/auth/organization/update", map[string]any{
			"organizationId": orgID,
			"data":           map[string]any{"name": emptyName},
		}, cookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestSetActiveOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")
	org1 := createOrg(t, h, cookies, "Org 1", "org-1")
	org1ID, _ := org1["id"].(string)
	org2 := createOrg(t, h, cookies, "Org 2", "org-2")
	org2ID, _ := org2["id"].(string)

	t.Run("sets active by id", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
			"organizationId": org1ID,
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		sess, _ := resp["session"].(map[string]any)
		if sess["activeOrganizationId"] != org1ID {
			t.Errorf("expected activeOrganizationId %s, got %v", org1ID, sess["activeOrganizationId"])
		}
	})

	t.Run("sets active by slug", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
			"organizationSlug": "org-2",
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		sess, _ := resp["session"].(map[string]any)
		if sess["activeOrganizationId"] != org2ID {
			t.Errorf("expected activeOrganizationId %s, got %v", org2ID, sess["activeOrganizationId"])
		}
	})
}

func TestGetFullOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "TestUser")
	createOrg(t, h, cookies, "Full Org", "full-org")

	t.Run("returns org with members", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-full-organization", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["name"] != "Full Org" {
			t.Errorf("expected name 'Full Org', got %v", resp["name"])
		}
		members, _ := resp["members"].([]any)
		if len(members) != 1 {
			t.Errorf("expected 1 member, got %d", len(members))
		}
	})

	t.Run("returns org by slug", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-full-organization?organizationSlug=full-org", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["name"] != "Full Org" {
			t.Errorf("expected name 'Full Org', got %v", resp["name"])
		}
	})
}

// --- Tests: Invitation Flow ---

func TestInviteMember(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Invite Org", "invite-org")

	t.Run("invites user with member role", func(t *testing.T) {
		inv := inviteMember(t, h, ownerCookies, "member@test.com", "member")
		if inv["email"] != "member@test.com" {
			t.Errorf("expected email member@test.com, got %v", inv["email"])
		}
		if inv["role"] != "member" {
			t.Errorf("expected role 'member', got %v", inv["role"])
		}
		if inv["status"] != "pending" {
			t.Errorf("expected status 'pending', got %v", inv["status"])
		}
	})

	t.Run("invites user with admin role", func(t *testing.T) {
		inv := inviteMember(t, h, ownerCookies, "admin@test.com", "admin")
		if inv["role"] != "admin" {
			t.Errorf("expected role 'admin', got %v", inv["role"])
		}
	})

	t.Run("prevents inviting user with owner role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "co-owner@test.com",
			"role":  "owner",
		}, ownerCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE" {
			t.Errorf("expected YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE, got %v", resp["code"])
		}
	})

	t.Run("invites with multiple roles", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "multirole@test.com",
			"role":  []string{"admin", "member"},
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "admin,member" {
			t.Errorf("expected role 'admin,member', got %v", resp["role"])
		}
	})

	t.Run("prevents duplicate invitation", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "member@test.com",
			"role":  "member",
		}, ownerCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("prevents duplicate invitation case-insensitive", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "MEMBER@test.com",
			"role":  "member",
		}, ownerCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestAcceptInvitation(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Accept Org", "accept-org")

	t.Run("accepts invitation and becomes member", func(t *testing.T) {
		inv := inviteMember(t, h, ownerCookies, "invitee@test.com", "member")
		invID, _ := inv["id"].(string)

		// Create the invitee user.
		inviteeCookies := signUpUser(t, h, "invitee@test.com", "password123", "Invitee")

		// Accept the invitation.
		result := acceptInvitation(t, h, inviteeCookies, invID)
		member, _ := result["member"].(map[string]any)
		if member["role"] != "member" {
			t.Errorf("expected role 'member', got %v", member["role"])
		}
	})

	t.Run("prevents accepting invitation for a different email", func(t *testing.T) {
		inv := inviteMember(t, h, ownerCookies, "realinvitee@test.com", "member")
		invID, _ := inv["id"].(string)

		attackerCookies := signUpUser(t, h, "attacker@test.com", "password123", "Attacker")
		rr := postJSON(t, h, "/api/auth/organization/accept-invitation", map[string]any{
			"invitationId": invID,
		}, attackerCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("prevents re-inviting accepted member", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "invitee@test.com",
			"role":  "member",
		}, ownerCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION" {
			t.Errorf("expected USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION, got %v", resp["code"])
		}
	})
}

func TestRejectInvitation(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Reject Org", "reject-org")

	inv := inviteMember(t, h, ownerCookies, "rejectee@test.com", "member")
	invID, _ := inv["id"].(string)

	t.Run("rejects invitation", func(t *testing.T) {
		rejecteeCookies := signUpUser(t, h, "rejectee@test.com", "password123", "Rejectee")
		rr := postJSON(t, h, "/api/auth/organization/reject-invitation", map[string]any{
			"invitationId": invID,
		}, rejecteeCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["status"] != "rejected" {
			t.Errorf("expected status 'rejected', got %v", resp["status"])
		}
	})

	t.Run("prevents rejecting invitation for a different email", func(t *testing.T) {
		inv2 := inviteMember(t, h, ownerCookies, "realrejectee@test.com", "member")
		inv2ID, _ := inv2["id"].(string)
		otherCookies := signUpUser(t, h, "other@test.com", "password123", "Other")
		rr := postJSON(t, h, "/api/auth/organization/reject-invitation", map[string]any{
			"invitationId": inv2ID,
		}, otherCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCancelInvitation(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Cancel Org", "cancel-org")

	inv := inviteMember(t, h, ownerCookies, "cancelee@test.com", "member")
	invID, _ := inv["id"].(string)

	t.Run("cancels invitation", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/cancel-invitation", map[string]any{
			"invitationId": invID,
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["status"] != "cancelled" {
			t.Errorf("expected status 'cancelled', got %v", resp["status"])
		}
	})
}

// --- Tests: Member Management ---

func TestGetActiveMember(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "User")
	createOrg(t, h, cookies, "Active Org", "active-org")

	t.Run("returns active member with owner role", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-active-member", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "owner" {
			t.Errorf("expected role 'owner', got %v", resp["role"])
		}
	})
}

func TestUpdateMemberRole(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Role Org", "role-org")

	// Add a member via invitation.
	inv := inviteMember(t, h, ownerCookies, "member@test.com", "member")
	invID, _ := inv["id"].(string)
	memberCookies := signUpUser(t, h, "member@test.com", "password123", "Member")
	result := acceptInvitation(t, h, memberCookies, invID)
	member, _ := result["member"].(map[string]any)
	memberID, _ := member["id"].(string)

	t.Run("updates member role to admin", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update-member-role", map[string]any{
			"memberId": memberID,
			"role":     "admin",
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "admin" {
			t.Errorf("expected role 'admin', got %v", resp["role"])
		}
	})

	t.Run("sets multiple roles on member", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update-member-role", map[string]any{
			"memberId": memberID,
			"role":     []string{"member", "admin"},
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "member,admin" {
			t.Errorf("expected role 'member,admin', got %v", resp["role"])
		}
	})

	t.Run("owner can transfer ownership and remain non-owner", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update-member-role", map[string]any{
			"memberId": memberID,
			"role":     "owner",
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		rr = getJSON(t, h, "/api/auth/organization/get-full-organization", ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		members, _ := resp["members"].([]any)
		ownerCount := 0
		oldOwnerStillOwner := false
		newOwnerSet := false
		for _, m := range members {
			mm, _ := m.(map[string]any)
			role, _ := mm["role"].(string)
			if role == "owner" {
				ownerCount++
			}
			id, _ := mm["id"].(string)
			if id == memberID && role == "owner" {
				newOwnerSet = true
			}
			if id != memberID && role == "owner" {
				oldOwnerStillOwner = true
			}
		}
		if ownerCount != 1 {
			t.Fatalf("expected exactly 1 owner, got %d", ownerCount)
		}
		if !newOwnerSet {
			t.Fatal("expected target member to become owner")
		}
		if oldOwnerStillOwner {
			t.Fatal("expected previous owner to be demoted")
		}
	})
}

func TestNonOwnerCannotInviteOwner(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Restrict Org", "restrict-org")

	// Add admin via invitation.
	inv := inviteMember(t, h, ownerCookies, "admin@test.com", "admin")
	invID, _ := inv["id"].(string)
	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	acceptInvitation(t, h, adminCookies, invID)
	// Re-sign in so session has the org active.
	adminCookies = signInUser(t, h, "admin@test.com", "password123")
	// Set active org.
	rr := getJSON(t, h, "/api/auth/organization/get-full-organization?organizationSlug=restrict-org", adminCookies)
	orgResp := decodeResp(t, rr)
	orgID, _ := orgResp["id"].(string)
	postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
		"organizationId": orgID,
	}, adminCookies)

	t.Run("admin cannot invite with owner role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "newowner@test.com",
			"role":  "owner",
		}, adminCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE" {
			t.Errorf("expected YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE, got %v", resp["code"])
		}
	})
}

func TestNonOwnerCannotUpdateOwnerRole(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Protect Org", "protect-org")

	// Get owner member ID.
	rr := getJSON(t, h, "/api/auth/organization/get-full-organization", ownerCookies)
	orgResp := decodeResp(t, rr)
	members, _ := orgResp["members"].([]any)
	ownerMember, _ := members[0].(map[string]any)
	ownerMemberID, _ := ownerMember["id"].(string)
	orgID, _ := orgResp["id"].(string)

	// Add admin.
	inv := inviteMember(t, h, ownerCookies, "admin@test.com", "admin")
	invID, _ := inv["id"].(string)
	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	acceptInvitation(t, h, adminCookies, invID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")
	postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
		"organizationId": orgID,
	}, adminCookies)

	t.Run("admin cannot update owner role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update-member-role", map[string]any{
			"memberId": ownerMemberID,
			"role":     "admin",
		}, adminCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestLeaveOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Leave Org", "leave-org")

	// Add admin member.
	inv := inviteMember(t, h, ownerCookies, "leaver@test.com", "admin")
	invID, _ := inv["id"].(string)
	leaverCookies := signUpUser(t, h, "leaver@test.com", "password123", "Leaver")
	acceptInvitation(t, h, leaverCookies, invID)

	t.Run("member can leave organization", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/leave", map[string]any{}, leaverCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["userId"] == nil || resp["userId"] == "" {
			t.Error("expected userId in response")
		}
	})
}

func TestRemoveMember(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Remove Org", "remove-org")

	// Add multiple members.
	for i := 0; i < 3; i++ {
		email := "rmuser" + string(rune('a'+i)) + "@test.com"
		inv := inviteMember(t, h, ownerCookies, email, "member")
		invID, _ := inv["id"].(string)
		memberCookies := signUpUser(t, h, email, "password123", "RmUser")
		acceptInvitation(t, h, memberCookies, invID)
	}

	t.Run("removes member by email", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/remove-member", map[string]any{
			"email": "rmusera@test.com",
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify member count.
		rr = getJSON(t, h, "/api/auth/organization/list-members", ownerCookies)
		members := decodeArray(t, rr)
		if len(members) != 3 { // owner + 2 remaining
			t.Errorf("expected 3 members after removal, got %d", len(members))
		}
	})

	t.Run("prevents removing last owner", func(t *testing.T) {
		// Get owner member ID.
		rr := getJSON(t, h, "/api/auth/organization/get-active-member", ownerCookies)
		resp := decodeResp(t, rr)
		ownerMemberID, _ := resp["id"].(string)

		rr = postJSON(t, h, "/api/auth/organization/remove-member", map[string]any{
			"memberId": ownerMemberID,
		}, ownerCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestMemberIDIsScopedToActiveOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	org1 := createOrg(t, h, ownerCookies, "Scoped Org 1", "scoped-org-1")
	org1ID, _ := org1["id"].(string)

	inv1 := inviteMember(t, h, ownerCookies, "scoped1@test.com", "member")
	inv1ID, _ := inv1["id"].(string)
	m1Cookies := signUpUser(t, h, "scoped1@test.com", "password123", "Scoped1")
	member1 := acceptInvitation(t, h, m1Cookies, inv1ID)
	member1Data, _ := member1["member"].(map[string]any)
	member1ID, _ := member1Data["id"].(string)
	if member1ID == "" {
		t.Fatal("expected member1 id")
	}

	org2 := createOrg(t, h, ownerCookies, "Scoped Org 2", "scoped-org-2")
	org2ID, _ := org2["id"].(string)
	if org2ID == "" {
		t.Fatal("expected org2 id")
	}
	inv2 := inviteMember(t, h, ownerCookies, "scoped2@test.com", "member")
	inv2ID, _ := inv2["id"].(string)
	m2Cookies := signUpUser(t, h, "scoped2@test.com", "password123", "Scoped2")
	member2 := acceptInvitation(t, h, m2Cookies, inv2ID)
	member2Data, _ := member2["member"].(map[string]any)
	member2ID, _ := member2Data["id"].(string)
	if member2ID == "" {
		t.Fatal("expected member2 id")
	}

	// Ensure active org is org1.
	setActive := postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
		"organizationId": org1ID,
	}, ownerCookies)
	if setActive.Code != http.StatusOK {
		t.Fatalf("failed to set active org: %d %s", setActive.Code, setActive.Body.String())
	}

	t.Run("cannot update member from another organization by memberId", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/update-member-role", map[string]any{
			"memberId": member2ID,
			"role":     "admin",
		}, ownerCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cannot remove member from another organization by memberId", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/remove-member", map[string]any{
			"memberId": member2ID,
		}, ownerCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- Tests: Permissions ---

func TestHasPermission(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Perm Org", "perm-org")

	t.Run("owner has member update permission", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/has-permission", map[string]any{
			"permissions": map[string][]string{
				"member": {"update"},
			},
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["success"] != true {
			t.Error("expected success true for owner member:update")
		}
	})

	t.Run("owner has multiple permissions", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/has-permission", map[string]any{
			"permissions": map[string][]string{
				"member":     {"update"},
				"invitation": {"create"},
			},
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["success"] != true {
			t.Error("expected success true for owner with multiple permissions")
		}
	})
}

func TestAccessControlUnit(t *testing.T) {
	roles := organization.DefaultRoles()

	t.Run("owner has all permissions", func(t *testing.T) {
		result := organization.HasPermission("owner", map[string][]string{
			"organization": {"update", "delete"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
		}, roles)
		if !result {
			t.Error("expected owner to have all permissions")
		}
	})

	t.Run("admin has update but not delete org", func(t *testing.T) {
		result := organization.HasPermission("admin", map[string][]string{
			"organization": {"update"},
		}, roles)
		if !result {
			t.Error("expected admin to have org:update")
		}

		result = organization.HasPermission("admin", map[string][]string{
			"organization": {"delete"},
		}, roles)
		if result {
			t.Error("expected admin to NOT have org:delete")
		}
	})

	t.Run("member has no permissions", func(t *testing.T) {
		result := organization.HasPermission("member", map[string][]string{
			"organization": {"update"},
		}, roles)
		if result {
			t.Error("expected member to NOT have org:update")
		}

		result = organization.HasPermission("member", map[string][]string{
			"member": {"create"},
		}, roles)
		if result {
			t.Error("expected member to NOT have member:create")
		}
	})

	t.Run("comma-separated roles checked", func(t *testing.T) {
		result := organization.HasPermission("member,admin", map[string][]string{
			"member": {"create"},
		}, roles)
		if !result {
			t.Error("expected member,admin to have member:create (via admin)")
		}
	})
}

// --- Tests: Invitation Limits ---

func TestInvitationLimit(t *testing.T) {
	p := organization.New(&organization.Options{
		InvitationLimit: 1,
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "User")
	createOrg(t, h, cookies, "Limit Org", "limit-org")

	t.Run("allows invite within limit", func(t *testing.T) {
		inv := inviteMember(t, h, cookies, "first@test.com", "member")
		if inv["status"] != "pending" {
			t.Errorf("expected pending, got %v", inv["status"])
		}
	})

	t.Run("prevents invite exceeding limit", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "second@test.com",
			"role":  "member",
		}, cookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "INVITATION_LIMIT_REACHED" {
			t.Errorf("expected INVITATION_LIMIT_REACHED, got %v", resp["code"])
		}
	})
}

// --- Tests: Membership Limits ---

func TestMembershipLimit(t *testing.T) {
	p := organization.New(&organization.Options{
		MembershipLimit: 3, // owner + 2 members max
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, cookies, "MLimit Org", "mlimit-org")

	// Add first member (total: 2).
	inv1 := inviteMember(t, h, cookies, "m1@test.com", "member")
	invID1, _ := inv1["id"].(string)
	m1Cookies := signUpUser(t, h, "m1@test.com", "password123", "M1")
	acceptInvitation(t, h, m1Cookies, invID1)

	// Add second member (total: 3).
	inv2 := inviteMember(t, h, cookies, "m2@test.com", "member")
	invID2, _ := inv2["id"].(string)
	m2Cookies := signUpUser(t, h, "m2@test.com", "password123", "M2")
	acceptInvitation(t, h, m2Cookies, invID2)

	t.Run("prevents exceeding membership limit on invite", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email": "m3@test.com",
			"role":  "member",
		}, cookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED" {
			t.Errorf("expected ORGANIZATION_MEMBERSHIP_LIMIT_REACHED, got %v", resp["code"])
		}
	})
}

// --- Tests: Cancel Pending on Re-invite ---

func TestCancelPendingOnReInvite(t *testing.T) {
	p := organization.New(&organization.Options{
		CancelPendingInvitationsOnReInvite: true,
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, cookies, "ReInvite Org", "reinvite-org")

	t.Run("cancels pending invitation and creates new one", func(t *testing.T) {
		// First invitation.
		inviteMember(t, h, cookies, "user@test.com", "member")

		// Re-invite the same email.
		inv2 := inviteMember(t, h, cookies, "user@test.com", "admin")
		if inv2["role"] != "admin" {
			t.Errorf("expected new invitation with role 'admin', got %v", inv2["role"])
		}

		// List invitations - should have 1 pending (old is cancelled).
		rr := getJSON(t, h, "/api/auth/organization/get-full-organization", cookies)
		resp := decodeResp(t, rr)
		invitations, _ := resp["invitations"].([]any)
		pendingCount := 0
		for _, inv := range invitations {
			invMap, _ := inv.(map[string]any)
			if invMap["status"] == "pending" {
				pendingCount++
			}
		}
		if pendingCount != 1 {
			t.Errorf("expected 1 pending invitation, got %d", pendingCount)
		}
	})
}

func TestResendInvitation(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, cookies, "Resend Org", "resend-org")

	t.Run("returns existing invitation on resend", func(t *testing.T) {
		inv1 := inviteMember(t, h, cookies, "resend@test.com", "member")
		inv1ID, _ := inv1["id"].(string)

		rr := postJSON(t, h, "/api/auth/organization/invite-member", map[string]any{
			"email":  "resend@test.com",
			"role":   "member",
			"resend": true,
		}, cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["id"] != inv1ID {
			t.Errorf("expected same invitation ID %s, got %v", inv1ID, resp["id"])
		}
	})
}

// --- Tests: List Invitations ---

func TestListInvitations(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, cookies, "ListInv Org", "listinv-org")

	// Create multiple invitations.
	for i := 0; i < 5; i++ {
		email := "inv" + string(rune('a'+i)) + "@test.com"
		inviteMember(t, h, cookies, email, "member")
	}

	t.Run("lists all invitations for organization", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/list-invitations", cookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		invitations := decodeArray(t, rr)
		if len(invitations) != 5 {
			t.Errorf("expected 5 invitations, got %d", len(invitations))
		}
	})
}

func TestListUserInvitations(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "UserInv Org", "userinv-org")

	t.Run("lists pending invitations for user", func(t *testing.T) {
		inviteMember(t, h, ownerCookies, "target@test.com", "member")

		targetCookies := signUpUser(t, h, "target@test.com", "password123", "Target")
		rr := getJSON(t, h, "/api/auth/organization/list-user-invitations", targetCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		invitations := decodeArray(t, rr)
		if len(invitations) != 1 {
			t.Errorf("expected 1 invitation, got %d", len(invitations))
		}
		if len(invitations) > 0 {
			inv, _ := invitations[0].(map[string]any)
			if inv["organizationName"] != "UserInv Org" {
				t.Errorf("expected organizationName 'UserInv Org', got %v", inv["organizationName"])
			}
		}
	})

	t.Run("ignores explicit email query and only returns current user's invitations", func(t *testing.T) {
		otherCookies := signUpUser(t, h, "otherlist@test.com", "password123", "OtherList")
		rr := getJSON(t, h, "/api/auth/organization/list-user-invitations?email=target@test.com", otherCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		invitations := decodeArray(t, rr)
		if len(invitations) != 0 {
			t.Errorf("expected 0 invitations for unrelated user, got %d", len(invitations))
		}
	})

	t.Run("excludes accepted invitations from list", func(t *testing.T) {
		// The user above now has a pending invitation. Accept it.
		targetCookies := signInUser(t, h, "target@test.com", "password123")
		rr := getJSON(t, h, "/api/auth/organization/list-user-invitations", targetCookies)
		invitations := decodeArray(t, rr)
		if len(invitations) != 1 {
			t.Fatalf("expected 1 pending invitation before acceptance, got %d", len(invitations))
		}
		inv, _ := invitations[0].(map[string]any)
		invID, _ := inv["id"].(string)
		acceptInvitation(t, h, targetCookies, invID)

		// Now list again.
		rr = getJSON(t, h, "/api/auth/organization/list-user-invitations", targetCookies)
		invitations = decodeArray(t, rr)
		if len(invitations) != 0 {
			t.Errorf("expected 0 pending invitations after acceptance, got %d", len(invitations))
		}
	})

	t.Run("excludes rejected invitations from list", func(t *testing.T) {
		inviteMember(t, h, ownerCookies, "rejecter@test.com", "member")
		rejecterCookies := signUpUser(t, h, "rejecter@test.com", "password123", "Rejecter")

		rr := getJSON(t, h, "/api/auth/organization/list-user-invitations", rejecterCookies)
		invitations := decodeArray(t, rr)
		inv, _ := invitations[0].(map[string]any)
		invID, _ := inv["id"].(string)

		// Reject.
		postJSON(t, h, "/api/auth/organization/reject-invitation", map[string]any{
			"invitationId": invID,
		}, rejecterCookies)

		rr = getJSON(t, h, "/api/auth/organization/list-user-invitations", rejecterCookies)
		invitations = decodeArray(t, rr)
		if len(invitations) != 0 {
			t.Errorf("expected 0 pending invitations after rejection, got %d", len(invitations))
		}
	})
}

// --- Tests: Organization Deletion ---

func TestDeleteOrganization(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	org := createOrg(t, h, ownerCookies, "Delete Org", "delete-org")
	orgID, _ := org["id"].(string)

	t.Run("non-member cannot delete org", func(t *testing.T) {
		nonMemberCookies := signUpUser(t, h, "nonmember@test.com", "password123", "NonMember")
		rr := postJSON(t, h, "/api/auth/organization/delete", map[string]any{
			"organizationId": orgID,
		}, nonMemberCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("owner can delete organization", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/delete", map[string]any{
			"organizationId": orgID,
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify org is gone.
		rr = getJSON(t, h, "/api/auth/organization/get-full-organization?organizationId="+orgID, ownerCookies)
		if rr.Code == http.StatusOK {
			t.Error("expected error accessing deleted org, but got 200")
		}
	})
}

func TestMemberCannotDeleteOrg(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	org := createOrg(t, h, ownerCookies, "NoDel Org", "nodel-org")
	orgID, _ := org["id"].(string)

	// Add member.
	inv := inviteMember(t, h, ownerCookies, "member@test.com", "member")
	invID, _ := inv["id"].(string)
	memberCookies := signUpUser(t, h, "member@test.com", "password123", "Member")
	acceptInvitation(t, h, memberCookies, invID)
	memberCookies = signInUser(t, h, "member@test.com", "password123")
	postJSON(t, h, "/api/auth/organization/set-active", map[string]any{
		"organizationId": orgID,
	}, memberCookies)

	t.Run("member cannot delete organization", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/delete", map[string]any{
			"organizationId": orgID,
		}, memberCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- Tests: Add Member (Server-side) ---

func TestAddMember(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "AddMember Org", "addmember-org")

	// Create a user to add.
	signUpUser(t, h, "newmember@test.com", "password123", "NewMember")
	nmCookies := signInUser(t, h, "newmember@test.com", "password123")
	nmID := getUserID(t, h, nmCookies)

	t.Run("adds member with admin role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/add-member", map[string]any{
			"userId": nmID,
			"role":   "admin",
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "admin" {
			t.Errorf("expected role 'admin', got %v", resp["role"])
		}
	})

	t.Run("prevents adding duplicate member", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/add-member", map[string]any{
			"userId": nmID,
			"role":   "member",
		}, ownerCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("adds member with multiple roles", func(t *testing.T) {
		signUpUser(t, h, "multi@test.com", "password123", "Multi")
		multiCookies := signInUser(t, h, "multi@test.com", "password123")
		multiID := getUserID(t, h, multiCookies)

		rr := postJSON(t, h, "/api/auth/organization/add-member", map[string]any{
			"userId": multiID,
			"role":   []string{"admin", "member"},
		}, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["role"] != "admin,member" {
			t.Errorf("expected role 'admin,member', got %v", resp["role"])
		}
	})
}

// --- Tests: List Members ---

func TestListMembers(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "Members Org", "members-org")

	// Add 2 members.
	for i := 0; i < 2; i++ {
		email := "lm" + string(rune('a'+i)) + "@test.com"
		inv := inviteMember(t, h, ownerCookies, email, "member")
		invID, _ := inv["id"].(string)
		mc := signUpUser(t, h, email, "password123", "LM")
		acceptInvitation(t, h, mc, invID)
	}

	t.Run("lists all members", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/list-members", ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		members := decodeArray(t, rr)
		if len(members) != 3 { // owner + 2 members
			t.Errorf("expected 3 members, got %d", len(members))
		}
	})
}

// --- Tests: Get Invitation ---

func TestGetInvitation(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	ownerCookies := signUpUser(t, h, "owner@test.com", "password123", "Owner")
	createOrg(t, h, ownerCookies, "GetInv Org", "getinv-org")

	inv := inviteMember(t, h, ownerCookies, "getinv@test.com", "member")
	invID, _ := inv["id"].(string)

	t.Run("returns invitation with org details", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-invitation?invitationId="+invID, ownerCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["organizationName"] != "GetInv Org" {
			t.Errorf("expected organizationName 'GetInv Org', got %v", resp["organizationName"])
		}
		if resp["organizationSlug"] != "getinv-org" {
			t.Errorf("expected organizationSlug 'getinv-org', got %v", resp["organizationSlug"])
		}
	})

	t.Run("returns 404 for non-existent invitation", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/organization/get-invitation?invitationId=nonexistent", ownerCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("non-member and non-invitee cannot access invitation", func(t *testing.T) {
		otherCookies := signUpUser(t, h, "outsider@test.com", "password123", "Outsider")
		rr := getJSON(t, h, "/api/auth/organization/get-invitation?invitationId="+invID, otherCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- Tests: Unauthenticated access ---

func TestUnauthenticatedAccess(t *testing.T) {
	p := organization.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/auth/organization/create"},
		{http.MethodGet, "/api/auth/organization/list"},
		{http.MethodPost, "/api/auth/organization/set-active"},
		{http.MethodGet, "/api/auth/organization/get-full-organization"},
		{http.MethodPost, "/api/auth/organization/invite-member"},
		{http.MethodPost, "/api/auth/organization/accept-invitation"},
		{http.MethodPost, "/api/auth/organization/has-permission"},
		{http.MethodGet, "/api/auth/organization/get-active-member"},
	}

	for _, ep := range endpoints {
		t.Run("returns 401 for "+ep.method+" "+ep.path, func(t *testing.T) {
			var rr *httptest.ResponseRecorder
			if ep.method == http.MethodPost {
				rr = postJSON(t, h, ep.path, map[string]any{}, nil)
			} else {
				rr = getJSON(t, h, ep.path, nil)
			}
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for %s %s, got %d", ep.method, ep.path, rr.Code)
			}
		})
	}
}

// --- Tests: Organization Limit ---

func TestOrganizationLimit(t *testing.T) {
	p := organization.New(&organization.Options{
		OrganizationLimit: 2,
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "User")
	createOrg(t, h, cookies, "Org 1", "org-1")
	createOrg(t, h, cookies, "Org 2", "org-2")

	t.Run("prevents exceeding organization limit", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
			"name": "Org 3",
			"slug": "org-3",
		}, cookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["code"] != "ORGANIZATION_LIMIT_REACHED" {
			t.Errorf("expected ORGANIZATION_LIMIT_REACHED, got %v", resp["code"])
		}
	})
}

// --- Tests: Disallow User Creating Orgs ---

func TestDisallowUserCreateOrganization(t *testing.T) {
	disallow := false
	p := organization.New(&organization.Options{
		AllowUserToCreateOrganization: &disallow,
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "user@test.com", "password123", "User")

	t.Run("prevents user from creating organization", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/organization/create", map[string]any{
			"name": "Blocked Org",
			"slug": "blocked",
		}, cookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- Tests: Custom Roles ---

func TestCustomRoles(t *testing.T) {
	customRoles := map[string]*organization.Role{
		"owner": organization.NewRole(organization.Statements{
			"organization": {"update", "delete"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
		}),
		"editor": organization.NewRole(organization.Statements{
			"organization": {"update"},
			"member":       {},
			"invitation":   {},
		}),
		"viewer": organization.NewRole(organization.Statements{
			"organization": {},
			"member":       {},
			"invitation":   {},
		}),
	}

	t.Run("custom role has defined permissions", func(t *testing.T) {
		result := organization.HasPermission("editor", map[string][]string{
			"organization": {"update"},
		}, customRoles)
		if !result {
			t.Error("expected editor to have org:update")
		}
	})

	t.Run("custom role lacks undefined permissions", func(t *testing.T) {
		result := organization.HasPermission("editor", map[string][]string{
			"organization": {"delete"},
		}, customRoles)
		if result {
			t.Error("expected editor to NOT have org:delete")
		}
	})

	t.Run("viewer has no permissions", func(t *testing.T) {
		result := organization.HasPermission("viewer", map[string][]string{
			"organization": {"update"},
		}, customRoles)
		if result {
			t.Error("expected viewer to NOT have org:update")
		}
	})
}

// --- Tests: CanManageRole ---

func TestCanManageRole(t *testing.T) {
	t.Run("owner can manage anyone", func(t *testing.T) {
		if !organization.CanManageRole("owner", "admin") {
			t.Error("expected owner to manage admin")
		}
		if !organization.CanManageRole("owner", "member") {
			t.Error("expected owner to manage member")
		}
		if !organization.CanManageRole("owner", "owner") {
			t.Error("expected owner to manage owner")
		}
	})

	t.Run("admin cannot manage owners", func(t *testing.T) {
		if organization.CanManageRole("admin", "owner") {
			t.Error("expected admin to NOT manage owner")
		}
	})

	t.Run("admin can manage members", func(t *testing.T) {
		if !organization.CanManageRole("admin", "member") {
			t.Error("expected admin to manage member")
		}
	})

	t.Run("member cannot manage anyone", func(t *testing.T) {
		if organization.CanManageRole("member", "member") {
			t.Error("expected member to NOT manage member")
		}
	})
}
