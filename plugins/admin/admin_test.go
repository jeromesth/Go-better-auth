package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter/memory"
	"github.com/jeromesth/go-better-auth/plugin"
	"github.com/jeromesth/go-better-auth/plugins/admin"
)

// --- Test helpers ---

func newTestAuth(adminPlugin *admin.Plugin) *betterauth.Auth {
	return betterauth.New(betterauth.BetterAuthOptions{
		AppName:  "Admin Test",
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
		Plugins:   []plugin.Plugin{adminPlugin},
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

// signUpUser creates a user and returns the session cookies.
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

// signInUser signs in and returns session cookies.
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

// getUserID extracts the user ID from a sign-up/sign-in response or get-session.
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

// promoteToAdmin sets a user's role to admin directly via the internal adapter.
func promoteToAdmin(t *testing.T, auth *betterauth.Auth, userID string) {
	t.Helper()
	_, err := auth.InternalAdapter().UpdateUserRaw(t.Context(), userID, map[string]any{
		"role": "admin",
	})
	if err != nil {
		t.Fatalf("promote to admin: %v", err)
	}
}

// --- Tests ---

func TestCreateUser(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	// Sign up an admin user.
	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	// Re-sign in to get fresh session.
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	t.Run("creates a user with password", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/create-user", map[string]any{
			"email":    "newuser@test.com",
			"password": "userpass123",
			"name":     "New User",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		user, _ := resp["user"].(map[string]any)
		if user["email"] != "newuser@test.com" {
			t.Errorf("expected email newuser@test.com, got %v", user["email"])
		}
		if user["role"] != "user" {
			t.Errorf("expected default role 'user', got %v", user["role"])
		}
	})

	t.Run("creates a user without password", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/create-user", map[string]any{
			"email": "nopass@test.com",
			"name":  "No Password",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("rejects duplicate email", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/create-user", map[string]any{
			"email":    "newuser@test.com",
			"password": "pass123456",
			"name":     "Dup",
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("creates user with custom role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/create-user", map[string]any{
			"email":    "roleuser@test.com",
			"password": "rolepass123",
			"name":     "Role User",
			"role":     "admin",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		user, _ := resp["user"].(map[string]any)
		if user["role"] != "admin" {
			t.Errorf("expected role 'admin', got %v", user["role"])
		}
	})

	t.Run("non-admin cannot create users", func(t *testing.T) {
		userCookies := signUpUser(t, h, "regular@test.com", "password123", "Regular")
		rr := postJSON(t, h, "/api/auth/admin/create-user", map[string]any{
			"email":    "shouldfail@test.com",
			"password": "password123",
			"name":     "Fail",
		}, userCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestGetUser(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	// Create a target user.
	signUpUser(t, h, "target@test.com", "password123", "Target")

	t.Run("gets user by id", func(t *testing.T) {
		// First find the target user via list.
		rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("list-users failed: %d", rr.Code)
		}
		resp := decodeResp(t, rr)
		users, _ := resp["users"].([]any)
		var targetID string
		for _, u := range users {
			um, _ := u.(map[string]any)
			if um["email"] == "target@test.com" {
				targetID, _ = um["id"].(string)
			}
		}
		if targetID == "" {
			t.Fatal("target user not found")
		}

		rr = getJSON(t, h, "/api/auth/admin/get-user?id="+targetID, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("get-user failed: %d: %s", rr.Code, rr.Body.String())
		}
		resp = decodeResp(t, rr)
		if resp["email"] != "target@test.com" {
			t.Errorf("expected target@test.com, got %v", resp["email"])
		}
	})

	t.Run("returns 404 for non-existent user", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/admin/get-user?id=nonexistent", adminCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})
}

func TestListUsers(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	// Create some users.
	signUpUser(t, h, "alice@test.com", "password123", "Alice")
	signUpUser(t, h, "bob@test.com", "password123", "Bob")
	signUpUser(t, h, "charlie@test.com", "password123", "Charlie")

	t.Run("lists all users", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		resp := decodeResp(t, rr)
		users, _ := resp["users"].([]any)
		total, _ := resp["total"].(float64)
		if len(users) < 4 { // admin + 3 users
			t.Errorf("expected at least 4 users, got %d", len(users))
		}
		if total < 4 {
			t.Errorf("expected total >= 4, got %v", total)
		}
	})

	t.Run("always includes limit and offset", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
		resp := decodeResp(t, rr)
		if _, ok := resp["limit"]; !ok {
			t.Error("expected limit field in response")
		}
		if _, ok := resp["offset"]; !ok {
			t.Error("expected offset field in response")
		}
	})

	t.Run("supports pagination", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/admin/list-users?limit=2&offset=0", adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		resp := decodeResp(t, rr)
		users, _ := resp["users"].([]any)
		if len(users) != 2 {
			t.Errorf("expected 2 users, got %d", len(users))
		}
	})

	t.Run("supports search", func(t *testing.T) {
		rr := getJSON(t, h, "/api/auth/admin/list-users?searchValue=alice&searchField=email", adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		resp := decodeResp(t, rr)
		users, _ := resp["users"].([]any)
		if len(users) != 1 {
			t.Errorf("expected 1 user matching 'alice', got %d", len(users))
		}
	})
}

func TestSetRole(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	userCookies := signUpUser(t, h, "user@test.com", "password123", "User")
	userID := getUserID(t, h, userCookies)

	t.Run("sets role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/set-role", map[string]any{
			"userId": userID,
			"role":   "admin",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		user, _ := resp["user"].(map[string]any)
		if user["role"] != "admin" {
			t.Errorf("expected role 'admin', got %v", user["role"])
		}
	})

	t.Run("rejects non-existent role", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/set-role", map[string]any{
			"userId": userID,
			"role":   "superduper",
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestUpdateUser(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	userCookies := signUpUser(t, h, "user@test.com", "password123", "User")
	userID := getUserID(t, h, userCookies)

	t.Run("updates user name", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/update-user", map[string]any{
			"userId": userID,
			"data": map[string]any{
				"name": "Updated Name",
			},
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["name"] != "Updated Name" {
			t.Errorf("expected 'Updated Name', got %v", resp["name"])
		}
	})

	t.Run("rejects empty data", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/update-user", map[string]any{
			"userId": userID,
			"data":   map[string]any{},
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestSetUserPassword(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	signUpUser(t, h, "pwuser@test.com", "password123", "PW User")
	// Get userID from list
	rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
	resp := decodeResp(t, rr)
	users, _ := resp["users"].([]any)
	var pwUserID string
	for _, u := range users {
		um, _ := u.(map[string]any)
		if um["email"] == "pwuser@test.com" {
			pwUserID, _ = um["id"].(string)
		}
	}

	t.Run("sets user password", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/set-user-password", map[string]any{
			"userId":      pwUserID,
			"newPassword": "newpassword123",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify new password works.
		loginRR := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
			"email":    "pwuser@test.com",
			"password": "newpassword123",
		}, nil)
		if loginRR.Code != http.StatusOK {
			t.Fatalf("new password sign-in failed: %d %s", loginRR.Code, loginRR.Body.String())
		}
	})

	t.Run("rejects too short password", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/set-user-password", map[string]any{
			"userId":      pwUserID,
			"newPassword": "short",
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestBanUnban(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	signUpUser(t, h, "banme@test.com", "password123", "BanMe")
	rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
	resp := decodeResp(t, rr)
	users, _ := resp["users"].([]any)
	var banUserID string
	for _, u := range users {
		um, _ := u.(map[string]any)
		if um["email"] == "banme@test.com" {
			banUserID, _ = um["id"].(string)
		}
	}

	t.Run("bans a user", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/ban-user", map[string]any{
			"userId":    banUserID,
			"banReason": "Testing ban",
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		user, _ := resp["user"].(map[string]any)
		if user["banned"] != true {
			t.Error("expected banned to be true")
		}
		if user["banReason"] != "Testing ban" {
			t.Errorf("expected ban reason 'Testing ban', got %v", user["banReason"])
		}
	})

	t.Run("banned user cannot sign in", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
			"email":    "banme@test.com",
			"password": "password123",
		}, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for banned user, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cannot ban yourself", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/ban-user", map[string]any{
			"userId": adminID,
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unbans a user", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/unban-user", map[string]any{
			"userId": banUserID,
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify user can sign in again.
		loginRR := postJSON(t, h, "/api/auth/sign-in/email", map[string]string{
			"email":    "banme@test.com",
			"password": "password123",
		}, nil)
		if loginRR.Code != http.StatusOK {
			t.Fatalf("unbanned user sign-in failed: %d %s", loginRR.Code, loginRR.Body.String())
		}
	})
}

func TestRemoveUser(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	signUpUser(t, h, "removeme@test.com", "password123", "RemoveMe")
	rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
	resp := decodeResp(t, rr)
	users, _ := resp["users"].([]any)
	var removeUserID string
	for _, u := range users {
		um, _ := u.(map[string]any)
		if um["email"] == "removeme@test.com" {
			removeUserID, _ = um["id"].(string)
		}
	}

	t.Run("cannot remove yourself", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/remove-user", map[string]any{
			"userId": adminID,
		}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("removes a user", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/remove-user", map[string]any{
			"userId": removeUserID,
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify user is gone.
		rr = getJSON(t, h, "/api/auth/admin/get-user?id="+removeUserID, adminCookies)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for deleted user, got %d", rr.Code)
		}
	})
}

func TestSessionManagement(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	userCookies := signUpUser(t, h, "sessuser@test.com", "password123", "SessUser")
	userID := getUserID(t, h, userCookies)

	t.Run("lists user sessions", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/list-user-sessions", map[string]any{
			"userId": userID,
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		sessions, _ := resp["sessions"].([]any)
		if len(sessions) == 0 {
			t.Error("expected at least one session")
		}
	})

	t.Run("revokes all user sessions", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/revoke-user-sessions", map[string]any{
			"userId": userID,
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify sessions are gone.
		rr = postJSON(t, h, "/api/auth/admin/list-user-sessions", map[string]any{
			"userId": userID,
		}, adminCookies)
		resp := decodeResp(t, rr)
		sessions, _ := resp["sessions"].([]any)
		if len(sessions) != 0 {
			t.Errorf("expected 0 sessions after revocation, got %d", len(sessions))
		}
	})
}

func TestImpersonation(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	userCookies := signUpUser(t, h, "impuser@test.com", "password123", "ImpUser")
	userID := getUserID(t, h, userCookies)

	t.Run("impersonates a user", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/impersonate-user", map[string]any{
			"userId": userID,
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		user, _ := resp["user"].(map[string]any)
		if user["email"] != "impuser@test.com" {
			t.Errorf("expected impersonated user email, got %v", user["email"])
		}

		// Should have set cookies.
		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Error("expected session cookies from impersonation")
		}
	})

	t.Run("non-admin cannot impersonate", func(t *testing.T) {
		regCookies := signUpUser(t, h, "regular@test.com", "password123", "Regular")
		rr := postJSON(t, h, "/api/auth/admin/impersonate-user", map[string]any{
			"userId": userID,
		}, regCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cannot impersonate admin without permission", func(t *testing.T) {
		// Create another admin.
		signUpUser(t, h, "admin2@test.com", "password123", "Admin2")
		rr := getJSON(t, h, "/api/auth/admin/list-users", adminCookies)
		resp := decodeResp(t, rr)
		users, _ := resp["users"].([]any)
		var admin2ID string
		for _, u := range users {
			um, _ := u.(map[string]any)
			if um["email"] == "admin2@test.com" {
				admin2ID, _ = um["id"].(string)
			}
		}
		promoteToAdmin(t, auth, admin2ID)

		rr = postJSON(t, h, "/api/auth/admin/impersonate-user", map[string]any{
			"userId": admin2ID,
		}, adminCookies)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for impersonating admin, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestHasPermission(t *testing.T) {
	t.Parallel()
	p := admin.New(nil)
	auth := newTestAuth(p)
	h := auth.Handler()

	adminCookies := signUpUser(t, h, "admin@test.com", "password123", "Admin")
	adminID := getUserID(t, h, adminCookies)
	promoteToAdmin(t, auth, adminID)
	adminCookies = signInUser(t, h, "admin@test.com", "password123")

	t.Run("admin has user create permission", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/has-permission", map[string]any{
			"permissions": map[string][]string{
				"user": {"create"},
			},
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["success"] != true {
			t.Errorf("expected success true, got %v", resp["success"])
		}
	})

	t.Run("user role lacks create permission", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/has-permission", map[string]any{
			"role": "user",
			"permissions": map[string][]string{
				"user": {"create"},
			},
		}, adminCookies)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		resp := decodeResp(t, rr)
		if resp["success"] != false {
			t.Errorf("expected success false, got %v", resp["success"])
		}
	})

	t.Run("rejects missing permissions", func(t *testing.T) {
		rr := postJSON(t, h, "/api/auth/admin/has-permission", map[string]any{}, adminCookies)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestDefaultRoleOnSignUp(t *testing.T) {
	t.Parallel()
	p := admin.New(&admin.Options{
		DefaultRole: "member",
	})
	auth := newTestAuth(p)
	h := auth.Handler()

	cookies := signUpUser(t, h, "member@test.com", "password123", "Member")
	userID := getUserID(t, h, cookies)

	// Promote to admin to query.
	promoteToAdmin(t, auth, userID)
	cookies = signInUser(t, h, "member@test.com", "password123")

	// Create another user to check their role.
	signUpUser(t, h, "new@test.com", "password123", "New User")

	rr := getJSON(t, h, "/api/auth/admin/list-users", cookies)
	resp := decodeResp(t, rr)
	users, _ := resp["users"].([]any)
	for _, u := range users {
		um, _ := u.(map[string]any)
		if um["email"] == "new@test.com" {
			if um["role"] != "member" {
				t.Errorf("expected default role 'member', got %v", um["role"])
			}
		}
	}
}

func TestAccessControl(t *testing.T) {
	t.Parallel()
	t.Run("default admin role has user create", func(t *testing.T) {
		result := admin.HasPermission(admin.HasPermissionInput{
			Role:        "admin",
			Permissions: map[string][]string{"user": {"create"}},
		})
		if !result {
			t.Error("expected admin to have user:create permission")
		}
	})

	t.Run("default user role lacks user create", func(t *testing.T) {
		result := admin.HasPermission(admin.HasPermissionInput{
			Role:        "user",
			Permissions: map[string][]string{"user": {"create"}},
		})
		if result {
			t.Error("expected user to NOT have user:create permission")
		}
	})

	t.Run("admin role lacks impersonate-admins", func(t *testing.T) {
		result := admin.HasPermission(admin.HasPermissionInput{
			Role:        "admin",
			Permissions: map[string][]string{"user": {"impersonate-admins"}},
		})
		if result {
			t.Error("expected default admin to NOT have impersonate-admins permission")
		}
	})

	t.Run("admin user IDs bypass role check", func(t *testing.T) {
		result := admin.HasPermission(admin.HasPermissionInput{
			UserID: "special-id",
			Role:   "user",
			Options: &admin.Options{
				AdminUserIds: []string{"special-id"},
			},
			Permissions: map[string][]string{"user": {"create", "delete", "ban"}},
		})
		if !result {
			t.Error("expected admin user ID to have all permissions")
		}
	})

	t.Run("custom role permissions", func(t *testing.T) {
		customRoles := map[string]*admin.Role{
			"moderator": admin.NewRole(admin.Statements{
				"user":    {"ban", "list"},
				"session": {"list"},
			}),
			"user": admin.NewRole(admin.Statements{
				"user":    {},
				"session": {},
			}),
		}
		result := admin.HasPermission(admin.HasPermissionInput{
			Role: "moderator",
			Options: &admin.Options{
				Roles: customRoles,
			},
			Permissions: map[string][]string{"user": {"ban"}},
		})
		if !result {
			t.Error("expected moderator to have ban permission")
		}

		result = admin.HasPermission(admin.HasPermissionInput{
			Role: "moderator",
			Options: &admin.Options{
				Roles: customRoles,
			},
			Permissions: map[string][]string{"user": {"create"}},
		})
		if result {
			t.Error("expected moderator to NOT have create permission")
		}
	})
}
