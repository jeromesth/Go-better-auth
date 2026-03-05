package admin

import (
	"context"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/models"
	"github.com/jeromesth/go-better-auth/session"
)

// repository encapsulates all database operations for the admin plugin.
// Route handlers use this instead of directly accessing InternalAdapter or SessionManager.
type repository struct {
	ia  *betterauth.InternalAdapter
	sm  *session.Manager
	adp adapter.Adapter
}

func newRepository(auth *betterauth.Auth) *repository {
	return &repository{
		ia:  auth.InternalAdapter(),
		sm:  auth.SessionManager(),
		adp: auth.InternalAdapter().Adapter(),
	}
}

// --- User operations ---

// FindUserByEmail finds a user by email address.
func (r *repository) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return r.ia.FindUserByEmail(ctx, email)
}

// FindUserByID returns the raw user record including plugin-added fields.
func (r *repository) FindUserByID(ctx context.Context, id string) (map[string]any, error) {
	return r.ia.FindUserByIDRaw(ctx, id)
}

// CreateUser creates a user from the given data and returns the raw record.
func (r *repository) CreateUser(ctx context.Context, data map[string]any) (map[string]any, error) {
	return r.ia.CreateUserRaw(ctx, data)
}

// UpdateUser updates a user and returns the raw record.
func (r *repository) UpdateUser(ctx context.Context, id string, data map[string]any) (map[string]any, error) {
	return r.ia.UpdateUserRaw(ctx, id, data)
}

// DeleteUser deletes a user and their associated accounts and sessions.
func (r *repository) DeleteUser(ctx context.Context, id string) error {
	return r.ia.DeleteUser(ctx, id)
}

// ListUsers returns users matching the query criteria.
func (r *repository) ListUsers(ctx context.Context, q adapter.Query) ([]map[string]any, error) {
	return r.ia.ListUsers(ctx, q)
}

// CountUsers returns the total count of users matching the where clause.
func (r *repository) CountUsers(ctx context.Context, where []adapter.Where) (int64, error) {
	return r.ia.CountUsers(ctx, where)
}

// --- Account operations ---

// CreateCredentialAccount creates a credential account with the given hashed password.
func (r *repository) CreateCredentialAccount(ctx context.Context, userID, hashedPassword string) error {
	_, err := r.ia.CreateAccount(ctx, userID, userID, "credential", map[string]any{
		"password": hashedPassword,
	})
	return err
}

// UpdatePassword updates the password for a user's credential account.
func (r *repository) UpdatePassword(ctx context.Context, userID, hashedPassword string) error {
	return r.ia.UpdatePassword(ctx, userID, hashedPassword)
}

// --- Session operations ---

// FindSessionByToken retrieves a session by its token.
func (r *repository) FindSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	return r.sm.FindByToken(ctx, token)
}

// FindRawSession retrieves the raw session record, including plugin-added fields.
func (r *repository) FindRawSession(ctx context.Context, token string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", token)},
	})
}

// FindSessionsByUserID returns all raw session records for a user.
func (r *repository) FindSessionsByUserID(ctx context.Context, userID string) ([]map[string]any, error) {
	return r.adp.FindMany(ctx, "session", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

// CreateImpersonationSession creates a session for the impersonated user.
func (r *repository) CreateImpersonationSession(ctx context.Context, userID, adminID string, expiresAt time.Time) (*models.Session, error) {
	return r.sm.CreateWithExtra(ctx, userID, "", "", map[string]any{
		"impersonated_by": adminID,
		"expires_at":      expiresAt,
	})
}

// RevokeSession deletes a session by its token.
func (r *repository) RevokeSession(ctx context.Context, token string) error {
	return r.sm.Revoke(ctx, token)
}

// RevokeAllUserSessions deletes all sessions for the given user.
func (r *repository) RevokeAllUserSessions(ctx context.Context, userID string) error {
	return r.sm.DeleteAllForUser(ctx, userID)
}
