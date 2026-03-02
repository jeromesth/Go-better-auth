// Package session provides session creation, validation, and management logic.
package session

import (
	"context"
	"fmt"
	"time"

	"github.com/jeromesth/go-better-auth/packages/betterauth/adapter"
	"github.com/jeromesth/go-better-auth/packages/betterauth/crypto"
	"github.com/jeromesth/go-better-auth/packages/betterauth/internal"
	"github.com/jeromesth/go-better-auth/packages/betterauth/models"
)

const modelSession = "session"

// Manager handles session lifecycle operations.
type Manager struct {
	adapter   adapter.Adapter
	expiresIn time.Duration
	updateAge time.Duration
}

// NewManager creates a session Manager with the given adapter and config.
func NewManager(adp adapter.Adapter, expiresIn, updateAge int) *Manager {
	return &Manager{
		adapter:   adp,
		expiresIn: time.Duration(expiresIn) * time.Second,
		updateAge: time.Duration(updateAge) * time.Second,
	}
}

// Create creates a new session for the given user.
func (m *Manager) Create(ctx context.Context, userID, ipAddress, userAgent string) (*models.Session, error) {
	token, err := crypto.GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	now := time.Now().UTC()
	sess := map[string]any{
		"id":         internal.NewID(),
		"token":      token,
		"user_id":    userID,
		"expires_at": now.Add(m.expiresIn),
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"created_at": now,
		"updated_at": now,
	}

	rec, err := m.adapter.Create(ctx, modelSession, sess)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}
	return recordToSession(rec), nil
}

// FindByToken retrieves a session by its token.
func (m *Manager) FindByToken(ctx context.Context, token string) (*models.Session, error) {
	rec, err := m.adapter.FindOne(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", token)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToSession(rec), nil
}

// FindByID retrieves a session by its ID.
func (m *Manager) FindByID(ctx context.Context, id string) (*models.Session, error) {
	rec, err := m.adapter.FindOne(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToSession(rec), nil
}

// ListByUserID returns all sessions for a given user.
func (m *Manager) ListByUserID(ctx context.Context, userID string) ([]*models.Session, error) {
	recs, err := m.adapter.FindMany(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]*models.Session, 0, len(recs))
	for _, r := range recs {
		sessions = append(sessions, recordToSession(r))
	}
	return sessions, nil
}

// RefreshIfNeeded extends the session expiry if it's older than updateAge.
// Returns the (possibly updated) session.
func (m *Manager) RefreshIfNeeded(ctx context.Context, sess *models.Session) (*models.Session, error) {
	now := time.Now().UTC()
	age := now.Sub(sess.UpdatedAt)
	if age < m.updateAge {
		return sess, nil
	}

	newExpiry := now.Add(m.expiresIn)
	rec, err := m.adapter.Update(ctx, modelSession,
		adapter.Query{Where: []adapter.Where{adapter.EQ("id", sess.ID)}},
		map[string]any{
			"expires_at": newExpiry,
			"updated_at": now,
		},
	)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return sess, nil
	}
	return recordToSession(rec), nil
}

// Revoke deletes a session by its token.
func (m *Manager) Revoke(ctx context.Context, token string) error {
	return m.adapter.Delete(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("token", token)},
	})
}

// RevokeByID deletes a session by its ID.
func (m *Manager) RevokeByID(ctx context.Context, id string) error {
	return m.adapter.Delete(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
}

// RevokeAllForUser deletes all sessions for the given user, except optionally one.
func (m *Manager) RevokeAllForUser(ctx context.Context, userID string, exceptToken string) error {
	recs, err := m.adapter.FindMany(ctx, modelSession, adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
	if err != nil {
		return err
	}
	for _, r := range recs {
		tok, _ := r["token"].(string)
		if tok == exceptToken {
			continue
		}
		id, _ := r["id"].(string)
		if err := m.RevokeByID(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// IsExpired reports whether the session has expired.
func IsExpired(sess *models.Session) bool {
	return time.Now().UTC().After(sess.ExpiresAt)
}

func recordToSession(r map[string]any) *models.Session {
	s := &models.Session{}
	s.ID, _ = r["id"].(string)
	s.Token, _ = r["token"].(string)
	s.UserID, _ = r["user_id"].(string)
	if v, ok := r["expires_at"].(time.Time); ok {
		s.ExpiresAt = v
	}
	if v, ok := r["ip_address"].(string); ok {
		s.IPAddress = &v
	}
	if v, ok := r["user_agent"].(string); ok {
		s.UserAgent = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		s.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		s.UpdatedAt = v
	}
	return s
}
