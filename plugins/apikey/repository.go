package apikey

import (
	"context"
	"time"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal"
)

type repository struct {
	adp adapter.Adapter
}

func newRepository(auth *betterauth.Auth) *repository {
	return &repository{adp: auth.InternalAdapter().Adapter()}
}

func (r *repository) create(ctx context.Context, userID, name, prefix, keyHash string, expiresAt *time.Time) (map[string]any, error) {
	now := time.Now().UTC()
	data := map[string]any{
		"id":           internal.NewID(),
		"user_id":      userID,
		"key_hash":     keyHash,
		"name":         name,
		"prefix":       prefix,
		"last_used_at": nil,
		"created_at":   now,
		"updated_at":   now,
	}
	if expiresAt != nil {
		data["expires_at"] = *expiresAt
	} else {
		data["expires_at"] = nil
	}
	return r.adp.Create(ctx, "apiKey", data)
}

func (r *repository) findByHash(ctx context.Context, keyHash string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "apiKey", adapter.Query{
		Where: []adapter.Where{adapter.EQ("key_hash", keyHash)},
	})
}

func (r *repository) listByUser(ctx context.Context, userID string) ([]map[string]any, error) {
	return r.adp.FindMany(ctx, "apiKey", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

func (r *repository) deleteByID(ctx context.Context, id, userID string) error {
	return r.adp.Delete(ctx, "apiKey", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("id", id),
			adapter.EQ("user_id", userID),
		},
	})
}

func (r *repository) touchLastUsed(ctx context.Context, id string) {
	_, _ = r.adp.Update(ctx, "apiKey", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	}, map[string]any{"last_used_at": time.Now().UTC()})
}
