package organization

import (
	"context"

	betterauth "github.com/jeromesth/go-better-auth"
	"github.com/jeromesth/go-better-auth/adapter"
)

// repository encapsulates common database operations for the organization plugin.
type repository struct {
	ia  *betterauth.InternalAdapter
	adp adapter.Adapter
}

func newRepository(auth *betterauth.Auth) *repository {
	return &repository{
		ia:  auth.InternalAdapter(),
		adp: auth.InternalAdapter().Adapter(),
	}
}

func (r *repository) findOrganizationByID(ctx context.Context, id string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
}

func (r *repository) findOrganizationBySlug(ctx context.Context, slug string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "organization", adapter.Query{
		Where: []adapter.Where{adapter.EQ("slug", slug)},
	})
}

func (r *repository) findMemberByUserAndOrg(ctx context.Context, userID, orgID string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "member", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("user_id", userID),
			adapter.EQ("organization_id", orgID),
		},
	})
}

func (r *repository) listMembersByOrg(ctx context.Context, orgID string) ([]map[string]any, error) {
	return r.adp.FindMany(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
}

func (r *repository) findInvitationByID(ctx context.Context, id string) (map[string]any, error) {
	return r.adp.FindOne(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
}

func (r *repository) countMembersByUser(ctx context.Context, userID string) (int64, error) {
	return r.adp.Count(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
}

func (r *repository) countMembersByOrg(ctx context.Context, orgID string) (int64, error) {
	return r.adp.Count(ctx, "member", adapter.Query{
		Where: []adapter.Where{adapter.EQ("organization_id", orgID)},
	})
}

func (r *repository) countPendingInvitations(ctx context.Context, orgID string) (int64, error) {
	return r.adp.Count(ctx, "invitation", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("organization_id", orgID),
			adapter.EQ("status", "pending"),
		},
	})
}
