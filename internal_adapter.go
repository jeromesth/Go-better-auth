package betterauth

import (
	"context"
	"fmt"
	"time"

	"github.com/jeromesth/go-better-auth/adapter"
	"github.com/jeromesth/go-better-auth/internal"
	"github.com/jeromesth/go-better-auth/models"
)

// InternalAdapter provides typed, higher-level methods on top of the raw adapter.
type InternalAdapter struct {
	adp      adapter.Adapter
	generateID func(model string) string
}

func newInternalAdapter(adp adapter.Adapter, generateID GenerateIDFn) *InternalAdapter {
	if generateID == nil {
		generateID = func(_ string) string { return internal.NewID() }
	}
	return &InternalAdapter{adp: adp, generateID: generateID}
}

// --- Users ---

func (a *InternalAdapter) CreateUser(ctx context.Context, email, name string, emailVerified bool) (*models.User, error) {
	now := time.Now().UTC()
	rec, err := a.adp.Create(ctx, "user", map[string]any{
		"id":             a.generateID("user"),
		"email":          email,
		"name":           name,
		"email_verified": emailVerified,
		"created_at":     now,
		"updated_at":     now,
	})
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return recordToUser(rec), nil
}

func (a *InternalAdapter) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	rec, err := a.adp.FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("email", email)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToUser(rec), nil
}

func (a *InternalAdapter) FindUserByID(ctx context.Context, id string) (*models.User, error) {
	rec, err := a.adp.FindOne(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToUser(rec), nil
}

func (a *InternalAdapter) UpdateUser(ctx context.Context, id string, data map[string]any) (*models.User, error) {
	data["updated_at"] = time.Now().UTC()
	rec, err := a.adp.Update(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	}, data)
	if err != nil {
		return nil, err
	}
	return recordToUser(rec), nil
}

func (a *InternalAdapter) DeleteUser(ctx context.Context, id string) error {
	return a.adp.Delete(ctx, "user", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
}

// --- Accounts ---

func (a *InternalAdapter) CreateAccount(ctx context.Context, userID, accountID, providerID string, extra map[string]any) (*models.Account, error) {
	now := time.Now().UTC()
	data := map[string]any{
		"id":          a.generateID("account"),
		"user_id":     userID,
		"account_id":  accountID,
		"provider_id": providerID,
		"created_at":  now,
		"updated_at":  now,
	}
	for k, v := range extra {
		data[k] = v
	}
	rec, err := a.adp.Create(ctx, "account", data)
	if err != nil {
		return nil, fmt.Errorf("creating account: %w", err)
	}
	return recordToAccount(rec), nil
}

func (a *InternalAdapter) FindAccountByProviderAndID(ctx context.Context, providerID, accountID string) (*models.Account, error) {
	rec, err := a.adp.FindOne(ctx, "account", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("provider_id", providerID),
			adapter.EQ("account_id", accountID),
		},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToAccount(rec), nil
}

func (a *InternalAdapter) FindAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	recs, err := a.adp.FindMany(ctx, "account", adapter.Query{
		Where: []adapter.Where{adapter.EQ("user_id", userID)},
	})
	if err != nil {
		return nil, err
	}
	accounts := make([]*models.Account, 0, len(recs))
	for _, r := range recs {
		accounts = append(accounts, recordToAccount(r))
	}
	return accounts, nil
}

func (a *InternalAdapter) UpdateAccount(ctx context.Context, id string, data map[string]any) (*models.Account, error) {
	data["updated_at"] = time.Now().UTC()
	rec, err := a.adp.Update(ctx, "account", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	}, data)
	if err != nil {
		return nil, err
	}
	return recordToAccount(rec), nil
}

// --- Verifications ---

func (a *InternalAdapter) CreateVerification(ctx context.Context, identifier, value string, expiresIn time.Duration) (*models.Verification, error) {
	now := time.Now().UTC()
	rec, err := a.adp.Create(ctx, "verification", map[string]any{
		"id":         a.generateID("verification"),
		"identifier": identifier,
		"value":      value,
		"expires_at": now.Add(expiresIn),
		"created_at": now,
		"updated_at": now,
	})
	if err != nil {
		return nil, fmt.Errorf("creating verification: %w", err)
	}
	return recordToVerification(rec), nil
}

func (a *InternalAdapter) FindVerification(ctx context.Context, identifier, value string) (*models.Verification, error) {
	rec, err := a.adp.FindOne(ctx, "verification", adapter.Query{
		Where: []adapter.Where{
			adapter.EQ("identifier", identifier),
			adapter.EQ("value", value),
		},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToVerification(rec), nil
}

func (a *InternalAdapter) FindVerificationByValue(ctx context.Context, value string) (*models.Verification, error) {
	rec, err := a.adp.FindOne(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("value", value)},
	})
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return recordToVerification(rec), nil
}

func (a *InternalAdapter) DeleteVerification(ctx context.Context, id string) error {
	return a.adp.Delete(ctx, "verification", adapter.Query{
		Where: []adapter.Where{adapter.EQ("id", id)},
	})
}

// --- Record converters ---

func recordToUser(r map[string]any) *models.User {
	u := &models.User{}
	u.ID, _ = r["id"].(string)
	u.Email, _ = r["email"].(string)
	u.Name, _ = r["name"].(string)
	u.EmailVerified, _ = r["email_verified"].(bool)
	if v, ok := r["image"].(string); ok {
		u.Image = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		u.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		u.UpdatedAt = v
	}
	return u
}

func recordToAccount(r map[string]any) *models.Account {
	acc := &models.Account{}
	acc.ID, _ = r["id"].(string)
	acc.UserID, _ = r["user_id"].(string)
	acc.AccountID, _ = r["account_id"].(string)
	acc.ProviderID, _ = r["provider_id"].(string)
	if v, ok := r["access_token"].(string); ok {
		acc.AccessToken = &v
	}
	if v, ok := r["refresh_token"].(string); ok {
		acc.RefreshToken = &v
	}
	if v, ok := r["password"].(string); ok {
		acc.Password = &v
	}
	if v, ok := r["created_at"].(time.Time); ok {
		acc.CreatedAt = v
	}
	if v, ok := r["updated_at"].(time.Time); ok {
		acc.UpdatedAt = v
	}
	return acc
}

func recordToVerification(r map[string]any) *models.Verification {
	v := &models.Verification{}
	v.ID, _ = r["id"].(string)
	v.Identifier, _ = r["identifier"].(string)
	v.Value, _ = r["value"].(string)
	if t, ok := r["expires_at"].(time.Time); ok {
		v.ExpiresAt = t
	}
	if t, ok := r["created_at"].(time.Time); ok {
		v.CreatedAt = t
	}
	if t, ok := r["updated_at"].(time.Time); ok {
		v.UpdatedAt = t
	}
	return v
}
