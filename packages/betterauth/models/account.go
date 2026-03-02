package models

import "time"

// Account represents an OAuth account or password credential linked to a user.
type Account struct {
	ID                    string     `json:"id" db:"id"`
	UserID                string     `json:"userId" db:"user_id"`
	AccountID             string     `json:"accountId" db:"account_id"`
	ProviderID            string     `json:"providerId" db:"provider_id"`
	AccessToken           *string    `json:"accessToken,omitempty" db:"access_token"`
	RefreshToken          *string    `json:"refreshToken,omitempty" db:"refresh_token"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty" db:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty" db:"refresh_token_expires_at"`
	Scope                 *string    `json:"scope,omitempty" db:"scope"`
	IDToken               *string    `json:"idToken,omitempty" db:"id_token"`
	Password              *string    `json:"password,omitempty" db:"password"`
	CreatedAt             time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt             time.Time  `json:"updatedAt" db:"updated_at"`
}
