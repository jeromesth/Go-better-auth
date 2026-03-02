package models

import "time"

// Verification represents a verification token (email verification, password reset, etc.).
type Verification struct {
	ID         string    `json:"id" db:"id"`
	Identifier string    `json:"identifier" db:"identifier"`
	Value      string    `json:"value" db:"value"`
	ExpiresAt  time.Time `json:"expiresAt" db:"expires_at"`
	CreatedAt  time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt  time.Time `json:"updatedAt" db:"updated_at"`
}
