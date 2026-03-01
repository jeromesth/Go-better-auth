package models

import "time"

// User represents an authenticated user in the system.
type User struct {
	ID            string    `json:"id" db:"id"`
	Email         string    `json:"email" db:"email"`
	Name          string    `json:"name" db:"name"`
	EmailVerified bool      `json:"emailVerified" db:"email_verified"`
	Image         *string   `json:"image,omitempty" db:"image"`
	CreatedAt     time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt     time.Time `json:"updatedAt" db:"updated_at"`
}
