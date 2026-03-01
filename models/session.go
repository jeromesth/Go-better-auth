package models

import "time"

// Session represents an active user session.
type Session struct {
	ID        string    `json:"id" db:"id"`
	Token     string    `json:"token" db:"token"`
	UserID    string    `json:"userId" db:"user_id"`
	ExpiresAt time.Time `json:"expiresAt" db:"expires_at"`
	IPAddress *string   `json:"ipAddress,omitempty" db:"ip_address"`
	UserAgent *string   `json:"userAgent,omitempty" db:"user_agent"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}
