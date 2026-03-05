package models

// RateLimit tracks request counts for rate limiting.
type RateLimit struct {
	ID          string `json:"id" db:"id"`
	Key         string `json:"key" db:"key"`
	Count       int    `json:"count" db:"count"`
	LastRequest int64  `json:"lastRequest" db:"last_request"`
}
