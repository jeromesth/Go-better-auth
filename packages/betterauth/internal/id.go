// Package internal contains shared utilities used internally by go-better-auth.
package internal

import (
	"crypto/rand"
	"encoding/hex"
)

// NewID generates a cryptographically random 21-character hex ID.
func NewID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
