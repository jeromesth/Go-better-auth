package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateToken creates a cryptographically random URL-safe token of the given byte length.
func GenerateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateSessionToken generates a 32-byte URL-safe session token.
func GenerateSessionToken() (string, error) {
	return GenerateToken(32)
}

// GenerateVerificationToken generates a 32-byte URL-safe verification token.
func GenerateVerificationToken() (string, error) {
	return GenerateToken(32)
}
