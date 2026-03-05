// Package crypto provides cryptographic utilities for password hashing, token generation, and HMAC signing.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN      = 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// HashPassword hashes a plaintext password using scrypt.
// The returned string encodes the salt + hash in a single base64 value.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}

	combined := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// VerifyPassword checks that a plaintext password matches the stored hash.
func VerifyPassword(encoded, password string) (bool, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}
	if len(combined) < saltLen {
		return false, fmt.Errorf("invalid hash length")
	}

	salt := combined[:saltLen]
	storedHash := combined[saltLen:]

	hash, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return false, fmt.Errorf("hashing password: %w", err)
	}

	return subtle.ConstantTimeCompare(hash, storedHash) == 1, nil
}
