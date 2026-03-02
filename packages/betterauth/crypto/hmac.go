package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Sign creates an HMAC-SHA256 signature of the given data using the secret.
func Sign(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks that the provided signature matches the HMAC-SHA256 of data.
func Verify(data, signature, secret string) bool {
	expected := Sign(data, secret)
	return hmac.Equal([]byte(expected), []byte(signature))
}
