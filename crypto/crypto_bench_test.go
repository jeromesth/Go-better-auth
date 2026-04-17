// Benchmarks for password hashing. scrypt is intentionally expensive to resist
// brute-force attacks. Expect ~100–500ms per hash on typical hardware; tune
// the scrypt parameters in crypto.go if latency is a concern.
package crypto_test

import (
	"testing"

	"github.com/jeromesth/go-better-auth/crypto"
)

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		_, err := crypto.HashPassword("correct-horse-battery-staple")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := crypto.HashPassword("correct-horse-battery-staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = crypto.VerifyPassword(hash, "correct-horse-battery-staple")
	}
}
