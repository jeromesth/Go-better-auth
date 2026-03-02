package crypto_test

import (
	"testing"

	"github.com/jeromesth/go-better-auth/packages/betterauth/crypto"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "supersecretpassword"

	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	ok, err := crypto.VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if !ok {
		t.Fatal("expected password to match")
	}

	ok, err = crypto.VerifyPassword(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to not match")
	}
}

func TestGenerateToken(t *testing.T) {
	tok1, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken error: %v", err)
	}
	tok2, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken error: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("expected tokens to be unique")
	}
	if len(tok1) < 10 {
		t.Fatalf("token too short: %q", tok1)
	}
}

func TestSignAndVerify(t *testing.T) {
	sig := crypto.Sign("hello", "mysecret")
	if !crypto.Verify("hello", sig, "mysecret") {
		t.Fatal("expected signature to verify")
	}
	if crypto.Verify("hello", sig, "wrongsecret") {
		t.Fatal("expected signature to fail with wrong secret")
	}
}
