package handlers

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	hash := HashPassword("mypassword")

	parts := strings.SplitN(hash, "$", 2)
	if len(parts) != 2 {
		t.Fatalf("expected format salt$hash, got: %s", hash)
	}

	salt := parts[0]
	hashVal := parts[1]

	if len(salt) != 32 {
		t.Errorf("expected 32-char hex salt, got %d chars", len(salt))
	}
	if len(hashVal) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(hashVal))
	}
}

func TestHashPassword_DifferentSalts(t *testing.T) {
	h1 := HashPassword("same_password")
	h2 := HashPassword("same_password")

	if h1 == h2 {
		t.Error("two hashes of the same password should differ (random salt)")
	}
}

func TestHashPassword_EmptyString(t *testing.T) {
	hash := HashPassword("")
	parts := strings.SplitN(hash, "$", 2)
	if len(parts) != 2 {
		t.Fatalf("expected format salt$hash for empty password, got: %s", hash)
	}
}

func TestVerifyPassword_Correct(t *testing.T) {
	password := "test_password_123"
	hash := HashPassword(password)

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should return true for correct password")
	}
}

func TestVerifyPassword_Wrong(t *testing.T) {
	hash := HashPassword("correct_password")

	if VerifyPassword("wrong_password", hash) {
		t.Error("VerifyPassword should return false for wrong password")
	}
}

func TestVerifyPassword_Bcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("bcrypt_test"), bcrypt.DefaultCost)
	if err != nil {
		t.Skip("bcrypt not available:", err)
	}

	if !VerifyPassword("bcrypt_test", string(hash)) {
		t.Error("VerifyPassword should work with bcrypt hashes")
	}

	if VerifyPassword("wrong", string(hash)) {
		t.Error("VerifyPassword should reject wrong password for bcrypt")
	}
}

func TestVerifyPassword_InvalidFormat(t *testing.T) {
	if VerifyPassword("pass", "not_a_valid_hash") {
		t.Error("should return false for invalid hash format")
	}
}

func TestVerifyPassword_EmptyHash(t *testing.T) {
	if VerifyPassword("pass", "") {
		t.Error("should return false for empty hash")
	}
}

func TestVerifyPassword_SpecialChars(t *testing.T) {
	password := "p@$$w0rd!#$%^&*()_+{}|:<>?"
	hash := HashPassword(password)

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should work with special characters")
	}
}

func TestVerifyPassword_Unicode(t *testing.T) {
	password := "пароль_тест_密码"
	hash := HashPassword(password)

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should work with unicode characters")
	}
}

func TestVerifyPassword_LongPassword(t *testing.T) {
	password := strings.Repeat("a", 10000)
	hash := HashPassword(password)

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should work with very long passwords")
	}
}
