package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// HashPassword hashes a password using PBKDF2 SHA-256 (compatible with Python's hashlib.pbkdf2_hmac).
func HashPassword(password string) string {
	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		// rand.Read should not fail in normal operation, but fallback if it does
		saltBytes = []byte("staticsaltforfallback")
	}
	salt := hex.EncodeToString(saltBytes)

	// pbkdf2 with sha256, salt.encode() as salt, 100000 iterations, 32 bytes key length
	hashBytes := pbkdf2.Key([]byte(password), []byte(salt), 100000, 32, sha256.New)
	hash := hex.EncodeToString(hashBytes)

	return fmt.Sprintf("%s$%s", salt, hash)
}

// VerifyPassword verifies a password against a hash (either PBKDF2 SHA-256 or bcrypt).
func VerifyPassword(password, passwordHash string) bool {
	// If it looks like a bcrypt hash, verify using bcrypt
	if strings.HasPrefix(passwordHash, "$2a$") || strings.HasPrefix(passwordHash, "$2b$") || strings.HasPrefix(passwordHash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) == nil
	}

	// Otherwise, verify using PBKDF2 SHA-256
	parts := strings.SplitN(passwordHash, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt := parts[0]
	hash := parts[1]

	hashBytes := pbkdf2.Key([]byte(password), []byte(salt), 100000, 32, sha256.New)
	expectedHash := hex.EncodeToString(hashBytes)

	return subtle.ConstantTimeCompare([]byte(hash), []byte(expectedHash)) == 1
}
