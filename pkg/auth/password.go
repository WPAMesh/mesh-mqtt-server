package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// HashPasswordWithSalt creates a SHA-256 hash of the password combined with the salt
func HashPasswordWithSalt(password, salt string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	return hex.EncodeToString(hasher.Sum(nil))
}

// RandomHex generates a random hexadecimal string of n bytes
func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateHashAndSalt creates a new random salt and hashes the password with it
func GenerateHashAndSalt(password string) (hash string, salt string) {
	salt, _ = RandomHex(16)
	hash = HashPasswordWithSalt(password, salt)
	return
}
