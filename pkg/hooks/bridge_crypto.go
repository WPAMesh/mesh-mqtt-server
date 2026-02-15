package hooks

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// MeshCore crypto constants
	meshCoreCipherKeySize   = 16 // AES-128
	meshCoreCipherBlockSize = 16
	meshCoreCipherMACSize   = 2  // HMAC-SHA256 truncated to 2 bytes
	meshCoreSecretSize      = 32 // Full secret key size for HMAC
)

var (
	// DefaultChannelKey is the default PSK for MeshCore's built-in "Public" group channel.
	// Base64: izOH6cXN6mrJ5e26oRXNcg==
	DefaultChannelKey = []byte{0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72}

	ErrInvalidKeySize    = errors.New("invalid key size: must be 16 or 32 bytes")
	ErrInvalidMACSize    = errors.New("ciphertext too short for MAC")
	ErrMACMismatch       = errors.New("MAC verification failed")
	ErrCiphertextTooLong = errors.New("ciphertext exceeds maximum payload size")
)

// ComputeChannelHash computes the MeshCore channel hash from a shared key.
// The channel hash is the first byte of SHA256(key).
func ComputeChannelHash(sharedKey []byte) uint8 {
	hash := sha256.Sum256(sharedKey)
	return hash[0]
}

// EncryptGroupMessage encrypts plaintext for a MeshCore GRP_TXT message.
// Uses AES-128 ECB encryption followed by HMAC-SHA256 (truncated to 2 bytes).
// Returns ciphertext with MAC prepended.
func EncryptGroupMessage(plaintext, sharedKey []byte) ([]byte, error) {
	if len(sharedKey) != 16 && len(sharedKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	// Pad plaintext to block size
	paddedLen := ((len(plaintext) + meshCoreCipherBlockSize - 1) / meshCoreCipherBlockSize) * meshCoreCipherBlockSize
	padded := make([]byte, paddedLen)
	copy(padded, plaintext)
	// Zero-pad the rest (Go slices are zero-initialized)

	// Encrypt using AES-128 ECB with first 16 bytes of key
	block, err := aes.NewCipher(sharedKey[:meshCoreCipherKeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext := make([]byte, paddedLen)
	for i := 0; i < paddedLen; i += meshCoreCipherBlockSize {
		block.Encrypt(ciphertext[i:i+meshCoreCipherBlockSize], padded[i:i+meshCoreCipherBlockSize])
	}

	// Compute HMAC-SHA256 over ciphertext, using full 32-byte key
	// If key is 16 bytes, pad with zeros for HMAC
	hmacKey := make([]byte, meshCoreSecretSize)
	copy(hmacKey, sharedKey)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	macSum := mac.Sum(nil)

	// Prepend 2-byte MAC to ciphertext
	result := make([]byte, meshCoreCipherMACSize+len(ciphertext))
	copy(result[:meshCoreCipherMACSize], macSum[:meshCoreCipherMACSize])
	copy(result[meshCoreCipherMACSize:], ciphertext)

	return result, nil
}

// DecryptGroupMessage decrypts a MeshCore GRP_TXT message.
// Expects data with MAC prepended (MAC + ciphertext).
// Returns the decrypted plaintext (may have trailing zero padding).
func DecryptGroupMessage(data, sharedKey []byte) ([]byte, error) {
	if len(sharedKey) != 16 && len(sharedKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	if len(data) <= meshCoreCipherMACSize {
		return nil, ErrInvalidMACSize
	}

	receivedMAC := data[:meshCoreCipherMACSize]
	ciphertext := data[meshCoreCipherMACSize:]

	// Verify HMAC-SHA256 using full 32-byte key
	hmacKey := make([]byte, meshCoreSecretSize)
	copy(hmacKey, sharedKey)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	computedMAC := mac.Sum(nil)

	// Compare first 2 bytes
	if receivedMAC[0] != computedMAC[0] || receivedMAC[1] != computedMAC[1] {
		return nil, ErrMACMismatch
	}

	// Decrypt using AES-128 ECB with first 16 bytes of key
	block, err := aes.NewCipher(sharedKey[:meshCoreCipherKeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += meshCoreCipherBlockSize {
		block.Decrypt(plaintext[i:i+meshCoreCipherBlockSize], ciphertext[i:i+meshCoreCipherBlockSize])
	}

	return plaintext, nil
}

// BuildGrpTxtPlaintext builds the plaintext for a MeshCore GRP_TXT message.
// Format: timestamp(4) + type_attempt(1) + message (null-terminated in MeshCore, but we don't need it)
func BuildGrpTxtPlaintext(timestamp uint32, message string) []byte {
	msgBytes := []byte(message)
	plaintext := make([]byte, 5+len(msgBytes))

	binary.LittleEndian.PutUint32(plaintext[0:4], timestamp)
	plaintext[4] = 0 // TXT_TYPE_PLAIN (0) with attempt 0
	copy(plaintext[5:], msgBytes)

	return plaintext
}

// ParseGrpTxtPlaintext parses the decrypted plaintext of a GRP_TXT message.
// Returns timestamp, message type, and the message text.
func ParseGrpTxtPlaintext(plaintext []byte) (timestamp uint32, txtType uint8, message string, err error) {
	if len(plaintext) < 5 {
		return 0, 0, "", errors.New("plaintext too short")
	}

	timestamp = binary.LittleEndian.Uint32(plaintext[0:4])
	txtType = plaintext[4] >> 2 // Upper 6 bits

	// Find null terminator or use remaining bytes
	msgBytes := plaintext[5:]
	for i, b := range msgBytes {
		if b == 0 {
			msgBytes = msgBytes[:i]
			break
		}
	}
	message = string(msgBytes)

	return timestamp, txtType, message, nil
}
