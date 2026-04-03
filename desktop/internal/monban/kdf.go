package monban

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveWrappingKey derives an AES-256 key from the YubiKey's hmac-secret output.
// Used to encrypt/decrypt the master secret for multi-key support.
func DeriveWrappingKey(hmacSecret, hmacSalt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, hmacSecret, hmacSalt, []byte("monban-keywrap-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF wrapping key: %w", err)
	}
	return key, nil
}

// DeriveEncryptionKey derives the file encryption key from the master secret.
// This key is used for AES-256-GCM file-level encryption.
func DeriveEncryptionKey(masterSecret, hmacSalt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, masterSecret, hmacSalt, []byte("monban-fileenc-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF encryption key: %w", err)
	}
	return key, nil
}

// GenerateMasterSecret generates a random 64-byte master secret.
// This secret is wrapped by each YubiKey's hmac-secret derived key.
func GenerateMasterSecret() ([]byte, error) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating master secret: %w", err)
	}
	return secret, nil
}

// WrapKey encrypts plaintext with AES-256-GCM using the given wrapping key.
// Returns nonce (12 bytes) || ciphertext+tag.
func WrapKey(wrappingKey, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(wrappingKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// UnwrapKey decrypts ciphertext (nonce || ciphertext+tag) with AES-256-GCM.
// Returns the plaintext master secret, or error if authentication fails
// (wrong key or tampered data).
func UnwrapKey(wrappingKey, data []byte) ([]byte, error) {
	gcm, err := newGCM(wrappingKey)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed (wrong key or corrupted): %w", err)
	}

	return plaintext, nil
}

// ZeroBytes overwrites byte slices with zeros.
// Call this on sensitive key material when it's no longer needed.
func ZeroBytes(slices ...[]byte) {
	for _, b := range slices {
		for i := range b {
			b[i] = 0
		}
	}
}

// GenerateHmacSalt generates a 32-byte random salt for FIDO2 hmac-secret.
func GenerateHmacSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating hmac salt: %w", err)
	}
	return salt, nil
}
