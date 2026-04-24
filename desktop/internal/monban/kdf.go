package monban

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// --- Public functions ---

// DeriveWrappingKey derives an AES-256 key from the security key's hmac-secret output.
// Used to encrypt/decrypt the master secret for multi-key support.
func DeriveWrappingKey(hmacSecret, hmacSalt []byte) ([]byte, error) {
	return hkdfKey(hmacSecret, hmacSalt, []byte("monban-keywrap-v1"), "wrapping")
}

// DeriveEncryptionKey derives the file encryption key from the master secret.
// This key is used for AES-256-GCM file-level encryption.
func DeriveEncryptionKey(masterSecret, hmacSalt []byte) ([]byte, error) {
	return hkdfKey(masterSecret, hmacSalt, []byte("monban-fileenc-v1"), "encryption")
}

// DeriveLazyStrictKey derives the file encryption key from the master secret for a particular lazy_strict vault.
// This key is used for AES-256-GCM file-level encryption for a specific vault.
func DeriveLazyStrictKey(masterSecret, hmacSalt []byte, vaultPath string) ([]byte, error) {
	return hkdfKey(masterSecret, hmacSalt, []byte("monban-lazy-strict-v1:"+vaultPath), "lazy-strict")
}

// DeriveConfigAuthKey derives a key for HMAC-signing the secure config.
// This key is derived from the master secret and is used to detect tampering.
func DeriveConfigAuthKey(masterSecret, hmacSalt []byte) ([]byte, error) {
	return hkdfKey(masterSecret, hmacSalt, []byte("monban-config-auth-v1"), "config auth")
}

// GenerateMasterSecret generates a random 64-byte master secret.
// This secret is wrapped by each security key's hmac-secret derived key.
func GenerateMasterSecret() ([]byte, error) {
	return randomBytes(64, "master secret")
}

// GenerateHmacSalt generates a 32-byte random salt for FIDO2 hmac-secret.
func GenerateHmacSalt() ([]byte, error) {
	return randomBytes(32, "hmac salt")
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

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed (wrong key or corrupted): %w", err)
	}
	return plaintext, nil
}

// ZeroBytes overwrites byte slices with zeros.
// Call this on sensitive key material when it's no longer needed.
func ZeroBytes(slices ...[]byte) {
	for _, b := range slices {
		clear(b)
	}
}

// --- Private helpers ---

// hkdfKey derives a 32-byte key via HKDF-SHA256. label is used only for error context.
func hkdfKey(ikm, salt, info []byte, label string) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF %s key: %w", label, err)
	}
	return key, nil
}

// randomBytes returns n cryptographically random bytes. label is used only for error context.
func randomBytes(n int, label string) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating %s: %w", label, err)
	}
	return b, nil
}
