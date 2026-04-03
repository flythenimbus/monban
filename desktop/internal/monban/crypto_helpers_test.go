package monban

import (
	"bytes"
	"testing"
)

func TestNewGCMValidKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)

	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	if gcm == nil {
		t.Fatal("expected non-nil AEAD")
	}
	if gcm.NonceSize() != 12 {
		t.Errorf("expected 12-byte nonce, got %d", gcm.NonceSize())
	}
	if gcm.Overhead() != 16 {
		t.Errorf("expected 16-byte overhead, got %d", gcm.Overhead())
	}
}

func TestNewGCMInvalidKeyLength(t *testing.T) {
	for _, size := range []int{0, 1, 15, 17, 31, 33, 64} {
		key := bytes.Repeat([]byte{0xBB}, size)
		_, err := newGCM(key)
		if err == nil {
			t.Errorf("expected error for %d-byte key", size)
		}
	}
}

func TestNewGCMAcceptsValidKeySizes(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{0xCC}, size)
		gcm, err := newGCM(key)
		if err != nil {
			t.Errorf("unexpected error for %d-byte key: %v", size, err)
		}
		if gcm == nil {
			t.Errorf("expected non-nil AEAD for %d-byte key", size)
		}
	}
}

func TestNewGCMSealUnseal(t *testing.T) {
	key := bytes.Repeat([]byte{0xDD}, 32)
	gcm, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := bytes.Repeat([]byte{0x01}, gcm.NonceSize())
	plaintext := []byte("test data for seal/unseal")

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("seal/unseal round-trip failed")
	}
}
