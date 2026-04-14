package monban

import (
	"bytes"
	"testing"
)

func TestDeriveWrappingKeyDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAA}, 32)
	salt := bytes.Repeat([]byte{0xBB}, 32)

	key1, err := DeriveWrappingKey(secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveWrappingKey(secret, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveWrappingKeyDifferentInputs(t *testing.T) {
	salt := bytes.Repeat([]byte{0xBB}, 32)

	key1, _ := DeriveWrappingKey(bytes.Repeat([]byte{0xAA}, 32), salt)
	key2, _ := DeriveWrappingKey(bytes.Repeat([]byte{0xCC}, 32), salt)

	if bytes.Equal(key1, key2) {
		t.Error("different secrets should produce different keys")
	}
}

func TestDeriveEncryptionKeyDeterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	key1, err := DeriveEncryptionKey(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveEncryptionKey(master, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveWrappingAndEncryptionKeysDiffer(t *testing.T) {
	// Same input material, but different HKDF info strings should produce different keys
	ikm := bytes.Repeat([]byte{0xFF}, 32)
	salt := bytes.Repeat([]byte{0x00}, 32)

	wrapping, _ := DeriveWrappingKey(ikm, salt)
	encryption, _ := DeriveEncryptionKey(ikm, salt)

	if bytes.Equal(wrapping, encryption) {
		t.Error("wrapping and encryption keys should differ (different HKDF info)")
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xDE}, 32)
	plaintext := []byte("this is the master secret that should survive round-trip")

	wrapped, err := WrapKey(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := UnwrapKey(key, wrapped)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, unwrapped) {
		t.Error("unwrapped plaintext does not match original")
	}
}

func TestWrapProducesDifferentCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0xDE}, 32)
	plaintext := []byte("same plaintext")

	wrapped1, _ := WrapKey(key, plaintext)
	wrapped2, _ := WrapKey(key, plaintext)

	if bytes.Equal(wrapped1, wrapped2) {
		t.Error("wrapping same plaintext twice should produce different ciphertext (random nonce)")
	}
}

func TestUnwrapWrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0xAA}, 32)
	key2 := bytes.Repeat([]byte{0xBB}, 32)
	plaintext := []byte("secret")

	wrapped, _ := WrapKey(key1, plaintext)

	_, err := UnwrapKey(key2, wrapped)
	if err == nil {
		t.Error("unwrap with wrong key should fail")
	}
}

func TestUnwrapTamperedData(t *testing.T) {
	key := bytes.Repeat([]byte{0xCC}, 32)
	plaintext := []byte("secret")

	wrapped, _ := WrapKey(key, plaintext)
	// Flip a byte in the ciphertext
	wrapped[len(wrapped)-1] ^= 0xFF

	_, err := UnwrapKey(key, wrapped)
	if err == nil {
		t.Error("unwrap of tampered data should fail")
	}
}

func TestUnwrapTooShort(t *testing.T) {
	key := bytes.Repeat([]byte{0xDD}, 32)

	_, err := UnwrapKey(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("unwrap of too-short data should fail")
	}
}

func TestZeroBytes(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{10, 20, 30}

	ZeroBytes(a, b)

	for i, v := range a {
		if v != 0 {
			t.Errorf("a[%d] = %d, want 0", i, v)
		}
	}
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d, want 0", i, v)
		}
	}
}

func TestZeroBytesNil(t *testing.T) {
	// Should not panic
	ZeroBytes(nil, nil)
}

func TestGenerateMasterSecret(t *testing.T) {
	secret, err := GenerateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 64 {
		t.Errorf("expected 64-byte secret, got %d", len(secret))
	}

	// Should not be all zeros
	allZero := true
	for _, b := range secret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("master secret should not be all zeros")
	}
}

func TestGenerateHmacSalt(t *testing.T) {
	salt, err := GenerateHmacSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != 32 {
		t.Errorf("expected 32-byte salt, got %d", len(salt))
	}
}

func TestDeriveLazyStrictKeyDeterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)
	path := "/home/user/Documents"

	key1, err := DeriveLazyStrictKey(master, salt, path)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveLazyStrictKey(master, salt, path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveLazyStrictKeyDifferentPaths(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	key1, _ := DeriveLazyStrictKey(master, salt, "/path/a")
	key2, _ := DeriveLazyStrictKey(master, salt, "/path/b")

	if bytes.Equal(key1, key2) {
		t.Error("different vault paths should produce different keys")
	}
}

func TestDeriveLazyStrictKeyDiffersFromEncKey(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 64)
	salt := bytes.Repeat([]byte{0x22}, 32)

	encKey, _ := DeriveEncryptionKey(master, salt)
	lazyKey, _ := DeriveLazyStrictKey(master, salt, "/any/path")

	if bytes.Equal(encKey, lazyKey) {
		t.Error("lazy strict key should differ from encryption key")
	}
}

func TestDeriveLazyStrictKeyDiffersFromWrappingKey(t *testing.T) {
	ikm := bytes.Repeat([]byte{0xFF}, 32)
	salt := bytes.Repeat([]byte{0x00}, 32)

	wrapping, _ := DeriveWrappingKey(ikm, salt)
	lazy, _ := DeriveLazyStrictKey(ikm, salt, "/vault")

	if bytes.Equal(wrapping, lazy) {
		t.Error("lazy strict key should differ from wrapping key")
	}
}

func TestDeriveConfigAuthKeyDeterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x33}, 64)
	salt := bytes.Repeat([]byte{0x44}, 32)

	key1, err := DeriveConfigAuthKey(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := DeriveConfigAuthKey(master, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
}

func TestDeriveConfigAuthKeyDiffersFromOtherKeys(t *testing.T) {
	ikm := bytes.Repeat([]byte{0xFF}, 64)
	salt := bytes.Repeat([]byte{0x00}, 32)

	authKey, _ := DeriveConfigAuthKey(ikm, salt)
	encKey, _ := DeriveEncryptionKey(ikm, salt)
	wrappingKey, _ := DeriveWrappingKey(ikm[:32], salt)

	if bytes.Equal(authKey, encKey) {
		t.Error("config auth key should differ from encryption key")
	}
	if bytes.Equal(authKey, wrappingKey) {
		t.Error("config auth key should differ from wrapping key")
	}
}
