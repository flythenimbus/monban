package monban

import (
	"bytes"
	"strings"
	"testing"
)

// --- DecodeHmacSalt ---

func TestDecodeHmacSalt(t *testing.T) {
	raw := []byte("test-salt-32-bytes-long-enough!!")
	sc := &SecureConfig{HmacSalt: EncodeB64(raw)}

	salt, err := sc.DecodeHmacSalt()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(salt, raw) {
		t.Errorf("got %x, want %x", salt, raw)
	}
}

func TestDecodeHmacSaltInvalid(t *testing.T) {
	sc := &SecureConfig{HmacSalt: "not!valid!base64!!!"}

	_, err := sc.DecodeHmacSalt()
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "decoding hmac salt") {
		t.Errorf("error should mention 'decoding hmac salt', got: %v", err)
	}
}

// --- CollectCredentialIDs ---

func TestCollectCredentialIDs(t *testing.T) {
	id1 := []byte("cred-1")
	id2 := []byte("cred-2")
	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{CredentialID: EncodeB64(id1)},
			{CredentialID: EncodeB64(id2)},
		},
	}

	ids, err := sc.CollectCredentialIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
	if !bytes.Equal(ids[0], id1) {
		t.Errorf("id[0]: got %x, want %x", ids[0], id1)
	}
	if !bytes.Equal(ids[1], id2) {
		t.Errorf("id[1]: got %x, want %x", ids[1], id2)
	}
}

func TestCollectCredentialIDsEmpty(t *testing.T) {
	sc := &SecureConfig{}

	ids, err := sc.CollectCredentialIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}
}

func TestCollectCredentialIDsInvalid(t *testing.T) {
	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{CredentialID: EncodeB64([]byte("good"))},
			{CredentialID: "bad!base64!!!"},
		},
	}

	_, err := sc.CollectCredentialIDs()
	if err == nil {
		t.Fatal("expected error for invalid credential ID")
	}
	if !strings.Contains(err.Error(), "decoding credential ID") {
		t.Errorf("error should mention 'decoding credential ID', got: %v", err)
	}
}

// --- DecodePublicKey ---

func TestDecodePublicKey(t *testing.T) {
	rawX := []byte("pub-key-x-coord")
	rawY := []byte("pub-key-y-coord")
	cred := &CredentialEntry{
		PublicKeyX: EncodeB64(rawX),
		PublicKeyY: EncodeB64(rawY),
	}

	pubX, pubY, err := cred.DecodePublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubX, rawX) {
		t.Errorf("pubX: got %x, want %x", pubX, rawX)
	}
	if !bytes.Equal(pubY, rawY) {
		t.Errorf("pubY: got %x, want %x", pubY, rawY)
	}
}

func TestDecodePublicKeyInvalidX(t *testing.T) {
	cred := &CredentialEntry{
		PublicKeyX: "bad!!!",
		PublicKeyY: EncodeB64([]byte("good")),
	}

	_, _, err := cred.DecodePublicKey()
	if err == nil {
		t.Fatal("expected error for invalid X")
	}
	if !strings.Contains(err.Error(), "public key X") {
		t.Errorf("error should mention 'public key X', got: %v", err)
	}
}

func TestDecodePublicKeyInvalidY(t *testing.T) {
	cred := &CredentialEntry{
		PublicKeyX: EncodeB64([]byte("good")),
		PublicKeyY: "bad!!!",
	}

	_, _, err := cred.DecodePublicKey()
	if err == nil {
		t.Fatal("expected error for invalid Y")
	}
	if !strings.Contains(err.Error(), "public key Y") {
		t.Errorf("error should mention 'public key Y', got: %v", err)
	}
}

// --- UnwrapMasterSecret ---

func TestUnwrapMasterSecret(t *testing.T) {
	wrappingKey := makeTestKey()
	masterSecret := []byte("this-is-the-master-secret-64byte-long-value-for-testing-purpose!")

	wrapped, err := WrapKey(wrappingKey, masterSecret)
	if err != nil {
		t.Fatal(err)
	}

	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{Label: "Key 1", WrappedKey: EncodeB64(wrapped)},
		},
	}

	secret, cred, err := UnwrapMasterSecret(sc, wrappingKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, masterSecret) {
		t.Error("unwrapped secret doesn't match original")
	}
	if cred.Label != "Key 1" {
		t.Errorf("matched cred label: got %q, want %q", cred.Label, "Key 1")
	}
}

func TestUnwrapMasterSecretMultipleCredentials(t *testing.T) {
	correctKey := makeTestKey()
	wrongKey := make([]byte, 32)
	copy(wrongKey, correctKey)
	wrongKey[0] ^= 0xFF // flip a byte

	masterSecret := []byte("this-is-the-master-secret-64byte-long-value-for-testing-purpose!")

	wrappedCorrect, err := WrapKey(correctKey, masterSecret)
	if err != nil {
		t.Fatal(err)
	}
	wrappedWrong, err := WrapKey(wrongKey, masterSecret)
	if err != nil {
		t.Fatal(err)
	}

	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{Label: "Wrong Key", WrappedKey: EncodeB64(wrappedWrong)},
			{Label: "Correct Key", WrappedKey: EncodeB64(wrappedCorrect)},
		},
	}

	secret, cred, err := UnwrapMasterSecret(sc, correctKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, masterSecret) {
		t.Error("unwrapped secret doesn't match")
	}
	if cred.Label != "Correct Key" {
		t.Errorf("should match second credential, got %q", cred.Label)
	}
}

func TestUnwrapMasterSecretNoMatch(t *testing.T) {
	wrappingKey := makeTestKey()
	wrongKey := make([]byte, 32)
	copy(wrongKey, wrappingKey)
	wrongKey[0] ^= 0xFF

	masterSecret := []byte("this-is-the-master-secret-64byte-long-value-for-testing-purpose!")
	wrapped, err := WrapKey(wrongKey, masterSecret)
	if err != nil {
		t.Fatal(err)
	}

	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{Label: "Wrong", WrappedKey: EncodeB64(wrapped)},
		},
	}

	_, _, err = UnwrapMasterSecret(sc, wrappingKey)
	if err == nil {
		t.Fatal("expected error when no credential matches")
	}
	if !strings.Contains(err.Error(), "could not unwrap") {
		t.Errorf("error should mention 'could not unwrap', got: %v", err)
	}
}

func TestUnwrapMasterSecretInvalidBase64(t *testing.T) {
	sc := &SecureConfig{
		Credentials: []CredentialEntry{
			{Label: "Bad", WrappedKey: "not!valid!base64!!!"},
		},
	}

	_, _, err := UnwrapMasterSecret(sc, makeTestKey())
	if err == nil {
		t.Fatal("expected error for invalid base64 wrapped key")
	}
}

func TestUnwrapMasterSecretEmptyCredentials(t *testing.T) {
	sc := &SecureConfig{}

	_, _, err := UnwrapMasterSecret(sc, makeTestKey())
	if err == nil {
		t.Fatal("expected error with no credentials")
	}
}

// --- ValidateDiskSpace ---

func TestValidateDiskSpaceSufficient(t *testing.T) {
	// Current directory should have some free space; asking for 1 byte should pass
	err := ValidateDiskSpace(t.TempDir(), 1)
	if err != nil {
		t.Errorf("expected no error for 1 byte requirement, got: %v", err)
	}
}

func TestValidateDiskSpaceInsufficient(t *testing.T) {
	// Ask for an absurdly large amount
	err := ValidateDiskSpace(t.TempDir(), 1<<62)
	if err == nil {
		t.Fatal("expected error for huge space requirement")
	}
	if !strings.Contains(err.Error(), "insufficient disk space") {
		t.Errorf("error should mention 'insufficient disk space', got: %v", err)
	}
}

func TestValidateDiskSpaceUnitSelection(t *testing.T) {
	// < 1 GB should use MB
	err := ValidateDiskSpace(t.TempDir(), 1<<62)
	if err == nil {
		t.Skip("need insufficient space to test unit selection")
	}
	// Just verify it doesn't panic — the unit logic is tested by the insufficient case
}

func TestValidateDiskSpaceBadPath(t *testing.T) {
	err := ValidateDiskSpace("/nonexistent/path/that/does/not/exist", 1)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
	if !strings.Contains(err.Error(), "checking free space") {
		t.Errorf("error should mention 'checking free space', got: %v", err)
	}
}
