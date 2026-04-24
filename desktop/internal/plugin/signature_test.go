package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// withTempKey generates an ed25519 keypair for the duration of the test and
// sets ReleasePubKeyHex to its public key. Returns the private key for
// signing payloads inside the test.
func withTempKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := ReleasePubKeyHex
	ReleasePubKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { ReleasePubKeyHex = orig })
	return priv
}

func TestVerifyRoundTrip(t *testing.T) {
	priv := withTempKey(t)
	payload := []byte(`{"name":"test","version":"1.0.0"}`)
	sig := ed25519.Sign(priv, payload)

	if err := Verify(payload, sig); err != nil {
		t.Fatalf("Verify valid payload: %v", err)
	}
}

func TestVerifyDetectsTamperedPayload(t *testing.T) {
	priv := withTempKey(t)
	payload := []byte(`{"name":"test"}`)
	sig := ed25519.Sign(priv, payload)

	tampered := []byte(`{"name":"evil"}`)
	err := Verify(tampered, sig)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch, got %v", err)
	}
}

func TestVerifyDetectsBadSignatureLength(t *testing.T) {
	withTempKey(t)
	if err := Verify([]byte("hi"), []byte("short")); err == nil {
		t.Fatal("expected error for short signature")
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	_ = withTempKey(t)
	// Sign with a different, unrelated key
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte(`{"name":"test"}`)
	sig := ed25519.Sign(otherPriv, payload)
	if !errors.Is(Verify(payload, sig), ErrSignatureMismatch) {
		t.Fatal("expected signature from unknown key to fail")
	}
}

func TestVerifyFileRoundTrip(t *testing.T) {
	priv := withTempKey(t)
	dir := t.TempDir()
	payload := []byte("hello plugin world")
	payloadPath := filepath.Join(dir, "manifest.json")
	sigPath := payloadPath + ".sig"

	if err := os.WriteFile(payloadPath, payload, 0644); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		t.Fatal(err)
	}

	if err := VerifyFile(payloadPath, sigPath); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
}

func TestTrustedPubKeyRejectsBadHex(t *testing.T) {
	orig := ReleasePubKeyHex
	defer func() { ReleasePubKeyHex = orig }()
	ReleasePubKeyHex = "not-hex"
	if _, err := TrustedPubKey(); err == nil {
		t.Fatal("expected error for non-hex key")
	}
}
