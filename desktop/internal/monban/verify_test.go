package monban

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildAuthData creates a minimal FIDO2 authData with the given flags.
// Layout: rpIdHash (32) || flags (1) || signCount (4)
func buildAuthData(flags byte) []byte {
	rpIdHash := sha256.Sum256([]byte("monban.local"))
	authData := make([]byte, 37)
	copy(authData[:32], rpIdHash[:])
	authData[32] = flags
	return authData
}

func signAuthData(t *testing.T, key *ecdsa.PrivateKey, authData, clientDataHash []byte) []byte {
	t.Helper()
	signed := append(authData, clientDataHash...)
	digest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifyAssertionValid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cdh := sha256.Sum256([]byte("test challenge"))

	// UP (0x01) + UV (0x04) = 0x05
	authData := buildAuthData(0x05)
	sig := signAuthData(t, key, authData, cdh[:])

	err := VerifyAssertion(
		key.X.Bytes(),
		key.Y.Bytes(),
		cdh[:],
		authData, // raw, not CBOR-wrapped
		sig,
	)
	if err != nil {
		t.Fatalf("valid assertion should verify: %v", err)
	}
}

func TestVerifyAssertionBadSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cdh := sha256.Sum256([]byte("test challenge"))
	authData := buildAuthData(0x05)
	sig := signAuthData(t, key, authData, cdh[:])

	// Tamper with signature
	sig[len(sig)-1] ^= 0xFF

	err := VerifyAssertion(
		key.X.Bytes(),
		key.Y.Bytes(),
		cdh[:],
		authData,
		sig,
	)
	if err == nil {
		t.Error("tampered signature should fail verification")
	}
}

func TestVerifyAssertionMissingUP(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cdh := sha256.Sum256([]byte("test"))

	// UV set but not UP
	authData := buildAuthData(0x04)
	sig := signAuthData(t, key, authData, cdh[:])

	err := VerifyAssertion(
		key.X.Bytes(),
		key.Y.Bytes(),
		cdh[:],
		authData,
		sig,
	)
	if err == nil {
		t.Error("missing UP flag should fail")
	}
}

func TestVerifyAssertionMissingUV(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cdh := sha256.Sum256([]byte("test"))

	// UP set but not UV
	authData := buildAuthData(0x01)
	sig := signAuthData(t, key, authData, cdh[:])

	err := VerifyAssertion(
		key.X.Bytes(),
		key.Y.Bytes(),
		cdh[:],
		authData,
		sig,
	)
	if err == nil {
		t.Error("missing UV flag should fail")
	}
}

func TestUnwrapAuthDataCBOR(t *testing.T) {
	raw := buildAuthData(0x05)

	// CBOR-wrap it (as go-libfido2 does)
	wrapped, err := cbor.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := UnwrapAuthData(wrapped)
	if err != nil {
		t.Fatal(err)
	}

	if string(unwrapped) != string(raw) {
		t.Error("unwrapped authData doesn't match original")
	}
}

func TestUnwrapAuthDataRawPassthrough(t *testing.T) {
	raw := buildAuthData(0x05)

	// Pass raw bytes (not CBOR-wrapped) — should still work
	result, err := UnwrapAuthData(raw)
	if err != nil {
		t.Fatal(err)
	}

	if string(result) != string(raw) {
		t.Error("raw passthrough failed")
	}
}

func TestVerifyAssertionShortAuthData(t *testing.T) {
	err := VerifyAssertion(
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 10), // too short
		make([]byte, 64),
	)
	if err == nil {
		t.Error("short authData should fail")
	}
}
