package monban

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func generateTestP256Key(t *testing.T) (x, y []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()
}

func TestParseRawXY(t *testing.T) {
	origX, origY := generateTestP256Key(t)

	raw := make([]byte, 64)
	copy(raw[:32], origX)
	copy(raw[32:], origY)

	x, y, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(origX) || string(y) != string(origY) {
		t.Error("parsed coordinates don't match original")
	}
}

func TestParseUncompressedPoint(t *testing.T) {
	origX, origY := generateTestP256Key(t)

	raw := make([]byte, 65)
	raw[0] = 0x04
	copy(raw[1:33], origX)
	copy(raw[33:65], origY)

	x, y, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(origX) || string(y) != string(origY) {
		t.Error("parsed coordinates don't match original")
	}
}

func TestParseCOSEKey(t *testing.T) {
	origX, origY := generateTestP256Key(t)

	// Build CBOR COSE key
	cose := map[int]interface{}{
		1:  2,      // kty: EC2
		3:  -7,     // alg: ES256
		-1: 1,      // crv: P-256
		-2: origX,  // x
		-3: origY,  // y
	}
	raw, err := cbor.Marshal(cose)
	if err != nil {
		t.Fatal(err)
	}

	x, y, err := ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(origX) || string(y) != string(origY) {
		t.Error("parsed COSE coordinates don't match original")
	}
}

func TestParseInvalidLength(t *testing.T) {
	_, _, err := ParsePublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Error("should fail on invalid length")
	}
}

func TestParseOffCurvePoint(t *testing.T) {
	// All zeros is not on P-256
	raw := make([]byte, 64)

	_, _, err := ParsePublicKey(raw)
	if err == nil {
		t.Error("should fail on off-curve point")
	}
}
