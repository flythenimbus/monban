package monban

import (
	"crypto/ecdh"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint,omitempty"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// ParsePublicKey extracts P-256 X and Y coordinates from a FIDO2 attestation public key.
// Tries three formats in order: raw X||Y, uncompressed EC point, then CBOR COSE key.
func ParsePublicKey(raw []byte) (x, y []byte, err error) {
	if x, y, err := parseRawXY(raw); err == nil {
		return x, y, nil
	}
	if x, y, err := parseUncompressedPoint(raw); err == nil {
		return x, y, nil
	}
	return parseCOSEKey(raw)
}

func parseRawXY(raw []byte) ([]byte, []byte, error) {
	if len(raw) != 64 {
		return nil, nil, fmt.Errorf("not raw XY: length %d", len(raw))
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x, raw[:32])
	copy(y, raw[32:])
	if err := validateP256Point(x, y); err != nil {
		return nil, nil, err
	}
	return x, y, nil
}

func parseUncompressedPoint(raw []byte) ([]byte, []byte, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, nil, fmt.Errorf("not uncompressed point: length %d", len(raw))
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x, raw[1:33])
	copy(y, raw[33:65])
	if err := validateP256Point(x, y); err != nil {
		return nil, nil, err
	}
	return x, y, nil
}

func parseCOSEKey(raw []byte) ([]byte, []byte, error) {
	decMode, _ := cbor.DecOptions{ExtraReturnErrors: 0}.DecMode()

	var key coseKey
	if err := decMode.Unmarshal(raw, &key); err != nil {
		return nil, nil, fmt.Errorf("decoding COSE key (%d bytes): %w", len(raw), err)
	}
	if key.Kty != 2 {
		return nil, nil, fmt.Errorf("unexpected COSE kty: %d (want 2=EC2)", key.Kty)
	}
	if key.Crv != 1 {
		return nil, nil, fmt.Errorf("unexpected COSE crv: %d (want 1=P-256)", key.Crv)
	}
	if len(key.X) != 32 || len(key.Y) != 32 {
		return nil, nil, fmt.Errorf("invalid coordinate length: X=%d Y=%d (want 32)", len(key.X), len(key.Y))
	}
	if err := validateP256Point(key.X, key.Y); err != nil {
		return nil, nil, err
	}
	return key.X, key.Y, nil
}

func validateP256Point(x, y []byte) error {
	uncompressed := make([]byte, 1+len(x)+len(y))
	uncompressed[0] = 0x04
	copy(uncompressed[1:], x)
	copy(uncompressed[1+len(x):], y)

	_, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return fmt.Errorf("public key point is not on P-256 curve: %w", err)
	}
	return nil
}
