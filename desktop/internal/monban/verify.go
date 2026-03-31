package monban

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type ecdsaSig struct {
	R, S *big.Int
}

// UnwrapAuthData extracts raw authData bytes from the CBOR-encoded AuthDataCBOR
// returned by go-libfido2. The CBOR wrapping is a byte string.
func UnwrapAuthData(authDataCBOR []byte) ([]byte, error) {
	var raw []byte
	if err := cbor.Unmarshal(authDataCBOR, &raw); err != nil {
		// If CBOR unwrapping fails, the data might already be raw authData
		if len(authDataCBOR) >= 37 {
			return authDataCBOR, nil
		}
		return nil, fmt.Errorf("unwrapping authData CBOR: %w", err)
	}
	return raw, nil
}

// VerifyAssertion verifies a FIDO2 assertion signature using the stored public key.
// Checks ECDSA P-256 signature over authData || clientDataHash, plus UP and UV flags.
func VerifyAssertion(pubKeyX, pubKeyY []byte, clientDataHash []byte, authDataCBOR []byte, sig []byte) error {
	authData, err := UnwrapAuthData(authDataCBOR)
	if err != nil {
		return fmt.Errorf("unwrapping auth data: %w", err)
	}

	if len(authData) < 37 {
		return fmt.Errorf("authData too short: %d bytes", len(authData))
	}

	flags := authData[32]
	if flags&0x01 == 0 {
		return fmt.Errorf("User Present (UP) flag not set")
	}
	if flags&0x04 == 0 {
		return fmt.Errorf("User Verified (UV) flag not set")
	}

	pubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pubKeyX),
		Y:     new(big.Int).SetBytes(pubKeyY),
	}

	// Signature is over authData || clientDataHash
	signedData := make([]byte, len(authData)+len(clientDataHash))
	copy(signedData, authData)
	copy(signedData[len(authData):], clientDataHash)
	digest := sha256.Sum256(signedData)

	var parsedSig ecdsaSig
	rest, err := asn1.Unmarshal(sig, &parsedSig)
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("trailing data after signature")
	}

	if !ecdsa.Verify(&pubKey, digest[:], parsedSig.R, parsedSig.S) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}
