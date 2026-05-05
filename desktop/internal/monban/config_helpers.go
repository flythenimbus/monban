package monban

import (
	"crypto/sha256"
	"fmt"
)

// DecodeHmacSalt decodes the base64url hmac salt from the secure config.
func (sc *SecureConfig) DecodeHmacSalt() ([]byte, error) {
	salt, err := DecodeB64(sc.HmacSalt)
	if err != nil {
		return nil, fmt.Errorf("decoding hmac salt: %w", err)
	}
	return salt, nil
}

// CollectCredentialIDs decodes all credential IDs from the secure config.
func (sc *SecureConfig) CollectCredentialIDs() ([][]byte, error) {
	credIDs := make([][]byte, len(sc.Credentials))
	for i, c := range sc.Credentials {
		id, err := DecodeB64(c.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("decoding credential ID: %w", err)
		}
		credIDs[i] = id
	}
	return credIDs, nil
}

// DecodePublicKey decodes the X and Y coordinates from the credential entry.
func (c *CredentialEntry) DecodePublicKey() (pubX, pubY []byte, err error) {
	pubX, err = DecodeB64(c.PublicKeyX)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding public key X: %w", err)
	}
	pubY, err = DecodeB64(c.PublicKeyY)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding public key Y: %w", err)
	}
	return pubX, pubY, nil
}

// UnwrapMasterSecret tries each credential's wrapped key until one succeeds.
// Returns the unwrapped master secret as a typed handle and the matched
// credential entry. Caller owns the returned *MasterSecret and is
// responsible for Zero()-ing it.
func UnwrapMasterSecret(sc *SecureConfig, wrappingKey []byte) (*MasterSecret, *CredentialEntry, error) {
	for i := range sc.Credentials {
		wrapped, err := DecodeB64(sc.Credentials[i].WrappedKey)
		if err != nil {
			continue
		}
		secret, err := UnwrapKey(wrappingKey, wrapped)
		if err != nil {
			continue
		}
		return WrapMasterSecret(secret), &sc.Credentials[i], nil
	}
	return nil, nil, fmt.Errorf("could not unwrap master secret — no matching credential found")
}

// VerifyAssertionWithSalt is a convenience wrapper that hashes the hmac salt
// into a client data hash and verifies the assertion signature.
func VerifyAssertionWithSalt(rpID string, cred *CredentialEntry, hmacSalt, authDataCBOR, sig []byte) error {
	pubX, pubY, err := cred.DecodePublicKey()
	if err != nil {
		return err
	}
	cdh := sha256.Sum256(hmacSalt)
	return VerifyAssertion(rpID, pubX, pubY, cdh[:], authDataCBOR, sig)
}

// ValidateDiskSpace checks that there is enough free space at path for the
// given number of bytes. Returns a formatted error if not.
func ValidateDiskSpace(path string, requiredBytes int64) error {
	freeBytes, err := FreeSpace(path)
	if err != nil {
		return fmt.Errorf("checking free space: %w", err)
	}
	if freeBytes < requiredBytes {
		need := float64(requiredBytes) / (1024 * 1024 * 1024)
		have := float64(freeBytes) / (1024 * 1024 * 1024)
		unit := "GB"
		if requiredBytes < 1024*1024*1024 {
			need = float64(requiredBytes) / (1024 * 1024)
			have = float64(freeBytes) / (1024 * 1024)
			unit = "MB"
		}
		return fmt.Errorf("insufficient disk space: need %.1f %s free, have %.1f %s", need, unit, have, unit)
	}
	return nil
}
