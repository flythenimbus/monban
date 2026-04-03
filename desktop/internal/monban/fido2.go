package monban

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"

	libfido2 "github.com/keys-pub/go-libfido2"
)

type FIDOCredential struct {
	ID   []byte
	PubX []byte
	PubY []byte
}

type FIDOAssertion struct {
	AuthDataCBOR []byte
	Sig          []byte
	HMACSecret   []byte
	CredentialID []byte
}

func DetectDevice() (bool, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return false, fmt.Errorf("detecting devices: %w", err)
	}
	return len(locs) > 0, nil
}

func openDevice() (*libfido2.Device, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("detecting FIDO2 devices: %w", err)
	}
	if len(locs) == 0 {
		return nil, fmt.Errorf("no FIDO2 device found — insert your security key")
	}

	dev, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return nil, fmt.Errorf("opening FIDO2 device: %w", err)
	}
	return dev, nil
}

// CheckHMACSecret verifies that the connected FIDO2 device supports the
// hmac-secret extension, which is required for key derivation.
func CheckHMACSecret() error {
	dev, err := openDevice()
	if err != nil {
		return err
	}

	info, err := dev.Info()
	if err != nil {
		return fmt.Errorf("reading device info: %w", err)
	}

	if !slices.Contains(info.Extensions, "hmac-secret") {
		return fmt.Errorf("device does not support hmac-secret — a FIDO2 key with hmac-secret is required")
	}

	return nil
}

func Register(pin string) (*FIDOCredential, error) {
	if err := CheckHMACSecret(); err != nil {
		return nil, err
	}

	dev, err := openDevice()
	if err != nil {
		return nil, err
	}
	// Device manages open/close internally per operation — no Close() needed

	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, fmt.Errorf("generating user ID: %w", err)
	}

	attest, err := dev.MakeCredential(
		cdh,
		libfido2.RelyingParty{ID: "monban.local", Name: "Monban"},
		libfido2.User{ID: userID, Name: "monban-user"},
		libfido2.ES256,
		pin,
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UV:         libfido2.True,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("MakeCredential: %w", err)
	}

	pubX, pubY, err := ParsePublicKey(attest.PubKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &FIDOCredential{
		ID:   attest.CredentialID,
		PubX: pubX,
		PubY: pubY,
	}, nil
}

// Assert performs a FIDO2 assertion with hmac-secret extension.
// Returns a single assertion — the device responds to whichever credential ID it recognizes.
func Assert(pin string, credIDs [][]byte, hmacSalt []byte) (*FIDOAssertion, error) {
	dev, err := openDevice()
	if err != nil {
		return nil, err
	}

	cdh := sha256.Sum256(hmacSalt)

	assertion, err := dev.Assertion(
		"monban.local",
		cdh[:],
		credIDs,
		pin,
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
			UV:         libfido2.True,
			UP:         libfido2.True,
			HMACSalt:   hmacSalt,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Assertion: %w", err)
	}

	return &FIDOAssertion{
		AuthDataCBOR: assertion.AuthDataCBOR,
		Sig:          assertion.Sig,
		HMACSecret:   assertion.HMACSecret,
		CredentialID: assertion.CredentialID,
	}, nil
}
