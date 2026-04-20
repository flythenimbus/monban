package plugin

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// ReleasePubKeyHex is the hex-encoded ed25519 public key trusted to sign
// official plugin manifests and tarballs. Overridden at release time via
// `-ldflags "-X monban/internal/plugin.ReleasePubKeyHex=<hex>"`.
//
// The default is a committed dev key used for local iteration; dev builds
// should sign with the matching private key in cmd/monban-sign/testkeys/.
var ReleasePubKeyHex = defaultDevPubKeyHex

// ErrSignatureMismatch indicates the signature does not verify against the
// trusted release key.
var ErrSignatureMismatch = errors.New("plugin signature does not match trusted key")

// TrustedPubKey returns the ed25519 public key used for signature verification.
// Returns an error if ReleasePubKeyHex is malformed — fatal at startup.
func TrustedPubKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(ReleasePubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode trusted pubkey: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted pubkey length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Verify checks an ed25519 signature against the payload and the trusted
// release key. Returns ErrSignatureMismatch on a bad signature.
func Verify(payload, signature []byte) error {
	pub, err := TrustedPubKey()
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature length %d, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, payload, signature) {
		return ErrSignatureMismatch
	}
	return nil
}

// VerifyFile reads path and sigPath from disk and verifies the signature.
func VerifyFile(path, sigPath string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sigPath, err)
	}
	return Verify(payload, sig)
}
