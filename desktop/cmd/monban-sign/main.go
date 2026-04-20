// monban-sign is the ed25519 signing utility for Monban plugin artefacts.
//
//	monban-sign generate-key  <pub-out> <key-out>
//	monban-sign sign --key <key> <payload>         → writes <payload>.sig
//	monban-sign verify --pubkey <pub> <payload> <payload.sig>
//
// The release workflow uses `sign` in CI with the private key pulled from
// a GitHub Actions secret. Keys are raw 32-byte ed25519 pubkey / 64-byte
// ed25519 private key values, written as hex with a trailing newline.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "generate-key":
		err = generateKey(args)
	case "sign":
		err = sign(args)
	case "verify":
		err = verify(args)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `monban-sign — ed25519 signing for Monban plugin artefacts

  monban-sign generate-key <pub-out> <key-out>
  monban-sign sign --key <key-file> <payload>
  monban-sign verify --pubkey <pub-file> <payload> <payload.sig>

Keys are written as hex with a trailing newline.
`)
}

func generateKey(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: generate-key <pub-out> <key-out>")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeHex(args[0], pub); err != nil {
		return fmt.Errorf("write pub: %w", err)
	}
	if err := writeHex(args[1], priv); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	_ = os.Chmod(args[1], 0600)
	fmt.Printf("wrote %s (%d bytes pub)\nwrote %s (%d bytes priv, mode 0600)\n", args[0], len(pub), args[1], len(priv))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "path to ed25519 private key (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || fs.NArg() != 1 {
		return errors.New("usage: sign --key <key-file> <payload>")
	}
	payloadPath := fs.Arg(0)

	priv, err := readHex(*keyFile, ed25519.PrivateKeySize)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	sig := ed25519.Sign(ed25519.PrivateKey(priv), payload)
	sigPath := payloadPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		return fmt.Errorf("write sig: %w", err)
	}
	fmt.Printf("signed %s → %s (%d bytes)\n", payloadPath, sigPath, len(sig))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubFile := fs.String("pubkey", "", "path to ed25519 public key (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubFile == "" || fs.NArg() != 2 {
		return errors.New("usage: verify --pubkey <pub-file> <payload> <payload.sig>")
	}
	pub, err := readHex(*pubFile, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("read pubkey: %w", err)
	}
	payload, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	sig, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return fmt.Errorf("read sig: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("signature does NOT verify")
	}
	fmt.Println("signature OK")
	return nil
}

func writeHex(path string, b []byte) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(b)+"\n"), 0644)
}

func readHex(path string, wantLen int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("key length %d, want %d", len(b), wantLen)
	}
	return b, nil
}
