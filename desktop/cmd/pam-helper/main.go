// monban-pam-helper is a standalone binary invoked by pam_exec.so to gate
// sudo (and optionally ssh) behind a FIDO2 YubiKey assertion.
//
// Usage:
//
//	pam_exec.so invokes this binary (no args) for authentication.
//	sudo monban-pam-helper --install default|strict   Install to /usr/local/bin and configure PAM.
//	sudo monban-pam-helper --uninstall                Remove PAM config and installed binary.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"monban/internal/monban"

	"golang.org/x/term"
)

const (
	installPath    = "/usr/local/bin/monban-pam-helper"
	pamModuleDir   = "/usr/local/lib/pam"
	pamModulePath  = "/usr/local/lib/pam/pam_monban.so"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--install":
			mode := "default"
			if len(os.Args) > 2 {
				mode = os.Args[2]
			}
			if err := install(mode); err != nil {
				fmt.Fprintf(os.Stderr, "monban: install failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "--uninstall":
			if err := uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "monban: uninstall failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := authenticate(); err != nil {
		fmt.Fprintf(os.Stderr, "monban: %v\n", err)
		os.Exit(1)
	}
}

func install(mode string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run with sudo")
	}

	pamMode := "sufficient"
	if mode == "strict" {
		pamMode = "required"
	}

	// Copy the helper binary to /usr/local/bin/.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving symlinks: %w", err)
	}

	if exe != installPath {
		if err := copyFile(exe, installPath, 0755); err != nil {
			return err
		}
		fmt.Printf("Installed %s\n", installPath)
	}

	// Copy the PAM module to /usr/local/lib/pam/.
	pamModuleSrc := filepath.Join(filepath.Dir(exe), "pam_monban.so")
	if _, err := os.Stat(pamModuleSrc); err != nil {
		return fmt.Errorf("pam_monban.so not found next to binary (%s) — rebuild with 'task build:pam-helper'", filepath.Dir(exe))
	}
	if err := os.MkdirAll(pamModuleDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", pamModuleDir, err)
	}
	if err := copyFile(pamModuleSrc, pamModulePath, 0644); err != nil {
		return err
	}
	fmt.Printf("Installed %s\n", pamModulePath)

	// Verify the installed module and helper exist before writing PAM config.
	// A broken PAM config locks out sudo entirely.
	if _, err := os.Stat(pamModulePath); err != nil {
		return fmt.Errorf("PAM module not found at %s after install", pamModulePath)
	}
	if _, err := os.Stat(installPath); err != nil {
		return fmt.Errorf("helper not found at %s after install", installPath)
	}

	// Write PAM config referencing the module.
	pamLine := fmt.Sprintf("auth %s %s %s\n",
		pamMode, pamModulePath, monban.PamTag())

	pamPath := monban.PamSudoPath()
	if err := os.WriteFile(pamPath, []byte(pamLine), 0444); err != nil {
		return fmt.Errorf("writing %s: %w", pamPath, err)
	}
	fmt.Printf("Configured %s (%s mode)\n", pamPath, mode)

	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	return nil
}

func uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run with sudo")
	}

	for _, path := range []string{monban.PamSudoPath(), installPath, pamModulePath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		fmt.Printf("Removed %s\n", path)
	}

	return nil
}

func authenticate() error {
	// Load the system-level secure config (root-owned, world-readable).
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	// Open /dev/tty for interactive PIN prompt (same technique as ssh).
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("opening /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, "monban: YubiKey PIN: ")
	pinBytes, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty) // newline after hidden input
	if err != nil {
		return fmt.Errorf("reading PIN: %w", err)
	}
	pin := strings.TrimSpace(string(pinBytes))

	// Collect all credential IDs.
	credIDs := make([][]byte, len(sc.Credentials))
	for i, c := range sc.Credentials {
		id, err := monban.DecodeB64(c.CredentialID)
		if err != nil {
			return fmt.Errorf("decoding credential ID: %w", err)
		}
		credIDs[i] = id
	}

	// Perform FIDO2 assertion — requires touch + PIN.
	fmt.Fprint(tty, "monban: touch your YubiKey...\n")
	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	// Find the matched credential and verify the signature.
	var verified bool
	for _, cred := range sc.Credentials {
		credID, _ := monban.DecodeB64(cred.CredentialID)
		if assertion.CredentialID != nil && !bytesEqual(credID, assertion.CredentialID) {
			continue
		}
		pubX, err := monban.DecodeB64(cred.PublicKeyX)
		if err != nil {
			continue
		}
		pubY, err := monban.DecodeB64(cred.PublicKeyY)
		if err != nil {
			continue
		}
		cdh := sha256.Sum256(hmacSalt)
		if err := monban.VerifyAssertion(pubX, pubY, cdh[:], assertion.AuthDataCBOR, assertion.Sig); err == nil {
			verified = true
			break
		}
	}

	if !verified {
		return fmt.Errorf("assertion verification failed — no matching registered key")
	}

	fmt.Fprint(tty, "monban: authenticated\n")
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
