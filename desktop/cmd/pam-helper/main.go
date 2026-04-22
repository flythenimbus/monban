// monban-pam-helper is invoked by pam_monban.so (running as root via
// the PAM stack: sudo, su, etc.) to gate privileged actions behind a
// FIDO2 security-key assertion.
//
// The helper is self-contained: it reads the PIN from /dev/tty,
// loads the invoking user's SecureConfig, calls libfido2.Assert(),
// and exits 0 on a verified signature. It does NOT need Monban's GUI
// app to be running — the crypto runs right here in this binary.
//
// Source lives under desktop/ because it imports monban's internal
// crypto; compiled output ships with the admin-gate plugin's
// install_pkg and is placed at /usr/local/bin/monban-pam-helper.
//
// Environment from pam_monban.so:
//
//	MONBAN_PAM_USER     — PAM user (e.g. "alice")
//	MONBAN_PAM_SERVICE  — PAM service (e.g. "sudo")
//
// Exit 0 → PAM_SUCCESS. Anything else → PAM_AUTH_ERR so the stack
// falls through to the next rule (typically the password prompt).
//
// If the user hasn't registered Monban yet, or there's no TTY
// available to prompt, we exit 1 silently so sudo just falls back
// without a confusing error on the terminal.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"monban/internal/monban"
)

// errSilent signals main() not to print anything — just exit 1 so PAM
// falls through to the next rule. Used for "no TTY", "user not
// registered", "missing env" — all conditions where the gate simply
// isn't applicable and shouldn't annoy the user.
var errSilent = errors.New("silent")

// ttyPrint is a convenience wrapper around fmt.Fprintf for writing to
// /dev/tty. We discard the return values deliberately: if the tty we
// just opened has vanished mid-auth, there's nothing sensible to do.
func ttyPrint(tty *os.File, format string, args ...any) {
	_, _ = fmt.Fprintf(tty, format, args...)
}

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errSilent) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "monban: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	username := os.Getenv("MONBAN_PAM_USER")
	if username == "" {
		return errSilent
	}
	u, err := user.Lookup(username)
	if err != nil {
		return errSilent
	}

	cfgPath := filepath.Join(u.HomeDir, ".config", "monban", "credentials.json")
	if _, err := os.Stat(cfgPath); err != nil {
		// User never registered Monban — silently fall through.
		return errSilent
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		// No controlling terminal — stage 3 will route this through
		// Monban's UI via the authorizationdb SecurityAgent plugin.
		// For now, fall through silently.
		return errSilent
	}
	defer func() { _ = tty.Close() }()

	pin, err := promptPIN(tty)
	if err != nil {
		return err
	}
	if pin == "" {
		ttyPrint(tty, "✗ cancelled\n")
		return errSilent
	}

	return assertFIDO2(tty, cfgPath, pin)
}

// maxPINBytes caps how much we accept from the TTY when reading a PIN.
// L2: without a cap a pathological write to /dev/tty could stuff many
// megabytes before we get a newline. FIDO2 PINs are 4–63 UTF-8 bytes
// by spec; 1 KB is a very generous upper bound that still keeps the
// helper bounded.
const maxPINBytes = 1024

// promptPIN reads a PIN from the TTY without echoing it. Falls back
// to a plain read if term.ReadPassword fails (rare — e.g. if we
// somehow inherited a non-TTY fd on stdin). Output is capped at
// maxPINBytes to prevent runaway input.
func promptPIN(tty *os.File) (string, error) {
	ttyPrint(tty, "Security key PIN: ")
	raw, err := term.ReadPassword(int(tty.Fd()))
	ttyPrint(tty, "\n")
	if err == nil {
		if len(raw) > maxPINBytes {
			raw = raw[:maxPINBytes]
		}
		return string(raw), nil
	}
	var buf [maxPINBytes]byte
	n, rerr := tty.Read(buf[:])
	if rerr != nil && rerr != io.EOF {
		return "", fmt.Errorf("read PIN: %w", rerr)
	}
	return strings.TrimRight(string(buf[:n]), "\r\n"), nil
}

// assertFIDO2 loads the user's SecureConfig and performs the full
// unlock-style FIDO2 flow:
//
//  1. Assert against registered credential IDs (user touches key).
//  2. Derive a wrapping key from hmac-secret and unwrap the master
//     secret — AES-GCM auth tag fails for every credential except
//     the one we actually asserted with.
//  3. Verify the assertion signature against the matched credential's
//     registered public key.
//  4. Verify the SecureConfig's HMAC with the just-unwrapped master
//     secret — this is the tamper check; a modified credentials.json
//     produces a different HMAC and we refuse to authenticate.
//
// Master secret is zeroed before we return, success or failure.
func assertFIDO2(tty *os.File, cfgPath, pin string) error {
	sc, err := monban.LoadSecureConfigFrom(cfgPath)
	if err != nil {
		ttyPrint(tty, "✗ cannot read monban config\n")
		return fmt.Errorf("load config: %w", err)
	}
	if len(sc.Credentials) == 0 {
		ttyPrint(tty, "✗ no security keys registered\n")
		return errSilent
	}
	// H3: apply the admin allowlist (if one is provisioned at
	// /etc/monban/authorized_keys.json). Without this, any sudoer
	// could replace ~/.config/monban/credentials.json with a
	// registration to a random YubiKey and satisfy the PAM gate.
	allowed, err := filterAuthorized(sc.Credentials)
	if err != nil {
		ttyPrint(tty, "✗ admin allowlist is misconfigured — refusing\n")
		return fmt.Errorf("allowlist: %w", err)
	}
	if len(allowed) == 0 {
		// Either the user has no admin-approved keys, or the allowlist
		// is empty. Fall through silently so sudo prompts for password.
		return errSilent
	}
	sc.Credentials = allowed

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return fmt.Errorf("decode hmac salt: %w", err)
	}
	credIDs, err := sc.CollectCredentialIDs()
	if err != nil {
		return fmt.Errorf("collect credential ids: %w", err)
	}

	ttyPrint(tty, "Touch your security key…\n")

	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		ttyPrint(tty, "✗ %s\n", friendly(err))
		return err
	}
	if len(assertion.HMACSecret) == 0 {
		ttyPrint(tty, "✗ key did not return hmac-secret\n")
		return fmt.Errorf("no hmac-secret from key")
	}

	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return fmt.Errorf("derive wrapping key: %w", err)
	}

	masterSecret, matchedCred, err := monban.UnwrapMasterSecret(sc, wrappingKey)
	if err != nil {
		ttyPrint(tty, "✗ no matching registered key\n")
		return fmt.Errorf("unwrap master secret: %w", err)
	}
	defer monban.ZeroBytes(masterSecret)

	if err := monban.VerifyAssertionWithSalt(sc.RpID, matchedCred, hmacSalt, assertion.AuthDataCBOR, assertion.Sig); err != nil {
		ttyPrint(tty, "✗ assertion signature verification failed\n")
		return fmt.Errorf("verify assertion: %w", err)
	}

	// Tamper check: HMAC over credentials, vaults, settings, etc.
	// A modified credentials.json produces a mismatching HMAC and we
	// refuse even when the key physically authenticated, because
	// something outside Monban has been editing the config.
	if err := monban.VerifySecureConfig(sc, masterSecret, hmacSalt); err != nil {
		if err == monban.ErrConfigTampered {
			ttyPrint(tty, "✗ monban config has been tampered with — open Monban to investigate\n")
			return fmt.Errorf("%w", err)
		}
		if err == monban.ErrConfigUnsigned {
			// Legacy configs from before HMAC signing: let auth pass
			// but warn. They'll be signed on the next Monban unlock.
			ttyPrint(tty, "! config unsigned (legacy) — auth accepted\n")
		} else {
			ttyPrint(tty, "✗ config check: %s\n", err)
			return err
		}
	}

	ttyPrint(tty, "✓ authenticated\n")
	return nil
}

// friendly turns noisier libfido2 errors into something a user
// actually wants to see in a terminal.
func friendly(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "PIN"):
		return "incorrect PIN or locked key"
	case strings.Contains(s, "no device"):
		return "no security key detected"
	case strings.Contains(s, "timeout"), strings.Contains(s, "ERR_USER_ACTION_TIMEOUT"):
		return "timed out waiting for touch"
	}
	return s
}
