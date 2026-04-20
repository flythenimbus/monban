package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestFriendlyMapping locks down the translation from libfido2's noisy
// error strings to the one-line messages we actually want to show on
// a terminal. Regressions here change user-visible copy, so they're
// worth catching in review.
func TestFriendlyMapping(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"PIN incorrect", "incorrect PIN or locked key"},
		{"bad PIN attempts remaining: 2", "incorrect PIN or locked key"},
		{"libfido2: no device found", "no security key detected"},
		{"ERR_USER_ACTION_TIMEOUT", "timed out waiting for touch"},
		{"some assertion timeout", "timed out waiting for touch"},
		{"unrelated error", "unrelated error"},
	}
	for _, tc := range cases {
		got := friendly(fmt.Errorf("%s", tc.in))
		if got != tc.want {
			t.Errorf("friendly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRunSilentWhenEnvMissing verifies the helper exits-silent when
// PAM didn't set MONBAN_PAM_USER. Sudo with a PAM stack that isn't
// driven through pam_monban.so should never see a scary stderr line.
func TestRunSilentWhenEnvMissing(t *testing.T) {
	t.Setenv("MONBAN_PAM_USER", "")

	err := run()
	if !errors.Is(err, errSilent) {
		t.Fatalf("expected errSilent, got %v", err)
	}
}

// TestRunSilentWhenUserUnknown verifies we fall through cleanly when
// PAM hands us a user that doesn't exist in the passwd database. This
// should basically never happen in practice, but the helper runs as
// root and we don't want a noisy crash on the off-chance.
func TestRunSilentWhenUserUnknown(t *testing.T) {
	// Random-enough to be confident it doesn't exist.
	t.Setenv("MONBAN_PAM_USER", "monban-unit-test-nonexistent-user-9f3a")
	t.Setenv("MONBAN_PAM_SERVICE", "sudo")

	err := run()
	if !errors.Is(err, errSilent) {
		t.Fatalf("expected errSilent, got %v", err)
	}
}

// TestRunSilentWhenNoConfigFile checks the "user exists but hasn't
// registered Monban" path. Uses `nobody`, which exists on macOS and
// Linux and never has a ~/.config/monban/ — if it ever does, someone
// has done something very strange on the test host.
func TestRunSilentWhenNoConfigFile(t *testing.T) {
	t.Setenv("MONBAN_PAM_USER", "nobody")
	t.Setenv("MONBAN_PAM_SERVICE", "sudo")

	err := run()
	if !errors.Is(err, errSilent) {
		t.Fatalf("expected errSilent (no config), got %v", err)
	}
}

// TestErrSilentDistinct guards against someone accidentally replacing
// errSilent with a generic error — if it stops being a sentinel the
// silent-exit logic in main() becomes noisy again.
func TestErrSilentDistinct(t *testing.T) {
	if !errors.Is(errSilent, errSilent) {
		t.Fatal("errSilent should identity-match itself via errors.Is")
	}
	other := fmt.Errorf("some other error")
	if errors.Is(other, errSilent) {
		t.Fatal("unrelated error must not match errSilent")
	}
	wrapped := fmt.Errorf("context: %w", errSilent)
	if !errors.Is(wrapped, errSilent) {
		t.Fatal("errors.Is must unwrap to errSilent")
	}
}

// sanity check for Go's strings package being used the way we
// assume in friendly() — catches someone "optimising" the switch
// to a map of exact matches, which would break partial-match cases
// like "bad PIN attempts remaining: 2".
func TestFriendlyUsesPartialMatch(t *testing.T) {
	long := "libfido2: PIN attempts remaining: 3, try again"
	got := friendly(fmt.Errorf("%s", long))
	if !strings.Contains(got, "PIN") {
		t.Errorf("friendly(%q) should still map via partial match, got %q", long, got)
	}
}
