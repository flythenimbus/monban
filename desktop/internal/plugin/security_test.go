package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolvePluginPath_EscapeAttempts covers C5: a signed manifest must
// not be able to escape the plugin directory via relative paths in the
// binary or install_pkg fields.
func TestResolvePluginPath_EscapeAttempts(t *testing.T) {
	dir := t.TempDir()
	escapes := []string{
		"../../../usr/bin/osascript",
		"../..",
		"..",
		"bin/../../outside",
		"/etc/passwd",
		"/usr/bin/sh",
	}
	for _, p := range escapes {
		t.Run(p, func(t *testing.T) {
			if _, err := resolvePluginPath(dir, p); err == nil {
				t.Errorf("resolvePluginPath(%q) accepted path that escapes plugin dir", p)
			}
		})
	}
}

func TestResolvePluginPath_Accepts(t *testing.T) {
	dir := t.TempDir()
	ok := []string{
		"bin/plugin",
		"payload/binary",
		"installer.pkg",
		"./bin/plugin",
		"bin/sub/../plugin",
	}
	for _, p := range ok {
		t.Run(p, func(t *testing.T) {
			got, err := resolvePluginPath(dir, p)
			if err != nil {
				t.Fatalf("resolvePluginPath(%q) rejected valid in-dir path: %v", p, err)
			}
			absDir, _ := filepath.Abs(dir)
			if !strings.HasPrefix(got, absDir) {
				t.Errorf("resolved path %q does not live under plugin dir %q", got, absDir)
			}
		})
	}
}

func TestResolvePluginPath_Empty(t *testing.T) {
	if _, err := resolvePluginPath(t.TempDir(), ""); err == nil {
		t.Errorf("empty path should error")
	}
}

// TestVerifyFileSHA256 covers the manifest-pinned binary hash check
// that closes the swap-after-extract window.
func TestVerifyFileSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	content := []byte("hello plugin binary")
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	goodHex := hex.EncodeToString(sum[:])

	t.Run("match", func(t *testing.T) {
		if err := verifyFileSHA256(path, goodHex); err != nil {
			t.Errorf("matching hash rejected: %v", err)
		}
	})
	t.Run("case-insensitive", func(t *testing.T) {
		if err := verifyFileSHA256(path, strings.ToUpper(goodHex)); err != nil {
			t.Errorf("uppercase hex rejected: %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		if err := verifyFileSHA256(path, strings.Repeat("0", 64)); err == nil {
			t.Errorf("mismatched hash accepted")
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		if err := verifyFileSHA256(path, "deadbeef"); err == nil {
			t.Errorf("short hash accepted")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if err := verifyFileSHA256(filepath.Join(dir, "nope"), goodHex); err == nil {
			t.Errorf("missing file accepted")
		}
	})
}

// TestSanitizePromptField confirms M3's title/subtitle hygiene strips
// control chars and clips to the configured max. N6: also strips
// Unicode bidi/zero-width formatting that could misrepresent the
// displayed text.
func TestSanitizePromptField(t *testing.T) {
	cases := []struct {
		name, in, out string
		max           int
	}{
		{"plain", "hello", "hello", 100},
		{"newline stripped", "hello\nworld", "helloworld", 100},
		{"ansi stripped", "hello\x1b[31mred", "hello[31mred", 100},
		{"tab stripped", "tab\tsep", "tabsep", 100},
		{"controls only", "\x00\x01\x02\x03", "", 100},
		{"clip", "aaaaaaaaaaaaaaaa", "aaaaa", 5},
		{"rtl override stripped", "Approve\u202Eetadpu metsyS", "Approveetadpu metsyS", 100},
		{"zero-width stripped", "Approve\u200BSystem\u200CUpdate", "ApproveSystemUpdate", 100},
		{"bom stripped", "\uFEFFhello", "hello", 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizePromptField(c.in, c.max)
			if got != c.out {
				t.Errorf("sanitizePromptField(%q, %d) = %q, want %q", c.in, c.max, got, c.out)
			}
		})
	}
}

// TestSanitizeStderrLine confirms M5's stderr hygiene replaces control
// bytes with `?` and clips to the line cap.
func TestSanitizeStderrLine(t *testing.T) {
	in := "monban: fake log\x1b[31mred\x00\x07"
	got := sanitizeStderrLine(in)
	if strings.ContainsAny(got, "\x00\x07\x1b") {
		t.Errorf("sanitizeStderrLine left a control char: %q", got)
	}
	if !strings.HasPrefix(got, "monban: fake log") {
		t.Errorf("sanitizeStderrLine mangled prefix: %q", got)
	}
}

// TestAssertPinRateLimit covers N11's per-plugin cooldown. First
// call must pass; a second call inside the cooldown window must be
// refused with an error.
func TestAssertPinRateLimit(t *testing.T) {
	p := &Plugin{}
	if err := p.throttleAssertPin(); err != nil {
		t.Fatalf("first call must pass: %v", err)
	}
	if err := p.throttleAssertPin(); err == nil {
		t.Errorf("second immediate call must be rate-limited")
	}
}

// TestAssertGlobalLockout covers N11's cross-plugin lockout. N
// consecutive failures must latch the flag, and only a user-initiated
// unlock (NotifyUserUnlockSucceeded) may clear it.
func TestAssertGlobalLockout(t *testing.T) {
	h := NewHost(HostConfig{HostVersion: "0.0.0-test"})

	// Under threshold — no lockout.
	for i := 0; i < assertFailureThreshold-1; i++ {
		h.recordAssertOutcome(false)
	}
	if h.assertLockedOut() {
		t.Fatalf("locked out before threshold")
	}

	// Hit the threshold.
	h.recordAssertOutcome(false)
	if !h.assertLockedOut() {
		t.Fatalf("should be locked out after %d failures", assertFailureThreshold)
	}

	// A further plugin-side success must NOT clear the lockout —
	// only a user-initiated unlock does.
	h.recordAssertOutcome(true)
	if !h.assertLockedOut() {
		t.Errorf("plugin success cleared lockout; only NotifyUserUnlockSucceeded should")
	}

	h.NotifyUserUnlockSucceeded()
	if h.assertLockedOut() {
		t.Errorf("NotifyUserUnlockSucceeded did not clear lockout")
	}
}

// TestLogNotifyTokenBucket checks the N12 rate limit: a burst up to
// capacity is allowed, subsequent calls without elapsed time are
// dropped.
func TestLogNotifyTokenBucket(t *testing.T) {
	p := &Plugin{}
	// Burn the whole bucket.
	for i := 0; i < int(logBucketCapacity); i++ {
		if !p.allowLogNotify() {
			t.Fatalf("burst call %d refused, expected bucket capacity %v", i, logBucketCapacity)
		}
	}
	// Next call should be refused (no time to refill).
	if p.allowLogNotify() {
		t.Errorf("call past capacity accepted, expected drop")
	}
}

// TestInstallRollbackOnConsentCancel covers N21: when the second-
// touch consent (or any post-commit step) fails, the plugin dir must
// be rolled back so next Monban start doesn't load a half-installed
// plugin whose privileged side-effects never ran.
func TestInstallRollbackOnConsentCancel(t *testing.T) {
	priv := withTempKey(t)
	pluginsDir := t.TempDir()
	plat := CurrentPlatform()

	binBytes := []byte("fake-binary")
	binHash := sha256.Sum256(binBytes)

	manifest := map[string]any{
		"name":          "rollback-test",
		"version":       "0.1.0",
		"monban_api":    HostAPIVersion,
		"platforms":     []string{plat},
		"kind":          []string{"system"},
		"binary":        map[string]string{plat: "bin/rollback-test"},
		"binary_sha256": map[string]string{plat: hex.EncodeToString(binHash[:])},
		"install_pkg":   "installer.pkg",
	}
	mBytes, _ := json.Marshal(manifest)
	mSig := ed25519.Sign(priv, mBytes)
	tar := buildTarGz(t, map[string][]byte{
		"bin/rollback-test": binBytes,
		"installer.pkg":     []byte("fake-pkg"),
	})
	tarSig := ed25519.Sign(priv, tar)

	mux := http.NewServeMux()
	mux.HandleFunc("/m", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(mBytes) })
	mux.HandleFunc("/ms", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(mSig) })
	mux.HandleFunc("/t", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tar) })
	mux.HandleFunc("/ts", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarSig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	inst := &Installer{
		PluginsDir:    pluginsDir,
		HTTPClient:    srv.Client(),
		RunInstallPkg: func(context.Context, string) error { return nil },
		ConfirmInstallPkg: func(context.Context, *Manifest) error {
			return errors.New("user cancelled")
		},
	}
	entry := &CatalogEntry{
		Name:           "rollback-test",
		Version:        "0.1.0",
		Platforms:      []string{plat},
		ManifestURL:    srv.URL + "/m",
		ManifestSigURL: srv.URL + "/ms",
		TarballURL:     srv.URL + "/t",
		TarballSigURL:  srv.URL + "/ts",
	}
	if _, err := inst.Install(context.Background(), entry); err == nil {
		t.Fatal("Install should have failed due to consent cancellation")
	}
	if _, err := os.Stat(filepath.Join(pluginsDir, "rollback-test")); !os.IsNotExist(err) {
		t.Errorf("half-installed plugin dir left behind: Stat err = %v (want NotExist)", err)
	}
}

// TestManifestCapabilityCheck confirms Manifest.HasCapability matches
// declared strings exactly. Guards N13 against a mis-spelled capability
// name silently bypassing the gate.
func TestManifestCapabilityCheck(t *testing.T) {
	m := &Manifest{Capabilities: []string{"pkg_postinstall", CapFIDOAssertWithPin}}
	if !m.HasCapability(CapFIDOAssertWithPin) {
		t.Errorf("expected capability %q to match", CapFIDOAssertWithPin)
	}
	if m.HasCapability("nonexistent") {
		t.Errorf("unknown capability must not match")
	}
	empty := &Manifest{}
	if empty.HasCapability(CapFIDOAssertWithPin) {
		t.Errorf("missing capabilities field must not match any capability")
	}
}
