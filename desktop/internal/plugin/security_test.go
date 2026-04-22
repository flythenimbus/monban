package plugin

import (
	"crypto/sha256"
	"encoding/hex"
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
// control chars and clips to the configured max.
func TestSanitizePromptField(t *testing.T) {
	cases := []struct {
		in, out string
		max     int
	}{
		{"hello", "hello", 100},
		{"hello\nworld", "helloworld", 100},
		{"hello\x1b[31mred", "hello[31mred", 100},
		{"tab\tsep", "tabsep", 100},
		{"\x00\x01\x02\x03", "", 100},
		{"aaaaaaaaaaaaaaaa", "aaaaa", 5},
	}
	for _, c := range cases {
		got := sanitizePromptField(c.in, c.max)
		if got != c.out {
			t.Errorf("sanitizePromptField(%q, %d) = %q, want %q", c.in, c.max, got, c.out)
		}
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
