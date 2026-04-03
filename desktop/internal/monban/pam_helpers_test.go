package monban

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveExe(t *testing.T) {
	dir := t.TempDir()

	// Resolve the temp dir itself (macOS /var -> /private/var symlink)
	dir, _ = filepath.EvalSymlinks(dir)

	// Create a real file
	target := filepath.Join(dir, "real-binary")
	if err := os.WriteFile(target, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to it
	link := filepath.Join(dir, "symlink-binary")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveExe(link)
	if err != nil {
		t.Fatal(err)
	}

	if resolved != target {
		t.Errorf("expected %s, got %s", target, resolved)
	}
}

func TestResolveExeNoSymlink(t *testing.T) {
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)

	target := filepath.Join(dir, "binary")
	if err := os.WriteFile(target, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveExe(target)
	if err != nil {
		t.Fatal(err)
	}

	if resolved != target {
		t.Errorf("expected %s, got %s", target, resolved)
	}
}

func TestResolveExeNonExistent(t *testing.T) {
	_, err := resolveExe("/nonexistent/path/to/binary")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestDirOf(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/usr/local/bin/monban", "/usr/local/bin"},
		{"/tmp/binary", "/tmp"},
		{"relative/path/binary", "relative/path"},
	}

	for _, tt := range tests {
		got := dirOf(tt.input)
		if got != tt.want {
			t.Errorf("dirOf(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
