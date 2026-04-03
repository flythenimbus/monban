package monban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveExe resolves any symlinks in the executable path.
func resolveExe(exe string) (string, error) {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks: %w", err)
	}
	return resolved, nil
}

// dirOf returns the directory containing the given path.
func dirOf(exe string) string {
	return filepath.Dir(exe)
}

// shellQuote wraps a string in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
}

// writeTempFile writes content to a temp file and returns its path.
func writeTempFile(content string) (string, error) {
	f, err := os.CreateTemp("", "monban-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("writing temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	// Make readable by root when it copies.
	os.Chmod(path, 0644)
	return path, nil
}
