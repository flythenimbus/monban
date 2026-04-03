package monban

import (
	"fmt"
	"path/filepath"
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
