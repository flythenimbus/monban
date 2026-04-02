package monban

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func pamSudoPath() string {
	return "/etc/pam.d/sudo"
}

func secureConfigDir() string {
	return "/etc/monban"
}

func resolveExe(exe string) (string, error) {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks: %w", err)
	}
	return resolved, nil
}

func dirOf(exe string) string {
	return filepath.Dir(exe)
}

// RunWithPrivileges executes a shell command with root privileges using pkexec.
func RunWithPrivileges(shellCmd string) error {
	cmd := exec.Command("pkexec", "sh", "-c", shellCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
