package monban

import (
	"fmt"
	"os"
)

const pamTag = "# monban sudo gate"

// PamTag returns the tag used to identify monban PAM lines.
func PamTag() string { return pamTag }

// PamHelperPath returns the expected location of the PAM helper binary,
// adjacent to the running executable.
func PamHelperPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	exe, err = resolveExe(exe)
	if err != nil {
		return "", err
	}
	dir := dirOf(exe)
	return dir + "/monban-pam-helper", nil
}

// PamLine returns the pam_exec line for the given mode and helper path.
func PamLine(mode, helperPath string) string {
	pamMode := "sufficient"
	if mode == "strict" {
		pamMode = "required"
	}
	return fmt.Sprintf("auth %s pam_exec.so quiet %s %s", pamMode, helperPath, pamTag)
}

// PamSudoPath returns the platform-specific path to the sudo PAM config.
func PamSudoPath() string {
	return pamSudoPath()
}

// PamSuPath returns the platform-specific path to the su PAM config.
func PamSuPath() string {
	return pamSuPath()
}
