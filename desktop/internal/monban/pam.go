package monban

import (
	"fmt"
	"os"
	"strings"
)

// PrivilegedWrite describes a single file write that requires root.
type PrivilegedWrite struct {
	Path      string
	Content   string
	Mode      os.FileMode
	MkdirPath string // optional: create this directory first
}

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

// IsPamInstalled checks if the monban PAM line is present in the sudo config.
func IsPamInstalled() bool {
	data, err := os.ReadFile(PamSudoPath())
	if err != nil {
		return false
	}
	return strings.Contains(string(data), pamTag)
}

// BuildPamContent reads the current sudo PAM config and returns the new content
// with the monban line inserted (or updated for mode="off", removes the line).
func BuildPamContent(mode string) (string, error) {
	return buildPamContentForPath(PamSudoPath(), mode)
}

// InstallSudoGate inserts the monban PAM line into the sudo config, with
// root escalation via the platform-native authorization dialog.
func InstallSudoGate(mode string) error {
	content, err := BuildPamContent(mode)
	if err != nil {
		return err
	}
	return writeFilePrivileged(PamSudoPath(), content, 0644)
}

// RemoveSudoGate removes the monban PAM line from the sudo config.
func RemoveSudoGate() error {
	if !IsPamInstalled() {
		return nil
	}
	content, err := BuildPamContent("off")
	if err != nil {
		return err
	}
	return writeFilePrivileged(PamSudoPath(), content, 0644)
}

// BatchPrivilegedWrites performs multiple file writes in a single privilege
// escalation. Each entry maps a destination path to its temp file source.
// All files are written atomically — if the escalation fails, nothing changes.
func BatchPrivilegedWrites(writes []PrivilegedWrite) error {
	if len(writes) == 0 {
		return nil
	}

	var parts []string
	var tmpFiles []string

	for _, w := range writes {
		tmp, err := writeTempFile(w.Content)
		if err != nil {
			// Clean up any temp files already created.
			for _, t := range tmpFiles {
				_ = os.Remove(t)
			}
			return err
		}
		tmpFiles = append(tmpFiles, tmp)

		if w.MkdirPath != "" {
			parts = append(parts, fmt.Sprintf("mkdir -p %s", shellQuote(w.MkdirPath)))
		}
		parts = append(parts, fmt.Sprintf("cp %s %s && chmod %o %s",
			shellQuote(tmp), shellQuote(w.Path), w.Mode, shellQuote(w.Path)))
	}

	defer func() {
		for _, t := range tmpFiles {
			_ = os.Remove(t)
		}
	}()

	cmd := strings.Join(parts, " && ")
	return RunWithPrivileges(cmd)
}

// --- Private functions ---

// buildPamContentForPath reads a PAM config file and returns the new content
// with the monban line inserted (or removed for mode="off").
func buildPamContentForPath(pamPath, mode string) (string, error) {
	helperPath, err := PamHelperPath()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(helperPath); err != nil {
		return "", fmt.Errorf("PAM helper not found at %s: %w", helperPath, err)
	}

	data, _ := os.ReadFile(pamPath) // may not exist yet (e.g. sudo_local on macOS)

	lines := strings.Split(string(data), "\n")

	// Remove any existing monban line.
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, pamTag) {
			filtered = append(filtered, line)
		}
	}

	if mode == "" || mode == "off" {
		return strings.Join(filtered, "\n"), nil
	}

	// Insert the monban line before the first auth entry.
	newLine := PamLine(mode, helperPath)
	result := make([]string, 0, len(filtered)+1)
	inserted := false
	for _, line := range filtered {
		if !inserted && strings.HasPrefix(strings.TrimSpace(line), "auth") {
			result = append(result, newLine)
			inserted = true
		}
		result = append(result, line)
	}
	if !inserted {
		result = append(result, newLine)
	}

	return strings.Join(result, "\n"), nil
}

// writeFilePrivileged writes content to a root-owned file by writing to a
// temp file first, then copying with privilege escalation.
func writeFilePrivileged(path, content string, mode os.FileMode) error {
	tmp, err := writeTempFile(content)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()

	cmd := fmt.Sprintf("cp %s %s && chmod %o %s",
		shellQuote(tmp), shellQuote(path), mode, shellQuote(path))
	return RunWithPrivileges(cmd)
}
