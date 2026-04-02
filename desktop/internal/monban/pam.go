package monban

import (
	"fmt"
	"os"
	"strings"
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
	helperPath, err := PamHelperPath()
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(helperPath); err != nil {
		return "", fmt.Errorf("PAM helper not found at %s: %w", helperPath, err)
	}

	pamPath := PamSudoPath()
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

// writeFilePrivileged writes content to a root-owned file by writing to a
// temp file first, then copying with privilege escalation.
func writeFilePrivileged(path, content string, mode os.FileMode) error {
	tmp, err := writeTempFile(content)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	cmd := fmt.Sprintf("cp %s %s && chmod %o %s",
		shellQuote(tmp), shellQuote(path), mode, shellQuote(path))
	return RunWithPrivileges(cmd)
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

// shellQuote wraps a string in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
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
				os.Remove(t)
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
			os.Remove(t)
		}
	}()

	cmd := strings.Join(parts, " && ")
	return RunWithPrivileges(cmd)
}

// PrivilegedWrite describes a single file write that requires root.
type PrivilegedWrite struct {
	Path      string
	Content   string
	Mode      os.FileMode
	MkdirPath string // optional: create this directory first
}
