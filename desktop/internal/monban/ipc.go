package monban

import (
	"os"
	"path/filepath"
)

type IPCRequest struct {
	Type    string `json:"type"`    // "auth"
	User    string `json:"user"`    // invoking user
	Service string `json:"service"` // PAM service (e.g. "sudo", "authorization")
}

type IPCResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// IPCSocketPath returns the path to the IPC socket in the config directory.
func IPCSocketPath() string {
	return filepath.Join(ConfigDir(), "monban.sock")
}

// CleanStaleSocket removes a leftover socket file if present.
// Temporarily unlocks the config directory if needed.
func CleanStaleSocket() {
	path := IPCSocketPath()
	if _, err := os.Stat(path); err != nil {
		return
	}
	wasLocked := unlockConfigDir()
	_ = os.Remove(path)
	if wasLocked {
		LockConfigDir()
	}
}
