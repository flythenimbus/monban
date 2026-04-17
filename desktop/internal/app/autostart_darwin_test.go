//go:build darwin

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchAgentPath(t *testing.T) {
	path := launchAgentPath()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("could not get home dir: %v", err)
	}

	expected := filepath.Join(home, "Library", "LaunchAgents", "com.monban.agent.plist")
	if path != expected {
		t.Errorf("launchAgentPath() = %q, want %q", path, expected)
	}
}

func TestLaunchAgentPath_ContainsPlist(t *testing.T) {
	path := launchAgentPath()
	if !strings.HasSuffix(path, ".plist") {
		t.Errorf("launchAgentPath() should end with .plist, got %q", path)
	}
}

func TestLaunchAgentPath_ContainsLabel(t *testing.T) {
	path := launchAgentPath()
	if !strings.Contains(path, launchAgentLabel) {
		t.Errorf("launchAgentPath() should contain label %q, got %q", launchAgentLabel, path)
	}
}

func TestLaunchAgentExists_NoFile(t *testing.T) {
	// The plist file may or may not exist on the dev machine.
	// We just test that the function doesn't panic.
	_ = launchAgentExists()
}
