package app

import (
	"strings"
	"testing"
)

func TestGetAdminGateCommand_Off(t *testing.T) {
	a := NewApp()
	cmd, err := a.GetAdminGateCommand("off")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "--uninstall") {
		t.Errorf("off mode should produce --uninstall command, got %q", cmd)
	}
}

func TestGetAdminGateCommand_Empty(t *testing.T) {
	a := NewApp()
	cmd, err := a.GetAdminGateCommand("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "--uninstall") {
		t.Errorf("empty mode should produce --uninstall command, got %q", cmd)
	}
}

func TestGetAdminGateCommand_Default(t *testing.T) {
	a := NewApp()
	cmd, err := a.GetAdminGateCommand("default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "--install default") {
		t.Errorf("default mode should produce --install default, got %q", cmd)
	}
}

func TestGetAdminGateCommand_Strict(t *testing.T) {
	a := NewApp()
	cmd, err := a.GetAdminGateCommand("strict")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cmd, "--install strict") {
		t.Errorf("strict mode should produce --install strict, got %q", cmd)
	}
}

func TestRemoveKey_Locked(t *testing.T) {
	a := NewApp() // starts locked

	err := a.RemoveKey("some-cred-id", "1234")
	if err == nil {
		t.Fatal("RemoveKey should fail when locked")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}
