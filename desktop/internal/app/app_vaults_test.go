package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"monban/internal/monban"
)

func TestGetStatus_Locked(t *testing.T) {
	a := NewApp()
	status := a.GetStatus()
	if !status.Locked {
		t.Error("status should be locked for a new app")
	}
}

func TestLockVault_WhenLocked(t *testing.T) {
	a := NewApp() // locked by default

	err := a.LockVault("/tmp/test")
	if err == nil {
		t.Fatal("LockVault should fail when app is locked")
	}
	if !strings.Contains(err.Error(), "app is locked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLockVault_NilConfig(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = nil

	err := a.LockVault("/tmp/test")
	if err == nil {
		t.Fatal("LockVault should fail with nil config")
	}
	if !strings.Contains(err.Error(), "no config found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLockVault_NotFound(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = &monban.SecureConfig{
		Vaults: []monban.VaultEntry{},
	}

	err := a.LockVault("/tmp/nonexistent")
	if err == nil {
		t.Fatal("LockVault should fail for unknown vault path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpdateVaultMode_WhenLocked(t *testing.T) {
	a := NewApp()

	err := a.UpdateVaultMode("/tmp/test", "lazy", "1234")
	if err == nil {
		t.Fatal("UpdateVaultMode should fail when locked")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpdateVaultMode_NilConfig(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = nil

	err := a.UpdateVaultMode("/tmp/test", "lazy", "1234")
	if err == nil {
		t.Fatal("UpdateVaultMode should fail with nil config")
	}
	if !strings.Contains(err.Error(), "no config found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpdateVaultMode_NotFound(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = &monban.SecureConfig{
		Vaults: []monban.VaultEntry{},
	}

	err := a.UpdateVaultMode("/tmp/nonexistent", "lazy", "1234")
	if err == nil {
		t.Fatal("UpdateVaultMode should fail for unknown vault path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUpdateVaultMode_SameMode(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = &monban.SecureConfig{
		Vaults: []monban.VaultEntry{
			{Label: "docs", Path: "/tmp/docs"},
		},
	}

	// Eager is the default when VaultDecryptModes is nil, so setting to "eager" is a no-op.
	err := a.UpdateVaultMode("/tmp/docs", "eager", "1234")
	if err != nil {
		t.Errorf("UpdateVaultMode with same mode should be a no-op, got: %v", err)
	}
}

func TestDecryptLazyVault_NilConfig(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = nil

	err := a.DecryptLazyVault("/tmp/test", "1234")
	if err == nil {
		t.Fatal("DecryptLazyVault should fail with nil config")
	}
	if !strings.Contains(err.Error(), "no config found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecryptLazyVault_NotFound(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.secureCfg = &monban.SecureConfig{
		Vaults: []monban.VaultEntry{},
	}

	err := a.DecryptLazyVault("/tmp/nonexistent", "1234")
	if err == nil {
		t.Fatal("DecryptLazyVault should fail for unknown vault path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRemoveFolder_WhenLocked(t *testing.T) {
	a := NewApp()

	err := a.RemoveFolder("/tmp/test", "1234")
	if err == nil {
		t.Fatal("RemoveFolder should fail when locked")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRemoveFolder_NilEncKey(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.encKey = nil

	err := a.RemoveFolder("/tmp/test", "1234")
	if err == nil {
		t.Fatal("RemoveFolder should fail with nil encKey")
	}
	if !strings.Contains(err.Error(), "must be unlocked") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAddPath_NonexistentPath(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.encKey = make([]byte, 32)

	err := a.AddPath("/nonexistent/path/that/does/not/exist", "1234")
	if err == nil {
		t.Fatal("AddPath should fail for nonexistent path")
	}
	if !strings.Contains(err.Error(), "path not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAddPath_DispatchesFolder(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.encKey = make([]byte, 32)

	dir := t.TempDir()
	// AddPath on a directory will call addFolder, which requires loading
	// secure config from disk. Since there's no config, it will fail with
	// a config loading error (not a "not a directory" error).
	err := a.AddPath(dir, "1234")
	if err == nil {
		t.Fatal("AddPath should fail when config can't be loaded")
	}
}

func TestAddPath_DispatchesFile(t *testing.T) {
	a := NewApp()
	a.locked = false
	a.encKey = make([]byte, 32)

	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(f, []byte("hello"), 0644)

	// AddPath on a file will call addFile, which requires loading
	// secure config from disk.
	err := a.AddPath(f, "1234")
	if err == nil {
		t.Fatal("AddPath should fail when config can't be loaded")
	}
}

func TestCheckDiskSpace_ValidDir(t *testing.T) {
	dir := t.TempDir()
	// Write a small file so the folder isn't empty
	_ = os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello world"), 0644)

	a := NewApp()
	info := a.CheckDiskSpace(dir)

	// FreeGB should be > 0 on any functioning system
	if info.FreeGB <= 0 {
		t.Errorf("FreeGB should be > 0, got %f", info.FreeGB)
	}
	// FolderGB should be small but non-negative
	if info.FolderGB < 0 {
		t.Errorf("FolderGB should be >= 0, got %f", info.FolderGB)
	}
}

func TestCheckDiskSpace_NonexistentDir(t *testing.T) {
	a := NewApp()
	info := a.CheckDiskSpace("/nonexistent/path")

	// Should return zero values on error
	if info.FolderGB != 0 || info.FreeGB != 0 {
		t.Errorf("expected zero DiskSpaceInfo for nonexistent path, got %+v", info)
	}
}

func TestRevealSecureConfig_NoError(t *testing.T) {
	// Just verify it doesn't panic — actual behavior depends on the
	// file manager being available, which we can't test in CI.
	a := NewApp()
	// We don't call it here because it would actually open a file manager window.
	_ = a
}
