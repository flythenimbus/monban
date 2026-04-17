package app

import (
	"testing"
)

func TestNewApp(t *testing.T) {
	a := NewApp()
	if a == nil {
		t.Fatal("NewApp() returned nil")
	}
	if !a.locked {
		t.Error("new app should start locked")
	}
	if a.window != nil {
		t.Error("new app should have nil window")
	}
	if a.masterSecret != nil {
		t.Error("new app should have nil masterSecret")
	}
	if a.encKey != nil {
		t.Error("new app should have nil encKey")
	}
	if a.secureCfg != nil {
		t.Error("new app should have nil secureCfg")
	}
	if a.ipc != nil {
		t.Error("new app should have nil ipc")
	}
}

func TestIsLocked_Default(t *testing.T) {
	a := NewApp()
	if !a.IsLocked() {
		t.Error("IsLocked() should return true for a new app")
	}
}

func TestIsLocked_SetFalse(t *testing.T) {
	a := NewApp()
	a.mu.Lock()
	a.locked = false
	a.mu.Unlock()

	if a.IsLocked() {
		t.Error("IsLocked() should return false after setting locked=false")
	}
}

func TestSetWindow_Nil(t *testing.T) {
	a := NewApp()
	a.SetWindow(nil) // should not panic
	if a.window != nil {
		t.Error("SetWindow(nil) should set window to nil")
	}
}

func TestResizeWindow_NilWindow(t *testing.T) {
	a := NewApp()
	// Should not panic with nil window
	a.ResizeWindow(800, 600)
}

// stubHooks replaces all platform hooks with no-ops for the duration of the test.
func stubHooks(t *testing.T) {
	t.Helper()
	origExit := exitKioskMode
	origEnter := enterKioskMode
	origShow := showInDock
	origHide := hideFromDock
	origHasA11y := hasAccessibilityPermission
	origPromptA11y := promptAccessibilityPermission
	origInvoke := invokeSync

	exitKioskMode = func() {}
	enterKioskMode = func() {}
	showInDock = func() {}
	hideFromDock = func() {}
	hasAccessibilityPermission = func() bool { return false }
	promptAccessibilityPermission = func() bool { return false }
	invokeSync = func(fn func()) { fn() }

	t.Cleanup(func() {
		exitKioskMode = origExit
		enterKioskMode = origEnter
		showInDock = origShow
		hideFromDock = origHide
		hasAccessibilityPermission = origHasA11y
		promptAccessibilityPermission = origPromptA11y
		invokeSync = origInvoke
	})
}

func TestExitFullscreen_NilWindow(t *testing.T) {
	stubHooks(t)
	a := NewApp()
	a.ExitFullscreen() // should not panic with nil window
}

func TestExitFullscreen_CallsExitKioskMode(t *testing.T) {
	stubHooks(t)
	called := false
	exitKioskMode = func() { called = true }

	a := NewApp()
	a.ExitFullscreen()

	if !called {
		t.Error("ExitFullscreen should call exitKioskMode")
	}
}

func TestEnterFullscreen_NilWindow(t *testing.T) {
	stubHooks(t)
	a := NewApp()
	a.EnterFullscreen() // nil window → early return
}

func TestHideToTray_NilWindow_Hooks(t *testing.T) {
	stubHooks(t)
	a := NewApp()
	a.HideToTray() // nil window → early return, no panic
}

func TestAppStatus_JSONFields(t *testing.T) {
	status := AppStatus{
		Locked:     true,
		Registered: false,
		Vaults: []VaultStatus{
			{Label: "docs", Path: "/tmp/docs", Locked: true, DecryptMode: "eager"},
		},
	}

	if !status.Locked {
		t.Error("status should be locked")
	}
	if status.Registered {
		t.Error("status should not be registered")
	}
	if len(status.Vaults) != 1 {
		t.Fatalf("expected 1 vault, got %d", len(status.Vaults))
	}
	if status.Vaults[0].Label != "docs" {
		t.Errorf("vault label = %q, want %q", status.Vaults[0].Label, "docs")
	}
}

func TestVaultStatus_Fields(t *testing.T) {
	vs := VaultStatus{
		Label:       "test",
		Path:        "/tmp/test",
		Type:        "file",
		Locked:      false,
		DecryptMode: "lazy_strict",
	}

	if vs.Label != "test" {
		t.Errorf("Label = %q, want %q", vs.Label, "test")
	}
	if vs.Type != "file" {
		t.Errorf("Type = %q, want %q", vs.Type, "file")
	}
	if vs.DecryptMode != "lazy_strict" {
		t.Errorf("DecryptMode = %q, want %q", vs.DecryptMode, "lazy_strict")
	}
}

func TestKeyInfo_Fields(t *testing.T) {
	ki := KeyInfo{
		Label:        "YubiKey 5C",
		CredentialID: "abc123",
	}
	if ki.Label != "YubiKey 5C" {
		t.Errorf("Label = %q, want %q", ki.Label, "YubiKey 5C")
	}
	if ki.CredentialID != "abc123" {
		t.Errorf("CredentialID = %q, want %q", ki.CredentialID, "abc123")
	}
}

func TestDiskSpaceInfo_Fields(t *testing.T) {
	dsi := DiskSpaceInfo{
		FolderGB:      1.5,
		FreeGB:        10.0,
		SafeToMigrate: true,
	}
	if dsi.FolderGB != 1.5 {
		t.Errorf("FolderGB = %f, want 1.5", dsi.FolderGB)
	}
	if !dsi.SafeToMigrate {
		t.Error("SafeToMigrate should be true")
	}
}

func TestCombinedSettings_Defaults(t *testing.T) {
	cs := CombinedSettings{}
	if cs.OpenOnStartup {
		t.Error("default OpenOnStartup should be false")
	}
	if cs.ForceAuthentication {
		t.Error("default ForceAuthentication should be false")
	}
	if cs.AdminGate != "" {
		t.Errorf("default AdminGate should be empty, got %q", cs.AdminGate)
	}
}
