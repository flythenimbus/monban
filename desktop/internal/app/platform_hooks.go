package app

import "github.com/wailsapp/wails/v3/pkg/application"

// Platform hook variables — set by hardening_darwin.go / hardening_linux.go
// via init(). Tests can override these to avoid requiring a running Wails
// event loop or platform-specific frameworks.

var (
	exitKioskMode             = func() {}
	enterKioskMode            = func() {}
	showInDock                = func() {}
	hideFromDock              = func() {}
	hasAccessibilityPermission    = func() bool { return false }
	promptAccessibilityPermission = func() bool { return false }

	// invokeSync wraps application.InvokeSync so tests can stub it out.
	invokeSync = application.InvokeSync
)

// Exported wrappers for use by main.go and other packages.

func ShowInDock()  { showInDock() }
func HideFromDock() { hideFromDock() }
func EnterKioskMode() { enterKioskMode() }
func ExitKioskMode()  { exitKioskMode() }
func HasAccessibilityPermission() bool  { return hasAccessibilityPermission() }
func PromptAccessibilityPermission() bool { return promptAccessibilityPermission() }
