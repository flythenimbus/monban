//go:build !ios

package main

import "github.com/wailsapp/wails/v3/pkg/application"

// modifyOptionsForIOS is a no-op on non-iOS platforms
//
//nolint:unused
func modifyOptionsForIOS(opts *application.Options) {
	// No modifications needed for non-iOS platforms
}