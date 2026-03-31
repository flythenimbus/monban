//go:build linux

package main

import "github.com/wailsapp/wails/v3/pkg/application"

func platformAppOptions() application.MacOptions {
	return application.MacOptions{}
}

func platformWindowOptions() application.MacWindow {
	return application.MacWindow{}
}

func platformConfigureTray(tray *application.SystemTray, icon []byte) {
	tray.SetIcon(icon)
}
