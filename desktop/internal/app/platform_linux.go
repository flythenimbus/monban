//go:build linux

package app

import "github.com/wailsapp/wails/v3/pkg/application"

func PlatformAppOptions() application.MacOptions {
	return application.MacOptions{}
}

func PlatformWindowOptions() application.MacWindow {
	return application.MacWindow{}
}

func PlatformConfigureTray(tray *application.SystemTray, icon []byte) {
	tray.SetIcon(icon)
}
