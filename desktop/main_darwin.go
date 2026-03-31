//go:build darwin

package main

import "github.com/wailsapp/wails/v3/pkg/application"

func platformAppOptions() application.MacOptions {
	return application.MacOptions{
		ActivationPolicy: application.ActivationPolicyAccessory,
	}
}

func platformWindowOptions() application.MacWindow {
	return application.MacWindow{
		InvisibleTitleBarHeight: 50,
		Backdrop:                application.MacBackdropTranslucent,
		TitleBar:                application.MacTitleBarHiddenInset,
	}
}

func platformConfigureTray(tray *application.SystemTray, icon []byte) {
	tray.SetTemplateIcon(icon)
}
