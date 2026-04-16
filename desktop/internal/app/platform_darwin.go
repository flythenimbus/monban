//go:build darwin

package app

import "github.com/wailsapp/wails/v3/pkg/application"

func PlatformAppOptions() application.MacOptions {
	return application.MacOptions{
		ActivationPolicy: application.ActivationPolicyAccessory,
	}
}

func PlatformWindowOptions() application.MacWindow {
	return application.MacWindow{
		InvisibleTitleBarHeight: 50,
		Backdrop:                application.MacBackdropTranslucent,
		TitleBar:                application.MacTitleBarHiddenInset,
	}
}

func PlatformConfigureTray(tray *application.SystemTray, icon []byte) {
	tray.SetTemplateIcon(icon)
}
