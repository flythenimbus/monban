package main

import (
	"context"
	"embed"
	"log"
	"os"
	"slices"

	monbanapp "monban/internal/app"
	"monban/internal/plugin"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/trayicon.png
var trayIconBytes []byte

func main() {
	// C4: refuse to start a production binary that still trusts the
	// committed dev pubkey. Fatal in prod builds, logs a warning in dev.
	plugin.CheckReleaseKeyConfig()

	app := monbanapp.NewApp()

	wailsApp := application.New(application.Options{
		Name:        "Monban",
		Description: "Security key-based folder encryption",
		Services: []application.Service{
			application.NewService(app),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: monbanapp.PlatformAppOptions(),
		ShouldQuit: func() bool {
			if app.IsLocked() && app.GetSettings().ForceAuthentication {
				log.Println("monban: quit blocked (force authentication active)")
				return false
			}
			return true
		},
		OnShutdown: func() {
			log.Println("monban: shutting down, locking vaults...")
			app.ShutdownPluginHost()
			if err := app.Lock(); err != nil {
				log.Printf("monban: error locking on shutdown: %v", err)
			}
		},
	})

	systemTray := wailsApp.SystemTray.New()
	monbanapp.PlatformConfigureTray(systemTray, trayIconBytes)

	win := wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Monban",
		Width:            420,
		Height:           300,
		MinWidth:         380,
		MinHeight:        200,
		Hidden:           true,
		Mac:              monbanapp.PlatformWindowOptions(),
		BackgroundColour: application.NewRGB(245, 240, 235),
		URL:              "/",
	})

	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if app.IsLocked() && app.GetSettings().ForceAuthentication {
			e.Cancel()
			return
		}
		win.Hide()
		monbanapp.HideFromDock()
		e.Cancel()
	})

	trayMenu := wailsApp.NewMenu()
	trayMenu.Add("Open Monban").OnClick(func(ctx *application.Context) {
		monbanapp.ShowInDock()
		win.Show()
		win.Focus()
	})
	trayMenu.AddSeparator()
	trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
		wailsApp.Quit()
	})
	systemTray.SetMenu(trayMenu)

	app.SetWindow(win)
	app.SetWailsApp(wailsApp)

	monbanapp.RegisterHardeningHooks(app)
	if app.GetSettings().OpenOnStartup {
		monbanapp.InstallLaunchAgent()
	}
	app.StartDeviceWatcher()

	// --disable-plugins is the lockout-recovery escape for a broken
	// auth_gate plugin. When set, plugins are never loaded — unlock
	// proceeds as if nothing was installed — so a misconfigured
	// sso-gate (or any denial chain) can't brick the user's ability
	// to reach their own vaults.
	//
	// C1: the flag is gated on a root-owned sentinel at
	// /etc/monban/allow_disable_plugins. Personal users can `sudo
	// touch` the file to enable the escape hatch; enterprise MDM
	// simply never provisions it, so a user in possession of the
	// YubiKey + PIN can't bypass a corporate auth_gate by adding a
	// CLI flag to a LaunchAgent or shortcut. Noisy in the log so
	// incident tooling can spot both the attempt and the bypass.
	if slices.Contains(os.Args[1:], "--disable-plugins") {
		if err := monbanapp.AllowDisablePlugins(); err != nil {
			log.Printf("monban: --disable-plugins requested but not permitted: %v — starting plugin host anyway", err)
			app.StartPluginHost(context.Background())
		} else {
			log.Println("monban: --disable-plugins passed and sentinel present; skipping plugin host startup")
		}
	} else {
		app.StartPluginHost(context.Background())
	}

	wailsApp.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(event *application.ApplicationEvent) {
		app.FirePluginEvent("on:app_started", nil)
		if app.IsRegistered() {
			settings := app.GetSettings()
			if settings.ForceAuthentication {
				app.EnterFullscreen()
			}
		}
		monbanapp.ShowInDock()
		win.Show()
		win.Focus()
	})

	if err := wailsApp.Run(); err != nil {
		log.Fatal(err)
	}
}
