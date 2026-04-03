package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/trayicon.png
var trayIconBytes []byte

func main() {
	app := NewApp()

	wailsApp := application.New(application.Options{
		Name:        "Monban",
		Description: "Security key-based folder encryption",
		Services: []application.Service{
			application.NewService(app),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: platformAppOptions(),
		ShouldQuit: func() bool {
			// Block quit while locked with force authentication
			if app.IsLocked() && app.GetSettings().ForceAuthentication {
				log.Println("monban: quit blocked (force authentication active)")
				return false
			}
			return true
		},
		OnShutdown: func() {
			log.Println("monban: shutting down, locking vaults...")
			if err := app.Lock(); err != nil {
				log.Printf("monban: error locking on shutdown: %v", err)
			}
		},
	})

	// Create system tray first (before window)
	systemTray := wailsApp.SystemTray.New()

	platformConfigureTray(systemTray, trayIconBytes)

	win := wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "Monban",
		Width:  420,
		Height: 300,
		MinWidth: 380,
		MinHeight: 200,
		Hidden: true,
		Mac: platformWindowOptions(),
		BackgroundColour: application.NewRGB(245, 240, 235),
		URL:              "/",
	})

	// Intercept close — if locked + force auth, prevent entirely; otherwise hide to tray
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if app.IsLocked() && app.GetSettings().ForceAuthentication {
			e.Cancel()
			return
		}
		win.Hide()
		e.Cancel()
	})

	// Tray menu
	trayMenu := wailsApp.NewMenu()
	trayMenu.Add("Open Monban").OnClick(func(ctx *application.Context) {
		win.Show()
		win.Focus()
	})
	trayMenu.AddSeparator()
	trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
		wailsApp.Quit()
	})
	systemTray.SetMenu(trayMenu)

	app.SetWindow(win)

	RegisterHardeningHooks(app)
	installLaunchAgent()
	app.StartDeviceWatcher()

	// Show window after app is running (hooks need the run loop active).
	wailsApp.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(event *application.ApplicationEvent) {
		if app.IsRegistered() {
			settings := app.GetSettings()
			if settings.ForceAuthentication {
				app.EnterFullscreen()
			}
		}
		win.Show()
		win.Focus()
	})

	if err := wailsApp.Run(); err != nil {
		log.Fatal(err)
	}
}
