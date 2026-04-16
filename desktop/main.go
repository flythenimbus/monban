package main

import (
	"embed"
	"log"

	monbanapp "monban/internal/app"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/trayicon.png
var trayIconBytes []byte

func main() {
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
			app.StopIPCListener()
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

	monbanapp.RegisterHardeningHooks(app)
	if app.GetSettings().OpenOnStartup {
		monbanapp.InstallLaunchAgent()
	}
	app.StartDeviceWatcher()
	app.StartIPCListener()

	wailsApp.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(event *application.ApplicationEvent) {
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
