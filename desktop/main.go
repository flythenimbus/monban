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

	var wailsApp *application.App
	wailsApp = application.New(application.Options{
		Name:        "Monban",
		Description: "Security key-based folder encryption",
		Services: []application.Service{
			application.NewService(app),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: monbanapp.PlatformAppOptions(),
		// Quit policy. By the time Cocoa fires ShouldQuit, the run
		// loop is in applicationShouldTerminate: and Lock()ing inline
		// would block the main thread for the entire encryption,
		// leaving the webview unable to render progress. The tray
		// Quit handler runs Lock first (it executes in its own
		// goroutine — see Wails menuitem.go handleClick) and only
		// then calls wailsApp.Quit(); by then locked=true and
		// ShouldQuit just returns true. The cancel-and-reissue branch
		// here exists only for Cmd+Q / dock-menu Quit, which have no
		// pre-Quit hook of their own.
		ShouldQuit: func() bool {
			if app.IsShuttingDown() {
				return app.IsLocked()
			}
			if app.IsLocked() {
				if app.GetSettings().ForceAuthentication {
					log.Println("monban: quit blocked (force authentication active)")
					return false
				}
				return true
			}
			app.SetShuttingDown()
			app.SurfaceWindow()
			go func() {
				if err := app.Lock(); err != nil {
					log.Printf("monban: error locking on shutdown: %v", err)
				}
				app.ShutdownPluginHost()
				// See tray Quit handler for why os.Exit instead of
				// wailsApp.Quit: avoids hanging on the main-thread
				// ExecJS backlog accumulated during encryption.
				os.Exit(0)
			}()
			return false
		},
		OnShutdown: func() {
			log.Println("monban: shutting down")
			app.ShutdownPluginHost()
			// Defensive: signal handlers and platform hooks can also
			// reach OnShutdown without going through ShouldQuit
			// (SIGTERM, watchSleep, etc). Idempotent if already locked.
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
		// During the actual termination pass, let the window close
		// so Cocoa can finish tearing down. Otherwise windowShouldClose
		// returns NO and termination aborts (app appears frozen).
		if app.IsShuttingDown() {
			return
		}
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
		// Tray-menu callbacks already run in their own goroutine, so
		// Lock can run synchronously here without blocking the main
		// thread. Surface the window first so the progress screen is
		// visible while encryption runs.
		//
		// Why os.Exit instead of wailsApp.Quit:
		// Every EmitEvent during a long encryption ultimately funnels
		// through window.ExecJS → application.InvokeSync, which posts
		// to the Cocoa main queue. After 30+ seconds of throttled
		// progress updates, Wails' shutdown path (which also runs on
		// the main thread, processing the queue serially) can hang
		// behind the backlog and leave the window stuck at 100%.
		// Vaults are already encrypted and secrets zeroed by the
		// time we reach this point, so there's nothing critical that
		// Wails' lifecycle cleanup needs to do. Exit directly.
		if app.IsLocked() {
			if app.GetSettings().ForceAuthentication {
				log.Println("monban: quit blocked (force authentication active)")
				return
			}
			wailsApp.Quit()
			return
		}
		if app.IsShuttingDown() {
			return
		}
		app.SetShuttingDown()
		app.SurfaceWindow()
		if err := app.Lock(); err != nil {
			log.Printf("monban: error locking on shutdown: %v", err)
		}
		app.ShutdownPluginHost()
		os.Exit(0)
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
