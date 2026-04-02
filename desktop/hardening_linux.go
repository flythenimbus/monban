//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"
)

var globalApp *App

func RegisterHardeningHooks(app *App) {
	globalApp = app

	// Signal handling (SIGTERM/SIGINT)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Println("monban: signal received, locking vaults...")
		_ = app.Lock()
		os.Exit(0)
	}()

	// D-Bus: lock vaults on system sleep
	go watchSleep()

	// D-Bus: lock vaults on session lock
	go watchSessionLock()
}

// Kiosk mode stubs for Linux (not yet implemented)
func HasAccessibilityPermission() bool   { return false }
func PromptAccessibilityPermission() bool { return false }
func EnterKioskMode()                    {}
func ExitKioskMode()                     {}


// watchSleep listens for systemd-logind PrepareForSleep signals.
func watchSleep() {
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Printf("monban: could not connect to system D-Bus: %v", err)
		return
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
		dbus.WithMatchMember("PrepareForSleep"),
	); err != nil {
		log.Printf("monban: could not subscribe to PrepareForSleep: %v", err)
		return
	}

	ch := make(chan *dbus.Signal, 10)
	conn.Signal(ch)

	for sig := range ch {
		if sig.Name == "org.freedesktop.login1.Manager.PrepareForSleep" && len(sig.Body) > 0 {
			if entering, ok := sig.Body[0].(bool); ok && entering {
				log.Println("monban: system sleep detected, locking vaults...")
				_ = globalApp.Lock()
			}
		}
	}
}

// watchSessionLock listens for systemd-logind session Lock signals.
func watchSessionLock() {
	conn, err := dbus.SystemBus()
	if err != nil {
		log.Printf("monban: could not connect to system D-Bus: %v", err)
		return
	}

	// Get session path for current process
	obj := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	var sessionPath dbus.ObjectPath
	if err := obj.Call("org.freedesktop.login1.Manager.GetSessionByPID", 0, uint32(os.Getpid())).Store(&sessionPath); err != nil {
		log.Printf("monban: could not get session path: %v", err)
		return
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.login1.Session"),
		dbus.WithMatchMember("Lock"),
		dbus.WithMatchObjectPath(sessionPath),
	); err != nil {
		log.Printf("monban: could not subscribe to session Lock: %v", err)
		return
	}

	ch := make(chan *dbus.Signal, 10)
	conn.Signal(ch)

	for sig := range ch {
		if sig.Name == "org.freedesktop.login1.Session.Lock" {
			log.Println("monban: session lock detected, locking vaults...")
			_ = globalApp.Lock()
		}
	}
}
