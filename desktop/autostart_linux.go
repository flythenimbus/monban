//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func autostartPath() string {
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "autostart", "monban.desktop")
}

func launchAgentExists() bool {
	_, err := os.Stat(autostartPath())
	return err == nil
}

// installLaunchAgent writes an XDG autostart .desktop file.
func installLaunchAgent() {
	if launchAgentExists() {
		return
	}

	execPath, err := os.Executable()
	if err != nil {
		log.Printf("monban: could not determine executable path: %v", err)
		return
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	desktop := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Monban
Exec=%s
Icon=monban
Terminal=false
X-GNOME-Autostart-enabled=true
Comment=Security key-based folder encryption
`, execPath)

	path := autostartPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("monban: could not create autostart dir: %v", err)
		return
	}

	if err := os.WriteFile(path, []byte(desktop), 0644); err != nil {
		log.Printf("monban: could not write desktop file: %v", err)
		return
	}

	log.Println("monban: XDG autostart installed — will start on login")
}

// removeLaunchAgent removes the XDG autostart .desktop file.
func removeLaunchAgent() {
	if !launchAgentExists() {
		return
	}
	_ = os.Remove(autostartPath())
	log.Println("monban: XDG autostart removed")
}
