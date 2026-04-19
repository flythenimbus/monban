//go:build darwin

package app

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const launchAgentLabel = "com.monban.agent"

func launchAgentPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
}

func launchAgentExists() bool {
	_, err := os.Stat(launchAgentPath())
	return err == nil
}

// InstallLaunchAgent writes the plist and loads it.
func InstallLaunchAgent() {
	path := launchAgentPath()

	if launchAgentExists() {
		return
	}

	execPath, err := os.Executable()
	if err != nil {
		log.Printf("monban: could not determine executable path: %v", err)
		return
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/monban.err</string>
</dict>
</plist>
`, launchAgentLabel, execPath)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("monban: could not create LaunchAgents dir: %v", err)
		return
	}

	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		log.Printf("monban: could not write plist: %v", err)
		return
	}

	out, err := exec.Command("launchctl", "load", path).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already loaded") {
		log.Printf("monban: launchctl load: %s %v", out, err)
		return
	}

	log.Println("monban: LaunchAgent installed — will start on login")
}

// RemoveLaunchAgent unloads and deletes the plist.
func RemoveLaunchAgent() {
	path := launchAgentPath()
	if !launchAgentExists() {
		return
	}
	_ = exec.Command("launchctl", "unload", path).Run()
	_ = os.Remove(path)
	log.Println("monban: LaunchAgent removed")
}
