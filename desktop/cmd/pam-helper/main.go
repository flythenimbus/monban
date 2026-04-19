// monban-pam-helper is a standalone binary invoked by pam_exec.so to gate
// sudo (and optionally authorization) behind a FIDO2 security key assertion.
//
// Usage:
//
//	pam_exec.so invokes this binary (no args) for authentication.
//	sudo monban-pam-helper --install default|strict   Install to /usr/local/bin and configure PAM.
//	sudo monban-pam-helper --uninstall                Remove PAM config and installed binary.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"monban/internal/monban"

	"golang.org/x/term"
)

const (
	installPath      = "/usr/local/bin/monban-pam-helper"
	pamModuleDir     = "/usr/local/lib/pam"
	pamModulePath    = "/usr/local/lib/pam/pam_monban.so"
	authPluginDir    = "/Library/Security/SecurityAgentPlugins"
	authPluginName   = "monban-auth.bundle"
	authPluginPath   = authPluginDir + "/" + authPluginName
	authMechanismID  = "monban-auth:auth"
	authBackupSuffix = ".monban-backup"
)

// Authorization rights that monban gates on macOS.
var authorizationRights = []string{
	"system.preferences",
	"system.preferences.security",
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--install":
			mode := "default"
			if len(os.Args) > 2 {
				mode = os.Args[2]
			}
			if err := install(mode); err != nil {
				fmt.Fprintf(os.Stderr, "monban: install failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "--uninstall":
			if err := uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "monban: uninstall failed: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := authenticate(); err != nil {
		fmt.Fprintf(os.Stderr, "monban: %v\n", err)
		os.Exit(1)
	}
}

func install(mode string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run with sudo")
	}

	pamMode := "sufficient"
	if mode == "strict" {
		pamMode = "required"
	}

	// Copy the helper binary to /usr/local/bin/.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving symlinks: %w", err)
	}

	if exe != installPath {
		if err := copyFile(exe, installPath, 0755); err != nil {
			return err
		}
		fmt.Printf("Installed %s\n", installPath)
	}

	// Copy the PAM module to /usr/local/lib/pam/.
	pamModuleSrc := filepath.Join(filepath.Dir(exe), "pam_monban.so")
	if _, err := os.Stat(pamModuleSrc); err != nil {
		return fmt.Errorf("pam_monban.so not found next to binary (%s) — rebuild with 'task build:pam-helper'", filepath.Dir(exe))
	}
	if err := os.MkdirAll(pamModuleDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", pamModuleDir, err)
	}
	if err := copyFile(pamModuleSrc, pamModulePath, 0644); err != nil {
		return err
	}
	fmt.Printf("Installed %s\n", pamModulePath)

	// Verify the installed module and helper exist before writing PAM config.
	// A broken PAM config locks out sudo entirely.
	if _, err := os.Stat(pamModulePath); err != nil {
		return fmt.Errorf("PAM module not found at %s after install", pamModulePath)
	}
	if _, err := os.Stat(installPath); err != nil {
		return fmt.Errorf("helper not found at %s after install", installPath)
	}

	// Write sudo PAM config referencing the module.
	pamLine := fmt.Sprintf("auth %s %s %s\n",
		pamMode, pamModulePath, monban.PamTag())

	pamPath := monban.PamSudoPath()
	if err := os.WriteFile(pamPath, []byte(pamLine), 0444); err != nil {
		return fmt.Errorf("writing %s: %w", pamPath, err)
	}
	fmt.Printf("Configured %s (%s mode)\n", pamPath, mode)

	// Strict mode also gates su to prevent root user activation bypass.
	// On macOS, /etc/pam.d/su is SIP-protected and cannot be modified.
	suPath := monban.PamSuPath()
	if runtime.GOOS != "darwin" && mode == "strict" {
		suData, _ := os.ReadFile(suPath)
		suLines := strings.Split(string(suData), "\n")

		// Remove any existing monban line.
		filtered := make([]string, 0, len(suLines))
		for _, line := range suLines {
			if !strings.Contains(line, monban.PamTag()) {
				filtered = append(filtered, line)
			}
		}

		// Insert monban line before the first auth entry.
		suPamLine := fmt.Sprintf("auth required %s %s", pamModulePath, monban.PamTag())
		result := make([]string, 0, len(filtered)+1)
		inserted := false
		for _, line := range filtered {
			if !inserted && strings.HasPrefix(strings.TrimSpace(line), "auth") {
				result = append(result, suPamLine)
				inserted = true
			}
			result = append(result, line)
		}
		if !inserted {
			result = append(result, suPamLine)
		}

		if err := os.WriteFile(suPath, []byte(strings.Join(result, "\n")), 0444); err != nil {
			return fmt.Errorf("writing %s: %w", suPath, err)
		}
		fmt.Printf("Configured %s (strict mode)\n", suPath)
	} else {
		// Non-strict: ensure su is clean.
		removePamTag(suPath)
	}

	// Install macOS Authorization Plugin (gates system admin dialogs).
	if runtime.GOOS == "darwin" {
		if err := installAuthPlugin(exe); err != nil {
			fmt.Fprintf(os.Stderr, "monban: auth plugin install warning: %v\n", err)
		}
	}

	return nil
}


// --- macOS Authorization Plugin ---

func installAuthPlugin(exe string) error {
	// Find the auth plugin bundle adjacent to the binary (inside .app bundle).
	appDir := filepath.Dir(exe)
	bundleSrc := filepath.Join(appDir, "..", "Resources", authPluginName)
	if _, err := os.Stat(bundleSrc); err != nil {
		// Try next to the binary (dev builds).
		bundleSrc = filepath.Join(appDir, authPluginName)
		if _, err := os.Stat(bundleSrc); err != nil {
			return fmt.Errorf("auth plugin bundle not found near %s", exe)
		}
	}

	// Copy bundle to /Library/Security/SecurityAgentPlugins/
	if err := os.RemoveAll(authPluginPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing old auth plugin: %w", err)
	}
	if err := copyDir(bundleSrc, authPluginPath); err != nil {
		return fmt.Errorf("copying auth plugin: %w", err)
	}
	fmt.Printf("Installed %s\n", authPluginPath)

	// Modify authorization rights to use our plugin mechanism.
	for _, right := range authorizationRights {
		if err := addAuthMechanism(right); err != nil {
			fmt.Fprintf(os.Stderr, "monban: warning: could not configure right %s: %v\n", right, err)
		} else {
			fmt.Printf("Configured authorization right: %s\n", right)
		}
	}

	return nil
}

func uninstallAuthPlugin() {
	// Restore authorization rights to their default (remove our mechanism).
	for _, right := range authorizationRights {
		if err := removeAuthMechanism(right); err != nil {
			fmt.Fprintf(os.Stderr, "monban: warning: could not restore right %s: %v\n", right, err)
		} else {
			fmt.Printf("Restored authorization right: %s\n", right)
		}
	}

	// Remove the plugin bundle.
	if err := os.RemoveAll(authPluginPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "monban: warning: could not remove auth plugin: %v\n", err)
	} else {
		fmt.Printf("Removed %s\n", authPluginPath)
	}
}

// addAuthMechanism converts an authorization right from class:user (password-based)
// to class:evaluate-mechanisms with our plugin, preserving a backup of the original.
func addAuthMechanism(right string) error {
	// Read current right.
	out, err := exec.Command("security", "authorizationdb", "read", right).Output()
	if err != nil {
		return fmt.Errorf("reading right: %w", err)
	}

	// Save backup of original right.
	backupPath := filepath.Join(authPluginDir, right+authBackupSuffix)
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		_ = os.WriteFile(backupPath, out, 0600)
	}

	// Build new right with evaluate-mechanisms class.
	newRight := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>class</key>
	<string>evaluate-mechanisms</string>
	<key>comment</key>
	<string>Monban: FIDO2 security key authentication</string>
	<key>mechanisms</key>
	<array>
		<string>%s</string>
	</array>
	<key>shared</key>
	<false/>
	<key>tries</key>
	<integer>3</integer>
</dict>
</plist>`, authMechanismID)

	cmd := exec.Command("security", "authorizationdb", "write", right)
	cmd.Stdin = strings.NewReader(newRight)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// removeAuthMechanism restores the original authorization right from backup.
func removeAuthMechanism(right string) error {
	backupPath := filepath.Join(authPluginDir, right+authBackupSuffix)
	data, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading backup: %w", err)
	}

	cmd := exec.Command("security", "authorizationdb", "write", right)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restoring right: %w", err)
	}

	_ = os.Remove(backupPath)
	return nil
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

// --- File helpers ---

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	return nil
}

func uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run with sudo")
	}

	// Clean monban line from su PAM config (don't delete the file — it has other entries).
	removePamTag(monban.PamSuPath())

	// Restore authorization rights and remove auth plugin (macOS).
	if runtime.GOOS == "darwin" {
		uninstallAuthPlugin()
	}

	for _, path := range []string{monban.PamSudoPath(), installPath, pamModulePath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		fmt.Printf("Removed %s\n", path)
	}

	return nil
}

// removePamTag removes the monban PAM line from a PAM config file, preserving
// all other content. Unlike sudo_local which is monban-owned, su has existing
// system entries that must be kept.
func removePamTag(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	tag := monban.PamTag()
	lines := strings.Split(string(data), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.Contains(line, tag) {
			filtered = append(filtered, line)
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(filtered, "\n")), 0444)
}


// resolveUserConfigDir determines the invoking user's config directory.
// When running as root via PAM, os.UserHomeDir() returns /var/root.
// We try multiple sources to find the real invoking user.
func resolveUserConfigDir() error {
	username := os.Getenv("PAM_USER")
	if username == "" {
		username = os.Getenv("SUDO_USER")
	}
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	// On macOS, the console owner is the logged-in user.
	if username == "" || username == "root" {
		if name := consoleUser(); name != "" {
			username = name
		}
	}
	if username == "" || username == "root" {
		return fmt.Errorf("cannot determine invoking user (PAM_USER, SUDO_USER, USER all unset or root)")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("looking up user %s: %w", username, err)
	}
	dir := filepath.Join(u.HomeDir, ".config", "monban")
	monban.ConfigDir = func() string { return dir }
	return nil
}

// consoleUser returns the owner of /dev/console (the logged-in GUI user on macOS).
func consoleUser() string {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return ""
	}
	// os.Stat returns *syscall.Stat_t via info.Sys()
	if sys := info.Sys(); sys != nil {
		if stat, ok := sys.(*syscall.Stat_t); ok {
			u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
			if err == nil {
				return u.Username
			}
		}
	}
	return ""
}

func authenticate() error {
	if err := resolveUserConfigDir(); err != nil {
		return err
	}

	// Try TTY-based auth first (works for terminal sudo).
	tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if ttyErr == nil {
		defer func() { _ = tty.Close() }()
		return authenticateViaTTY(tty)
	}

	// No TTY — try IPC to the running Monban app (GUI authorization flow).
	return authenticateViaIPC()
}

func authenticateViaTTY(tty *os.File) error {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := sc.DecodeHmacSalt()
	if err != nil {
		return err
	}

	_, _ = fmt.Fprint(tty, "monban: security key PIN: ")
	pinBytes, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return fmt.Errorf("reading PIN: %w", err)
	}
	pin := strings.TrimSpace(string(pinBytes))

	credIDs, err := sc.CollectCredentialIDs()
	if err != nil {
		return err
	}

	_, _ = fmt.Fprint(tty, "monban: touch your security key...\n")
	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	var verified bool
	for i := range sc.Credentials {
		cred := &sc.Credentials[i]
		credID, _ := monban.DecodeB64(cred.CredentialID)
		if assertion.CredentialID != nil && !bytes.Equal(credID, assertion.CredentialID) {
			continue
		}
		if err := monban.VerifyAssertionWithSalt(sc.RpID, cred, hmacSalt, assertion.AuthDataCBOR, assertion.Sig); err == nil {
			verified = true
			break
		}
	}

	if !verified {
		return fmt.Errorf("monban: no matching registered key")
	}

	_, _ = fmt.Fprint(tty, "monban: authenticated\n")
	return nil
}

func authenticateViaIPC() error {
	sockPath := monban.IPCSocketPath()

	conn, err := tryConnect(sockPath)
	if err != nil {
		// App not running — try launching it
		if launchErr := launchApp(); launchErr != nil {
			return fmt.Errorf("FIDO2 auth failed: no TTY and could not launch Monban: %w", launchErr)
		}

		conn, err = tryConnectWithRetry(sockPath, 5*time.Second)
		if err != nil {
			return fmt.Errorf("FIDO2 auth failed: could not connect to Monban after launch: %w", err)
		}
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	pamUser := os.Getenv("PAM_USER")
	if pamUser == "" {
		pamUser = os.Getenv("SUDO_USER")
	}
	pamService := os.Getenv("PAM_SERVICE")

	req := monban.IPCRequest{
		Type:    "auth",
		User:    pamUser,
		Service: pamService,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("sending IPC request: %w", err)
	}

	var resp monban.IPCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("reading IPC response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("auth denied: %s", resp.Error)
	}

	return nil
}

func tryConnect(sockPath string) (net.Conn, error) {
	return net.DialTimeout("unix", sockPath, 2*time.Second)
}

func tryConnectWithRetry(sockPath string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	delay := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		conn, err := tryConnect(sockPath)
		if err == nil {
			return conn, nil
		}
		time.Sleep(delay)
		if delay < 2*time.Second {
			delay *= 2
		}
	}
	return nil, fmt.Errorf("connection timed out")
}

func launchApp() error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", "-a", "Monban").Start()
	}
	return exec.Command("monban").Start()
}
