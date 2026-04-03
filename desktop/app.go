package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"monban/internal/monban"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type AppStatus struct {
	Locked     bool          `json:"locked"`
	Registered bool          `json:"registered"`
	Vaults     []VaultStatus `json:"vaults"`
}

type VaultStatus struct {
	Label  string `json:"label"`
	Path   string `json:"path"`
	Type   string `json:"type,omitempty"`
	Locked bool   `json:"locked"`
}

type KeyInfo struct {
	Label        string `json:"label"`
	CredentialID string `json:"credential_id"`
}

type DiskSpaceInfo struct {
	FolderGB      float64 `json:"folder_gb"`
	FreeGB        float64 `json:"free_gb"`
	SafeToMigrate bool    `json:"safe_to_migrate"`
}

// CombinedSettings is the frontend-facing settings object that merges
// fields from both user config and secure config.
type CombinedSettings struct {
	OpenOnStartup       bool   `json:"open_on_startup"`
	ForceAuthentication bool   `json:"force_authentication"`
	SudoGate            string `json:"sudo_gate"`
}

type App struct {
	mu           sync.Mutex
	config       *monban.Config
	secureCfg    *monban.SecureConfig
	locked       bool
	masterSecret []byte // in-memory only, zeroed on lock
	encKey       []byte // derived file encryption key, zeroed on lock
	window       *application.WebviewWindow
}

func NewApp() *App {
	return &App{locked: true}
}

func (a *App) SetWindow(w *application.WebviewWindow) {
	a.window = w
}

// StartDeviceWatcher polls for YubiKey presence and locks when removed.
func (a *App) StartDeviceWatcher() {
	const missThreshold = 2 // require 2 consecutive misses to avoid USB glitches
	misses := 0

	go func() {
		for {
			time.Sleep(2 * time.Second)

			if a.IsLocked() {
				misses = 0
				continue
			}

			connected, err := monban.DetectDevice()
			if err != nil || !connected {
				misses++
				if misses >= missThreshold {
					log.Println("monban: YubiKey removed, locking vaults...")
					if err := a.Lock(); err != nil {
						log.Printf("monban: error locking on device removal: %v", err)
					}
					a.EnterFullscreen()
					if a.window != nil {
						a.window.EmitEvent("app:locked")
					}
					misses = 0
				}
			} else {
				misses = 0
			}
		}
	}()
}

// ExitFullscreen switches the window to normal mode after unlock.
func (a *App) ExitFullscreen() {
	ExitKioskMode()
	if a.window != nil {
		a.window.UnFullscreen()
		a.window.SetSize(420, 300)
		a.window.Center()
		a.window.SetCloseButtonState(application.ButtonEnabled)
		a.window.SetMinimiseButtonState(application.ButtonEnabled)
		a.window.SetMaximiseButtonState(application.ButtonEnabled)
		a.window.SetAlwaysOnTop(false)
	}
}

// ResizeWindow resizes the window to fit content.
func (a *App) ResizeWindow(width, height int) {
	if a.window != nil {
		a.window.SetSize(width, height)
	}
}

// EnterFullscreen switches the window to fullscreen for the lock screen.
// If force authentication is enabled, activates kiosk mode.
func (a *App) EnterFullscreen() {
	if a.window == nil {
		return
	}
	settings := a.GetSettings()
	if settings.ForceAuthentication {
		a.window.SetCloseButtonState(application.ButtonHidden)
		a.window.SetMinimiseButtonState(application.ButtonHidden)
		a.window.SetMaximiseButtonState(application.ButtonHidden)
		a.window.SetAlwaysOnTop(true)
		a.window.Fullscreen()
		EnterKioskMode()
	}
}

func (a *App) IsLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.locked
}

func (a *App) IsRegistered() bool {
	return monban.SecureConfigExists()
}

// GetSettings returns the combined settings from both configs.
func (a *App) GetSettings() CombinedSettings {
	cfg, err := monban.LoadConfig()
	if err != nil {
		cfg = &monban.Config{Settings: monban.Settings{OpenOnStartup: true}}
	}

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		sc = &monban.SecureConfig{ForceAuthentication: true}
	}

	return CombinedSettings{
		OpenOnStartup:       cfg.Settings.OpenOnStartup,
		ForceAuthentication: sc.ForceAuthentication,
		SudoGate:            sc.SudoGate,
	}
}

// UpdateSettings saves settings, routing each field to the appropriate config.
// Sensitive settings (force_authentication, sudo_gate) go to the secure config.
// All privileged writes are batched into a single root escalation prompt.
func (a *App) UpdateSettings(settings CombinedSettings) error {
	// --- User config (no escalation) ---
	cfg, err := monban.LoadConfig()
	if err != nil {
		return err
	}
	cfg.Settings.OpenOnStartup = settings.OpenOnStartup
	if err := monban.SaveConfig(cfg); err != nil {
		return err
	}

	if settings.OpenOnStartup {
		installLaunchAgent()
	} else {
		removeLaunchAgent()
	}

	// --- Secure config (single batched root escalation) ---
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil // not registered yet
	}

	prevForceAuth := sc.ForceAuthentication
	prevSudoGate := sc.SudoGate
	sudoGateChanged := settings.SudoGate != prevSudoGate
	secureChanged := settings.ForceAuthentication != prevForceAuth || sudoGateChanged

	if !secureChanged {
		return nil
	}

	// Build all privileged writes for a single escalation.
	var writes []monban.PrivilegedWrite

	// 1. Updated secure config
	sc.ForceAuthentication = settings.ForceAuthentication
	sc.SudoGate = settings.SudoGate
	scData, err := monban.MarshalSecureConfig(sc)
	if err != nil {
		return err
	}
	writes = append(writes, monban.PrivilegedWrite{
		Path:      monban.SecureConfigPath(),
		Content:   string(scData),
		Mode:      0644,
		MkdirPath: monban.SecureConfigDir(),
	})

	// 2. PAM config update (if sudo gate changed)
	//    On macOS Tahoe+, /etc/pam.d/ is TCC-protected and cannot be written
	//    via osascript. The PAM file must be installed via Terminal with sudo.
	//    We provide the command via GetSudoGateCommand() for the UI to display.

	// Single privilege escalation for all writes.
	if err := monban.BatchPrivilegedWrites(writes); err != nil {
		return fmt.Errorf("applying secure settings: %w", err)
	}

	// Post-escalation side effects
	if settings.ForceAuthentication && !prevForceAuth && !HasAccessibilityPermission() {
		PromptAccessibilityPermission()
	}

	return nil
}

// GetSudoGateCommand returns the terminal command the user should run to
// install or remove the sudo gate PAM config. On macOS Tahoe+, /etc/pam.d/
// is TCC-protected and can only be written from Terminal with sudo.
func (a *App) GetSudoGateCommand(mode string) (string, error) {
	helperSrc, err := monban.PamHelperPath()
	if err != nil {
		return "", err
	}

	if mode == "" || mode == "off" {
		return fmt.Sprintf("sudo '%s' --uninstall", helperSrc), nil
	}

	return fmt.Sprintf("sudo '%s' --install %s", helperSrc, mode), nil
}

// DetectDevice checks if a FIDO2 device is connected.
func (a *App) DetectDevice() (bool, error) {
	return monban.DetectDevice()
}

// Register creates a new FIDO2 credential and initializes the config.
// If this is the first credential, generates the master secret and hmac salt.
// If credentials already exist, wraps the existing master secret with the new key.
func (a *App) Register(pin string, label string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Register credential on YubiKey
	cred, err := monban.Register(pin)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	var sc *monban.SecureConfig
	var hmacSalt []byte
	var masterSecret []byte

	if monban.SecureConfigExists() {
		// Adding to existing config — must be unlocked
		if a.locked || a.masterSecret == nil {
			return fmt.Errorf("must be unlocked to add a new key")
		}
		sc, err = monban.LoadSecureConfig()
		if err != nil {
			return fmt.Errorf("loading secure config: %w", err)
		}
		hmacSalt, err = monban.DecodeB64(sc.HmacSalt)
		if err != nil {
			return fmt.Errorf("decoding hmac salt: %w", err)
		}
		masterSecret = a.masterSecret
	} else {
		// First registration — generate everything
		hmacSalt, err = monban.GenerateHmacSalt()
		if err != nil {
			return err
		}
		masterSecret, err = monban.GenerateMasterSecret()
		if err != nil {
			return err
		}
		sc = &monban.SecureConfig{
			RpID:                "monban.local",
			HmacSalt:            monban.EncodeB64(hmacSalt),
			Credentials:         []monban.CredentialEntry{},
			ForceAuthentication: true,
		}

		// Create user config if it doesn't exist
		if !monban.ConfigExists() {
			cfg := &monban.Config{
				Vaults: []monban.VaultEntry{},
				Settings: monban.Settings{
					OpenOnStartup: true,
				},
			}
			if err := monban.SaveConfig(cfg); err != nil {
				return fmt.Errorf("saving user config: %w", err)
			}
		}
	}

	// Assert immediately to get hmac-secret for key wrapping
	assertion, err := monban.Assert(pin, [][]byte{cred.ID}, hmacSalt)
	if err != nil {
		return fmt.Errorf("assertion for key wrapping: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return fmt.Errorf("YubiKey did not return hmac-secret")
	}

	// Verify the assertion signature
	cdh := sha256.Sum256(hmacSalt)
	if err := monban.VerifyAssertion(cred.PubX, cred.PubY, cdh[:], assertion.AuthDataCBOR, assertion.Sig); err != nil {
		return fmt.Errorf("assertion verification failed: %w", err)
	}

	// Derive wrapping key and wrap the master secret
	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return err
	}

	wrapped, err := monban.WrapKey(wrappingKey, masterSecret)
	if err != nil {
		return fmt.Errorf("wrapping master secret: %w", err)
	}

	// Add credential to secure config
	sc.Credentials = append(sc.Credentials, monban.CredentialEntry{
		Label:        label,
		CredentialID: monban.EncodeB64(cred.ID),
		PublicKeyX:   monban.EncodeB64(cred.PubX),
		PublicKeyY:   monban.EncodeB64(cred.PubY),
		WrappedKey:   monban.EncodeB64(wrapped),
	})

	// Save secure config (root escalation)
	if err := monban.SaveSecureConfig(sc); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	// Derive encryption key and unlock
	encKey, err := monban.DeriveEncryptionKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}

	cfg, _ := monban.LoadConfig()
	a.config = cfg
	a.secureCfg = sc
	a.masterSecret = masterSecret
	a.encKey = encKey
	a.locked = false

	return nil
}

// Unlock performs FIDO2 assertion, unwraps the master secret, and decrypts all vaults.
func (a *App) Unlock(pin string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return fmt.Errorf("loading secure config: %w", err)
	}

	if len(sc.Credentials) == 0 {
		return fmt.Errorf("no credentials registered")
	}

	hmacSalt, err := monban.DecodeB64(sc.HmacSalt)
	if err != nil {
		return fmt.Errorf("decoding hmac salt: %w", err)
	}

	// Collect all credential IDs
	credIDs := make([][]byte, len(sc.Credentials))
	for i, c := range sc.Credentials {
		id, err := monban.DecodeB64(c.CredentialID)
		if err != nil {
			return fmt.Errorf("decoding credential ID: %w", err)
		}
		credIDs[i] = id
	}

	// Assert with all credential IDs — device responds to the one it recognizes
	assertion, err := monban.Assert(pin, credIDs, hmacSalt)
	if err != nil {
		return fmt.Errorf("FIDO2 assertion failed: %w", err)
	}

	if len(assertion.HMACSecret) == 0 {
		return fmt.Errorf("YubiKey did not return hmac-secret")
	}

	// Derive wrapping key from this assertion's hmac-secret
	wrappingKey, err := monban.DeriveWrappingKey(assertion.HMACSecret, hmacSalt)
	defer monban.ZeroBytes(assertion.HMACSecret, wrappingKey)
	if err != nil {
		return err
	}

	// Try unwrapping each credential's wrapped key — AES-GCM auth tag validates only for the correct one
	var masterSecret []byte
	var matchedCred *monban.CredentialEntry
	for i := range sc.Credentials {
		wrapped, err := monban.DecodeB64(sc.Credentials[i].WrappedKey)
		if err != nil {
			continue
		}
		secret, err := monban.UnwrapKey(wrappingKey, wrapped)
		if err != nil {
			continue // wrong key, try next
		}
		masterSecret = secret
		matchedCred = &sc.Credentials[i]
		break
	}

	if masterSecret == nil {
		return fmt.Errorf("could not unwrap master secret — no matching credential found")
	}

	// Verify assertion signature with the matched credential's public key
	pubX, err := monban.DecodeB64(matchedCred.PublicKeyX)
	if err != nil {
		return fmt.Errorf("decoding public key X: %w", err)
	}
	pubY, err := monban.DecodeB64(matchedCred.PublicKeyY)
	if err != nil {
		return fmt.Errorf("decoding public key Y: %w", err)
	}
	cdh := sha256.Sum256(hmacSalt)
	if err := monban.VerifyAssertion(pubX, pubY, cdh[:], assertion.AuthDataCBOR, assertion.Sig); err != nil {
		return fmt.Errorf("assertion verification failed: %w", err)
	}

	// Derive file encryption key
	encKey, err := monban.DeriveEncryptionKey(masterSecret, hmacSalt)
	if err != nil {
		return err
	}

	// Load user config for vault list
	cfg, err := monban.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Unlock all vaults
	for _, v := range cfg.Vaults {
		if err := monban.UnlockVaultEntry(encKey, v); err != nil {
			return err
		}
	}

	a.config = cfg
	a.secureCfg = sc
	a.masterSecret = masterSecret
	a.encKey = encKey
	a.locked = false

	return nil
}

// Lock encrypts all vaults and clears secrets from memory.
func (a *App) Lock() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.config != nil && a.encKey != nil {
		for _, v := range a.config.Vaults {
			if err := monban.LockVaultEntry(a.encKey, v); err != nil {
				return err
			}
		}
	}

	// Zero sensitive data
	monban.ZeroBytes(a.masterSecret)
	monban.ZeroBytes(a.encKey)
	a.masterSecret = nil
	a.encKey = nil
	a.locked = true

	return nil
}

// GetStatus returns the current app state.
func (a *App) GetStatus() AppStatus {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := AppStatus{
		Locked:     a.locked,
		Registered: monban.SecureConfigExists(),
	}

	cfg, err := monban.LoadConfig()
	if err != nil {
		return status
	}

	for _, v := range cfg.Vaults {
		locked := false
		if v.IsFile() {
			locked = monban.IsFileLocked(v.Path)
		} else {
			locked = monban.IsLocked(v.Path)
		}
		status.Vaults = append(status.Vaults, VaultStatus{
			Label:  v.Label,
			Path:   v.Path,
			Type:   v.Type,
			Locked: locked,
		})
	}

	return status
}

// ListKeys returns information about registered YubiKeys.
func (a *App) ListKeys() ([]KeyInfo, error) {
	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return nil, err
	}

	keys := make([]KeyInfo, len(sc.Credentials))
	for i, c := range sc.Credentials {
		keys[i] = KeyInfo{
			Label:        c.Label,
			CredentialID: c.CredentialID,
		}
	}
	return keys, nil
}

// RemoveKey removes a registered credential. Cannot remove the last key.
func (a *App) RemoveKey(credentialID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, err := monban.LoadSecureConfig()
	if err != nil {
		return err
	}

	if len(sc.Credentials) <= 1 {
		return fmt.Errorf("cannot remove the last registered key")
	}

	idx := -1
	for i, c := range sc.Credentials {
		if c.CredentialID == credentialID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("credential not found")
	}

	sc.Credentials = append(sc.Credentials[:idx], sc.Credentials[idx+1:]...)

	// Save secure config (root escalation)
	if err := monban.SaveSecureConfig(sc); err != nil {
		return fmt.Errorf("saving secure config: %w", err)
	}

	a.secureCfg = sc
	return nil
}

// CheckDiskSpace returns disk space info for a folder.
func (a *App) CheckDiskSpace(path string) DiskSpaceInfo {
	folderBytes, err := monban.FolderSize(path)
	if err != nil {
		return DiskSpaceInfo{}
	}

	freeBytes, err := monban.FreeSpace(path)
	if err != nil {
		return DiskSpaceInfo{}
	}

	folderGB := float64(folderBytes) / (1024 * 1024 * 1024)
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)

	return DiskSpaceInfo{
		FolderGB:      folderGB,
		FreeGB:        freeGB,
		SafeToMigrate: freeBytes >= 2*folderBytes,
	}
}

// AddFolder adds a folder to the protected list. Files are encrypted in place on lock.
func (a *App) AddFolder(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add folders")
	}

	cfg, err := monban.LoadConfig()
	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	if monban.FindVaultIndex(cfg.Vaults, absPath) != -1 {
		return fmt.Errorf("already protected: %s", absPath)
	}

	// Verify folder exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("folder not found: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", absPath)
	}

	// Disk space check — need room for .enc copies alongside originals during lock
	folderBytes, err := monban.FolderSize(absPath)
	if err != nil {
		return fmt.Errorf("measuring folder: %w", err)
	}
	freeBytes, err := monban.FreeSpace(absPath)
	if err != nil {
		return fmt.Errorf("checking free space: %w", err)
	}
	if freeBytes < folderBytes {
		needGB := float64(folderBytes) / (1024 * 1024 * 1024)
		haveGB := float64(freeBytes) / (1024 * 1024 * 1024)
		return fmt.Errorf("insufficient disk space: need %.1f GB free, have %.1f GB", needGB, haveGB)
	}

	label := filepath.Base(absPath)

	cfg.Vaults = append(cfg.Vaults, monban.VaultEntry{
		Label: label,
		Path:  absPath,
	})
	if err := monban.SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.config = cfg
	return nil
}

// RemoveFolder removes a folder from protection. Ensures files are decrypted first.
func (a *App) RemoveFolder(folderPath string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to remove folders")
	}

	cfg, err := monban.LoadConfig()
	if err != nil {
		return err
	}

	idx := monban.FindVaultIndex(cfg.Vaults, folderPath)
	if idx == -1 {
		return fmt.Errorf("folder not found: %s", folderPath)
	}

	// Ensure files are decrypted
	if err := monban.UnlockVaultEntry(a.encKey, cfg.Vaults[idx]); err != nil {
		return err
	}

	cfg.Vaults = append(cfg.Vaults[:idx], cfg.Vaults[idx+1:]...)
	if err := monban.SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.config = cfg
	return nil
}

// AddFile adds a single file to the protected list.
func (a *App) AddFile(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked || a.encKey == nil {
		return fmt.Errorf("must be unlocked to add files")
	}

	cfg, err := monban.LoadConfig()
	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path: %w", err)
	}

	if monban.FindVaultIndex(cfg.Vaults, absPath) != -1 {
		return fmt.Errorf("already protected: %s", absPath)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, use AddFolder: %s", absPath)
	}

	// Disk space check
	freeBytes, err := monban.FreeSpace(absPath)
	if err != nil {
		return fmt.Errorf("checking free space: %w", err)
	}
	fileSize := info.Size()
	if freeBytes < fileSize {
		needMB := float64(fileSize) / (1024 * 1024)
		haveMB := float64(freeBytes) / (1024 * 1024)
		return fmt.Errorf("insufficient disk space: need %.1f MB free, have %.1f MB", needMB, haveMB)
	}

	label := filepath.Base(absPath)

	cfg.Vaults = append(cfg.Vaults, monban.VaultEntry{
		Label: label,
		Path:  absPath,
		Type:  "file",
	})
	if err := monban.SaveConfig(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	a.config = cfg
	return nil
}
